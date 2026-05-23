import CryptoKit
import Foundation
import Security

/// Local CA for TLS interception. Generates a root cert, stores key as PEM,
/// and creates per-host leaf certs on demand.
///
/// Thread-safety: all mutable state protected by lock.
final class CertificateAuthority: @unchecked Sendable {
    private let lock = NSLock()
    private var _caKeyPEM: String?
    private var _caCertPEM: String?
    private var leafCache: [String: (cert: String, key: String)] = [:]
    private static let maxLeafCacheSize = 200

    static let storagePath: URL = {
        let dir = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!.appendingPathComponent("ai.bouclier.app", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        // Tighten directory perms to user-only. Application Support
        // inherits the default 0o755 on macOS, which would let any
        // process running as another user list and traverse our path.
        // The CA private key was already removed after Keychain import,
        // but the leaf-cert temp directory created beneath this path
        // briefly holds key material during openssl invocations.
        chmod(dir.path, 0o700)
        return dir
    }()

    static let caKeyPath = storagePath.appendingPathComponent("ca.key")
    static let caCertPath = storagePath.appendingPathComponent("ca.pem")

    var isInstalled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _caKeyPEM != nil && _caCertPEM != nil
    }

    var caCertFilePath: String? {
        lock.lock()
        defer { lock.unlock() }
        return _caKeyPEM != nil ? Self.caCertPath.path : nil
    }

    init() {
        loadExisting()
    }

    /// Test-only constructor that bypasses the Keychain load and accepts
    /// PEMs directly. Exposed so the end-to-end proxy test can stand up
    /// a real CA without prompting for Keychain access or persisting a
    /// trust setting into the user's profile — both of which would make
    /// the test unsafe to run in CI.
    init(testingKeyPEM keyPEM: String, certPEM: String) {
        self._caKeyPEM = keyPEM
        self._caCertPEM = certPEM
    }

    // MARK: - Install

    func installCA() -> Bool {
        if isInstalled { return true }

        let keyPath = Self.caKeyPath.path
        let certPath = Self.caCertPath.path

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = [
            "req", "-x509", "-new", "-newkey", "rsa:2048",
            "-keyout", keyPath, "-out", certPath,
            "-days", "3650", "-nodes",
            "-subj", "/CN=Bouclier Proxy CA/O=Bouclier",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return false }
        } catch { return false }

        // Restrict permissions on key file. The parent dir is 0o700
        // (see `storagePath`), so other users can't traverse to it
        // anyway, but locking the file down too is cheap defence in
        // depth.
        chmod(keyPath, 0o600)

        guard let keyPEM = try? String(contentsOfFile: keyPath, encoding: .utf8),
              let certPEM = try? String(contentsOfFile: certPath, encoding: .utf8)
        else { return false }

        // Import key into Keychain for encrypted-at-rest storage
        storeKeyInKeychain(keyPEM)

        // Delete the plaintext key file — Keychain is the permanent
        // store. Log loudly on failure: leaving the key on disk is a
        // P0 leak even though the parent dir is mode 0o700.
        do {
            try FileManager.default.removeItem(atPath: keyPath)
        } catch {
            print("[bouclier.ai-ca] WARNING: failed to remove plaintext CA key file at \(keyPath): \(error)")
        }

        // Trust the CA cert
        guard let certDER = pemToDER(certPEM),
              let secCert = SecCertificateCreateWithData(nil, certDER as CFData)
        else { return false }

        let trustSettings: [String: Any] = [
            kSecTrustSettingsResult as String: NSNumber(value: 1), // kSecTrustSettingsResultTrustRoot
        ]
        let status = SecTrustSettingsSetTrustSettings(secCert, .user, [trustSettings] as CFArray)
        guard status == errSecSuccess else { return false }

        lock.lock()
        _caKeyPEM = keyPEM
        _caCertPEM = certPEM
        lock.unlock()

        return true
    }

    func uninstallCA() {
        lock.lock()
        let certPEM = _caCertPEM
        _caKeyPEM = nil
        _caCertPEM = nil
        leafCache.removeAll()
        lock.unlock()

        if let certPEM, let certDER = pemToDER(certPEM),
           let secCert = SecCertificateCreateWithData(nil, certDER as CFData)
        {
            SecTrustSettingsRemoveTrustSettings(secCert, .user)
        }

        deleteKeyFromKeychain()
        try? FileManager.default.removeItem(at: Self.caKeyPath) // cleanup any legacy file
        try? FileManager.default.removeItem(at: Self.caCertPath)
    }

    // MARK: - Leaf Certificates

    func leafCertAndKey(forHost host: String) -> (cert: String, key: String)? {
        lock.lock()
        if let cached = leafCache[host] {
            lock.unlock()
            return cached
        }
        let caKey = _caKeyPEM
        let caCert = _caCertPEM
        lock.unlock()

        guard let caKey, let caCert else { return nil }

        // Validate host
        let sanitized = host.replacingOccurrences(of: "[^a-zA-Z0-9.\\-]", with: "", options: .regularExpression)
        guard !sanitized.isEmpty, sanitized == host else { return nil }

        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        // Lock the temp dir down before any private-key bytes land in
        // it. openssl writes leaf.key + ca.key under here and inherits
        // the parent's umask; the parent FS-level perms are the only
        // thing stopping a same-user process from racing in to read.
        chmod(tempDir.path, 0o700)
        defer {
            do {
                try FileManager.default.removeItem(at: tempDir)
            } catch {
                // Leaving CA key material on disk is a P0 leak — log
                // loudly so an operator notices instead of silently
                // swallowing.
                print("[bouclier.ai-ca] WARNING: failed to remove leaf temp dir \(tempDir.path): \(error)")
            }
        }

        let leafKeyPath = tempDir.appendingPathComponent("leaf.key").path
        let leafCsrPath = tempDir.appendingPathComponent("leaf.csr").path
        let leafCertPath = tempDir.appendingPathComponent("leaf.pem").path
        let extPath = tempDir.appendingPathComponent("ext.cnf").path
        let caKeyTmp = tempDir.appendingPathComponent("ca.key").path
        let caCertTmp = tempDir.appendingPathComponent("ca.pem").path

        // Write CA files to temp — restrict permissions
        try? caKey.write(toFile: caKeyTmp, atomically: true, encoding: .utf8)
        chmod(caKeyTmp, 0o600)
        try? caCert.write(toFile: caCertTmp, atomically: true, encoding: .utf8)

        // Generate leaf key + CSR
        let csrProcess = Process()
        csrProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        csrProcess.arguments = [
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", leafKeyPath, "-out", leafCsrPath,
            "-subj", "/CN=\(sanitized)",
        ]
        csrProcess.standardOutput = FileHandle.nullDevice
        csrProcess.standardError = FileHandle.nullDevice
        try? csrProcess.run()
        csrProcess.waitUntilExit()
        guard csrProcess.terminationStatus == 0 else { return nil }

        chmod(leafKeyPath, 0o600)

        let extContent = """
        authorityKeyIdentifier=keyid,issuer
        basicConstraints=CA:FALSE
        keyUsage=digitalSignature,keyEncipherment
        extendedKeyUsage=serverAuth
        subjectAltName=DNS:\(sanitized)
        """
        try? extContent.write(toFile: extPath, atomically: true, encoding: .utf8)

        let signProcess = Process()
        signProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        signProcess.arguments = [
            "x509", "-req", "-in", leafCsrPath,
            "-CA", caCertTmp, "-CAkey", caKeyTmp,
            "-CAcreateserial", "-out", leafCertPath,
            "-days", "365", "-sha256",
            "-extfile", extPath,
        ]
        signProcess.standardOutput = FileHandle.nullDevice
        signProcess.standardError = FileHandle.nullDevice
        try? signProcess.run()
        signProcess.waitUntilExit()
        guard signProcess.terminationStatus == 0 else { return nil }

        guard let leafCert = try? String(contentsOfFile: leafCertPath, encoding: .utf8),
              let leafKey = try? String(contentsOfFile: leafKeyPath, encoding: .utf8)
        else { return nil }

        let result = (cert: leafCert, key: leafKey)

        lock.lock()
        // Evict oldest entries if cache is full
        if leafCache.count >= Self.maxLeafCacheSize {
            let toRemove = leafCache.count - Self.maxLeafCacheSize + 1
            for key in leafCache.keys.prefix(toRemove) {
                leafCache.removeValue(forKey: key)
            }
        }
        leafCache[host] = result
        lock.unlock()

        return result
    }

    // MARK: - Private

    private func loadExisting() {
        lock.lock()
        defer { lock.unlock() }

        // Load key from Keychain first, fall back to file (migration path)
        let key: String?
        if let keychainKey = loadKeyFromKeychain() {
            key = keychainKey
        } else if let fileKey = try? String(contentsOf: Self.caKeyPath, encoding: .utf8) {
            // Migrate: import file key to Keychain, then delete file
            storeKeyInKeychain(fileKey)
            try? FileManager.default.removeItem(at: Self.caKeyPath)
            key = fileKey
        } else {
            key = nil
        }

        if let key, let cert = try? String(contentsOf: Self.caCertPath, encoding: .utf8) {
            _caKeyPEM = key
            _caCertPEM = cert
        }
    }

    // MARK: - Keychain Key Storage

    private static let keychainTag = "ai.bouclier.ca.key".data(using: .utf8)!

    private func storeKeyInKeychain(_ keyPEM: String) {
        guard let keyData = keyPEM.data(using: .utf8) else { return }

        // Delete existing
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "ai.bouclier.app",
            kSecAttrAccount as String: "ca-private-key",
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // Store
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "ai.bouclier.app",
            kSecAttrAccount as String: "ca-private-key",
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    private func loadKeyFromKeychain() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "ai.bouclier.app",
            kSecAttrAccount as String: "ca-private-key",
            kSecReturnData as String: true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func deleteKeyFromKeychain() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "ai.bouclier.app",
            kSecAttrAccount as String: "ca-private-key",
        ]
        SecItemDelete(query as CFDictionary)
    }

    private func pemToDER(_ pem: String) -> Data? {
        let base64 = pem
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
        return Data(base64Encoded: base64)
    }
}
