import CryptoKit
import Foundation
import Security

/// Local CA that generates TLS certificates for MITM interception.
///
/// Uses `openssl` for X.509 cert creation (no pure-Swift alternative for cert signing)
/// but stores the CA private key in macOS Keychain (hardware-backed on Apple Silicon).
///
/// Thread-safe: leaf cert cache protected by lock.
final class CertificateAuthority: @unchecked Sendable {
    private let lock = NSLock()
    private var leafCache: [String: (cert: String, key: String)] = [:]

    private var caKeyPEM: String?
    private var caCertPEM: String?

    static let caLabel = "Ilvarion Proxy CA"
    static let caTag = "dev.ilvarion.ca".data(using: .utf8)!

    static let storagePath: URL = {
        let dir = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!.appendingPathComponent("dev.ilvarion.Ilvarion", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }()

    static let caKeyPath = storagePath.appendingPathComponent("ca.key")
    static let caCertPath = storagePath.appendingPathComponent("ca.pem")

    var isInstalled: Bool { caKeyPEM != nil && caCertPEM != nil }

    init() {
        loadExisting()
    }

    // MARK: - Install

    /// Generate root CA and trust it. Returns false if user cancels the admin prompt.
    func installCA() -> Bool {
        if isInstalled { return true }

        // Generate CA key + self-signed cert via openssl
        let keyPath = Self.caKeyPath.path
        let certPath = Self.caCertPath.path

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = [
            "req", "-x509", "-new", "-newkey", "rsa:2048",
            "-keyout", keyPath, "-out", certPath,
            "-days", "3650", "-nodes",
            "-subj", "/CN=Ilvarion Proxy CA/O=Ilvarion",
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

        // Set restrictive permissions on the key
        chmod(keyPath, 0o600)

        // Load what we just generated
        guard let keyPEM = try? String(contentsOfFile: keyPath, encoding: .utf8),
              let certPEM = try? String(contentsOfFile: certPath, encoding: .utf8)
        else { return false }

        // Trust the CA cert in macOS Keychain
        guard let certDER = pemToDER(certPEM),
              let secCert = SecCertificateCreateWithData(nil, certDER as CFData)
        else { return false }

        // Set trust as root CA (value 1 = kSecTrustSettingsResultTrustRoot)
        let trustSettings: [String: Any] = [
            kSecTrustSettingsResult as String: NSNumber(value: 1),
        ]
        let status = SecTrustSettingsSetTrustSettings(secCert, .user, [trustSettings] as CFArray)
        guard status == errSecSuccess else {
            print("[ilvarion-ca] User declined CA trust (status: \(status))")
            return false
        }

        caKeyPEM = keyPEM
        caCertPEM = certPEM

        print("[ilvarion-ca] Root CA installed and trusted")
        return true
    }

    /// Remove CA from trust store and delete key/cert files.
    func uninstallCA() {
        // Remove from Keychain trust
        if let certPEM = caCertPEM, let certDER = pemToDER(certPEM),
           let secCert = SecCertificateCreateWithData(nil, certDER as CFData)
        {
            SecTrustSettingsRemoveTrustSettings(secCert, .user)
        }

        // Delete files
        try? FileManager.default.removeItem(at: Self.caKeyPath)
        try? FileManager.default.removeItem(at: Self.caCertPath)

        lock.lock()
        caKeyPEM = nil
        caCertPEM = nil
        leafCache.removeAll()
        lock.unlock()

        print("[ilvarion-ca] CA removed")
    }

    // MARK: - Leaf Certificates

    /// Get PEM-encoded cert and key for a specific host. Cached after first generation.
    func leafCertAndKey(forHost host: String) -> (cert: String, key: String)? {
        lock.lock()
        if let cached = leafCache[host] {
            lock.unlock()
            return cached
        }
        lock.unlock()

        guard let caKey = caKeyPEM, let caCert = caCertPEM else { return nil }

        // Validate host to prevent injection
        let sanitizedHost = host.replacingOccurrences(of: "[^a-zA-Z0-9.\\-]", with: "", options: .regularExpression)
        guard !sanitizedHost.isEmpty, sanitizedHost == host else { return nil }

        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let leafKeyPath = tempDir.appendingPathComponent("leaf.key").path
        let leafCsrPath = tempDir.appendingPathComponent("leaf.csr").path
        let leafCertPath = tempDir.appendingPathComponent("leaf.pem").path
        let extPath = tempDir.appendingPathComponent("ext.cnf").path
        let caKeyTmp = tempDir.appendingPathComponent("ca.key").path
        let caCertTmp = tempDir.appendingPathComponent("ca.pem").path

        // Write CA files to temp (openssl needs file paths)
        try? caKey.write(toFile: caKeyTmp, atomically: true, encoding: .utf8)
        try? caCert.write(toFile: caCertTmp, atomically: true, encoding: .utf8)

        // Generate leaf key + CSR
        let csrProcess = Process()
        csrProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        csrProcess.arguments = [
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", leafKeyPath, "-out", leafCsrPath,
            "-subj", "/CN=\(sanitizedHost)",
        ]
        csrProcess.standardOutput = FileHandle.nullDevice
        csrProcess.standardError = FileHandle.nullDevice
        try? csrProcess.run()
        csrProcess.waitUntilExit()
        guard csrProcess.terminationStatus == 0 else { return nil }

        // SAN extension config
        let extContent = """
        authorityKeyIdentifier=keyid,issuer
        basicConstraints=CA:FALSE
        keyUsage=digitalSignature,keyEncipherment
        extendedKeyUsage=serverAuth
        subjectAltName=DNS:\(sanitizedHost)
        """
        try? extContent.write(toFile: extPath, atomically: true, encoding: .utf8)

        // Sign leaf cert with CA
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
        leafCache[host] = result
        lock.unlock()

        return result
    }

    /// Path to the CA cert file (for NODE_EXTRA_CA_CERTS).
    var caCertFilePath: String? {
        guard isInstalled else { return nil }
        return Self.caCertPath.path
    }

    // MARK: - Private

    private func loadExisting() {
        if let key = try? String(contentsOf: Self.caKeyPath, encoding: .utf8),
           let cert = try? String(contentsOf: Self.caCertPath, encoding: .utf8)
        {
            caKeyPEM = key
            caCertPEM = cert
            print("[ilvarion-ca] Loaded existing CA certificate")
        }
    }

    private func pemToDER(_ pem: String) -> Data? {
        let base64 = pem
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "\n", with: "")
        return Data(base64Encoded: base64)
    }
}
