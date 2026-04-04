import Foundation
import Security

/// Manages a local root CA certificate for TLS interception.
///
/// On first launch, generates a self-signed root CA and stores it in the user's Keychain.
/// The user is prompted to trust it (standard macOS admin password dialog).
/// Per-host leaf certificates are generated on-demand and cached.
final class CertificateAuthority: @unchecked Sendable {
    private let lock = NSLock()
    private var leafCache: [String: SecIdentity] = [:]

    private var rootKey: SecKey?
    private var rootCert: SecCertificate?

    static let caLabel = "Ilvarion Proxy CA"
    static let caTag = "dev.ilvarion.ca".data(using: .utf8)!

    var isInstalled: Bool {
        rootKey != nil && rootCert != nil
    }

    init() {
        loadExisting()
    }

    // MARK: - Setup (called once, prompts admin)

    /// Generate the root CA and install it as a trusted root. Returns false if user cancels.
    func installCA() -> Bool {
        // Check if already installed
        if isInstalled { return true }

        // Generate RSA 2048 key pair
        guard let keyPair = generateKeyPair() else {
            print("[ilvarion-ca] Failed to generate key pair")
            return false
        }

        let (privateKey, publicKey) = keyPair

        // Create self-signed root certificate
        guard let cert = createSelfSignedCert(privateKey: privateKey, publicKey: publicKey) else {
            print("[ilvarion-ca] Failed to create self-signed certificate")
            return false
        }

        // Store in Keychain
        guard storeInKeychain(privateKey: privateKey, certificate: cert) else {
            print("[ilvarion-ca] Failed to store in Keychain")
            return false
        }

        // Trust the CA (triggers admin password prompt)
        guard trustCertificate(cert) else {
            print("[ilvarion-ca] User declined to trust CA")
            return false
        }

        rootKey = privateKey
        rootCert = cert

        print("[ilvarion-ca] Root CA installed and trusted")
        return true
    }

    /// Remove the CA from Keychain and untrust it.
    func uninstallCA() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: Self.caLabel,
        ]
        SecItemDelete(query as CFDictionary)

        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.caTag,
        ]
        SecItemDelete(keyQuery as CFDictionary)

        lock.lock()
        leafCache.removeAll()
        rootKey = nil
        rootCert = nil
        lock.unlock()

        print("[ilvarion-ca] CA removed")
    }

    // MARK: - Per-Host Leaf Certificates

    /// Get or create a TLS identity for a specific host (e.g., "api.openai.com").
    func identityForHost(_ host: String) -> SecIdentity? {
        lock.lock()
        if let cached = leafCache[host] {
            lock.unlock()
            return cached
        }
        lock.unlock()

        guard let caKey = rootKey, let caCert = rootCert else { return nil }

        // Generate leaf key pair
        guard let leafKeyPair = generateKeyPair(tag: "dev.ilvarion.leaf.\(host)") else { return nil }
        let (leafPrivateKey, leafPublicKey) = leafKeyPair

        // Create leaf cert signed by CA
        guard let leafCert = createLeafCert(
            host: host,
            publicKey: leafPublicKey,
            signingKey: caKey,
            caCert: caCert
        ) else { return nil }

        // Create identity from key + cert
        // Store leaf cert temporarily in keychain to create identity
        let addCertQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: leafCert,
            kSecAttrLabel as String: "Ilvarion Leaf: \(host)",
        ]
        SecItemAdd(addCertQuery as CFDictionary, nil)

        let addKeyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: leafPrivateKey,
            kSecAttrLabel as String: "Ilvarion Leaf Key: \(host)",
        ]
        SecItemAdd(addKeyQuery as CFDictionary, nil)

        // Retrieve identity
        let identityQuery: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: "Ilvarion Leaf: \(host)",
            kSecReturnRef as String: true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(identityQuery as CFDictionary, &item)
        guard status == errSecSuccess, let identity = item else {
            print("[ilvarion-ca] Failed to create identity for \(host): \(status)")
            return nil
        }

        let secIdentity = identity as! SecIdentity

        lock.lock()
        leafCache[host] = secIdentity
        lock.unlock()

        return secIdentity
    }

    // MARK: - Private: Key Generation

    private func generateKeyPair(tag: String = "dev.ilvarion.ca") -> (SecKey, SecKey)? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecAttrApplicationTag as String: tag.data(using: .utf8)!,
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print("[ilvarion-ca] Key generation error: \(error?.takeRetainedValue().localizedDescription ?? "unknown")")
            return nil
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }
        return (privateKey, publicKey)
    }

    // MARK: - Private: Certificate Creation

    private func createSelfSignedCert(privateKey: SecKey, publicKey: SecKey) -> SecCertificate? {
        // Use the Security framework's SecCertificateCreateWithData approach.
        // For self-signed CA generation, we use a helper process since Security.framework
        // doesn't have a pure Swift API for cert creation.
        // We shell out to `openssl` which is available on all macOS systems.

        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let keyPath = tempDir.appendingPathComponent("ca.key").path
        let certPath = tempDir.appendingPathComponent("ca.pem").path

        // Export the private key to PEM via openssl
        // Generate key + self-signed cert in one openssl command
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        process.arguments = [
            "req", "-x509", "-new", "-newkey", "rsa:2048",
            "-keyout", keyPath, "-out", certPath,
            "-days", "3650", "-nodes",
            "-subj", "/CN=Ilvarion Proxy CA/O=Ilvarion/C=US",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ]
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return nil }
        } catch { return nil }

        // Read the generated cert
        guard let certData = try? Data(contentsOf: URL(fileURLWithPath: certPath)),
              let certPEM = String(data: certData, encoding: .utf8)
        else { return nil }

        // Convert PEM to DER
        let base64 = certPEM
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "\n", with: "")

        guard let derData = Data(base64Encoded: base64),
              let cert = SecCertificateCreateWithData(nil, derData as CFData)
        else { return nil }

        // Also import the private key from PEM
        guard let keyData = try? Data(contentsOf: URL(fileURLWithPath: keyPath)),
              let keyPEM = String(data: keyData, encoding: .utf8)
        else { return nil }

        let keyBase64 = keyPEM
            .replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
            .replacingOccurrences(of: "\n", with: "")

        if let keyDER = Data(base64Encoded: keyBase64) {
            let keyAttrs: [String: Any] = [
                kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
                kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                kSecAttrKeySizeInBits as String: 2048,
            ]
            if let importedKey = SecKeyCreateWithData(keyDER as CFData, keyAttrs as CFDictionary, nil) {
                rootKey = importedKey
            }
        }

        return cert
    }

    private func createLeafCert(host: String, publicKey: SecKey, signingKey: SecKey, caCert: SecCertificate) -> SecCertificate? {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let caKeyPath = tempDir.appendingPathComponent("ca.key").path
        let caCertPath = tempDir.appendingPathComponent("ca.pem").path
        let leafKeyPath = tempDir.appendingPathComponent("leaf.key").path
        let leafCsrPath = tempDir.appendingPathComponent("leaf.csr").path
        let leafCertPath = tempDir.appendingPathComponent("leaf.pem").path
        let extPath = tempDir.appendingPathComponent("ext.cnf").path

        // Export CA key and cert
        exportKeyToPEM(signingKey, path: caKeyPath)
        exportCertToPEM(caCert, path: caCertPath)

        // Generate leaf key + CSR
        let genProcess = Process()
        genProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        genProcess.arguments = [
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", leafKeyPath, "-out", leafCsrPath,
            "-subj", "/CN=\(host)/O=Ilvarion Proxy",
        ]
        genProcess.standardError = FileHandle.nullDevice
        try? genProcess.run()
        genProcess.waitUntilExit()

        // Write extensions config for SAN
        let extContent = """
        authorityKeyIdentifier=keyid,issuer
        basicConstraints=CA:FALSE
        keyUsage=digitalSignature,keyEncipherment
        extendedKeyUsage=serverAuth
        subjectAltName=DNS:\(host)
        """
        try? extContent.write(toFile: extPath, atomically: true, encoding: .utf8)

        // Sign with CA
        let signProcess = Process()
        signProcess.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        signProcess.arguments = [
            "x509", "-req", "-in", leafCsrPath,
            "-CA", caCertPath, "-CAkey", caKeyPath,
            "-CAcreateserial", "-out", leafCertPath,
            "-days", "365", "-sha256",
            "-extfile", extPath,
        ]
        signProcess.standardError = FileHandle.nullDevice
        try? signProcess.run()
        signProcess.waitUntilExit()
        guard signProcess.terminationStatus == 0 else { return nil }

        // Read leaf cert
        guard let certData = try? Data(contentsOf: URL(fileURLWithPath: leafCertPath)),
              let certPEM = String(data: certData, encoding: .utf8)
        else { return nil }

        let base64 = certPEM
            .replacingOccurrences(of: "-----BEGIN CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "-----END CERTIFICATE-----", with: "")
            .replacingOccurrences(of: "\n", with: "")

        guard let derData = Data(base64Encoded: base64) else { return nil }
        return SecCertificateCreateWithData(nil, derData as CFData)
    }

    // MARK: - Private: Keychain

    private func loadExisting() {
        // Try to load existing CA key
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Self.caTag,
            kSecReturnRef as String: true,
        ]
        var keyItem: CFTypeRef?
        if SecItemCopyMatching(keyQuery as CFDictionary, &keyItem) == errSecSuccess {
            rootKey = (keyItem as! SecKey)
        }

        // Try to load existing CA cert
        let certQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: Self.caLabel,
            kSecReturnRef as String: true,
        ]
        var certItem: CFTypeRef?
        if SecItemCopyMatching(certQuery as CFDictionary, &certItem) == errSecSuccess {
            rootCert = (certItem as! SecCertificate)
        }
    }

    private func storeInKeychain(privateKey: SecKey, certificate: SecCertificate) -> Bool {
        // Store private key
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: privateKey,
            kSecAttrApplicationTag as String: Self.caTag,
            kSecAttrLabel as String: Self.caLabel,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let keyStatus = SecItemAdd(keyQuery as CFDictionary, nil)
        guard keyStatus == errSecSuccess || keyStatus == errSecDuplicateItem else { return false }

        // Store certificate
        let certQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrLabel as String: Self.caLabel,
        ]
        let certStatus = SecItemAdd(certQuery as CFDictionary, nil)
        return certStatus == errSecSuccess || certStatus == errSecDuplicateItem
    }

    private func trustCertificate(_ cert: SecCertificate) -> Bool {
        // Add to system trust settings — this triggers the admin password prompt
        let status = SecTrustSettingsSetTrustSettings(cert, .user, nil)
        return status == errSecSuccess
    }

    // MARK: - Private: PEM Export Helpers

    private func exportKeyToPEM(_ key: SecKey, path: String) {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(key, &error) as Data? else { return }
        let pem = "-----BEGIN PRIVATE KEY-----\n\(data.base64EncodedString(options: .lineLength76Characters))\n-----END PRIVATE KEY-----\n"
        try? pem.write(toFile: path, atomically: true, encoding: .utf8)
    }

    private func exportCertToPEM(_ cert: SecCertificate, path: String) {
        let data = SecCertificateCopyData(cert) as Data
        let pem = "-----BEGIN CERTIFICATE-----\n\(data.base64EncodedString(options: .lineLength76Characters))\n-----END CERTIFICATE-----\n"
        try? pem.write(toFile: path, atomically: true, encoding: .utf8)
    }
}
