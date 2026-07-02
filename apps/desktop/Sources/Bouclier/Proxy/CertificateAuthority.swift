import Foundation
import Security

/// Cleanup-only remnant of the local CA that used to back "extreme mode"
/// (CA-based TLS interception, removed). Bouclier no longer installs or
/// uses a CA — this type exists solely so `ProxyManager`'s one-shot
/// migration (`ExtremeModeMigration`) can detect a CA left over from a
/// pre-removal install and uninstall it: remove the Keychain-stored
/// private key, strip the trust setting, and delete any legacy on-disk
/// key/cert files. Safe to delete entirely once telemetry-free confidence
/// exists that every install has migrated (there's no telemetry, so in
/// practice: after a few releases with no reports of stale CA state).
final class CertificateAuthority: @unchecked Sendable {
    private let lock = NSLock()
    private var _caCertPEM: String?

    static let storagePath: URL = {
        let dir = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!.appendingPathComponent("ai.bouclier.app", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        chmod(dir.path, 0o700)
        return dir
    }()

    static let caKeyPath = storagePath.appendingPathComponent("ca.key")
    static let caCertPath = storagePath.appendingPathComponent("ca.pem")

    var isInstalled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _caCertPEM != nil
    }

    init() {
        loadExisting()
    }

    /// Remove the CA entirely: strip the trust setting, delete the
    /// Keychain-stored key, and remove any legacy on-disk files. No-op
    /// (but safe) if no CA was ever installed.
    func uninstallCA() {
        lock.lock()
        let certPEM = _caCertPEM
        _caCertPEM = nil
        lock.unlock()

        if let certPEM, let certDER = pemToDER(certPEM),
           let secCert = SecCertificateCreateWithData(nil, certDER as CFData)
        {
            SecTrustSettingsRemoveTrustSettings(secCert, .user)
        }

        deleteKeyFromKeychain()
        try? FileManager.default.removeItem(at: Self.caKeyPath)
        try? FileManager.default.removeItem(at: Self.caCertPath)
    }

    // MARK: - Private

    private func loadExisting() {
        lock.lock()
        defer { lock.unlock() }
        // Only need to know whether a CA exists (for `isInstalled` and to
        // gate the migration) — the key material itself is never used
        // again, so it's read only far enough to confirm presence.
        if let cert = try? String(contentsOf: Self.caCertPath, encoding: .utf8) {
            _caCertPEM = cert
        }
    }

    // MARK: - Keychain Key Storage

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
