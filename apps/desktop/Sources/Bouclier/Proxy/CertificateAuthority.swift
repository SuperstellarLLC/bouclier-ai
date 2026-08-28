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
    private var _caCertificateDER: Data?

    private static let keychainService = "ai.bouclier.app"
    private static let privateKeyAccount = "ca-private-key"
    private static let certificateBackupAccount = "legacy-ca-certificate-der"

    private enum TrustState {
        case trusted
        case absent
        case unreadable
    }

    private enum PotentialLegacyTrustState {
        case found
        case absent
        case unreadable
    }

    private enum KeychainDataState {
        case value(Data)
        case absent
        case unreadable
    }

    private enum PathEntryState {
        case present(stat)
        case absent
        case unreadable
    }

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
        let certificateDER = _caCertificateDER
        lock.unlock()

        guard let certificateDER,
              let certificate = SecCertificateCreateWithData(
                nil, certificateDER as CFData
              )
        else {
            // Corrupt/missing retry material is not proof of absence. Report
            // conservative state while any Bouclier-owned CA artifact remains.
            return hasUnresolvedLegacyMaterial()
        }
        return Self.trustState(for: certificate) != .absent
    }

    init() {
        loadExisting()
    }

    /// Remove the CA entirely: strip the trust setting, delete the
    /// Keychain-stored key, and remove any legacy on-disk files. No-op
    /// (but safe) if no CA was ever installed.
    @discardableResult
    func uninstallCA() -> Bool {
        lock.lock()
        let certificateDER = _caCertificateDER
        lock.unlock()

        guard let certificateDER else {
            // With neither exact DER nor any remaining app-owned evidence,
            // there is nothing safe to identify or remove. If evidence does
            // remain (for example a corrupt ca.pem), require manual attention
            // instead of guessing by certificate name and risking another CA.
            return !hasUnresolvedLegacyMaterial()
        }
        guard let certificate = SecCertificateCreateWithData(
            nil, certificateDER as CFData
        ) else { return false }

        switch Self.trustState(for: certificate) {
        case .trusted:
            let status = SecTrustSettingsRemoveTrustSettings(certificate, .user)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                return false
            }
        case .absent:
            break
        case .unreadable:
            return false
        }

        // A successful mutation callback is not the postcondition. Keep the
        // exact DER and files as retry material until trust settings can be
        // read back and prove that this certificate is no longer trusted.
        guard Self.trustState(for: certificate) == .absent else { return false }

        let privateKeyComplete = deleteKeyFromKeychain()
        let keyFileComplete = removeIfPresent(Self.caKeyPath)
        let certificateFileComplete = removeIfPresent(Self.caCertPath)
        guard privateKeyComplete, keyFileComplete, certificateFileComplete
        else { return false }
        // Delete the exact-DER backup last, after every other cleanup target,
        // so any partial filesystem/Keychain result remains safely retryable.
        guard deleteCertificateBackupFromKeychain() else { return false }

        lock.lock()
        _caCertificateDER = nil
        lock.unlock()
        return true
    }

    // MARK: - Private

    private func loadExisting() {
        // Prefer the app-owned Keychain backup when present. It survives a
        // missing ca.pem and prevents cleanup from having to identify a root
        // by a non-unique subject string. Older installs do not have the
        // backup, so seed it from their regular on-disk PEM before mutation.
        let storedBackup = readGenericPassword(account: Self.certificateBackupAccount)
        let backup = storedBackup.flatMap(Self.validCertificateDER)
        let fileDER = readRegularCertificateFile().flatMap(Self.certificateDER(fromPEM:))
        let certificateDER = backup ?? fileDER ?? certificateMatchingStoredPrivateKey()

        if backup == nil, let certificateDER {
            _ = saveCertificateBackupToKeychain(certificateDER)
        }

        lock.lock()
        _caCertificateDER = certificateDER
        lock.unlock()
    }

    // MARK: - Keychain Key Storage

    private func deleteKeyFromKeychain() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: Self.privateKeyAccount,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    private func saveCertificateBackupToKeychain(_ data: Data) -> Bool {
        let identity: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: Self.certificateBackupAccount,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
        ]
        let add = identity.merging(attributes) { _, new in new }
        let status = SecItemAdd(add as CFDictionary, nil)
        if status == errSecDuplicateItem {
            return SecItemUpdate(
                identity as CFDictionary,
                attributes as CFDictionary
            ) == errSecSuccess
        }
        return status == errSecSuccess
    }

    private func deleteCertificateBackupFromKeychain() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: Self.certificateBackupAccount,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    private func readGenericPassword(account: String) -> Data? {
        guard case .value(let data) = genericPasswordState(account: account)
        else { return nil }
        return data
    }

    private func genericPasswordState(account: String) -> KeychainDataState {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return .absent }
        guard status == errSecSuccess, let data = result as? Data else {
            return .unreadable
        }
        return .value(data)
    }

    private func genericPasswordMayExist(account: String) -> Bool {
        switch genericPasswordState(account: account) {
        case .absent:
            return false
        case .value, .unreadable:
            return true
        }
    }

    /// Older builds kept the generated private key in an app-owned generic
    /// password item. If ca.pem was deleted, match that private key's exact
    /// public key to certificates in every readable trust domain. This
    /// recovers cryptographic identity without deleting by a non-unique
    /// certificate name.
    private func certificateMatchingStoredPrivateKey() -> Data? {
        guard let storedKey = readGenericPassword(account: Self.privateKeyAccount),
              let trusted = Self.trustedCertificates()
        else { return nil }

        for keyData in Self.privateKeyDataCandidates(storedKey) {
            for keyType in [kSecAttrKeyTypeRSA, kSecAttrKeyTypeECSECPrimeRandom] {
                let attributes: [String: Any] = [
                    kSecAttrKeyType as String: keyType,
                    kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
                ]
                var creationError: Unmanaged<CFError>?
                guard let privateKey = SecKeyCreateWithData(
                    keyData as CFData,
                    attributes as CFDictionary,
                    &creationError
                ),
                let expectedPublicKey = SecKeyCopyPublicKey(privateKey),
                let expectedRepresentation = Self.externalRepresentation(of: expectedPublicKey)
                else { continue }

                for certificate in trusted {
                    guard let publicKey = SecCertificateCopyKey(certificate),
                          Self.externalRepresentation(of: publicKey) == expectedRepresentation
                    else { continue }
                    return SecCertificateCopyData(certificate) as Data
                }
            }
        }
        return nil
    }

    private static func privateKeyDataCandidates(_ stored: Data) -> [Data] {
        guard let pem = String(data: stored, encoding: .utf8) else { return [stored] }
        let lines = pem.components(separatedBy: .newlines)
        guard let begin = lines.firstIndex(where: { $0.hasPrefix("-----BEGIN ") }),
              begin + 1 < lines.endIndex,
              let end = lines[(begin + 1)...].firstIndex(where: { $0.hasPrefix("-----END ") }),
              begin + 1 < end
        else {
            let compact = pem.filter { !$0.isWhitespace }
            if let decoded = Data(base64Encoded: compact), decoded != stored {
                return [stored, decoded]
            }
            return [stored]
        }

        let base64 = lines[(begin + 1)..<end].joined().filter { !$0.isWhitespace }
        guard let decoded = Data(base64Encoded: String(base64)), decoded != stored
        else { return [stored] }
        return [stored, decoded]
    }

    private static func externalRepresentation(of key: SecKey) -> Data? {
        var error: Unmanaged<CFError>?
        return SecKeyCopyExternalRepresentation(key, &error) as Data?
    }

    private static func trustedCertificates() -> [SecCertificate]? {
        var result: [SecCertificate] = []
        for domain in [
            SecTrustSettingsDomain.user,
            SecTrustSettingsDomain.admin,
            SecTrustSettingsDomain.system,
        ] {
            var certificates: CFArray?
            let status = SecTrustSettingsCopyCertificates(domain, &certificates)
            if status == errSecNoTrustSettings { continue }
            guard status == errSecSuccess,
                  let domainCertificates = certificates as? [SecCertificate]
            else { return nil }
            result.append(contentsOf: domainCertificates)
        }
        return result
    }

    private func hasUnresolvedLegacyMaterial() -> Bool {
        pathEntryMayExist(Self.caKeyPath)
            || pathEntryMayExist(Self.caCertPath)
            || genericPasswordMayExist(account: Self.privateKeyAccount)
            || genericPasswordMayExist(account: Self.certificateBackupAccount)
            || Self.potentialLegacyTrustState() != .absent
    }

    private func readRegularCertificateFile() -> String? {
        guard case .present(let info) = pathEntryState(Self.caCertPath),
              info.st_mode & S_IFMT == S_IFREG
        else { return nil }
        return try? String(contentsOf: Self.caCertPath, encoding: .utf8)
    }

    private func pathEntryState(_ url: URL) -> PathEntryState {
        var info = stat()
        if url.path.withCString({ lstat($0, &info) == 0 }) {
            return .present(info)
        }
        return errno == ENOENT || errno == ENOTDIR ? .absent : .unreadable
    }

    private func pathEntryMayExist(_ url: URL) -> Bool {
        switch pathEntryState(url) {
        case .absent:
            return false
        case .present, .unreadable:
            return true
        }
    }

    private func removeIfPresent(_ url: URL) -> Bool {
        switch pathEntryState(url) {
        case .absent:
            return true
        case .unreadable:
            return false
        case .present:
            break
        }
        do {
            try FileManager.default.removeItem(at: url)
            return true
        } catch {
            return false
        }
    }

    static func certificateDER(fromPEM pem: String) -> Data? {
        let begin = "-----BEGIN CERTIFICATE-----"
        let end = "-----END CERTIFICATE-----"
        guard let beginRange = pem.range(of: begin),
              let endRange = pem.range(of: end),
              beginRange.upperBound <= endRange.lowerBound
        else { return nil }
        let base64 = pem[beginRange.upperBound..<endRange.lowerBound]
            .filter { !$0.isWhitespace }
        guard !base64.isEmpty else { return nil }
        return Data(base64Encoded: String(base64), options: []).flatMap(validCertificateDER)
    }

    private static func validCertificateDER(_ data: Data) -> Data? {
        SecCertificateCreateWithData(nil, data as CFData) == nil ? nil : data
    }

    private static func trustState(for certificate: SecCertificate) -> TrustState {
        var foundTrust = false
        for domain in [
            SecTrustSettingsDomain.user,
            SecTrustSettingsDomain.admin,
            SecTrustSettingsDomain.system,
        ] {
            var settings: CFArray?
            let status = SecTrustSettingsCopyTrustSettings(certificate, domain, &settings)
            switch status {
            case errSecSuccess:
                foundTrust = true
            case errSecItemNotFound:
                continue
            default:
                return .unreadable
            }
        }
        return foundTrust ? .trusted : .absent
    }

    /// If every exact identifier was lost by an older/corrupt install, a
    /// subject string is not safe authority to delete a certificate. It is,
    /// however, safe to use as a conservative reason not to claim success and
    /// to direct the user to Keychain Access for an explicit decision.
    private static func potentialLegacyTrustState() -> PotentialLegacyTrustState {
        guard let trusted = trustedCertificates() else { return .unreadable }

        for certificate in trusted {
            guard let summary = SecCertificateCopySubjectSummary(certificate) as String?
            else { continue }
            if summary.range(of: "bouclier", options: [.caseInsensitive, .diacriticInsensitive]) != nil {
                return .found
            }
        }
        return .absent
    }
}
