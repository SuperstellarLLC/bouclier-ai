import Foundation
import Security

/// Local, Keychain-backed store of managed secrets for the "secret
/// keeper" feature (see `docs/secret-injection.md`).
///
/// Split storage, mirroring `CertificateAuthority`:
///   • Secret *values* live in the macOS Keychain
///     (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) — encrypted at
///     rest, never written to disk in plaintext.
///   • Rule *metadata* (name + allowedHosts, no secret material) lives
///     in `secret-rules.json` under Application Support.
///
/// An in-memory cache backs `rules()` / `resolve()` so the proxy's
/// event-loop hot path never blocks on a Keychain round-trip per
/// request. The cache is the source of truth at runtime; disk/Keychain
/// are written through on mutation and read once on launch.
///
/// Thread-safety: all mutable state is guarded by `lock`. Reads from the
/// event loop and writes from the UI thread are both serialized through
/// it; the critical sections are dictionary lookups, so contention is
/// negligible.
final class SecretStore: @unchecked Sendable {
    static let shared = SecretStore()

    private let lock = NSLock()
    private var _rules: [String: SecretRule] = [:]
    private var _values: [String: String] = [:]

    private static let keychainService = "ai.bouclier.app"
    private static let accountPrefix = "secret-"

    private static let rulesFile: URL = {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first!.appendingPathComponent("ai.bouclier.app", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        chmod(dir.path, 0o700)
        return dir.appendingPathComponent("secret-rules.json")
    }()

    init() {
        loadExisting()
    }

    /// Test-only constructor: builds an isolated, in-memory-only store
    /// that never touches the Keychain or disk. Used by unit tests so
    /// they don't prompt for Keychain access or mutate the user's store.
    init(testing rules: [SecretRule], values: [String: String]) {
        for r in rules { _rules[r.name] = r }
        _values = values
    }

    // MARK: - Test seam

    /// Test-only: replace the in-memory cache directly, with no Keychain
    /// or disk I/O. Lets E2E tests drive the real `SecretStore.shared`
    /// (which the proxy reads) without prompting for Keychain access or
    /// mutating the user's stored secrets. Mirrors the always-compiled
    /// test seams elsewhere (`CertificateAuthority(testingKeyPEM:)`,
    /// `SystemProxy.testAdditionalDomains`).
    func seedForTesting(rules: [SecretRule], values: [String: String]) {
        lock.lock()
        _rules = Dictionary(uniqueKeysWithValues: rules.map { ($0.name, $0) })
        _values = values
        lock.unlock()
    }

    func clearForTesting() {
        lock.lock()
        _rules.removeAll()
        _values.removeAll()
        lock.unlock()
    }

    // MARK: - Hot-path reads (event loop)

    /// Snapshot of all rules. Cheap: a dictionary-values copy under lock.
    func rules() -> [SecretRule] {
        lock.lock(); defer { lock.unlock() }
        return Array(_rules.values)
    }

    /// Resolve a rule name to its real secret value from the in-memory
    /// cache. Never hits the Keychain — values are loaded at launch and
    /// kept warm.
    func resolve(_ name: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        return _values[name]
    }

    /// Every host any rule is bound to. Merged into
    /// `SystemProxy.interceptedDomains` so these hosts are MITM'd and
    /// PAC-routed; a host with no rule is never intercepted.
    func allHosts() -> Set<String> {
        lock.lock(); defer { lock.unlock() }
        var hosts: Set<String> = []
        for rule in _rules.values { for h in rule.allowedHosts { hosts.insert(h) } }
        return hosts
    }

    // MARK: - Mutations (UI thread)

    /// Add or replace a managed secret. Returns false unless the name,
    /// value, and at least one host all pass validation; invalid hosts
    /// are dropped, and a rule with no valid host is rejected entirely so
    /// a secret can never be stored without a binding. The value goes to
    /// the Keychain; metadata to disk.
    @discardableResult
    func addSecret(name: String, value: String, allowedHosts: [String], agentAccess: Bool = true, envVar: String? = nil) -> Bool {
        guard SecretRule.isValidName(name), SecretRule.isValidValue(value) else { return false }
        // A custom env var name, if given, must be shell-safe.
        if let envVar, !envVar.isEmpty, !SecretRule.isValidEnvVar(envVar) { return false }
        // Validate + normalize every host; silently drop the bad ones (the
        // UI surfaces them separately). An EMPTY host list is allowed — that
        // makes a scrub-only secret (standard mode): never injected into a
        // third party, only scrubbed out of model-provider requests. But if
        // hosts WERE provided and all were invalid, refuse rather than
        // silently downgrade an injectable secret to scrub-only.
        let validHosts = allowedHosts.compactMap { SecretRule.validatedHost($0) }
        guard allowedHosts.isEmpty || !validHosts.isEmpty else { return false }
        let rule = SecretRule(name: name, allowedHosts: validHosts, agentAccess: agentAccess, envVar: (envVar?.isEmpty == true ? nil : envVar))

        lock.lock()
        _rules[name] = rule
        _values[name] = value
        let snapshot = Array(_rules.values)
        lock.unlock()

        storeValueInKeychain(name: name, value: value)
        persistRules(snapshot)
        return true
    }

    /// Toggle whether the agent may materialize this secret via MCP.
    /// Re-persists the rule metadata; never touches the value.
    func setAgentAccess(name: String, _ allowed: Bool) {
        lock.lock()
        guard let existing = _rules[name] else { lock.unlock(); return }
        _rules[name] = SecretRule(name: existing.name, allowedHosts: existing.allowedHosts, agentAccess: allowed, envVar: existing.envVar)
        let snapshot = Array(_rules.values)
        lock.unlock()
        persistRules(snapshot)
    }

    func removeSecret(name: String) {
        lock.lock()
        _rules.removeValue(forKey: name)
        _values.removeValue(forKey: name)
        let snapshot = Array(_rules.values)
        lock.unlock()

        deleteValueFromKeychain(name: name)
        persistRules(snapshot)
    }

    // MARK: - Persistence

    private func loadExisting() {
        guard let data = try? Data(contentsOf: Self.rulesFile),
              let rules = try? JSONDecoder().decode([SecretRule].self, from: data)
        else { return }
        lock.lock(); defer { lock.unlock() }
        for rule in rules {
            _rules[rule.name] = rule
            if let value = loadValueFromKeychain(name: rule.name) {
                _values[rule.name] = value
            }
            // A rule whose Keychain value is missing stays registered but
            // unresolvable — the injection pass fails closed on it rather
            // than forwarding a literal placeholder.
        }
    }

    private func persistRules(_ rules: [SecretRule]) {
        guard let data = try? JSONEncoder().encode(rules.sorted(by: { $0.name < $1.name })) else { return }
        try? data.write(to: Self.rulesFile, options: [.atomic])
        chmod(Self.rulesFile.path, 0o600)
    }

    // MARK: - Keychain (mirrors CertificateAuthority)

    private func storeValueInKeychain(name: String, value: String) {
        guard let data = value.data(using: .utf8) else { return }
        let account = Self.accountPrefix + name
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    private func loadValueFromKeychain(name: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: Self.accountPrefix + name,
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func deleteValueFromKeychain(name: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.keychainService,
            kSecAttrAccount as String: Self.accountPrefix + name,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
