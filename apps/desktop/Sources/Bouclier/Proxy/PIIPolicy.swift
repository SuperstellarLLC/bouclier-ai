import Foundation

/// Per-domain PII redaction policy.
///
/// Some operators run an internal LLM gateway that already enforces
/// compliance, or an embedding endpoint that breaks if placeholders
/// are substituted into the input. Per-domain rules let those hosts
/// bypass redaction without disabling the feature for OpenAI,
/// Anthropic, Gemini, and friends.
///
/// **Resolution order** (first matching rule wins):
/// 1. MDM-managed `denyDomains` (enterprise IT)
/// 2. MDM-managed `allowDomains`
/// 3. User-set `denyDomains` (UserDefaults)
/// 4. User-set `allowDomains` (UserDefaults)
/// 5. Default: allow (redact) when global feature flag is on
///
/// `denyDomains` always wins over `allowDomains` so an MDM admin can
/// block a domain that a user accidentally allowed. Matching is suffix-
/// based on the lowercased host: a rule `openai.com` matches
/// `api.openai.com`, `eu.api.openai.com`, etc.
final class PIIPolicy: @unchecked Sendable {
    static let shared = PIIPolicy()

    /// User-facing UserDefaults key for the allow list (JSON-encoded
    /// [String]). Exposed so SettingsView can bind to the same store.
    static let allowDomainsKey = "piiAllowDomains"
    /// User-facing UserDefaults key for the deny list.
    static let denyDomainsKey = "piiDenyDomains"

    /// Default deny list — applied when the user hasn't customized
    /// anything. Includes hosts where redaction is provably wrong
    /// (embeddings endpoints destroy the vector; the redacted prompt
    /// is semantically different). Documented in
    /// `docs/PII_PROTOCOL_COMPATIBILITY.md`.
    static let defaultDenyDomains: [String] = [
        // Embeddings — redaction breaks the semantic vector.
        "api.openai.com/v1/embeddings",
        "api.cohere.com/v2/embed",
        "api.voyageai.com/v1/embeddings",
        // Moderation — the model needs the raw text.
        "api.openai.com/v1/moderations",
    ]

    /// Test-only override mirror of the FeatureFlags pattern. Set to
    /// nil to clear.
    nonisolated(unsafe) private(set) var testAllowOverride: [String]? = nil
    nonisolated(unsafe) private(set) var testDenyOverride: [String]? = nil

    func setTestOverrides(allow: [String]? = nil, deny: [String]? = nil) {
        testAllowOverride = allow
        testDenyOverride = deny
    }

    func clearTestOverrides() {
        testAllowOverride = nil
        testDenyOverride = nil
    }

    /// Should the redactor run for the given host? Combines MDM,
    /// user, and default policy. Suffix-matches.
    func shouldRedact(host: String) -> Bool {
        let normalized = host.lowercased()

        // MDM denies win.
        for rule in mdmDenyDomains() {
            if normalized.hasSuffix(rule) { return false }
        }

        // MDM allows confirm.
        let mdmAllow = mdmAllowDomains()
        if !mdmAllow.isEmpty {
            return mdmAllow.contains(where: { normalized.hasSuffix($0) })
        }

        // User denies win over user allows (operator's intent: "never
        // for this host" must be respected).
        for rule in userDenyDomains() {
            if normalized.hasSuffix(rule) { return false }
        }

        let userAllow = userAllowDomains()
        if !userAllow.isEmpty {
            return userAllow.contains(where: { normalized.hasSuffix($0) })
        }

        // No explicit rules → default to allow. The global feature
        // flag is the outer gate; this method only answers "if the
        // flag is on, should redaction happen for *this* host".
        return true
    }

    // MARK: - Sources

    private func mdmAllowDomains() -> [String] {
        if let override = testAllowOverride { return override }
        guard let dict = ManagedConfig.featureFlagsDict,
              let list = dict["piiAllowDomains"] as? [String]
        else { return [] }
        return list.map { $0.lowercased() }
    }

    private func mdmDenyDomains() -> [String] {
        if let override = testDenyOverride { return override }
        guard let dict = ManagedConfig.featureFlagsDict,
              let list = dict["piiDenyDomains"] as? [String]
        else { return [] }
        return list.map { $0.lowercased() }
    }

    private func userAllowDomains() -> [String] {
        // The MDM-shaped test override also short-circuits the user lists.
        // Without this, a stale `UserDefaults` entry from a developer's
        // own machine (e.g. they once tested a per-domain allow rule)
        // leaks into the e2e test's policy resolution and flips
        // `shouldRedact("localhost")` to false for non-obvious reasons.
        if testAllowOverride != nil { return [] }
        return decodeList(forKey: PIIPolicy.allowDomainsKey)
    }

    private func userDenyDomains() -> [String] {
        if testDenyOverride != nil { return [] }
        var list = decodeList(forKey: PIIPolicy.denyDomainsKey)
        // Add the default deny rules unless the user explicitly cleared
        // them (we detect "explicitly cleared" via a sentinel key —
        // absence means "use defaults").
        if UserDefaults.standard.object(forKey: PIIPolicy.denyDomainsKey + ".overridden") == nil {
            list.append(contentsOf: PIIPolicy.defaultDenyDomains.map { $0.lowercased() })
        }
        return list
    }

    private func decodeList(forKey key: String) -> [String] {
        guard let raw = UserDefaults.standard.string(forKey: key),
              let data = raw.data(using: .utf8),
              let arr = try? JSONDecoder().decode([String].self, from: data)
        else { return [] }
        return arr.map { $0.lowercased() }
    }
}

extension PIIPolicy {
    /// Helper for SettingsView to persist a user-edited list.
    static func saveUserList(_ list: [String], forKey key: String) {
        let encoded = (try? JSONEncoder().encode(list)).flatMap { String(data: $0, encoding: .utf8) }
        UserDefaults.standard.set(encoded ?? "[]", forKey: key)
        if key == denyDomainsKey {
            UserDefaults.standard.set(true, forKey: key + ".overridden")
        }
    }
}
