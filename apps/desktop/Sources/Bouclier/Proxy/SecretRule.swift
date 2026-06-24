import Foundation

/// A single managed secret: an opaque placeholder the agent/LLM is
/// allowed to know, bound to the host(s) where the real value may be
/// injected.
///
/// The agent never holds the real value — only `placeholder`. Bouclier
/// swaps the placeholder for the real secret at egress, and *only* when
/// the outbound request targets one of `allowedHosts`. See
/// `docs/secret-injection.md`.
struct SecretRule: Sendable, Codable, Equatable {
    /// Stable identifier, `[a-z0-9_]+`. Doubles as the Keychain account
    /// suffix and the interpolated middle of the placeholder.
    let name: String

    /// Hosts where this secret may be injected. Exact, lowercased host
    /// match (no wildcards in the MVP — `api.stripe.com`, not
    /// `*.stripe.com`). A placeholder for this rule arriving at any
    /// other host is treated as an exfiltration attempt and blocked.
    let allowedHosts: [String]

    /// Whether an AI agent may materialize this secret into its execution
    /// environment via the Bouclier MCP server. Default `true` — secrets
    /// exist to be used; lock down sensitive ones by setting this false.
    /// The model NEVER sees the value either way; this gates whether the
    /// agent can use it at all.
    let agentAccess: Bool

    /// The environment-variable name the agent's shell sees when this
    /// secret is activated (e.g. `STRIPE_KEY`). `nil` ⇒ the uppercased
    /// rule name. The *value* is read from the Keychain at shell-init by
    /// `bouclier-ai-env --secrets`; it is never stored here or sent to the
    /// model.
    let envVar: String?

    init(name: String, allowedHosts: [String], agentAccess: Bool = true, envVar: String? = nil) {
        self.name = name
        self.allowedHosts = allowedHosts.map { $0.lowercased() }
        self.agentAccess = agentAccess
        self.envVar = envVar
    }

    // Backward-compatible decoding: rules written before these fields
    // existed decode with `agentAccess = true` and `envVar = nil`.
    enum CodingKeys: String, CodingKey { case name, allowedHosts, agentAccess, envVar }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        // Normalize like the memberwise init, so a hand-edited or legacy
        // rules file with mixed-case hosts still matches case-insensitively
        // and feeds normalized hosts into the intercept set.
        allowedHosts = ((try c.decodeIfPresent([String].self, forKey: .allowedHosts)) ?? []).map { $0.lowercased() }
        agentAccess = (try c.decodeIfPresent(Bool.self, forKey: .agentAccess)) ?? true
        envVar = try c.decodeIfPresent(String.self, forKey: .envVar)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(name, forKey: .name)
        try c.encode(allowedHosts, forKey: .allowedHosts)
        try c.encode(agentAccess, forKey: .agentAccess)
        try c.encodeIfPresent(envVar, forKey: .envVar)
    }

    /// The environment variable the agent's shell exports for this secret.
    var environmentVariable: String {
        if let v = envVar, !v.isEmpty { return v }
        return name.uppercased()
    }

    /// Env var names must be `[A-Za-z_][A-Za-z0-9_]*` so they're safe to
    /// `export` and can't smuggle shell syntax.
    static func isValidEnvVar(_ raw: String) -> Bool {
        guard let first = raw.first, first.isLetter || first == "_" else { return false }
        return raw.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }
    }

    /// The token the agent embeds in its tool call. Namespaced so it
    /// can't plausibly collide with real request content.
    var placeholder: String { Self.placeholder(for: name) }

    static func placeholder(for name: String) -> String {
        "__BOUCLIER_SECRET_\(name)__"
    }

    /// Names must be `[a-z0-9_]+` so the placeholder stays a clean ASCII
    /// token and the Keychain account is well-formed.
    static func isValidName(_ name: String) -> Bool {
        !name.isEmpty && name.allSatisfy { $0.isASCII && ($0.isLowercase || $0.isNumber || $0 == "_") }
    }

    func allows(host: String) -> Bool {
        allowedHosts.contains(host.lowercased())
    }

    /// A scrub-only secret has no host binding: it's never *injected* into
    /// a third-party request (that's extreme mode), it's only *scrubbed*
    /// out of requests to the model provider (standard mode). Injectable
    /// secrets carry at least one allowed host.
    var isScrubOnly: Bool { allowedHosts.isEmpty }

    /// Maximum stored secret length. Bounds Keychain/memory use and stops
    /// an absurd value from being injected. Real credentials are far
    /// shorter; 8 KiB is generous headroom (e.g. multi-line PEM keys).
    static let maxValueBytes = 8 * 1024

    /// Validate + normalize a host a secret may be bound to. Returns the
    /// lowercased FQDN, or nil if it's malformed or a target we must
    /// never intercept. Binding to a cloud-metadata endpoint or a
    /// loopback/local service would turn the secret keeper into an
    /// SSRF/exfiltration primitive or break local tooling, so both are
    /// rejected outright.
    static func validatedHost(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespaces).lowercased()
        guard let host = ManagedConfigValidator.validatedHostname(trimmed) else { return nil }
        if TLSProxy.isCloudMetadataHost(host) { return nil }
        if CorporateProxy.isLoopbackHost(host) { return nil }
        return host
    }

    /// Whether a secret value is safe to store and inject. Rejects empty
    /// values, anything carrying CR/LF/NUL (which would enable
    /// header/request smuggling once injected into a header), and values
    /// over `maxValueBytes`.
    static func isValidValue(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= maxValueBytes else { return false }
        for byte in value.utf8 where byte == 0x00 || byte == 0x0A || byte == 0x0D {
            return false
        }
        return true
    }
}
