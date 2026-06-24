import Foundation

/// Which proxy the app runs.
///
/// - `.extreme` — the MITM/CA TLS-intercepting proxy (`TLSProxy`): full
///   egress inspection, injection filtering, multimodal PII, and
///   third-party secret injection. Requires a trusted root CA.
/// - `.standard` — the non-CA base-URL gateway (`GatewayServer`): the
///   agent points `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` at us and we
///   protect the **LLM channel only** (secrets scrub→restore). No CA
///   install, no system-trust changes.
///
/// Resolution mirrors `FeatureFlags`: test override → MDM → user default
/// → compile default. The compile default is `.standard` — the non-CA
/// gateway is the safe, frictionless default; extreme (MITM/CA) is an
/// opt-in, experimental power-user mode that can alter system network
/// configuration, so it is never selected implicitly.
enum ProxyMode: String, Sendable, CaseIterable {
    case standard
    case extreme

    static let userDefaultsKey = "proxyMode"
    static let compileDefault: ProxyMode = .standard

    /// Test-only override. `nil` clears it.
    static nonisolated(unsafe) private(set) var testOverride: ProxyMode?
    static func setTestOverride(_ mode: ProxyMode?) { testOverride = mode }

    static var current: ProxyMode {
        if let o = testOverride { return o }
        if let dict = ManagedConfig.featureFlagsDict,
           let raw = dict[userDefaultsKey] as? String,
           let m = ProxyMode(rawValue: raw) { return m }
        if let raw = UserDefaults.standard.string(forKey: userDefaultsKey),
           let m = ProxyMode(rawValue: raw) { return m }
        return compileDefault
    }

    /// Human label for Settings / logs.
    var title: String {
        switch self {
        case .standard: return "Standard (no CA)"
        case .extreme: return "Extreme (full interception)"
        }
    }
}
