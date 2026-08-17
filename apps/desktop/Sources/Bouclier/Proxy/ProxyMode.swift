import Foundation

/// Which proxy the app runs.
///
/// `.standard` is the only mode: the non-CA base-URL gateway
/// (`GatewayServer`). The agent points `ANTHROPIC_BASE_URL` /
/// `OPENAI_BASE_URL` at us and we inspect the **LLM channel** for prompt
/// injection, refusing or forwarding a request byte-for-byte — never
/// rewriting it. No CA install, no system-trust changes.
///
/// The previous `.extreme` mode (a CA-based TLS-intercepting proxy with
/// a System Extension) was removed — it required a trusted root CA and
/// a system-wide network filter, both of which added startup-ordering
/// and reliability risk disproportionate to the value it added over the
/// gateway. The enum and `current` resolution stay in place (rather than
/// being deleted) because `.rawValue` is a stable, persisted value read
/// from `UserDefaults`/MDM config and reported in `BouclierStatus`/CLI
/// output — collapsing to a single case keeps that surface unchanged.
enum ProxyMode: String, Sendable, CaseIterable {
    case standard

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
        }
    }
}
