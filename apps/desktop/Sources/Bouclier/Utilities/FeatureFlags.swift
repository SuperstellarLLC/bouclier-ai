import Foundation

/// Runtime feature flags.
///
/// Resolution order (first wins):
/// 1. MDM profile via `ManagedConfig` — enterprise IT owns the final say
/// 2. Compile-time defaults — what ships in the public DMG
///
/// Flags are **read-only at runtime**. There is deliberately no
/// user-facing toggle: a power-user flipping a detection off in the
/// UI would defeat the point of an enterprise firewall. Anything the
/// user can change lives in Settings; anything that affects detection
/// fidelity lives here and is MDM-controlled.
///
/// The flag keys match the MDM dictionary keys so IT can ship:
/// ```xml
/// <key>featureFlags</key>
/// <dict>
///   <key>sseInspection</key><true/>
///   <key>uriScanning</key><true/>
///   <key>telemetryEnabled</key><false/>
/// </dict>
/// ```
enum FeatureFlags {
    /// Whether the upstream relay runs SSE streams through the
    /// `SSEStreamInspector`. Default: on. Turning this off restores
    /// pre-v0.2 behaviour of raw pass-through for streaming responses.
    static var sseInspection: Bool {
        resolve(key: "sseInspection", default: true)
    }

    /// Whether query strings are scanned in addition to request bodies.
    /// Default: on. Used by `HTTPRequestInspector`.
    static var uriScanning: Bool {
        resolve(key: "uriScanning", default: true)
    }

    /// Whether Bouclier records in-process metrics at all. Privacy-
    /// conscious deployments can disable this without disabling the
    /// firewall itself. Default: on.
    static var telemetryEnabled: Bool {
        resolve(key: "telemetryEnabled", default: true)
    }

    /// Whether the hot-reload watcher on `patterns.json` is active.
    /// Default: on in debug builds, off in release builds.
    static var hotReloadPatterns: Bool {
        #if DEBUG
        return resolve(key: "hotReloadPatterns", default: true)
        #else
        return resolve(key: "hotReloadPatterns", default: false)
        #endif
    }

    /// Whether the PII redactor runs on outbound chat-completion
    /// bodies. Ships off so users opt in explicitly while the
    /// detector set matures; MDM admins can flip it on for the whole
    /// org. The default will flip on once the ML tier and streaming
    /// reversal have shipped and bedded in.
    ///
    /// The user-facing pause button (RedactionPause) layers on top of
    /// this: even when the flag is on, an active pause short-circuits
    /// the resolver to false. Per-domain policy adds a second gate at
    /// the call site (`PIIPolicy.shouldRedact(host:)`).
    static var piiRedaction: Bool {
        if RedactionPause.isPaused() { return false }
        return resolve(key: "piiRedaction", default: false)
    }

    /// Whether outbound multimodal requests (images + PDFs today;
    /// audio in a later release) get inspected for PII via Vision +
    /// PDFKit + downstream scanners and have flagged media stripped
    /// before forwarding. Off by default in v0.4.0 so users opt in
    /// alongside the existing text PII redaction. Subject to the
    /// same pause switch.
    static var multimodalInspection: Bool {
        if RedactionPause.isPaused() { return false }
        return resolve(key: "multimodalInspection", default: false)
    }

    /// When true, the PII redactor also strips credential-class entities
    /// (API keys, JWTs, secrets, DB URLs, private keys) on requests
    /// bound for AI APIs. Off by default — see `PIICategory` for the
    /// rationale: pasting an API key into a Claude prompt while asking
    /// "why doesn't this work?" is usually functional context the model
    /// needs to help; redacting it both breaks the debugging session
    /// and trips upstream abuse detection. Opt-in for users with
    /// supply-chain-leak concerns.
    static var strictCredentialRedaction: Bool {
        resolve(key: "strictCredentialRedaction", default: false)
    }

    // MARK: - Resolution

    /// Test-only override: set a value here to force a flag regardless
    /// of MDM or defaults. `nil` clears the override. This is `internal`
    /// and only used by the test suite.
    static nonisolated(unsafe) private(set) var testOverrides: [String: Bool] = [:]

    static func setTestOverride(_ key: String, _ value: Bool?) {
        if let value { testOverrides[key] = value } else { testOverrides.removeValue(forKey: key) }
    }

    static func clearTestOverrides() {
        testOverrides.removeAll()
    }

    private static func resolve(key: String, default fallback: Bool) -> Bool {
        // Resolution order:
        //   1. Test override — for unit tests that need to flip a flag
        //      without mutating shared state.
        //   2. MDM-managed value — enterprise IT has the final say
        //      because compliance configs must be enforceable.
        //   3. User-set value via @AppStorage("<key>Enabled") — lets
        //      a power user opt in to the feature on a non-managed
        //      Mac without the Settings UI being purely cosmetic.
        //      AppStorage writes to standard UserDefaults under the
        //      key `<flag>Enabled` (mirroring the existing convention
        //      for `piiRedactionEnabled` and `multimodalInspectionEnabled`).
        //   4. Compile-time default — the conservative posture that
        //      ships in the public DMG.
        if let override = testOverrides[key] { return override }
        if let dict = ManagedConfig.featureFlagsDict,
           let value = dict[key] as? Bool
        { return value }
        let userKey = key + "Enabled"
        if UserDefaults.standard.object(forKey: userKey) != nil {
            return UserDefaults.standard.bool(forKey: userKey)
        }
        return fallback
    }
}

extension ManagedConfig {
    /// Raw feature-flags dictionary from the MDM profile. `nil` when no
    /// profile is installed or the key is absent.
    static var featureFlagsDict: [String: Any]? {
        let defaults = UserDefaults(suiteName: "com.apple.configuration.managed")
        return defaults?.dictionary(forKey: "featureFlags")
    }
}
