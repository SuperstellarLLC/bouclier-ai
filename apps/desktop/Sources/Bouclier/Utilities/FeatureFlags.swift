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
        if let override = testOverrides[key] { return override }
        if let dict = ManagedConfig.featureFlagsDict,
           let value = dict[key] as? Bool
        { return value }
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
