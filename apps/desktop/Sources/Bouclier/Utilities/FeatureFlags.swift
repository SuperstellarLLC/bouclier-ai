import Foundation

/// Runtime feature flags.
///
/// Resolution order (first wins):
/// 1. MDM profile via `ManagedConfig` — enterprise IT owns the final say
/// 2. Compile-time defaults — what ships in the public DMG
///
/// Detection-fidelity flags are read-only at runtime and MDM-controlled.
/// `injectionBlock` is the deliberate exception: on unmanaged Macs the
/// operator can choose Monitor or Block in Settings because refusing a
/// false positive is a material availability tradeoff. MDM still wins.
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
    /// Whether the gateway inspects request bodies for prompt injection
    /// arriving through **untrusted** content — tool results, retrieved
    /// documents, MCP tool output. Default: **on**. This is Bouclier's
    /// primary protection; turning it off leaves a bare relay.
    ///
    /// Distinct from `injectionBlock`: detection decides whether content is
    /// flagged; the separate Monitor/Block action decides whether an
    /// untrusted finding is refused. `injectionStrict` can additionally make
    /// operator-authored text enforceable under managed policy.
    static var injectionDetection: Bool {
        resolve(key: "injectionDetection", default: true)
    }

    /// Whether a detected injection in **untrusted** content is actually
    /// refused (422), versus only scanned and logged. Default: **off** —
    /// monitor mode. Blocking a detection means refusing the agent, and an
    /// untrusted span that trips a critical pattern is very often benign
    /// (source, diffs, email templates, LLM-prompt strings all quote
    /// "system prompt" / "ignore previous instructions"). A pattern engine
    /// can't tell a quoted payload from a live one, so block-by-default
    /// breaks normal agent work. Prevention is a deliberate opt-in; the
    /// default observes and records without ever breaking traffic. Enable
    /// in Settings ▸ Protection, via MDM, or with
    /// `defaults write ai.bouclier.app injectionBlockEnabled -bool true`.
    static var injectionBlock: Bool {
        if let override = testOverrides["injectionBlock"] { return override }
        if let managedInjectionBlock { return managedInjectionBlock }
        let userKey = "injectionBlockEnabled"
        if UserDefaults.standard.object(forKey: userKey) != nil {
            return UserDefaults.standard.bool(forKey: userKey)
        }
        return false
    }

    /// Effective MDM value, kept separate so Settings can both display the
    /// enforced state and disable the control. The featureFlags dictionary
    /// is preferred; `enforcementPolicy` remains supported for older fleet
    /// profiles documented by the app.
    static var managedInjectionBlock: Bool? {
        if let dict = ManagedConfig.featureFlagsDict,
           let value = dict["injectionBlock"] as? Bool {
            return value
        }
        switch ManagedConfig.enforcementPolicy {
        case "block": return true
        case "monitor", "warn", "log": return false
        default: return nil
        }
    }

    /// Whether a detection on the operator's **own** prompt also blocks.
    /// Default: **off**. The user is the principal — they are allowed to
    /// paste an OWASP advisory or say "ignore previous instructions" to
    /// their own model, and blocking that is the false positive that made
    /// the pre-v0.6 text-rewriting path unusable. MDM deployments that
    /// want to police user prompts, and accept the cost, can flip it.
    static var injectionStrict: Bool {
        resolve(key: "injectionStrict", default: false)
    }

    /// Whether a `tool_result` that can be **positively attributed** to a
    /// local read under a known canonical workspace root (the
    /// `Read`/`NotebookRead` tool, on a path outside vendored/download/temp
    /// dirs) is trusted like
    /// principal text — scanned and flagged, but never blocked. Default:
    /// **on**. This scopes enforcement to the external-content boundary
    /// (web/search/shell/external tools, retrieved documents) instead of
    /// treating the developer's own docs, research, and instructions to their
    /// own agent as injection — the false positive that makes people disable
    /// the firewall wholesale. Anything that cannot be attributed to an
    /// eligible local read stays untrusted.
    ///
    /// This is a request-local attribution heuristic, not file-origin proof:
    /// Bouclier does not track file taint or write history across requests. If
    /// external content is silently written into an otherwise eligible
    /// workspace path and later returned by a linked `Read`/`NotebookRead`,
    /// that later result can be classified `.authored`. An earlier fetch is
    /// inspected only if its output itself appeared as supported untrusted
    /// content in a routed model request. Turn this flag off (or enable strict
    /// mode) to police every tool result regardless of source. See
    /// `InjectionInspectionPass.provenance`.
    static var injectionTrustAuthoredReads: Bool {
        resolve(key: "injectionTrustAuthoredReads", default: true)
    }

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

    /// Dormant experimental response-action monitor. The production upstream
    /// path is a raw, byte-faithful HTTP/1.1 relay; without a non-consuming
    /// dechunk/content-decoding observation parser, feeding arbitrary network
    /// chunks into the SSE inspector can miss or misparse valid frames. Keep
    /// this hard-off in production until that parser has end-to-end coverage.
    /// Tests exercise `ResponseActionInspector` directly.
    static var responseActionMonitoring: Bool {
        testOverrides["responseActionMonitoring"] ?? false
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

    /// Dormant compatibility flag for the removed TLS-interception PII path.
    /// The live certificate-free gateway never calls
    /// `HTTPRequestInspector.applyMultimodalInspection`, and there is no
    /// user-facing setting or supported MDM promise for this feature. Kept
    /// only so the isolated attachment pipeline remains testable while a
    /// future byte-fidelity-preserving design is evaluated.
    static var multimodalInspection: Bool {
        resolve(key: "multimodalInspection", default: false)
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
        //   3. Compile-time default — the conservative posture that
        //      ships in the public DMG.
        //
        // Detection fidelity is intentionally not read from the writable
        // standard preferences domain. A Bash-capable agent can invoke
        // `defaults write`; accepting `<key>Enabled` here let it turn the
        // primary detector off while the shield continued to look active.
        // `injectionBlock` has its own explicit user setting because it is an
        // action/availability choice, not detector integrity.
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
