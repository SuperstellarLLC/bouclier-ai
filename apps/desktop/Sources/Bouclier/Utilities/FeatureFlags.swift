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
    /// Whether the gateway inspects request bodies for prompt injection
    /// arriving through **untrusted** content — tool results, retrieved
    /// documents, MCP tool output. Default: **on**. This is Bouclier's
    /// primary protection; turning it off leaves a bare relay.
    ///
    /// Distinct from `injectionStrict`: with this on and strict off, a
    /// detection inside tool output blocks the request, while the same
    /// text typed by the operator is only logged. See
    /// `InjectionInspectionPass` for why provenance decides the action.
    static var injectionDetection: Bool {
        resolve(key: "injectionDetection", default: true)
    }

    /// Whether a detected injection in **untrusted** content is actually
    /// refused (403), versus only scanned and logged. Default: **off** —
    /// monitor mode. Blocking a detection means 403-ing the agent, and an
    /// untrusted span that trips a critical pattern is very often benign
    /// (source, diffs, email templates, LLM-prompt strings all quote
    /// "system prompt" / "ignore previous instructions"). A pattern engine
    /// can't tell a quoted payload from a live one, so block-by-default
    /// breaks normal agent work. Prevention is a deliberate opt-in; the
    /// default observes and records without ever breaking traffic. Enable
    /// via MDM or `defaults write ai.bouclier.app injectionBlockEnabled -bool true`.
    static var injectionBlock: Bool {
        resolve(key: "injectionBlock", default: false)
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

    /// Whether outbound multimodal *attachments* (images, PDFs,
    /// audio) get inspected for PII via Vision + PDFKit + Speech and
    /// have flagged media replaced with a descriptive text placeholder
    /// before forwarding. This is the only PII rewrite path Bouclier
    /// runs — text prompts are forwarded unchanged. Off by default;
    /// users opt in via Settings → Privacy or MDM.
    static var multimodalInspection: Bool {
        resolve(key: "multimodalInspection", default: false)
    }

    /// Whether the proxy injects managed secrets at egress: the agent
    /// only ever holds an opaque placeholder, and Bouclier swaps in the
    /// real value (from the Keychain) bound to the rule's allowlisted
    /// host, blocking exfil/plaintext tripwires. Off by default; users
    /// opt in via Settings → Secrets or MDM. See
    /// `docs/secret-injection.md`. When off, no secret hosts are
    /// intercepted and the injection pass never runs.
    static var secretInjection: Bool {
        resolve(key: "secretInjection", default: false)
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
        //      key `<flag>Enabled` (e.g. `multimodalInspectionEnabled`).
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
