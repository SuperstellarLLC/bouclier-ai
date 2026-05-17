import Foundation
import Testing
@testable import Bouclier

@Suite("PIIPolicy — per-domain rules", .serialized)
struct PIIPolicyTests {
    init() {
        // Wipe persistent state before every test so order doesn't matter.
        UserDefaults.standard.removeObject(forKey: PIIPolicy.allowDomainsKey)
        UserDefaults.standard.removeObject(forKey: PIIPolicy.denyDomainsKey)
        UserDefaults.standard.removeObject(forKey: PIIPolicy.denyDomainsKey + ".overridden")
        PIIPolicy.shared.clearTestOverrides()
    }

    @Test("Default policy redacts every host when no rules are set")
    func defaultAllowsAll() {
        // Default deny list includes embeddings/moderation — those bypass.
        #expect(PIIPolicy.shared.shouldRedact(host: "api.anthropic.com"))
        #expect(PIIPolicy.shared.shouldRedact(host: "api.openai.com"))
        // Default deny entries (suffix-match).
        #expect(!PIIPolicy.shared.shouldRedact(host: "api.openai.com/v1/embeddings"))
    }

    @Test("User-set allow list narrows redaction to listed hosts only")
    func allowListNarrows() {
        PIIPolicy.saveUserList(["openai.com"], forKey: PIIPolicy.allowDomainsKey)
        #expect(PIIPolicy.shared.shouldRedact(host: "api.openai.com"))
        #expect(!PIIPolicy.shared.shouldRedact(host: "api.anthropic.com"))
    }

    @Test("User-set deny list blocks the listed hosts even if allowed")
    func denyOverridesAllow() {
        PIIPolicy.saveUserList(["openai.com"], forKey: PIIPolicy.allowDomainsKey)
        PIIPolicy.saveUserList(["embeddings.openai.com"], forKey: PIIPolicy.denyDomainsKey)
        #expect(PIIPolicy.shared.shouldRedact(host: "api.openai.com"))
        #expect(!PIIPolicy.shared.shouldRedact(host: "embeddings.openai.com"))
    }

    @Test("Suffix matching: 'openai.com' covers subdomains")
    func suffixMatch() {
        PIIPolicy.saveUserList(["openai.com"], forKey: PIIPolicy.allowDomainsKey)
        #expect(PIIPolicy.shared.shouldRedact(host: "eu.api.openai.com"))
        #expect(PIIPolicy.shared.shouldRedact(host: "openai.com"))
        #expect(!PIIPolicy.shared.shouldRedact(host: "openai.example.com"))
    }

    @Test("MDM deny overrides user allow (enterprise IT wins)")
    func mdmDenyWins() {
        PIIPolicy.saveUserList(["openai.com"], forKey: PIIPolicy.allowDomainsKey)
        PIIPolicy.shared.setTestOverrides(deny: ["api.openai.com"])
        defer { PIIPolicy.shared.clearTestOverrides() }
        #expect(!PIIPolicy.shared.shouldRedact(host: "api.openai.com"))
    }

    @Test("Case insensitive matching")
    func caseInsensitive() {
        PIIPolicy.saveUserList(["OPENAI.COM"], forKey: PIIPolicy.allowDomainsKey)
        #expect(PIIPolicy.shared.shouldRedact(host: "API.OpenAI.Com"))
    }
}

@Suite("RedactionPause — operator panic switch", .serialized)
struct RedactionPauseTests {
    init() {
        RedactionPause.resume()
    }

    @Test("Not paused by default")
    func notPausedDefault() {
        #expect(!RedactionPause.isPaused())
        #expect(RedactionPause.pausedUntil() == nil)
    }

    @Test("pause(for:) sets a TTL and isPaused reflects it")
    func pauseForSetsTTL() {
        RedactionPause.pause(for: 60)
        #expect(RedactionPause.isPaused())
        let remaining = RedactionPause.secondsRemaining()
        #expect(remaining > 0 && remaining <= 60)
    }

    @Test("Pause expires after the TTL")
    func ttlExpiry() {
        let past = Date().addingTimeInterval(-1)
        // Simulate "paused until 1s in the past" by writing directly.
        UserDefaults.standard.set(past.timeIntervalSinceReferenceDate, forKey: RedactionPause.pausedUntilKey)
        #expect(!RedactionPause.isPaused())
        // Side-effect: a stale pause must be cleaned up so subsequent
        // reads don't keep returning false-via-cleanup.
        #expect(UserDefaults.standard.object(forKey: RedactionPause.pausedUntilKey) == nil)
    }

    @Test("resume() clears the pause immediately")
    func resumeClears() {
        RedactionPause.pause(for: 300)
        #expect(RedactionPause.isPaused())
        RedactionPause.resume()
        #expect(!RedactionPause.isPaused())
    }

    @Test("FeatureFlags.piiRedaction returns false while paused (panic short-circuit)")
    func featureFlagShortCircuit() {
        FeatureFlags.setTestOverride("piiRedaction", true)
        defer { FeatureFlags.clearTestOverrides() }
        #expect(FeatureFlags.piiRedaction == true)
        RedactionPause.pause(for: 60)
        defer { RedactionPause.resume() }
        #expect(FeatureFlags.piiRedaction == false)
    }
}
