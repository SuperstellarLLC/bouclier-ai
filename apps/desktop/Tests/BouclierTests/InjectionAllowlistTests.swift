import Foundation
import Testing
@testable import Bouclier

/// Covers the span allowlist — the escape hatch that lets an operator
/// release a persistent false positive so it stops 403-ing a session on
/// every resume. Uses a nonsense trigger token ("QURTLE") as the stand-in
/// "attack" so the tests carry no real injection text.
@Suite("Span allowlist — release a persistent false positive")
struct InjectionAllowlistTests {

    private static let salt = Data("unit-test-salt".utf8)

    /// A filter that blocks on the nonsense token, nothing else.
    private func triggerFilter() -> InjectionFilter {
        let regex = try! NSRegularExpression(pattern: "QURTLE", options: [.caseInsensitive])
        let pattern = FilterPattern(
            id: "test-001", name: "test-trigger", category: "test",
            severity: "critical", regex: regex, enabled: true
        )
        return InjectionFilter(patterns: [pattern], dampeners: [], classifier: nil)
    }

    /// Anthropic body whose only untrusted span is a tool_result carrying
    /// the trigger token.
    private func bodyWithTrigger(_ text: String) -> Data {
        let json = """
        {"messages":[{"role":"user","content":[{"type":"tool_result","content":"\(text)"}]}]}
        """
        return Data(json.utf8)
    }

    @Test("Fingerprint is deterministic for identical span bytes, and salt-sensitive")
    func fingerprintStableAndSalted() {
        let a = InjectionInspectionPass.spanFingerprint("QURTLE here", salt: Self.salt)
        let b = InjectionInspectionPass.spanFingerprint("QURTLE here", salt: Self.salt)
        #expect(a == b, "Same span + same salt must fingerprint identically across resumes")
        let other = InjectionInspectionPass.spanFingerprint("QURTLE here", salt: Data("different".utf8))
        #expect(a != other, "A different install salt must yield a different fingerprint")
        #expect(a.count == 64, "SHA-256 hex is 64 chars")
    }

    @Test("An untrusted trigger blocks; releasing its fingerprint downgrades it to a flag")
    func allowlistDowngradesBlockToFlag() {
        let filter = triggerFilter()
        let spanText = "some QURTLE tool output"
        let body = bodyWithTrigger(spanText)

        // Baseline: blocks.
        let blocked = InjectionInspectionPass.inspect(
            body: body, filter: filter, allowlisted: [], salt: Self.salt
        )
        #expect(blocked.decision == .block, "Trigger in a tool_result must block by default")
        let fp = blocked.blockedFingerprint
        #expect(fp != nil, "A block on an untrusted span must expose a releasable fingerprint")

        // The exposed fingerprint matches the span the operator would see.
        #expect(fp == InjectionInspectionPass.spanFingerprint(spanText, salt: Self.salt))

        // Release it: same request now forwards as a flag, not a block.
        let released = InjectionInspectionPass.inspect(
            body: body, filter: filter, allowlisted: [fp!], salt: Self.salt
        )
        #expect(released.decision == .flag, "A released span must forward (flagged), not block")
        #expect(released.findings.contains { $0.allowlisted },
                "The released finding must be marked allowlisted for the audit trail")
    }

    @Test("Releasing one span does not release a different one")
    func allowlistIsSpanSpecific() {
        let filter = triggerFilter()
        let releasedFP = InjectionInspectionPass.spanFingerprint("some QURTLE tool output", salt: Self.salt)
        // A *different* offending span still blocks despite the allowlist.
        let other = InjectionInspectionPass.inspect(
            body: bodyWithTrigger("another QURTLE entirely"),
            filter: filter, allowlisted: [releasedFP], salt: Self.salt
        )
        #expect(other.decision == .block, "Allowlisting one span must not release a different one")
    }

    @Test("SpanAllowlist store round-trips and re-arms")
    func storeRoundTrips() {
        let defaults = UserDefaults(suiteName: "test-allowlist-\(UUID().uuidString)")!
        defer { defaults.removePersistentDomain(forName: defaults.dictionaryRepresentation().isEmpty ? "" : "") }

        #expect(SpanAllowlist.contains("abc", defaults) == false)
        SpanAllowlist.add("abc", defaults)
        SpanAllowlist.add("abc", defaults) // idempotent
        #expect(SpanAllowlist.contains("abc", defaults))
        #expect(SpanAllowlist.all(defaults) == ["abc"])
        SpanAllowlist.remove("abc", defaults)
        #expect(SpanAllowlist.contains("abc", defaults) == false)
        SpanAllowlist.add("x", defaults)
        SpanAllowlist.clear(defaults)
        #expect(SpanAllowlist.all(defaults).isEmpty)
    }

    @Test("Per-install salt is stable across reads")
    func saltIsStable() {
        let defaults = UserDefaults(suiteName: "test-salt-\(UUID().uuidString)")!
        let s1 = SpanAllowlist.salt(defaults)
        let s2 = SpanAllowlist.salt(defaults)
        #expect(s1 == s2, "Salt must be minted once and persist")
        #expect(s1.count == 32, "32 random bytes")
    }
}
