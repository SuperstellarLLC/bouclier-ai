import Foundation
import Testing
@testable import Bouclier

/// Covers the opt-in block explainer: given a block, `explain()` recovers
/// the offending untrusted span, the per-signal breakdown, and (when a
/// classifier is attached) the passage it reacted to. Uses a nonsense
/// trigger token ("QURTLE") so the tests carry no real injection text.
@Suite("Block explainer — capture and attribution")
struct InjectionExplainerTests {
    private static let salt = Data("explain-salt".utf8)

    private func triggerFilter() -> InjectionFilter {
        let regex = try! NSRegularExpression(pattern: "QURTLE", options: [.caseInsensitive])
        let p = FilterPattern(
            id: "t1", name: "trigger", category: "test",
            severity: "critical", regex: regex, enabled: true
        )
        return InjectionFilter(patterns: [p], dampeners: [], classifier: nil)
    }

    private func body(_ text: String) -> Data {
        Data(#"{"messages":[{"role":"user","content":[{"type":"tool_result","content":"\#(text)"}]}]}"#.utf8)
    }

    @Test("explain() captures the offending span, breakdown, and fingerprint")
    func explainCaptures() {
        let filter = triggerFilter()
        let spanText = "harmless preamble QURTLE payload trailer"
        let outcome = InjectionInspectionPass.inspect(body: body(spanText), filter: filter, salt: Self.salt)
        #expect(outcome.decision == .block)

        let sample = InjectionInspectionPass.explain(
            body: body(spanText), filter: filter, outcome: outcome,
            salt: Self.salt, targetHost: "api.anthropic.com", timestamp: "2026-08-11T00:00:00Z"
        )
        #expect(sample != nil)
        #expect(sample?.spanExcerpt.contains("QURTLE") == true, "excerpt must carry the offending span")
        #expect((sample?.matchCount ?? 0) >= 1)
        #expect(sample?.fingerprint == InjectionInspectionPass.spanFingerprint(spanText, salt: Self.salt),
                "sample fingerprint must match the releasable span fingerprint")
        #expect(sample?.topWindow == nil, "no classifier attached → no ML attribution")
        #expect(sample?.benignMultiplier == 1.0, "no benign markers → ML fully trusted (multiplier 1.0)")
    }

    @Test("Excerpt is capped so one giant span can't bloat the store")
    func excerptCapped() {
        let filter = triggerFilter()
        let big = String(repeating: "x", count: 20_000) + " QURTLE"
        let outcome = InjectionInspectionPass.inspect(body: body(big), filter: filter, salt: Self.salt)
        let sample = InjectionInspectionPass.explain(
            body: body(big), filter: filter, outcome: outcome,
            salt: Self.salt, targetHost: "h", timestamp: "t"
        )
        #expect((sample?.spanExcerpt.count ?? .max) <= BlockSampleStore.maxExcerptChars)
        #expect((sample?.spanLength ?? 0) >= 20_000, "full span length is recorded even though the excerpt is capped")
    }

    @Test("No block → nothing to explain")
    func noBlockNoSample() {
        let filter = triggerFilter()
        let outcome = InjectionInspectionPass.inspect(body: body("totally benign tool output"), filter: filter, salt: Self.salt)
        #expect(outcome.decision == .allow)
        let sample = InjectionInspectionPass.explain(
            body: body("totally benign tool output"), filter: filter, outcome: outcome,
            salt: Self.salt, targetHost: "h", timestamp: "t"
        )
        #expect(sample == nil)
    }

    @Test("BlockSample round-trips through JSON")
    func codableRoundTrip() throws {
        let s = BlockSample(
            timestamp: "t", targetHost: "h", locator: "l", spanExcerpt: "e", spanLength: 1,
            fusedScore: 0.9, mlScore: 0.8, entropyAnomaly: 0, matchCount: 1, patternNames: ["p"],
            benignMultiplier: 1, topWindow: nil, topWindowScore: nil, windowsScanned: 0,
            attributionTruncated: false, fingerprint: "f"
        )
        let data = try JSONEncoder().encode(s)
        let back = try JSONDecoder().decode(BlockSample.self, from: data)
        #expect(back.fingerprint == "f")
        #expect(back.fusedScore == 0.9)
        #expect(back.mlScore == 0.8)
    }
}
