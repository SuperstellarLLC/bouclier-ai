import Foundation
import Testing
@testable import Bouclier

@Suite("False-positive report")
struct FalsePositiveReportTests {
    // Benign excerpt text throughout (an email is the thing we redact) — never
    // injection-shaped fixtures, so exercising this suite can't self-block a
    // session running through the gateway.
    private func sample(fingerprint: String, excerpt: String, topWindow: String? = nil) -> BlockSample {
        BlockSample(
            timestamp: "2026-08-13T00:00:00Z",
            targetHost: "api.anthropic.com",
            locator: "messages[2].content[0].tool_result",
            spanExcerpt: excerpt,
            spanLength: excerpt.count,
            fusedScore: 0.91,
            mlScore: 0.99,
            entropyAnomaly: 0.1,
            matchCount: 1,
            patternNames: ["system-prompt-extraction"],
            benignMultiplier: 1.0,
            topWindow: topWindow,
            topWindowScore: topWindow == nil ? nil : 0.99,
            windowsScanned: 3,
            attributionTruncated: false,
            fingerprint: fingerprint
        )
    }

    @Test("find(byFingerprint:in:) returns the freshest match and nil for misses")
    func findByFingerprint() {
        let enc = JSONEncoder()
        enc.outputFormatting = [.sortedKeys]
        func line(_ s: BlockSample) -> String { String(data: try! enc.encode(s), encoding: .utf8)! }

        // Newest is appended last; two "fp-b" samples — the later one wins.
        let jsonl = [
            line(sample(fingerprint: "fp-a", excerpt: "alpha")),
            line(sample(fingerprint: "fp-b", excerpt: "bravo-old")),
            line(sample(fingerprint: "fp-b", excerpt: "bravo-new")),
        ].joined(separator: "\n") + "\n"

        #expect(BlockSampleStore.find(byFingerprint: "fp-a", in: jsonl)?.spanExcerpt == "alpha")
        #expect(BlockSampleStore.find(byFingerprint: "fp-b", in: jsonl)?.spanExcerpt == "bravo-new")
        #expect(BlockSampleStore.find(byFingerprint: "fp-missing", in: jsonl) == nil)
        #expect(BlockSampleStore.find(byFingerprint: "", in: jsonl) == nil)
    }

    @Test("apply() replaces detected spans with [redacted:type], right-to-left")
    func applyRedactions() {
        // "key AAAA and BBBB end" — AAAA at UTF-16 4..8, BBBB at 13..17.
        let text = "key AAAA and BBBB end"
        let dets = [
            PIIScanner.Detection(type: "API_KEY", start: 4, end: 8, value: "AAAA"),
            PIIScanner.Detection(type: "EMAIL", start: 13, end: 17, value: "BBBB"),
        ]
        #expect(ReportRedactor.apply(dets, to: text) == "key [redacted:api_key] and [redacted:email] end")
        #expect(ReportRedactor.apply([], to: text) == text)
    }

    @Test("redact() scrubs a PII/secret value from free text end-to-end")
    func redactEndToEnd() async {
        let out = await ReportRedactor.redact("owner is dev@example.com, thanks")
        #expect(!out.contains("dev@example.com"), "the email must be gone")
        #expect(out.contains("[redacted:"), "and replaced with a marker")
    }

    @Test("draft() maps fields and redacts the excerpt + top window before they reach the draft")
    func draftRedacts() async {
        let s = sample(
            fingerprint: "fp1",
            excerpt: "contact dev@example.com for the lint config",
            topWindow: "escalate to root@example.com"
        )
        let d = await FalsePositiveReporter.draft(from: s, appVersion: "0.9.8")
        #expect(d.appVersion == "0.9.8")
        #expect(d.targetHost == "api.anthropic.com")
        #expect(d.fingerprint == "fp1")
        #expect(!d.spanExcerpt.contains("dev@example.com"), "excerpt is redacted before it reaches the draft")
        #expect(d.topWindow?.contains("root@example.com") == false, "top window is redacted too")
    }

    @Test("previewJSON carries the wire shape, includes a trimmed note, never a client timestamp")
    func previewJSONShape() async {
        let d = await FalsePositiveReporter.draft(
            from: sample(fingerprint: "fp1", excerpt: "benign lint output, strict mode"),
            appVersion: "0.9.8"
        )

        let withNote = FalsePositiveReporter.previewJSON(for: d, note: "  this is a lint diff  ")
        #expect(withNote.contains("\"spanExcerpt\""))
        #expect(withNote.contains("\"targetHost\""))
        #expect(withNote.contains("\"appVersion\""))
        #expect(withNote.contains("this is a lint diff"), "the note is trimmed and included")
        #expect(!withNote.contains("\"ts\""), "the server stamps receipt time; the client must not send one")

        let noNote = FalsePositiveReporter.previewJSON(for: d, note: "   ")
        #expect(!noNote.contains("\"note\""), "a whitespace-only note is omitted, not sent as blank")

        // The preview must be byte-for-byte the body send() transmits — both
        // go through encodedBody, so the "exactly this will be sent" promise
        // is literally true, not just same-values.
        #expect(
            withNote == String(
                data: FalsePositiveReporter.encodedBody(for: d, note: "  this is a lint diff  "),
                encoding: .utf8
            )
        )
    }
}
