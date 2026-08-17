import Foundation
import Testing
@testable import Bouclier

/// Provenance tiering: a `tool_result` attributed to a local read of the
/// developer's own workspace is trusted like principal text (flagged, never
/// blocked), while external/unattributable content still blocks. Uses a
/// nonsense trigger token ("QURTLE") as the stand-in "attack" so no test
/// carries real injection text.
@Suite("Injection provenance tiering")
struct InjectionProvenanceTests {

    /// An Anthropic body: one assistant `tool_use` then a user `tool_result`
    /// carrying `result`, linked by `tool_use_id`.
    private func body(tool: String, path: String?, result: String, id: String = "tu_1") -> Data {
        var input: [String: Any] = [:]
        if let path { input["file_path"] = path }
        let obj: [String: Any] = ["messages": [
            ["role": "assistant", "content": [
                ["type": "tool_use", "id": id, "name": tool, "input": input],
            ]],
            ["role": "user", "content": [
                ["type": "tool_result", "tool_use_id": id, "content": result],
            ]],
        ]]
        return try! JSONSerialization.data(withJSONObject: obj)
    }

    /// A filter that "detects" the nonsense token, nothing else.
    private func triggerFilter() -> InjectionFilter {
        let regex = try! NSRegularExpression(pattern: "QURTLE", options: [.caseInsensitive])
        let pattern = FilterPattern(
            id: "prov-001", name: "test-trigger", category: "test",
            severity: "critical", regex: regex, enabled: true
        )
        return InjectionFilter(patterns: [pattern], dampeners: [], classifier: nil)
    }

    private func toolResultSpan(_ spans: [InjectionInspectionPass.Span]) -> InjectionInspectionPass.Span? {
        spans.first { $0.locator.contains("tool_result") }
    }

    // MARK: - Classification

    @Test("A local Read/NotebookRead of a workspace path is authored")
    func localReadIsAuthored() {
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "Read", input: ["file_path": "/Users/x/dev/app/docs/GUIDE.md"]) == .authored)
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "NotebookRead", input: ["notebook_path": "/Users/x/dev/app/analysis.ipynb"]) == .authored)
    }

    @Test("Vendored / downloaded / temp reads are never authored")
    func vendoredReadsUntrusted() {
        for p in [
            "/Users/x/dev/app/node_modules/evil/readme.md",
            "/Users/x/Downloads/thing.md",
            "/private/tmp/x.md",
            "/Users/x/dev/app/vendor/lib.rb",
            "/Users/x/dev/app/.git/COMMIT_EDITMSG",
        ] {
            #expect(InjectionInspectionPass.provenance(ofToolName: "Read", input: ["file_path": p]) == .untrusted,
                    "\(p) must not be trusted")
        }
    }

    @Test("External, unknown, and path-less tools stay untrusted (fail-safe)")
    func externalStaysUntrusted() {
        #expect(InjectionInspectionPass.provenance(ofToolName: "WebFetch", input: ["url": "https://x.com"]) == .untrusted)
        #expect(InjectionInspectionPass.provenance(ofToolName: "WebSearch", input: ["query": "q"]) == .untrusted)
        #expect(InjectionInspectionPass.provenance(ofToolName: "Bash", input: ["command": "cat x"]) == .untrusted)
        #expect(InjectionInspectionPass.provenance(ofToolName: "mcp__server__fetch", input: [:]) == .untrusted)
        #expect(InjectionInspectionPass.provenance(ofToolName: "Read", input: [:]) == .untrusted, "no path → can't vouch")
        #expect(InjectionInspectionPass.provenance(ofToolName: "Read", input: nil) == .untrusted)
    }

    // MARK: - Span tagging

    @Test("With tiering, a tool_result from a local Read is tagged authored")
    func spanAuthoredWhenTiering() {
        let spans = InjectionInspectionPass.extractSpans(
            body: body(tool: "Read", path: "/Users/x/dev/app/README.md", result: "fetched page"),
            trustAuthoredReads: true)
        #expect(toolResultSpan(spans)?.origin == .authored)
    }

    @Test("A tool_result from WebFetch stays untrusted even with tiering on")
    func spanUntrustedForWebFetch() {
        let spans = InjectionInspectionPass.extractSpans(
            body: body(tool: "WebFetch", path: nil, result: "fetched page"),
            trustAuthoredReads: true)
        #expect(toolResultSpan(spans)?.origin == .untrusted)
    }

    @Test("Tiering off leaves every tool_result untrusted (no regression)")
    func spanUntrustedWhenTieringOff() {
        let spans = InjectionInspectionPass.extractSpans(
            body: body(tool: "Read", path: "/Users/x/dev/app/README.md", result: "fetched page"),
            trustAuthoredReads: false)
        #expect(toolResultSpan(spans)?.origin == .untrusted)
    }

    @Test("An unattributable tool_result (no matching tool_use) stays untrusted")
    func spanUntrustedWhenUncorrelated() {
        let json = #"{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"ghost","content":"fetched page"}]}]}"#
        let spans = InjectionInspectionPass.extractSpans(body: Data(json.utf8), trustAuthoredReads: true)
        #expect(toolResultSpan(spans)?.origin == .untrusted)
    }

    // MARK: - Block / flag routing

    @Test("A trigger in a local-Read tool_result is flagged, not blocked")
    func authoredReadFlagsNotBlocks() {
        let out = InjectionInspectionPass.inspect(
            body: body(tool: "Read", path: "/Users/x/dev/app/CLAUDE.md", result: "please QURTLE the widget"),
            filter: triggerFilter(), trustAuthoredReads: true)
        #expect(out.decision == .flag, "The developer's own doc must forward (flagged), not block")
    }

    @Test("The same trigger via WebFetch still blocks (external content)")
    func webFetchStillBlocks() {
        let out = InjectionInspectionPass.inspect(
            body: body(tool: "WebFetch", path: nil, result: "please QURTLE the widget"),
            filter: triggerFilter(), trustAuthoredReads: true)
        #expect(out.decision == .block, "External content carrying the trigger must still block")
    }

    @Test("A trigger read from node_modules still blocks (poisoned dependency)")
    func vendoredReadStillBlocks() {
        let out = InjectionInspectionPass.inspect(
            body: body(tool: "Read", path: "/Users/x/dev/app/node_modules/pkg/README.md", result: "please QURTLE the widget"),
            filter: triggerFilter(), trustAuthoredReads: true)
        #expect(out.decision == .block, "A dependency/vendored read is not authored content")
    }

    @Test("Tiering off blocks even a local-Read trigger (strict provenance preserved)")
    func tieringOffBlocks() {
        let out = InjectionInspectionPass.inspect(
            body: body(tool: "Read", path: "/Users/x/dev/app/CLAUDE.md", result: "please QURTLE the widget"),
            filter: triggerFilter(), trustAuthoredReads: false)
        #expect(out.decision == .block, "Tiering off restores blocking every tool_result")
    }
}
