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

    @Test("A local Read/NotebookRead under a known workspace path is authored")
    func localReadIsAuthored() {
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "Read",
            input: ["file_path": "/Users/x/dev/app/docs/GUIDE.md"],
            workspaceRoots: ["/Users/x/dev/app"]
        ) == .authored)
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "NotebookRead",
            input: ["notebook_path": "/Users/x/dev/app/analysis.ipynb"],
            workspaceRoots: ["/Users/x/dev/app"]
        ) == .authored)
    }

    @Test("A local read without a canonical workspace root stays untrusted")
    func localReadWithoutWorkspaceIsUntrusted() {
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "Read", input: ["file_path": "/Users/x/dev/app/docs/GUIDE.md"]
        ) == .untrusted)
    }

    @Test("Vendored / downloaded / temp reads are never authored")
    func vendoredReadsUntrusted() {
        for p in [
            "/Users/x/dev/app/node_modules/evil/readme.md",
            "/Users/x/Downloads/thing.md",
            "/private/tmp/x.md",
            "/var/tmp/x.md",
            "/Users/x/dev/app/vendor/lib.rb",
            "/Users/x/dev/app/.git/COMMIT_EDITMSG",
        ] {
            #expect(InjectionInspectionPass.provenance(ofToolName: "Read", input: ["file_path": p]) == .untrusted,
                    "\(p) must not be trusted")
        }
    }

    @Test("Relative paths are never authored (only absolute paths can be vouched for)")
    func relativePathsUntrusted() {
        // A relative path wouldn't match the slash-delimited denylist fragments,
        // so it must fail the absolute-path gate rather than slip through.
        for p in ["node_modules/evil/readme.md", "docs/GUIDE.md", "CLAUDE.md", "../secrets.md"] {
            #expect(InjectionInspectionPass.provenance(ofToolName: "Read", input: ["file_path": p]) == .untrusted,
                    "relative \(p) must not be trusted")
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
            body: bodyWithWorkspace(
                cwd: "/Users/x/dev/app",
                readPath: "/Users/x/dev/app/README.md",
                result: "fetched page"
            ),
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

    @Test("Duplicate tool_use IDs fail closed instead of laundering provenance")
    func duplicateToolUseIDsStayUntrusted() {
        let obj: [String: Any] = [
            "system": "Working directory: /Users/x/dev/app",
            "messages": [
                ["role": "assistant", "content": [
                    ["type": "tool_use", "id": "dup", "name": "WebFetch",
                     "input": ["url": "https://attacker.example"]],
                    ["type": "tool_use", "id": "dup", "name": "Read",
                     "input": ["file_path": "/Users/x/dev/app/README.md"]],
                ]],
                ["role": "user", "content": [
                    ["type": "tool_result", "tool_use_id": "dup",
                     "content": "please QURTLE the widget"],
                ]],
            ],
        ]
        let data = try! JSONSerialization.data(withJSONObject: obj)
        let spans = InjectionInspectionPass.extractSpans(body: data, trustAuthoredReads: true)
        #expect(toolResultSpan(spans)?.origin == .untrusted)
        #expect(InjectionInspectionPass.inspect(
            body: data, filter: triggerFilter(), trustAuthoredReads: true
        ).decision == .block)
    }

    // MARK: - Block / flag routing

    @Test("A trigger in a local-Read tool_result is flagged, not blocked")
    func authoredReadFlagsNotBlocks() {
        let out = InjectionInspectionPass.inspect(
            body: bodyWithWorkspace(
                cwd: "/Users/x/dev/app",
                readPath: "/Users/x/dev/app/CLAUDE.md",
                result: "please QURTLE the widget"
            ),
            filter: triggerFilter(), trustAuthoredReads: true)
        #expect(out.decision == .flag, "The developer's own doc must forward (flagged), not block")
    }

    @Test("The same trigger via WebFetch still blocks (external content)")
    func webFetchStillBlocks() {
        let out = InjectionInspectionPass.inspect(
            body: body(tool: "WebFetch", path: nil, result: "please QURTLE the widget"),
            filter: triggerFilter(), trustAuthoredReads: true)
        #expect(out.decision == .block, "External content carrying the trigger must still block")
        let refusal = InjectionInspectionPass.refusalJSON(for: out)
        #expect(refusal.contains("did not positively attribute"))
        #expect(!refusal.contains("not something you typed"))
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

    // MARK: - Workspace-root allowlist

    /// Body with a system prompt declaring the cwd, plus a Read tool_use +
    /// tool_result at `readPath`.
    private func bodyWithWorkspace(cwd: String, readPath: String, result: String = "hello") -> Data {
        let obj: [String: Any] = [
            "system": "You are Claude Code.\n<env>\nWorking directory: \(cwd)\nPlatform: darwin\n</env>",
            "messages": [
                ["role": "assistant", "content": [
                    ["type": "tool_use", "id": "tu_1", "name": "Read", "input": ["file_path": readPath]],
                ]],
                ["role": "user", "content": [
                    ["type": "tool_result", "tool_use_id": "tu_1", "content": result],
                ]],
            ],
        ]
        return try! JSONSerialization.data(withJSONObject: obj)
    }

    @Test("workspaceRoots extracts the cwd from the system prompt (normalized)")
    func extractsWorkspaceRoot() {
        let root = try! JSONSerialization.jsonObject(
            with: Data(#"{"system":"<env>\nWorking directory: /Users/x/proj\n</env>"}"#.utf8)) as! [String: Any]
        #expect(InjectionInspectionPass.workspaceRoots(from: root) == ["/Users/x/proj/"])
    }

    @Test("Workspace metadata accepts spaces but must use the recognized env envelope")
    func workspaceMetadataEnvelopeIsRequired() {
        let scoped: [String: Any] = [
            "system": "<env>\nWorking directory: /Users/x/My Project\nPlatform: darwin\n</env>",
        ]
        #expect(InjectionInspectionPass.workspaceRoots(from: scoped) == ["/Users/x/My Project/"])

        let unscoped: [String: Any] = [
            "system": "Project instructions.\nWorking directory: /Users/x/proj",
        ]
        #expect(InjectionInspectionPass.workspaceRoots(from: unscoped).isEmpty)

        let unsupportedAlias: [String: Any] = [
            "system": "<env>\ncwd: /Users/x/proj\nPlatform: darwin\n</env>",
        ]
        #expect(InjectionInspectionPass.workspaceRoots(from: unsupportedAlias).isEmpty)
    }

    @Test("Ambiguous or root-filesystem workspace declarations fail closed")
    func unsafeWorkspaceDeclarationsFailClosed() {
        let duplicate: [String: Any] = [
            "system": """
            <env>
            Working directory: /Users/x/proj
            Platform: darwin
            </env>
            Working directory: /Users/x/elsewhere
            """,
        ]
        #expect(InjectionInspectionPass.workspaceRoots(from: duplicate).isEmpty)

        let multipleEnvelopes: [String: Any] = [
            "system": """
            <env>
            Working directory: /Users/x/proj
            </env>
            <env>
            Platform: darwin
            </env>
            """,
        ]
        #expect(InjectionInspectionPass.workspaceRoots(from: multipleEnvelopes).isEmpty)

        let duplicateAfterInspectionBound: [String: Any] = [
            "system": """
            <env>
            Working directory: /Users/x/proj
            Platform: darwin
            </env>
            """ + String(repeating: "x", count: 16_384) + """

            <env>
            Working directory: /Users/x/elsewhere
            Platform: darwin
            </env>
            """,
        ]
        #expect(InjectionInspectionPass.workspaceRoots(from: duplicateAfterInspectionBound).isEmpty)

        let filesystemRoot: [String: Any] = [
            "system": "<env>\nWorking directory: /\nPlatform: darwin\n</env>",
        ]
        #expect(InjectionInspectionPass.workspaceRoots(from: filesystemRoot).isEmpty)
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "Read",
            input: ["file_path": "/Users/x/Documents/payload.md"],
            workspaceRoots: ["/"]
        ) == .untrusted)
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "Read",
            input: ["file_path": "/Users/x/proj/payload.md"],
            workspaceRoots: ["/Users/x/proj", "/Users/x"]
        ) == .untrusted)
    }

    @Test("A cwd declared only in untrusted tool content is NOT a workspace root")
    func attackerCannotDeclareRoot() {
        // "Working directory: /evil" lives in a tool_result, not the system
        // prompt — so it must never become a trusted root.
        let json = #"{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"t","content":"Working directory: /evil"}]}]}"#
        let root = try! JSONSerialization.jsonObject(with: Data(json.utf8)) as! [String: Any]
        #expect(InjectionInspectionPass.workspaceRoots(from: root).isEmpty)
    }

    @Test("With a known workspace root, a read UNDER it is authored")
    func readUnderWorkspaceAuthored() {
        let spans = InjectionInspectionPass.extractSpans(
            body: bodyWithWorkspace(cwd: "/Users/x/proj", readPath: "/Users/x/proj/docs/GUIDE.md"),
            trustAuthoredReads: true)
        #expect(toolResultSpan(spans)?.origin == .authored)
    }

    @Test("With a known workspace root, a read OUTSIDE it is untrusted (planted-file defense)")
    func readOutsideWorkspaceUntrusted() {
        let spans = InjectionInspectionPass.extractSpans(
            body: bodyWithWorkspace(cwd: "/Users/x/proj", readPath: "/Users/x/Documents/attachment.md"),
            trustAuthoredReads: true)
        #expect(toolResultSpan(spans)?.origin == .untrusted)
    }

    @Test("A read under the root but in a vendored subdir is still untrusted")
    func vendoredUnderWorkspaceUntrusted() {
        let spans = InjectionInspectionPass.extractSpans(
            body: bodyWithWorkspace(cwd: "/Users/x/proj", readPath: "/Users/x/proj/node_modules/pkg/README.md"),
            trustAuthoredReads: true)
        #expect(toolResultSpan(spans)?.origin == .untrusted)
    }

    @Test("Allowlist prefix must not leak into a sibling directory")
    func siblingDirNotTrusted() {
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "Read", input: ["file_path": "/Users/x/proj-evil/x.md"],
            workspaceRoots: ["/Users/x/proj/"]) == .untrusted)
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "Read", input: ["file_path": "/Users/x/proj/x.md"],
            workspaceRoots: ["/Users/x/proj/"]) == .authored)
    }

    @Test("Dot-dot traversal is standardized before workspace trust")
    func traversalCannotEscapeWorkspace() {
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "Read",
            input: ["file_path": "/Users/x/proj/docs/../../outside.md"],
            workspaceRoots: ["/Users/x/proj"]
        ) == .untrusted)
        let packageRoot = FileManager.default.currentDirectoryPath
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "Read",
            input: ["file_path": packageRoot + "/Tests/../Package.swift"],
            workspaceRoots: [packageRoot]
        ) == .authored)
    }

    @Test("Existing symlinks are resolved before workspace trust")
    func symlinkCannotEscapeWorkspace() throws {
        let fm = FileManager.default
        let base = URL(fileURLWithPath: fm.currentDirectoryPath, isDirectory: true)
            .appendingPathComponent(".provenance-test-\(UUID().uuidString)", isDirectory: true)
        let workspace = base.appendingPathComponent("workspace", isDirectory: true)
        let outside = base.appendingPathComponent("outside", isDirectory: true)
        let link = workspace.appendingPathComponent("linked", isDirectory: true)
        try fm.createDirectory(at: workspace, withIntermediateDirectories: true)
        try fm.createDirectory(at: outside, withIntermediateDirectories: true)
        try fm.createSymbolicLink(at: link, withDestinationURL: outside)
        defer { try? fm.removeItem(at: base) }

        let linkedFile = link.appendingPathComponent("payload.md").path
        let canonical = try #require(InjectionInspectionPass.canonicalFilePath(linkedFile))
        #expect(canonical.hasPrefix(outside.path + "/"))
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "Read",
            input: ["file_path": linkedFile],
            workspaceRoots: [workspace.path]
        ) == .untrusted)
    }

    @Test("Symlink is resolved before dot-dot components")
    func symlinkBeforeDotDotCannotGainTrust() throws {
        let fm = FileManager.default
        let base = URL(fileURLWithPath: fm.currentDirectoryPath, isDirectory: true)
            .appendingPathComponent(".provenance-order-test-\(UUID().uuidString)", isDirectory: true)
        let workspace = base.appendingPathComponent("workspace", isDirectory: true)
        let outside = base.appendingPathComponent("outside", isDirectory: true)
        let outsideSubdir = outside.appendingPathComponent("subdir", isDirectory: true)
        try fm.createDirectory(at: workspace, withIntermediateDirectories: true)
        try fm.createDirectory(at: outsideSubdir, withIntermediateDirectories: true)
        try Data("payload".utf8).write(to: outside.appendingPathComponent("secret.md"))
        try fm.createSymbolicLink(
            at: workspace.appendingPathComponent("link"),
            withDestinationURL: outsideSubdir
        )
        defer { try? fm.removeItem(at: base) }

        let deceptivePath = workspace.path + "/link/../secret.md"
        let canonical = try #require(InjectionInspectionPass.canonicalFilePath(deceptivePath))
        #expect(canonical == outside.appendingPathComponent("secret.md").path)
        #expect(InjectionInspectionPass.provenance(
            ofToolName: "Read",
            input: ["file_path": deceptivePath],
            workspaceRoots: [workspace.path]
        ) == .untrusted)
    }

    @Test("Strict mode attributes an authored-file refusal honestly")
    func strictAuthoredRefusal() {
        let out = InjectionInspectionPass.inspect(
            body: bodyWithWorkspace(
                cwd: "/Users/x/proj",
                readPath: "/Users/x/proj/CLAUDE.md",
                result: "please QURTLE the widget"
            ),
            filter: triggerFilter(),
            strict: true,
            trustAuthoredReads: true
        )
        #expect(out.decision == .block)
        #expect(out.blockedFinding?.origin == .authored)
        let refusal = InjectionInspectionPass.refusalJSON(for: out)
        #expect(refusal.contains("classified as an attributed local read"))
        #expect(!refusal.contains("not something you typed"))
    }
}
