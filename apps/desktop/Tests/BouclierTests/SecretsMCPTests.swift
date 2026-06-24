import Foundation
import Testing
@testable import BouclierSecretsCore

// MARK: - Pure resolver

@Suite("SecretEnvResolver")
struct SecretEnvResolverTests {
    let metas = [
        SecretRuleMeta(name: "stripe", agentAccess: true, envVar: "STRIPE_KEY"),
        SecretRuleMeta(name: "openai", agentAccess: true, envVar: nil),     // default env = OPENAI
        SecretRuleMeta(name: "locked", agentAccess: false, envVar: "LOCKED_KEY"),
    ]

    @Test("Allowed + resolvable secrets export; locked/unknown are denied")
    func resolve() {
        let r = SecretEnvResolver.resolve(active: ["stripe", "openai", "locked", "ghost"], metas: metas) {
            ["stripe": "sk_live_AAAA", "openai": "sk-OOOO", "locked": "sk_live_LLLL"][$0]
        }
        #expect(r.exports == [
            .init(envVar: "STRIPE_KEY", value: "sk_live_AAAA"),
            .init(envVar: "OPENAI", value: "sk-OOOO"),
        ])
        #expect(r.denied == ["locked", "ghost"])
        #expect(r.unresolved.isEmpty)
    }

    @Test("Allowed but no value ⇒ unresolved, not exported")
    func unresolved() {
        let r = SecretEnvResolver.resolve(active: ["stripe"], metas: metas) { _ in nil }
        #expect(r.exports.isEmpty)
        #expect(r.unresolved == ["stripe"])
    }

    @Test("Export lines single-quote and escape values (no shell injection)")
    func exportEscaping() {
        let lines = SecretEnvResolver.exportLines([
            .init(envVar: "A", value: "plain"),
            .init(envVar: "B", value: "ab'cd"),       // embedded single quote
            .init(envVar: "C", value: "x$y;rm -rf"),  // shell metachars stay literal
        ])
        #expect(lines.contains("export A='plain';"))
        #expect(lines.contains("export B='ab'\\''cd';"))
        #expect(lines.contains("export C='x$y;rm -rf';"))
    }

    @Test("fish export lines use set -gx with fish-style quoting")
    func fishExport() {
        let lines = SecretEnvResolver.exportLinesFish([
            .init(envVar: "A", value: "plain"),
            .init(envVar: "B", value: "ab'cd"),    // single quote → \'
            .init(envVar: "C", value: "a\\b"),     // backslash → \\
        ])
        #expect(lines.contains("set -gx A 'plain';"))
        #expect(lines.contains("set -gx B 'ab\\'cd';"))
        #expect(lines.contains("set -gx C 'a\\\\b';"))
    }

    @Test("Invalid env-var name is denied (shell-injection defense at the executor)")
    func invalidEnvNameDenied() {
        let metas = [SecretRuleMeta(name: "x", agentAccess: true, envVar: "X; rm -rf ~ #")]
        let r = SecretEnvResolver.resolve(active: ["x"], metas: metas) { _ in "anything" }
        #expect(r.exports.isEmpty)
        #expect(r.denied == ["x"])
    }

    @Test("Value containing a newline is unresolved (can't break the export line)")
    func newlineValueUnresolved() {
        let metas = [SecretRuleMeta(name: "x", agentAccess: true, envVar: "X")]
        let r = SecretEnvResolver.resolve(active: ["x"], metas: metas) { _ in "a\nb" }
        #expect(r.exports.isEmpty)
        #expect(r.unresolved == ["x"])
    }

    @Test("Env-var collision: first occurrence wins, emitted once")
    func collisionFirstWins() {
        let metas = [
            SecretRuleMeta(name: "a", agentAccess: true, envVar: "SHARED"),
            SecretRuleMeta(name: "b", agentAccess: true, envVar: "SHARED"),
        ]
        let r = SecretEnvResolver.resolve(active: ["a", "b"], metas: metas) { ["a": "VA", "b": "VB"][$0] }
        #expect(r.exports == [.init(envVar: "SHARED", value: "VA")])
    }

    @Test("Empty envVar string falls back to uppercased name")
    func emptyEnvVarFallback() {
        #expect(SecretRuleMeta(name: "openai", envVar: "").environmentVariable == "OPENAI")
    }

    @Test("isValidEnvName edge cases")
    func envNameValidation() {
        #expect(SecretEnvResolver.isValidEnvName("STRIPE_KEY"))
        #expect(SecretEnvResolver.isValidEnvName("_X1"))
        #expect(!SecretEnvResolver.isValidEnvName(""))
        #expect(!SecretEnvResolver.isValidEnvName("1ABC"))
        #expect(!SecretEnvResolver.isValidEnvName("A B"))
        #expect(!SecretEnvResolver.isValidEnvName("A;B"))
    }
}

// MARK: - Rule metadata decode (backward compatible)

@Suite("SecretRuleMeta decode")
struct SecretRuleMetaTests {
    @Test("Rules saved before agentAccess existed decode as agent-usable")
    func legacyDefaultsToTrue() throws {
        let json = #"[{"name":"stripe","allowedHosts":["api.stripe.com"]}]"#
        let metas = try JSONDecoder().decode([SecretRuleMeta].self, from: Data(json.utf8))
        #expect(metas.first?.agentAccess == true)
        #expect(metas.first?.envVar == nil)
        #expect(metas.first?.environmentVariable == "STRIPE")
    }

    @Test("agentAccess + envVar decode when present")
    func decodesFields() throws {
        let json = #"[{"name":"x","allowedHosts":[],"agentAccess":false,"envVar":"MY_KEY"}]"#
        let metas = try JSONDecoder().decode([SecretRuleMeta].self, from: Data(json.utf8))
        #expect(metas.first?.agentAccess == false)
        #expect(metas.first?.environmentVariable == "MY_KEY")
    }
}

// MARK: - Manifest round-trip

@Suite("SecretEnvManifest", .serialized)
struct SecretEnvManifestTests {
    @Test("Save/load round-trips and de-dupes")
    func roundTrip() {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("bouclier-manifest-\(UUID()).json")
        defer { try? FileManager.default.removeItem(at: url) }
        #expect(SecretEnvManifest.save(["a", "b", "a", "c"], to: url))
        #expect(SecretEnvManifest.load(from: url) == ["a", "b", "c"])
        SecretEnvManifest.clear(at: url)
        #expect(SecretEnvManifest.load(from: url).isEmpty)
    }

    @Test("Malformed or wrong-typed manifest decodes to empty (fail-closed)")
    func malformedFailsClosed() {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("bouclier-manifest-bad-\(UUID()).json")
        defer { try? FileManager.default.removeItem(at: url) }
        try? "{ not json".data(using: .utf8)!.write(to: url)
        #expect(SecretEnvManifest.load(from: url).isEmpty)
        try? "[1,2,3]".data(using: .utf8)!.write(to: url)   // wrong element type
        #expect(SecretEnvManifest.load(from: url).isEmpty)
    }
}

// MARK: - MCP handler

@Suite("SecretsMCPHandler")
struct SecretsMCPHandlerTests {
    final class Box: @unchecked Sendable { var active: [String] = [] }

    private func makeHandler(_ box: Box) -> SecretsMCPHandler {
        SecretsMCPHandler(
            loadRules: {
                [
                    SecretRuleMeta(name: "stripe", agentAccess: true, envVar: "STRIPE_KEY"),
                    SecretRuleMeta(name: "locked", agentAccess: false, envVar: "LOCKED_KEY"),
                ]
            },
            loadActive: { box.active },
            saveActive: { box.active = $0 }
        )
    }

    private func result(_ resp: [String: Any]?) -> [String: Any]? { resp?["result"] as? [String: Any] }
    private func toolText(_ resp: [String: Any]?) -> String {
        guard let content = result(resp)?["content"] as? [[String: Any]] else { return "" }
        return content.compactMap { $0["text"] as? String }.joined(separator: "\n")
    }

    @Test("initialize announces protocol + server info")
    func initialize() {
        let r = makeHandler(Box()).handle(["jsonrpc": "2.0", "id": 1, "method": "initialize"])
        #expect(result(r)?["protocolVersion"] as? String == "2024-11-05")
        let info = result(r)?["serverInfo"] as? [String: Any]
        #expect(info?["name"] as? String == "bouclier-secrets")
    }

    @Test("tools/list exposes all five tools")
    func toolsList() {
        let r = makeHandler(Box()).handle(["jsonrpc": "2.0", "id": 2, "method": "tools/list"])
        let tools = (result(r)?["tools"] as? [[String: Any]])?.compactMap { $0["name"] as? String } ?? []
        #expect(Set(tools) == ["list_secrets", "set_env", "clear_env", "request_secret", "request_secrets"])
    }

    @Test("notifications/initialized produces no reply")
    func notification() {
        let r = makeHandler(Box()).handle(["jsonrpc": "2.0", "method": "notifications/initialized"])
        #expect(r == nil)
    }

    @Test("set_env activates allowed secrets, denies locked/unknown, returns NO values")
    func setEnv() {
        let box = Box()
        let h = makeHandler(box)
        let r = h.handle([
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": ["name": "set_env", "arguments": ["secrets": ["stripe", "locked", "ghost"]]],
        ])
        let text = toolText(r)
        #expect(box.active == ["stripe"], "only the allowed secret is activated")
        #expect(text.contains("$STRIPE_KEY"))
        #expect(text.contains("locked"))
        #expect(text.contains("ghost"))
        // The value must NEVER appear in an MCP response. The handler has no
        // value access by construction; assert the contract holds.
        #expect(!text.contains("sk_live"))
        #expect(result(r)?["isError"] as? Bool == false)
    }

    @Test("list_secrets shows names + env vars + access, never values")
    func listSecrets() {
        let box = Box(); box.active = ["stripe"]
        let r = makeHandler(box).handle([
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": ["name": "list_secrets", "arguments": [:]],
        ])
        let text = toolText(r)
        #expect(text.contains("stripe → $STRIPE_KEY"))
        #expect(text.contains("active"))
        #expect(text.contains("LOCKED"))
    }

    @Test("clear_env empties the manifest")
    func clearEnv() {
        let box = Box(); box.active = ["stripe", "openai"]
        _ = makeHandler(box).handle([
            "jsonrpc": "2.0", "id": 5, "method": "tools/call",
            "params": ["name": "clear_env", "arguments": [:]],
        ])
        #expect(box.active.isEmpty)
    }

    @Test("unknown method returns JSON-RPC error")
    func unknownMethod() {
        let r = makeHandler(Box()).handle(["jsonrpc": "2.0", "id": 6, "method": "bogus"])
        #expect((r?["error"] as? [String: Any])?["code"] as? Int == -32601)
    }

    @Test("set_env with a non-string element keeps the valid names")
    func setEnvHeterogeneousArray() {
        let box = Box()
        let r = makeHandler(box).handle([
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": ["name": "set_env", "arguments": ["secrets": ["stripe", 5, NSNull()]]],
        ])
        #expect(box.active == ["stripe"], "valid name dropped because of a non-string sibling")
        #expect(result(r)?["isError"] as? Bool == false)
    }

    @Test("tools/call set_env with missing arguments → in-band error")
    func setEnvMissingArgs() {
        let r = makeHandler(Box()).handle([
            "jsonrpc": "2.0", "id": 8, "method": "tools/call",
            "params": ["name": "set_env"],
        ])
        #expect(result(r)?["isError"] as? Bool == true)
    }

    @Test("tools/call as a notification (no id) returns nil and does not mutate")
    func toolCallNotification() {
        let box = Box(); box.active = ["x"]
        let r = makeHandler(box).handle([
            "jsonrpc": "2.0", "method": "tools/call",
            "params": ["name": "clear_env", "arguments": [:]],
        ])
        #expect(r == nil)
        #expect(box.active == ["x"], "clear_env ran for a notification")
    }

    @Test("Unknown tool returns in-band isError, not a JSON-RPC error")
    func unknownTool() {
        let r = makeHandler(Box()).handle([
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": ["name": "bogus", "arguments": [:]],
        ])
        #expect(r?["result"] != nil)
        #expect(r?["error"] == nil)
        #expect(result(r)?["isError"] as? Bool == true)
    }

    @Test("JSON-RPC id passthrough: string and null ids echo exactly")
    func idPassthrough() {
        let rs = makeHandler(Box()).handle(["jsonrpc": "2.0", "id": "abc", "method": "ping"])
        #expect(rs?["id"] as? String == "abc")
        let rn = makeHandler(Box()).handle(["jsonrpc": "2.0", "id": NSNull(), "method": "ping"])
        #expect(rn?["id"] is NSNull)
    }

    // MARK: request_secret(s)

    private func handlerWithRequest(_ rs: @escaping @Sendable ([String], String, Bool) -> SecretResponseIPC?) -> SecretsMCPHandler {
        SecretsMCPHandler(loadRules: { [] }, loadActive: { [] }, saveActive: { _ in }, requestSecrets: rs)
    }

    private func callRequestSecret(_ h: SecretsMCPHandler, envVar: String) -> [String: Any]? {
        h.handle(["jsonrpc": "2.0", "id": 10, "method": "tools/call",
                  "params": ["name": "request_secret", "arguments": ["env_var": envVar, "reason": "test"]]])
    }

    @Test("request_secret provided → success, mentions env var, never a value")
    func requestProvided() {
        let h = handlerWithRequest { vars, _, _ in
            SecretResponseIPC(id: "x", status: .provided, provided: vars, skipped: [])
        }
        let r = callRequestSecret(h, envVar: "STRIPE_KEY")
        #expect(result(r)?["isError"] as? Bool == false)
        #expect(toolText(r).contains("$STRIPE_KEY"))
    }

    @Test("request_secret cancelled / timeout / unreachable all report isError")
    func requestFailureModes() {
        let cancelled = handlerWithRequest { _, _, _ in SecretResponseIPC(id: "x", status: .cancelled, provided: [], skipped: ["STRIPE_KEY"]) }
        #expect(result(callRequestSecret(cancelled, envVar: "STRIPE_KEY"))?["isError"] as? Bool == true)

        let timeout = handlerWithRequest { _, _, _ in SecretResponseIPC(id: "x", status: .timeout, provided: [], skipped: ["STRIPE_KEY"]) }
        #expect(result(callRequestSecret(timeout, envVar: "STRIPE_KEY"))?["isError"] as? Bool == true)

        let unreachable = handlerWithRequest { _, _, _ in nil }
        let r = callRequestSecret(unreachable, envVar: "STRIPE_KEY")
        #expect(result(r)?["isError"] as? Bool == true)
        #expect(toolText(r).contains("isn't running"))
    }

    @Test("request_secret missing env_var → in-band error")
    func requestMissingArg() {
        let h = handlerWithRequest { _, _, _ in nil }
        let r = h.handle(["jsonrpc": "2.0", "id": 11, "method": "tools/call",
                          "params": ["name": "request_secret", "arguments": [:]]])
        #expect(result(r)?["isError"] as? Bool == true)
    }

    @Test("request_secrets multi: reports provided and skipped")
    func requestSecretsMulti() {
        let h = handlerWithRequest { vars, _, _ in
            SecretResponseIPC(id: "x", status: .provided, provided: [vars[0]], skipped: Array(vars.dropFirst()))
        }
        let r = h.handle(["jsonrpc": "2.0", "id": 12, "method": "tools/call",
                          "params": ["name": "request_secrets", "arguments": ["env_vars": ["STRIPE_KEY", "OPENAI_API_KEY"], "reason": "setup"]]])
        let t = toolText(r)
        #expect(result(r)?["isError"] as? Bool == false)
        #expect(t.contains("$STRIPE_KEY"))
        #expect(t.contains("$OPENAI_API_KEY"))   // listed as left-blank
    }

    @Test("request_secrets empty array → in-band error")
    func requestSecretsEmpty() {
        let h = handlerWithRequest { _, _, _ in nil }
        let r = h.handle(["jsonrpc": "2.0", "id": 13, "method": "tools/call",
                          "params": ["name": "request_secrets", "arguments": ["env_vars": [String]()]]])
        #expect(result(r)?["isError"] as? Bool == true)
    }

    @Test("generate flag is passed through to the request closure")
    func generateFlagPassedThrough() {
        final class Cap: @unchecked Sendable { var gen: Bool? }
        let cap = Cap()
        let h = handlerWithRequest { _, _, generate in
            cap.gen = generate
            return SecretResponseIPC(id: "x", status: .provided, provided: ["TOKEN"], skipped: [])
        }
        _ = h.handle(["jsonrpc": "2.0", "id": 14, "method": "tools/call",
                      "params": ["name": "request_secret", "arguments": ["env_var": "TOKEN", "generate": true]]])
        #expect(cap.gen == true)
    }
}
