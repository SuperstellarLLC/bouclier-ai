import Foundation
import Testing
@testable import BouclierCore

@Suite("MCP status server — read-only JSON-RPC contract")
struct MCPStatusCoreTests {
    private func object(_ line: String?) throws -> [String: Any] {
        let data = try #require(line?.data(using: .utf8))
        return try #require(JSONSerialization.jsonObject(with: data) as? [String: Any])
    }

    private func env(_ state: StatusReader.State) -> CLIEnv {
        CLIEnv(loadStatus: { state })
    }

    @Test("Initializes as a tools-capable read-only server")
    func initialize() throws {
        let line = #"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}"#
        let response = try object(MCPStatusCore.process(line: line, serverVersion: "0.9.10"))
        let result = try #require(response["result"] as? [String: Any])
        #expect(result["protocolVersion"] as? String == "2025-06-18")
        let info = try #require(result["serverInfo"] as? [String: Any])
        #expect(info["version"] as? String == "0.9.10")
        #expect(result["capabilities"] as? [String: Any] != nil)
    }

    @Test("Lists exactly the Bouclier status tool with read-only annotations")
    func listsTool() throws {
        let response = try object(MCPStatusCore.process(
            line: #"{"jsonrpc":"2.0","id":"list","method":"tools/list","params":{}}"#
        ))
        let result = try #require(response["result"] as? [String: Any])
        let tools = try #require(result["tools"] as? [[String: Any]])
        #expect(tools.count == 1)
        #expect(tools[0]["name"] as? String == MCPStatusCore.toolName)
        let annotations = try #require(tools[0]["annotations"] as? [String: Any])
        #expect(annotations["readOnlyHint"] as? Bool == true)
        #expect(annotations["destructiveHint"] as? Bool == false)
    }

    @Test("Status tool distinguishes monitoring from blocking and passthrough")
    func callsStatus() throws {
        let status = BouclierStatus(
            writtenAt: 1, pid: 1, appVersion: "0.9.10", running: true,
            mode: "standard", caInstalled: false, protectionEnabled: true,
            detectorEnabled: true, blockingEnabled: false,
            patternCount: 186, mlClassifierState: "active",
            activity: .init(requestsScanned: 12, injectionsBlocked: 0,
                            injectionFindingsFlagged: 4, requestsSkippedInspection: 2,
                            requestsBlockedByInspectionLimit: 1)
        )
        let request = #"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bouclier_status","arguments":{}}}"#
        let response = try object(MCPStatusCore.process(line: request, env: env(.running(status))))
        let result = try #require(response["result"] as? [String: Any])
        #expect(result["isError"] as? Bool == false)
        let structured = try #require(result["structuredContent"] as? [String: Any])
        #expect(structured["gatewayRunning"] as? Bool == true)
        #expect(structured["protectionEnabled"] as? Bool == true)
        #expect(structured["detectorEnabled"] as? Bool == true)
        #expect(structured["blockingEnabled"] as? Bool == false)
        let encodedStatus = try #require(structured["status"] as? [String: Any])
        #expect(encodedStatus["patternCount"] as? Int == 186)
        #expect(encodedStatus["mlClassifierState"] as? String == "active")
        let activity = try #require(encodedStatus["activity"] as? [String: Any])
        #expect(activity["injectionFindingsFlagged"] as? Int == 4)
        #expect(activity["requestsSkippedInspection"] as? Int == 2)
        #expect(activity["requestsBlockedByInspectionLimit"] as? Int == 1)
        let content = try #require(result["content"] as? [[String: Any]])
        #expect((content.first?["text"] as? String)?.contains("ON — monitoring") == true)
    }

    @Test("Status tool exposes a disabled detector as degraded, never monitor or block mode")
    func callsStatusWithDetectorDisabled() throws {
        let status = BouclierStatus(
            writtenAt: 1, pid: 1, appVersion: "0.9.10", running: true,
            mode: "standard", caInstalled: false, protectionEnabled: true,
            detectorEnabled: false, blockingEnabled: true,
            patternCount: 186, mlClassifierState: "active",
            activity: .init(requestsScanned: 12, injectionsBlocked: 2,
                            injectionFindingsFlagged: 4)
        )
        let request = #"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"bouclier_status","arguments":{}}}"#
        let response = try object(MCPStatusCore.process(line: request, env: env(.running(status))))
        let result = try #require(response["result"] as? [String: Any])
        let structured = try #require(result["structuredContent"] as? [String: Any])
        #expect(structured["detectorEnabled"] as? Bool == false)
        #expect(structured["blockingEnabled"] as? Bool == false)
        let encodedStatus = try #require(structured["status"] as? [String: Any])
        #expect(encodedStatus["detectorEnabled"] as? Bool == false)
        #expect(encodedStatus["blockingEnabled"] as? Bool == false)
        let content = try #require(result["content"] as? [[String: Any]])
        let text = try #require(content.first?["text"] as? String)
        #expect(text.contains("DEGRADED — detector disabled, not inspecting"))
        #expect(!text.contains("ON — blocking"))
        #expect(!text.contains("ON — monitoring"))
    }

    @Test("Notifications produce no stdout response; unknown tools are rejected")
    func notificationsAndUnknownTool() throws {
        #expect(MCPStatusCore.process(line: #"{"jsonrpc":"2.0","method":"notifications/initialized"}"#) == nil)
        let response = try object(MCPStatusCore.process(
            line: #"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"disable_protection","arguments":{}}}"#
        ))
        let error = try #require(response["error"] as? [String: Any])
        #expect(error["code"] as? Int == -32602)
    }

    @Test("Status tool rejects arguments outside its empty input schema")
    func rejectsArguments() throws {
        for arguments in [#"{"disable":true}"#, #""unexpected""#] {
            let line = #"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bouclier_status","arguments":\#(arguments)}}"#
            let response = try object(MCPStatusCore.process(line: line))
            let error = try #require(response["error"] as? [String: Any])
            #expect(error["code"] as? Int == -32602)
        }
    }

    @Test("Malformed JSON and valid non-request JSON return distinct protocol errors")
    func protocolErrors() throws {
        let malformed = try object(MCPStatusCore.process(line: "{"))
        #expect((malformed["error"] as? [String: Any])?["code"] as? Int == -32700)

        let nonObject = try object(MCPStatusCore.process(line: "[]"))
        #expect((nonObject["error"] as? [String: Any])?["code"] as? Int == -32600)

        let malformedObject = try object(MCPStatusCore.process(line: #"{"jsonrpc":"2.0"}"#))
        #expect((malformedObject["error"] as? [String: Any])?["code"] as? Int == -32600)
        #expect(malformedObject["id"] is NSNull)

        for invalidID in ["true", "{}", "[]"] {
            let invalid = try object(MCPStatusCore.process(
                line: #"{"jsonrpc":"2.0","id":\#(invalidID),"method":"ping"}"#
            ))
            #expect((invalid["error"] as? [String: Any])?["code"] as? Int == -32600)
            #expect(invalid["id"] is NSNull)
        }
    }
}
