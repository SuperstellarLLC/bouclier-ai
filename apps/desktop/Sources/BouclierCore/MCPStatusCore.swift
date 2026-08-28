import CoreFoundation
import Foundation

/// A minimal, read-only MCP server core for the bundled stdio helper.
///
/// The only exposed tool, `bouclier_status`, reads the same ephemeral
/// `status.json` snapshot as `bouclier status`. It cannot mutate app state,
/// disable protection, or access request content. Keeping JSON-RPC handling
/// here makes the executable a thin transport adapter and keeps the protocol
/// contract under unit test.
public enum MCPStatusCore {
    public static let protocolVersion = "2025-06-18"
    public static let toolName = "bouclier_status"

    /// Process one newline-delimited MCP/JSON-RPC message. Notifications
    /// intentionally return nil because JSON-RPC forbids responding to them.
    public static func process(
        line: String,
        env: CLIEnv = .live(),
        serverVersion: String = CLICore.version
    ) -> String? {
        guard let data = line.data(using: .utf8),
              let raw = try? JSONSerialization.jsonObject(with: data)
        else {
            return encode(error(code: -32700, message: "Parse error", id: NSNull()))
        }
        guard let request = raw as? [String: Any] else {
            return encode(error(code: -32600, message: "Invalid Request", id: NSNull()))
        }

        let id = request["id"]
        guard request["jsonrpc"] as? String == "2.0",
              let method = request["method"] as? String,
              !method.isEmpty
        else {
            return encode(error(code: -32600, message: "Invalid Request", id: id ?? NSNull()))
        }

        // JSON-RPC identifiers are strings, numbers, or null. Echoing an
        // object/array/bool supplied as an id would itself produce an invalid
        // protocol response and can confuse clients that correlate requests.
        if let id, !isValidRequestID(id) {
            return encode(error(code: -32600, message: "Invalid Request", id: NSNull()))
        }

        // Notifications never receive a response, including unknown ones.
        guard let id else { return nil }

        switch method {
        case "initialize":
            return encode(success(id: id, result: [
                "protocolVersion": protocolVersion,
                "capabilities": ["tools": ["listChanged": false]],
                "serverInfo": [
                    "name": "bouclier",
                    "title": "Bouclier.ai Status",
                    "version": serverVersion,
                ],
                "instructions": "Read-only local status for the Bouclier.ai gateway and prompt-injection firewall.",
            ]))

        case "ping":
            return encode(success(id: id, result: [:]))

        case "tools/list":
            return encode(success(id: id, result: [
                "tools": [[
                    "name": toolName,
                    "title": "Get Bouclier status",
                    "description": "Read whether the local Bouclier gateway is running, whether its detector is actually inspecting, whether findings are monitored or blocked, and session activity counts.",
                    "inputSchema": [
                        "type": "object",
                        "properties": [:],
                        "additionalProperties": false,
                    ],
                    "annotations": [
                        "readOnlyHint": true,
                        "destructiveHint": false,
                        "idempotentHint": true,
                        "openWorldHint": false,
                    ],
                ]],
            ]))

        case "tools/call":
            guard let params = request["params"] as? [String: Any],
                  params["name"] as? String == toolName
            else {
                return encode(error(code: -32602, message: "Unknown tool", id: id))
            }
            // The tool intentionally accepts no input. Enforce the advertised
            // schema instead of silently accepting misspelled or future
            // state-changing arguments that a caller may assume took effect.
            if let arguments = params["arguments"] {
                guard let object = arguments as? [String: Any], object.isEmpty else {
                    return encode(error(code: -32602, message: "Invalid tool arguments", id: id))
                }
            }
            let state = env.loadStatus()
            let payload = statusPayload(state)
            let text = statusText(state)
            return encode(success(id: id, result: [
                "content": [["type": "text", "text": text]],
                "structuredContent": payload,
                "isError": false,
            ]))

        default:
            return encode(error(code: -32601, message: "Method not found", id: id))
        }
    }

    private static func statusPayload(_ state: StatusReader.State) -> [String: Any] {
        switch state {
        case .notRunning(let reason):
            return [
                "state": "not_running",
                "gatewayRunning": false,
                "protectionEnabled": false,
                "detectorEnabled": false,
                "blockingEnabled": false,
                "message": reason,
            ]
        case .running(let status):
            var payload: [String: Any] = [
                "state": "running",
                "gatewayRunning": status.running,
                "protectionEnabled": status.protectionEnabled,
                "detectorEnabled": status.detectorEnabled,
                "blockingEnabled": status.detectorEnabled && status.blockingEnabled,
            ]
            if let data = try? JSONEncoder().encode(status),
               let encoded = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                payload["status"] = encoded
            }
            return payload
        }
    }

    private static func statusText(_ state: StatusReader.State) -> String {
        CLICore.run(["status"], env: CLIEnv(loadStatus: { state })).stdout
            .trimmingCharacters(in: .newlines)
    }

    private static func success(id: Any, result: [String: Any]) -> [String: Any] {
        ["jsonrpc": "2.0", "id": id, "result": result]
    }

    private static func error(code: Int, message: String, id: Any) -> [String: Any] {
        [
            "jsonrpc": "2.0",
            "id": id,
            "error": ["code": code, "message": message],
        ]
    }

    private static func isValidRequestID(_ id: Any) -> Bool {
        if id is NSNull || id is String { return true }
        guard let number = id as? NSNumber else { return false }
        // JSONSerialization bridges booleans to NSNumber as well; JSON-RPC
        // does not consider true/false numeric request identifiers.
        return CFGetTypeID(number) != CFBooleanGetTypeID()
    }

    private static func encode(_ object: [String: Any]) -> String? {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
              let string = String(data: data, encoding: .utf8)
        else { return nil }
        return string
    }
}
