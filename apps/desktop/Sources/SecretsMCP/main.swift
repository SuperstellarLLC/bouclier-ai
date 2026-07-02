import BouclierSecretsCore
import Foundation

/// bouclier-ai-secrets-mcp — the Bouclier secrets MCP server.
///
/// Register with Claude Code:
///   claude mcp add bouclier-secrets -- /path/to/bouclier-ai-secrets-mcp
///
/// Exposes tools so an agent can *use* a stored secret without ever
/// *seeing* its value:
///   • list_secrets — names + env-var names (no values)
///   • set_env      — activate secrets as env vars (returns names only)
///   • clear_env    — deactivate
///
/// The real values are materialized into the agent's shell by
/// `bouclier-ai-env --secrets` reading the Keychain — never here. Speaks
/// newline-delimited JSON-RPC 2.0 over stdio (the MCP stdio transport).

let handler = SecretsMCPHandler.live()

/// Accumulates partial stdin reads into complete newline-delimited lines.
final class LineBuffer: @unchecked Sendable {
    private var buffer = ""
    func append(_ data: Data) -> [String] {
        guard let str = String(data: data, encoding: .utf8) else { return [] }
        buffer += str
        var lines: [String] = []
        while let nl = buffer.firstIndex(of: "\n") {
            lines.append(String(buffer[buffer.startIndex..<nl]))
            buffer = String(buffer[buffer.index(after: nl)...])
        }
        return lines
    }
}

func writeResponse(_ object: [String: Any]) {
    guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.withoutEscapingSlashes]) else { return }
    FileHandle.standardOutput.write(data)
    FileHandle.standardOutput.write(Data([0x0A])) // newline-delimited
}

func process(line: String) {
    let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty,
          let data = trimmed.data(using: .utf8),
          let request = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    else { return }
    if let response = handler.handle(request) {
        writeResponse(response)
    }
}

let lineBuffer = LineBuffer()
let stdinSource = DispatchSource.makeReadSource(fileDescriptor: FileHandle.standardInput.fileDescriptor, queue: .main)
stdinSource.setEventHandler {
    let data = FileHandle.standardInput.availableData
    if data.isEmpty {
        stdinSource.cancel()
        exit(0)
    }
    for line in lineBuffer.append(data) { process(line: line) }
}
stdinSource.resume()

dispatchMain()
