import BouclierCore
import Foundation

/// `bouclier-ai-mcp-wrapper` is retained as the on-disk executable name for
/// compatibility with existing installs. Its behaviour is now the product's
/// documented one: a real, read-only MCP status server. It exposes one tool,
/// `bouclier_status`, backed by the same local snapshot as `bouclier status`.
///
/// stdio MCP messages are newline-delimited JSON-RPC. stdout must contain
/// protocol messages only; diagnostics, if ever added, belong on stderr.
while let line = readLine() {
    if let response = MCPStatusCore.process(line: line) {
        FileHandle.standardOutput.write(Data((response + "\n").utf8))
    }
}
