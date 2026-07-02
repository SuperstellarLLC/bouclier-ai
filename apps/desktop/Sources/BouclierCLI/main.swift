import BouclierSecretsCore
import Foundation

// Thin adapter: parse argv, run the shared core, print, exit with the
// stable code. All logic + the GREEN/YELLOW/RED gates live in CLICore,
// shared with the MCP server and app.
let result = CLICore.run(Array(CommandLine.arguments.dropFirst()))
if !result.stdout.isEmpty { FileHandle.standardOutput.write(Data(result.stdout.utf8)) }
if !result.stderr.isEmpty { FileHandle.standardError.write(Data(result.stderr.utf8)) }
exit(result.exitCode)
