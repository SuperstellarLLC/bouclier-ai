import Foundation

/// The `bouclier` CLI's logic, factored out of `main.swift` so it's fully
/// unit-testable (all side effects are injected via `CLIEnv`). Lets any
/// agent read Bouclier's state from Bash with stable exit codes and `--json`.
/// The CLI is read-only by design: there is no path to a state-changing
/// operation (disable the firewall, install a CA) — those simply don't exist
/// here.
public struct CLIResult: Equatable, Sendable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String
    public init(_ exitCode: Int32, stdout: String = "", stderr: String = "") {
        self.exitCode = exitCode; self.stdout = stdout; self.stderr = stderr
    }
}

/// Stable exit-code contract (modeled on `gh`/`op`) so an agent in a Bash
/// loop can branch without parsing prose.
public enum CLIExit {
    public static let ok: Int32 = 0
    public static let runtime: Int32 = 1     // I/O / unexpected
    public static let usage: Int32 = 2       // bad args
    public static let notRunning: Int32 = 4  // app unreachable
}

/// Injected side effects — defaults are the live wiring; tests pass fakes.
public struct CLIEnv: Sendable {
    public var loadStatus: @Sendable () -> StatusReader.State

    public init(loadStatus: @escaping @Sendable () -> StatusReader.State) {
        self.loadStatus = loadStatus
    }

    public static func live() -> CLIEnv {
        CLIEnv(loadStatus: { StatusReader.read() })
    }
}

public enum CLICore {
    public static let version = "1.0.0"

    public static func run(_ rawArgs: [String], env: CLIEnv = .live()) -> CLIResult {
        var args = rawArgs
        let json = extractFlag(&args, "--json")

        guard let cmd = args.first else { return usage(CLIExit.ok) }

        switch cmd {
        case "-h", "--help", "help": return usage(CLIExit.ok)
        case "--version", "version": return CLIResult(CLIExit.ok, stdout: json ? jsonLine(["version": version]) : "bouclier \(version)\n")
        case "status": return statusCmd(env, json: json)
        case "install": return installCmd(json: json)
        default: return usage(CLIExit.usage, error: "Unknown command: \(cmd)")
        }
    }

    // MARK: status

    private static func statusCmd(_ env: CLIEnv, json: Bool) -> CLIResult {
        switch env.loadStatus() {
        case .notRunning(let reason):
            // A successful read of "not running" is still a successful read → exit 0.
            if json { return CLIResult(CLIExit.ok, stdout: jsonLine(["ok": true, "state": "not_running", "message": reason])) }
            return CLIResult(CLIExit.ok, stdout: "Bouclier: not running — \(reason)\n")
        case .running(let s):
            if json {
                var obj: [String: Any] = ["ok": true, "state": "running"]
                if let data = try? JSONEncoder().encode(s),
                   let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    obj["status"] = dict
                }
                return CLIResult(CLIExit.ok, stdout: jsonLine(obj))
            }
            var l = ["Bouclier \(s.appVersion): protection \(s.running ? "ON" : "OFF") (\(s.mode) mode)"]
            l.append("  activity: \(s.activity.requestsScanned) inspected, \(s.activity.injectionsBlocked) injections blocked")
            return CLIResult(CLIExit.ok, stdout: l.joined(separator: "\n") + "\n")
        }
    }

    // MARK: install

    private static func installCmd(json: Bool) -> CLIResult {
        // Print-only by design: the CLI does NOT write to /usr/local/bin
        // itself. Mutating a frequently world-writable dir from a tool an
        // agent can invoke is a symlink-TOCTOU footgun — show the user the
        // two commands to run instead, so a human stays in the loop for the
        // privileged step.
        let cliPath = Bundle.main.executablePath ?? CommandLine.arguments.first ?? "bouclier"
        let dir = (cliPath as NSString).deletingLastPathComponent
        let mcpPath = dir + "/bouclier-ai-mcp-wrapper"
        let linkCmd = "sudo ln -sf \(cliPath) /usr/local/bin/bouclier"
        let mcpCmd = "claude mcp add bouclier -- \(mcpPath)"

        if json {
            return CLIResult(CLIExit.ok, stdout: jsonLine([
                "ok": true, "cli": cliPath, "mcp": mcpPath,
                "path_command": linkCmd, "mcp_command": mcpCmd,
            ]))
        }
        let text = """
        To put `bouclier` on your PATH (so Bash agents can find it):
          \(linkCmd)
        To register the MCP server with Claude Code:
          \(mcpCmd)
        """
        return CLIResult(CLIExit.ok, stdout: text + "\n")
    }

    // MARK: helpers

    private static func usage(_ code: Int32, error: String? = nil) -> CLIResult {
        let text = """
        bouclier — read Bouclier's state from the command line

        USAGE:
          bouclier status        Show protection state, mode, and activity counts
          bouclier install       Register the MCP server + symlink onto PATH
          bouclier --version

        GLOBAL: --json (machine output)

        Exit codes: 0 ok · 2 usage · 4 not-running
        """
        if let error { return CLIResult(code, stdout: "", stderr: "error: \(error)\n\n" + text + "\n") }
        return CLIResult(code, stdout: text + "\n")
    }

    private static func jsonLine(_ obj: [String: Any]) -> String {
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]),
              let s = String(data: data, encoding: .utf8) else { return "{\"ok\":false}\n" }
        return s + "\n"
    }

    /// Remove a boolean flag if present; return whether it was.
    private static func extractFlag(_ args: inout [String], _ flag: String) -> Bool {
        guard let i = args.firstIndex(of: flag) else { return false }
        args.remove(at: i); return true
    }
}
