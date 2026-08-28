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
    /// The CLI ships inside the app bundle, so its product version must come
    /// from that bundle rather than a second hard-coded constant that can
    /// drift from the release. `development` is intentionally non-numeric:
    /// a bare `swift run bouclier-cli --version` should not pretend to be a
    /// shipped build.
    public static var version: String {
        if let bundled = normalizedVersion(
            Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String
        ) {
            return bundled
        }
        let executable = Bundle.main.executableURL
            ?? CommandLine.arguments.first.map { URL(fileURLWithPath: $0) }
        return version(containingExecutableAt: executable) ?? "development"
    }

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
            // A stable non-zero code lets shells and agents branch on
            // availability without parsing either prose or JSON.
            if json {
                return CLIResult(
                    CLIExit.notRunning,
                    stdout: jsonLine(["ok": false, "state": "not_running", "message": reason])
                )
            }
            return CLIResult(CLIExit.notRunning, stdout: "Bouclier: not running — \(reason)\n")
        case .running(let s):
            if json {
                var obj: [String: Any] = ["ok": true, "state": "running"]
                if let data = try? JSONEncoder().encode(s),
                   let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                    obj["status"] = dict
                }
                return CLIResult(CLIExit.ok, stdout: jsonLine(obj))
            }
            let state: String
            if !s.running {
                state = "OFF — gateway stopped"
            } else if !s.protectionEnabled {
                state = "OFF — gateway passthrough"
            } else if !s.detectorEnabled {
                state = "DEGRADED — detector disabled, not inspecting"
            } else if s.blockingEnabled {
                state = "ON — blocking"
            } else {
                state = "ON — monitoring"
            }
            var l = ["Bouclier \(s.appVersion): protection \(state) (\(s.mode) mode)"]
            if s.schemaVersion >= 5 {
                if !s.detectorEnabled {
                    let detail: String
                    if !s.running {
                        detail = "idle — gateway stopped; request bodies are not inspected"
                    } else if !s.protectionEnabled {
                        detail = "idle — gateway passthrough does not inspect request bodies"
                    } else {
                        detail = "disabled by policy — request bodies are not inspected"
                    }
                    l.append("  engine: \(detail)")
                } else {
                    let ml = switch s.mlClassifierState {
                    case "active": "Prompt Guard 2 active"
                    case "loading": "Prompt Guard 2 loading"
                    case "unavailable": "Prompt Guard 2 unavailable"
                    default: "Prompt Guard 2 state unknown"
                    }
                    l.append("  engine: \(s.patternCount) patterns, \(ml)")
                }
            }
            let findings = s.activity.injectionFindingsFlagged
            let detectorBlocks = s.activity.injectionsBlocked
            let coverageRefusals = s.activity.requestsBlockedByInspectionLimit
            let inspectionSkips = s.activity.requestsSkippedInspection
            let inspected = s.activity.requestsScanned
            if !s.detectorEnabled {
                // Counters span the app session and may predate a managed
                // policy change. Keep them visible without describing any
                // blocking or monitoring action as currently operational.
                l.append(
                    "  recorded activity: \(inspected) previously inspected, "
                    + "\(findings) injection finding\(findings == 1 ? "" : "s"), "
                    + "\(detectorBlocks) injection refusal\(detectorBlocks == 1 ? "" : "s"), "
                    + "\(coverageRefusals) coverage refusal\(coverageRefusals == 1 ? "" : "s"), "
                    + "\(inspectionSkips) inspection skip\(inspectionSkips == 1 ? "" : "s"); "
                    + "detector currently disabled"
                )
            } else {
                l.append(
                    "  activity: \(inspected) request\(inspected == 1 ? "" : "s") inspected, "
                    + "\(findings) monitor finding\(findings == 1 ? "" : "s") allowed, "
                    + "\(detectorBlocks) request\(detectorBlocks == 1 ? "" : "s") blocked by the detector, "
                    + "\(coverageRefusals) coverage refusal\(coverageRefusals == 1 ? "" : "s"), "
                    + "\(inspectionSkips) inspection skip\(inspectionSkips == 1 ? "" : "s")"
                )
            }
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
        let invokedPath = Bundle.main.executablePath ?? CommandLine.arguments.first ?? "bouclier"
        let commands = installCommands(executablePath: invokedPath)
        let cliPath = commands.cliPath
        let mcpPath = commands.mcpPath
        let linkCmd = commands.pathCommand
        let mcpCmd = commands.mcpCommand

        if json {
            return CLIResult(CLIExit.ok, stdout: jsonLine([
                "ok": true, "cli": cliPath, "mcp": mcpPath,
                "path_command": linkCmd, "mcp_command": mcpCmd,
            ]))
        }
        let text = """
        To put `bouclier` on your PATH (so Bash agents can find it):
          \(linkCmd)
        To register the read-only Bouclier status MCP server with Claude Code:
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
          bouclier install       Print MCP status-server + PATH setup commands
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

    /// POSIX single-quote escaping for commands a human pastes into a shell.
    /// App bundles commonly contain spaces; treating the executable path as
    /// raw shell syntax made both install commands fail (and made a quote in
    /// a renamed app bundle an injection boundary).
    static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Derive setup commands from the *real* helper location. Once installed,
    /// argv[0]/Bundle.main points at `/usr/local/bin/bouclier`; without
    /// resolving that symlink, `bouclier install` advertised a nonexistent
    /// `/usr/local/bin/bouclier-ai-mcp-wrapper` and even re-linked the CLI to
    /// itself. The target lives beside the MCP binary inside the app bundle.
    static func installCommands(executablePath: String) -> (
        cliPath: String, mcpPath: String, pathCommand: String, mcpCommand: String
    ) {
        let cliPath = URL(fileURLWithPath: executablePath).resolvingSymlinksInPath().path
        let dir = (cliPath as NSString).deletingLastPathComponent
        let mcpPath = dir + "/bouclier-ai-mcp-wrapper"
        return (
            cliPath,
            mcpPath,
            "sudo ln -sf \(shellQuoted(cliPath)) '/usr/local/bin/bouclier'",
            "claude mcp add bouclier -- \(shellQuoted(mcpPath))"
        )
    }

    /// Resolve the version from an executable nested under
    /// `Some.app/Contents/MacOS`. This fallback is needed for helper
    /// executables: depending on how they are launched, Foundation may not
    /// expose the containing app as `Bundle.main` even though the executable
    /// is physically inside it. Symlinks (the normal `/usr/local/bin` install)
    /// are resolved before walking upward.
    static func version(containingExecutableAt executableURL: URL?) -> String? {
        guard let executableURL else { return nil }
        var cursor = executableURL.resolvingSymlinksInPath().deletingLastPathComponent()
        while cursor.path != "/" {
            if cursor.pathExtension.lowercased() == "app" {
                let infoURL = cursor.appendingPathComponent("Contents/Info.plist")
                guard let data = try? Data(contentsOf: infoURL),
                      let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
                      let dict = plist as? [String: Any]
                else { return nil }
                return normalizedVersion(dict["CFBundleShortVersionString"] as? String)
            }
            cursor.deleteLastPathComponent()
        }
        return nil
    }

    private static func normalizedVersion(_ raw: String?) -> String? {
        guard let version = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
              !version.isEmpty
        else { return nil }
        return version
    }
}
