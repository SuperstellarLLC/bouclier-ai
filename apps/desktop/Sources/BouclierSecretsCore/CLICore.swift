import Foundation

/// The `bouclier` CLI's logic, factored out of `main.swift` so it's fully
/// unit-testable (all side effects are injected via `CLIEnv`). Lets any
/// agent drive Bouclier from Bash with stable exit codes and `--json`,
/// sharing the exact same core — and the same GREEN/YELLOW/RED gates — as
/// the MCP server. There is no CLI path to a RED operation (read a value,
/// disable the firewall, install a CA): those simply don't exist here.
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
    public static let declined: Int32 = 5    // user said no
    public static let timeout: Int32 = 6     // no human response
    public static let denied: Int32 = 7      // locked / not agent-accessible
}

/// Injected side effects — defaults are the live wiring; tests pass fakes.
public struct CLIEnv: Sendable {
    public var loadStatus: @Sendable () -> StatusReader.State
    public var loadRules: @Sendable () -> [SecretRuleMeta]
    public var loadActive: @Sendable () -> [String]
    public var saveActive: @Sendable ([String]) -> Void
    public var requestSecrets: @Sendable (_ envVars: [String], _ reason: String, _ generate: Bool, _ timeout: TimeInterval) -> SecretResponseIPC?
    public var proposeEnable: @Sendable (_ mode: String, _ reason: String, _ timeout: TimeInterval) -> ActionResponseIPC?

    public init(
        loadStatus: @escaping @Sendable () -> StatusReader.State,
        loadRules: @escaping @Sendable () -> [SecretRuleMeta],
        loadActive: @escaping @Sendable () -> [String],
        saveActive: @escaping @Sendable ([String]) -> Void,
        requestSecrets: @escaping @Sendable (_ envVars: [String], _ reason: String, _ generate: Bool, _ timeout: TimeInterval) -> SecretResponseIPC?,
        proposeEnable: @escaping @Sendable (_ mode: String, _ reason: String, _ timeout: TimeInterval) -> ActionResponseIPC?
    ) {
        self.loadStatus = loadStatus; self.loadRules = loadRules; self.loadActive = loadActive
        self.saveActive = saveActive; self.requestSecrets = requestSecrets; self.proposeEnable = proposeEnable
    }

    public static func live() -> CLIEnv {
        CLIEnv(
            loadStatus: { StatusReader.read() },
            loadRules: { SecretRulesReader.load() },
            loadActive: { SecretEnvManifest.load() },
            saveActive: { SecretEnvManifest.save($0) },
            requestSecrets: { envVars, reason, generate, timeout in
                try? SecretRequestClient.request(envVars: envVars, reason: reason, generate: generate, timeout: timeout)
            },
            proposeEnable: { mode, reason, timeout in
                try? ActionClient.request(action: "enable_protection", params: ["mode": mode], reason: reason, timeout: timeout)
            }
        )
    }
}

public enum CLICore {
    public static let version = "1.0.0"

    public static func run(_ rawArgs: [String], env: CLIEnv = .live()) -> CLIResult {
        var args = rawArgs
        let json = extractFlag(&args, "--json")
        if let t = popValue(&args, "--timeout") { pendingTimeout = TimeInterval(t) ?? 120 } else { pendingTimeout = 120 }

        guard let cmd = args.first else { return usage(CLIExit.ok) }
        let rest = Array(args.dropFirst())

        switch cmd {
        case "-h", "--help", "help": return usage(CLIExit.ok)
        case "--version", "version": return CLIResult(CLIExit.ok, stdout: json ? jsonLine(["version": version]) : "bouclier \(version)\n")
        case "status": return statusCmd(env, json: json)
        case "secrets": return secretsCmd(rest, env, json: json)
        case "env": return envCmd(rest, env, json: json)
        case "protection": return protectionCmd(rest, env, json: json)
        case "install": return installCmd(json: json)
        default: return usage(CLIExit.usage, error: "Unknown command: \(cmd)")
        }
    }

    // Carried between run() and the subcommands without threading it everywhere.
    nonisolated(unsafe) private static var pendingTimeout: TimeInterval = 120

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
            l.append("  secret keeper: \(s.secretKeeper.circuitBreakerTripped ? "TRIPPED (not protecting)" : (s.secretKeeper.enabled ? (s.secretKeeper.healthy ? "on, healthy" : "on, unhealthy") : "off"))")
            l.append("  secrets: \(s.secrets.total) stored, \(s.secrets.agentAccessible) agent-usable, \(s.secrets.active) active")
            l.append("  activity: \(s.activity.requestsScanned) inspected, \(s.activity.injectionsBlocked) injections blocked, \(s.activity.secretsScrubbed) secrets scrubbed")
            return CLIResult(CLIExit.ok, stdout: l.joined(separator: "\n") + "\n")
        }
    }

    // MARK: secrets

    private static func secretsCmd(_ args: [String], _ env: CLIEnv, json: Bool) -> CLIResult {
        guard let sub = args.first else { return usage(CLIExit.usage, error: "secrets needs a subcommand: list | request") }
        switch sub {
        case "list":
            let rules = env.loadRules()
            let active = Set(env.loadActive())
            if json {
                let arr = rules.sorted { $0.name < $1.name }.map { r in
                    ["name": r.name, "env_var": r.environmentVariable, "agent_access": r.agentAccess, "active": active.contains(r.name)] as [String: Any]
                }
                return CLIResult(CLIExit.ok, stdout: jsonLine(["ok": true, "secrets": arr]))
            }
            if rules.isEmpty { return CLIResult(CLIExit.ok, stdout: "No secrets stored. Add them in the Bouclier app, or `bouclier secrets request <ENV_VAR>`.\n") }
            var l = ["Secrets (values never shown):"]
            for r in rules.sorted(by: { $0.name < $1.name }) {
                l.append("  \(r.name) → $\(r.environmentVariable)  [\(r.agentAccess ? "usable" : "LOCKED")\(active.contains(r.name) ? ", active" : "")]")
            }
            return CLIResult(CLIExit.ok, stdout: l.joined(separator: "\n") + "\n")

        case "request":
            var rest = Array(args.dropFirst())
            let generate = extractFlag(&rest, "--generate")
            let reason = popValue(&rest, "--reason") ?? ""
            let envVars = rest.filter { !$0.hasPrefix("-") }
            guard !envVars.isEmpty else { return usage(CLIExit.usage, error: "request needs at least one ENV_VAR name") }
            let timeout = pendingTimeout
            // Any number of vars: split into as many approval dialogs as
            // needed, aggregate, never drop.
            let outcome = SecretBatchRequest.requestAll(envVars: envVars, reason: reason, generate: generate) { batch, r, g in
                env.requestSecrets(batch, r, g, timeout)
            }
            if !outcome.reachable && outcome.provided.isEmpty && outcome.skipped.isEmpty {
                return result(json, CLIExit.notRunning, state: "not_running", message: "Bouclier isn't running — ask the user to open it.")
            }
            func l(_ xs: [String]) -> String { xs.map { "$\($0)" }.joined(separator: ", ") }
            var msgParts: [String] = []
            if !outcome.provided.isEmpty { msgParts.append("Provided: \(l(outcome.provided)) (use in a NEW shell).") }
            if !outcome.skipped.isEmpty { msgParts.append("Left blank: \(l(outcome.skipped)).") }
            if !outcome.pending.isEmpty { msgParts.append("Still pending: \(l(outcome.pending)) — re-request these.") }
            let extra: [String: Any] = ["provided": outcome.provided, "skipped": outcome.skipped, "pending": outcome.pending, "batches": outcome.batches]
            // Exit code reflects whether ANY secret was set.
            let code: Int32
            let state: String
            if !outcome.provided.isEmpty { code = CLIExit.ok; state = outcome.pending.isEmpty ? "provided" : "partial" }
            else if outcome.interruptedBy == .timeout { code = CLIExit.timeout; state = "timeout" }
            else if !outcome.reachable { code = CLIExit.notRunning; state = "not_running" }
            else { code = CLIExit.declined; state = "declined" }
            return result(json, code, state: state, message: msgParts.joined(separator: " "), extra: extra)
        default:
            return usage(CLIExit.usage, error: "Unknown secrets subcommand: \(sub)")
        }
    }

    // MARK: env

    private static func envCmd(_ args: [String], _ env: CLIEnv, json: Bool) -> CLIResult {
        guard let sub = args.first else { return usage(CLIExit.usage, error: "env needs a subcommand: set | clear | list") }
        switch sub {
        case "list":
            let active = env.loadActive()
            if json { return CLIResult(CLIExit.ok, stdout: jsonLine(["ok": true, "active": active])) }
            return CLIResult(CLIExit.ok, stdout: active.isEmpty ? "No active secrets.\n" : "Active: \(active.joined(separator: ", "))\n")

        case "clear":
            env.saveActive([])
            return result(json, CLIExit.ok, state: "cleared", message: "Cleared all active secrets. Open a new shell.")

        case "set":
            let names = Array(args.dropFirst()).filter { !$0.hasPrefix("-") }
            guard !names.isEmpty else { return usage(CLIExit.usage, error: "env set needs at least one secret name") }
            let rules = env.loadRules()
            let byName = Dictionary(rules.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
            var activated: [String] = [], denied: [String] = []
            for n in names {
                guard let m = byName[n] else { denied.append("\(n) (unknown)"); continue }
                guard m.agentAccess else { denied.append("\(n) (locked)"); continue }
                activated.append(n)
            }
            if !activated.isEmpty {
                let current = env.loadActive()
                env.saveActive(current + activated.filter { !current.contains($0) })
            }
            let code = activated.isEmpty ? CLIExit.denied : CLIExit.ok
            let msg = (activated.isEmpty ? "" : "Activated \(activated.joined(separator: ", ")) — use in a new shell. ")
                + (denied.isEmpty ? "" : "Not activated: \(denied.joined(separator: ", ")).")
            return result(json, code, state: activated.isEmpty ? "denied" : "ok", message: msg.trimmingCharacters(in: .whitespaces),
                          extra: ["activated": activated, "denied": denied])
        default:
            return usage(CLIExit.usage, error: "Unknown env subcommand: \(sub)")
        }
    }

    // MARK: protection

    private static func protectionCmd(_ args: [String], _ env: CLIEnv, json: Bool) -> CLIResult {
        guard let sub = args.first else { return usage(CLIExit.usage, error: "protection needs a subcommand: enable") }
        switch sub {
        case "enable":
            var rest = Array(args.dropFirst())
            let mode = popValue(&rest, "--mode") ?? "standard"
            let reason = popValue(&rest, "--reason") ?? ""
            guard let resp = env.proposeEnable(mode, reason, pendingTimeout) else {
                return result(json, CLIExit.notRunning, state: "not_running", message: "Bouclier isn't running — ask the user to open it.")
            }
            switch resp.status {
            case .approved: return result(json, CLIExit.ok, state: "approved", message: resp.message)
            case .declined: return result(json, CLIExit.declined, state: "declined", message: resp.message)
            case .timeout:  return result(json, CLIExit.timeout, state: "timeout", message: resp.message)
            case .invalid, .unsupported: return result(json, CLIExit.runtime, state: "error", message: resp.message)
            }
        case "disable":
            // Deliberately unsupported: an agent must never be able to turn
            // off the firewall that guards it. The user does this in the app.
            return result(json, CLIExit.denied, state: "denied",
                          message: "Disabling protection isn't available to agents — do it in the Bouclier app. (Bouclier won't let a tool turn off its own protection.)")
        default:
            return usage(CLIExit.usage, error: "Unknown protection subcommand: \(sub)")
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
        let mcpPath = dir + "/bouclier-ai-secrets-mcp"
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

    private static func result(_ json: Bool, _ code: Int32, state: String, message: String, extra: [String: Any] = [:]) -> CLIResult {
        if json {
            var obj: [String: Any] = ["ok": code == CLIExit.ok, "state": state, "message": message]
            for (k, v) in extra { obj[k] = v }
            return CLIResult(code, stdout: jsonLine(obj))
        }
        return CLIResult(code, stdout: message.isEmpty ? "" : message + "\n")
    }

    private static func usage(_ code: Int32, error: String? = nil) -> CLIResult {
        let text = """
        bouclier — drive Bouclier from the command line (no secret values ever printed)

        USAGE:
          bouclier status                       Show protection state, mode, secret + activity counts
          bouclier secrets list                 List secret names (never values)
          bouclier secrets request <ENV>...     Ask the user to provide/generate secrets [--reason R] [--generate]
          bouclier env set <NAME>...            Activate secrets as env vars in new shells
          bouclier env clear                    Deactivate all
          bouclier env list                     Show active secrets
          bouclier protection enable            Ask the user to turn protection on [--mode standard]
          bouclier install                      Register the MCP server + symlink onto PATH
          bouclier --version

        GLOBAL: --json (machine output)  --timeout <s> (for approval-gated commands)

        Exit codes: 0 ok · 2 usage · 4 not-running · 5 declined · 6 timeout · 7 denied
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

    /// Pop `--key value` and return value, removing both tokens.
    private static func popValue(_ args: inout [String], _ key: String) -> String? {
        guard let i = args.firstIndex(of: key), i + 1 < args.count else { return nil }
        let v = args[i + 1]
        args.removeSubrange(i...(i + 1))
        return v
    }
}
