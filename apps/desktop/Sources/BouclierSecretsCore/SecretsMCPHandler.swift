import Foundation

/// Pure MCP request handler for the Bouclier secrets server. Speaks a
/// minimal subset of the Model Context Protocol (JSON-RPC 2.0):
/// `initialize`, `tools/list`, `tools/call`, `ping`.
///
/// The contract that makes this safe: **no tool ever returns a secret
/// value.** `list_secrets` returns names + env-var names + access flags;
/// `set_env` records which secrets the agent wants and returns the env-var
/// names it activated. The real values are materialized into the agent's
/// shell environment later, by `bouclier-ai-env --secrets` reading the
/// Keychain — never through this server and never into the model's context.
///
/// I/O is injected (rules + manifest), so the whole protocol surface is
/// unit-testable without a filesystem.
public struct SecretsMCPHandler: Sendable {
    public var loadRules: @Sendable () -> [SecretRuleMeta]
    public var loadActive: @Sendable () -> [String]
    public var saveActive: @Sendable ([String]) -> Void
    /// Blocks until the user provides/declines the requested secrets in
    /// Bouclier's own dialog. Returns nil if Bouclier isn't reachable. The
    /// response carries only names/status — never values.
    public var requestSecrets: @Sendable (_ envVars: [String], _ reason: String, _ generate: Bool) -> SecretResponseIPC?
    /// Read the app's published status snapshot (running/mode/health/counts).
    /// Read-only — the agent's orientation primitive.
    public var loadStatus: @Sendable () -> StatusReader.State
    /// Propose a protection-ENABLE the user approves out-of-band. Returns nil
    /// if Bouclier isn't reachable. There is deliberately NO propose-disable:
    /// the agent can never weaken its own firewall.
    public var proposeEnable: @Sendable (_ mode: String, _ reason: String) -> ActionResponseIPC?

    public init(
        loadRules: @escaping @Sendable () -> [SecretRuleMeta],
        loadActive: @escaping @Sendable () -> [String],
        saveActive: @escaping @Sendable ([String]) -> Void,
        requestSecrets: @escaping @Sendable (_ envVars: [String], _ reason: String, _ generate: Bool) -> SecretResponseIPC? = { _, _, _ in nil },
        loadStatus: @escaping @Sendable () -> StatusReader.State = { .notRunning(reason: "Bouclier is not running") },
        proposeEnable: @escaping @Sendable (_ mode: String, _ reason: String) -> ActionResponseIPC? = { _, _ in nil }
    ) {
        self.loadRules = loadRules
        self.loadActive = loadActive
        self.saveActive = saveActive
        self.requestSecrets = requestSecrets
        self.loadStatus = loadStatus
        self.proposeEnable = proposeEnable
    }

    /// Production wiring: rules from `secret-rules.json`, manifest from
    /// `active-env-secrets.json`.
    public static func live() -> SecretsMCPHandler {
        SecretsMCPHandler(
            loadRules: { SecretRulesReader.load() },
            loadActive: { SecretEnvManifest.load() },
            saveActive: { SecretEnvManifest.save($0) },
            requestSecrets: { envVars, reason, generate in
                // Unreachable app / I/O error ⇒ nil (the tool reports it).
                try? SecretRequestClient.request(envVars: envVars, reason: reason, generate: generate)
            },
            loadStatus: { StatusReader.read() },
            proposeEnable: { mode, reason in
                try? ActionClient.request(action: "enable_protection", params: ["mode": mode], reason: reason)
            }
        )
    }

    public static let protocolVersion = "2024-11-05"
    public static let serverName = "bouclier-secrets"
    public static let serverVersion = "1.0.0"

    /// Handle one JSON-RPC request object. Returns the response object, or
    /// `nil` for notifications (no `id`) which must not be answered.
    public func handle(_ request: [String: Any]) -> [String: Any]? {
        let method = request["method"] as? String ?? ""
        let id = request["id"]
        let isNotification = id == nil

        switch method {
        case "initialize":
            return ok(id, [
                "protocolVersion": Self.protocolVersion,
                "capabilities": ["tools": [String: Any]()],
                "serverInfo": ["name": Self.serverName, "version": Self.serverVersion],
            ])

        case "notifications/initialized", "initialized":
            return nil // notification — no reply

        case "ping":
            return ok(id, [String: Any]())

        case "tools/list":
            return ok(id, ["tools": Self.toolDefinitions])

        case "tools/call":
            if isNotification { return nil }
            return handleToolCall(id: id, params: request["params"] as? [String: Any] ?? [:])

        default:
            if isNotification { return nil }
            return err(id, code: -32601, message: "Method not found: \(method)")
        }
    }

    // MARK: - tools/call

    private func handleToolCall(id: Any?, params: [String: Any]) -> [String: Any] {
        let name = params["name"] as? String ?? ""
        let args = params["arguments"] as? [String: Any] ?? [:]

        switch name {
        case "status":
            return toolText(id, statusText())

        case "enable_protection":
            return enableProtectionTool(id, mode: args["mode"] as? String ?? "standard", reason: args["reason"] as? String ?? "")

        case "list_secrets":
            return toolText(id, listSecretsText())

        case "set_env":
            // Decode element-wise: a single non-string element must not
            // drop the whole array (`as? [String]` fails on any non-string).
            let requested = (args["secrets"] as? [Any])?.compactMap { $0 as? String } ?? []
            if requested.isEmpty {
                return toolText(id, "No secrets requested. Pass `secrets: [\"name\", …]` (use list_secrets to see available names).", isError: true)
            }
            return toolText(id, setEnv(requested))

        case "clear_env":
            saveActive([])
            return toolText(id, "Cleared all active secret environment variables. Open a new shell for the change to take effect.")

        case "request_secret":
            guard let envVar = (args["env_var"] as? String), !envVar.isEmpty else {
                return toolText(id, "Pass env_var: the environment-variable name to request (e.g. \"STRIPE_KEY\").", isError: true)
            }
            return requestSecretsTool(id, [envVar], reason: args["reason"] as? String ?? "", generate: args["generate"] as? Bool ?? false)

        case "request_secrets":
            let names = (args["env_vars"] as? [Any])?.compactMap { $0 as? String } ?? []
            guard !names.isEmpty else {
                return toolText(id, "Pass env_vars: a list of environment-variable names to request (e.g. [\"STRIPE_KEY\",\"OPENAI_API_KEY\"]).", isError: true)
            }
            return requestSecretsTool(id, names, reason: args["reason"] as? String ?? "", generate: args["generate"] as? Bool ?? false)

        default:
            return toolText(id, "Unknown tool: \(name)", isError: true)
        }
    }

    /// Ask the user (via Bouclier's own dialog) to supply secret values for
    /// `envVars`, then report names/status to the agent. The agent NEVER
    /// receives a value — on success the values are already in the Keychain
    /// and active for new shells; the agent just uses $ENV_VAR.
    private func requestSecretsTool(_ id: Any?, _ envVars: [String], reason: String, generate: Bool) -> [String: Any] {
        guard let resp = requestSecrets(envVars, reason, generate) else {
            return toolText(id, "Bouclier isn't running, so it can't prompt the user for secrets. Ask the user to open the Bouclier app and tell you when it's ready before retrying.", isError: true)
        }
        switch resp.status {
        case .provided:
            guard !resp.provided.isEmpty else {
                return toolText(id, "No secrets were set — the user left the fields blank, or the values couldn't be stored. Don't assume they're available.", isError: true)
            }
            var msg = "The user provided \(resp.provided.map { "$\($0)" }.joined(separator: ", ")) — now available in NEW shells you spawn (run your command in a fresh shell; an already-open shell won't have them). The values were entered by the user and were never shown to you."
            if !resp.skipped.isEmpty {
                msg += " Left blank: \(resp.skipped.map { "$\($0)" }.joined(separator: ", "))."
            }
            return toolText(id, msg)
        case .cancelled:
            return toolText(id, "The user declined the secret request. Do not retry unless asked.", isError: true)
        case .timeout:
            return toolText(id, "The secret request timed out — the user may be away. Don't re-request automatically; ask them to retry when they're ready.", isError: true)
        case .invalid:
            return toolText(id, "Bouclier rejected the request before showing it (the env-var names may be malformed or the request expired). Check the names and try once — don't loop.", isError: true)
        }
    }

    /// Human-readable orientation summary. Counts only — never a value.
    private func statusText() -> String {
        switch loadStatus() {
        case .notRunning(let reason):
            return "Bouclier is installed but not active: \(reason). Ask the user to open the Bouclier app (or call enable_protection to propose turning it on). Until then, secrets aren't protected."
        case .running(let s):
            var lines = ["Bouclier \(s.appVersion) — \(s.running ? "protection ON" : "protection OFF") (\(s.mode) mode)."]
            let sk = s.secretKeeper
            if sk.circuitBreakerTripped {
                lines.append("⚠️ Secret keeper tripped a safety self-test — secrets are NOT being protected right now.")
            } else {
                lines.append("Secret keeper: \(sk.enabled ? (sk.healthy ? "on and healthy" : "on but unhealthy") : "off").")
            }
            lines.append("Secrets: \(s.secrets.total) stored, \(s.secrets.agentAccessible) you can use, \(s.secrets.active) active in shells.")
            lines.append("Activity: \(s.activity.requestsScanned) requests inspected, \(s.activity.secretsScrubbed) secrets scrubbed, \(s.activity.injectionsBlocked + s.activity.secretsBlocked) blocked.")
            if !s.running {
                lines.append("Protection is OFF — call enable_protection to propose turning it on (the user approves).")
            }
            return lines.joined(separator: "\n")
        }
    }

    private func enableProtectionTool(_ id: Any?, mode: String, reason: String) -> [String: Any] {
        guard let resp = proposeEnable(mode, reason) else {
            return toolText(id, "Bouclier isn't running, so it can't ask the user. Ask them to open the Bouclier app, then retry once.", isError: true)
        }
        switch resp.status {
        case .approved:
            return toolText(id, resp.message)
        case .declined:
            return toolText(id, "The user declined to enable protection. Don't retry unless they ask.", isError: true)
        case .timeout:
            return toolText(id, "No response — the user may be away. Don't auto-retry; ask them to enable Bouclier when ready.", isError: true)
        case .invalid, .unsupported:
            return toolText(id, resp.message.isEmpty ? "Bouclier could not enable protection." : resp.message, isError: true)
        }
    }

    private func listSecretsText() -> String {
        let rules = loadRules()
        let active = Set(loadActive())
        guard !rules.isEmpty else {
            return "No secrets are stored in Bouclier. Add them in the Bouclier app (Settings → Secrets)."
        }
        var lines = ["Available secrets (values are never shown — Bouclier injects them into your shell):"]
        for r in rules.sorted(by: { $0.name < $1.name }) {
            let access = r.agentAccess ? "agent-usable" : "LOCKED (not agent-accessible)"
            let state = active.contains(r.name) ? ", active" : ""
            lines.append("• \(r.name) → $\(r.environmentVariable) (\(access)\(state))")
        }
        lines.append("")
        lines.append("Call set_env with the names you need; then use $ENV_VAR in your shell commands.")
        return lines.joined(separator: "\n")
    }

    private func setEnv(_ requested: [String]) -> String {
        let rules = loadRules()
        let byName = Dictionary(rules.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })

        var activated: [String] = []
        var envVars: [String] = []
        var denied: [String] = []
        for name in requested {
            guard let meta = byName[name] else { denied.append("\(name) (unknown)"); continue }
            guard meta.agentAccess else { denied.append("\(name) (locked — enable agent access in Bouclier)"); continue }
            activated.append(name)
            envVars.append(meta.environmentVariable)
        }

        // Merge with whatever was already active (additive). Read once.
        let current = loadActive()
        let merged = current + activated.filter { !current.contains($0) }
        saveActive(merged)

        var msg = ""
        if !envVars.isEmpty {
            msg += "Activated: \(envVars.map { "$\($0)" }.joined(separator: ", ")). "
            msg += "These are now available in NEW shells you spawn — run your command in a fresh shell (Bouclier reads the real value from the Keychain; it never appears here or in the conversation)."
        }
        if !denied.isEmpty {
            if !msg.isEmpty { msg += "\n" }
            msg += "Not activated: \(denied.joined(separator: ", "))."
        }
        return msg
    }

    // MARK: - JSON-RPC helpers

    private func ok(_ id: Any?, _ result: [String: Any]) -> [String: Any] {
        ["jsonrpc": "2.0", "id": id ?? NSNull(), "result": result]
    }

    private func err(_ id: Any?, code: Int, message: String) -> [String: Any] {
        ["jsonrpc": "2.0", "id": id ?? NSNull(), "error": ["code": code, "message": message]]
    }

    private func toolText(_ id: Any?, _ text: String, isError: Bool = false) -> [String: Any] {
        ok(id, ["content": [["type": "text", "text": text]], "isError": isError])
    }

    // MARK: - Tool schema

    public static var toolDefinitions: [[String: Any]] { [
        [
            "name": "status",
            "description": "Read Bouclier's current state so you can orient yourself before acting: whether protection is on, which mode (standard/extreme), secret-keeper health, how many secrets you can use, and activity counts. Call this FIRST. Secret values are never returned. If it reports protection is off, you can call enable_protection to propose turning it on.",
            "inputSchema": ["type": "object", "properties": [String: Any](), "additionalProperties": false],
            "annotations": ["title": "Bouclier Status", "readOnlyHint": true, "openWorldHint": false],
        ],
        [
            "name": "list_secrets",
            "description": "List the secret names Bouclier can inject into your shell environment, with the environment-variable name each maps to and whether you're allowed to use it. Secret VALUES are never returned — only names. Call this first to discover what's available.",
            "inputSchema": ["type": "object", "properties": [String: Any](), "additionalProperties": false],
            "annotations": ["title": "List Secrets", "readOnlyHint": true, "openWorldHint": false],
        ],
        [
            "name": "enable_protection",
            "description": "Propose turning Bouclier protection ON. Bouclier asks the USER to approve in a dialog — you cannot enable it yourself. Use when status reports protection is off and the user wants their AI traffic protected. (Bouclier never lets an agent DISABLE protection or change modes — that's the user's job, by design.)",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "mode": ["type": "string", "description": "Requested mode; only \"standard\" is honored from an agent."],
                    "reason": ["type": "string", "description": "A short, honest explanation shown to the user."],
                ],
            ],
            "annotations": ["title": "Enable Protection (user approval)", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false],
        ],
        [
            "name": "set_env",
            "description": "Make the named secrets available as environment variables in shells you spawn afterward. You will receive only the environment-variable NAMES that were activated — never the values. Use the variables in shell commands (e.g. curl -H \"Authorization: Bearer $STRIPE_KEY\"); Bouclier reads the real value from the macOS Keychain at shell start so the secret never enters this conversation.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "secrets": [
                        "type": "array",
                        "items": ["type": "string"],
                        "description": "Secret names to activate (from list_secrets).",
                    ],
                ],
                "required": ["secrets"],
            ],
            "annotations": ["title": "Activate Secrets", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false],
        ],
        [
            "name": "clear_env",
            "description": "Deactivate all secret environment variables previously set via set_env.",
            "inputSchema": ["type": "object", "properties": [String: Any]()],
            "annotations": ["title": "Deactivate Secrets", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false],
        ],
        [
            "name": "request_secret",
            "description": "Ask the USER to provide a secret you need but that isn't stored yet. Bouclier shows the user a secure dialog where THEY paste the value — you never see it. On success the value is stored and the environment variable becomes available in new shells you spawn (use $ENV_VAR). Use this instead of asking the user to paste a secret into the chat. Set generate=true to have Bouclier CREATE a new random secret (e.g. a signing key) that the user just approves.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "env_var": ["type": "string", "description": "The environment-variable name to request, e.g. STRIPE_KEY."],
                    "reason": ["type": "string", "description": "A short, honest explanation of why you need it — shown to the user."],
                    "generate": ["type": "boolean", "description": "If true, Bouclier generates a new random value for the user to approve instead of pasting an existing one."],
                ],
                "required": ["env_var"],
            ],
            "annotations": ["title": "Request a Secret (user approval)", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false],
        ],
        [
            "name": "request_secrets",
            "description": "Like request_secret but for several at once: Bouclier shows ONE dialog with a field per name, the user fills in what they have, and each provided value becomes available as $ENV_VAR in new shells. You never see the values. Ideal for setting up a project that needs many secrets. Set generate=true to have Bouclier create new random values (e.g. a signing key) the user approves — you still never receive the value; reference it later as $ENV_VAR in your shell commands.",
            "inputSchema": [
                "type": "object",
                "properties": [
                    "env_vars": [
                        "type": "array",
                        "items": ["type": "string"],
                        "description": "Environment-variable names to request, e.g. [\"STRIPE_KEY\",\"OPENAI_API_KEY\"].",
                    ],
                    "reason": ["type": "string", "description": "A short, honest explanation shown to the user."],
                    "generate": ["type": "boolean", "description": "If true, Bouclier generates new random values for the user to approve instead of pasting."],
                ],
                "required": ["env_vars"],
            ],
            "annotations": ["title": "Request Secrets (user approval)", "readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false],
        ],
    ] }
}
