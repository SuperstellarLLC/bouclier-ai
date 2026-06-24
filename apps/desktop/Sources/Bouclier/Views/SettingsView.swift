import BouclierSecretsCore
import SwiftUI

struct SettingsView: View {
    @ObservedObject var proxyManager: ProxyManager
    @ObservedObject var updater: AutoUpdater

    var body: some View {
        // Tab order follows user task frequency: a first-time user wants
        // to know "is it on and what does it cover" (Protection), then
        // tune "what gets redacted" (Privacy). Operational knobs
        // (General, Logs) and About come after.
        TabView {
            ProtectionSettingsView(proxyManager: proxyManager)
                .tabItem { Label("Protection", systemImage: "shield.checkered") }

            PrivacySettingsView(proxyManager: proxyManager)
                .tabItem { Label("Privacy", systemImage: "eye.slash") }

            SecretsSettingsView(proxyManager: proxyManager)
                .tabItem { Label("Secrets", systemImage: "key.fill") }

            GeneralSettingsView(proxyManager: proxyManager)
                .tabItem { Label("General", systemImage: "gear") }

            LogsView(proxyManager: proxyManager)
                .tabItem { Label("Logs", systemImage: "doc.text") }

            AboutView(updater: updater, patternCount: proxyManager.patternsLoadedCount)
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .frame(width: 540, height: 420)
    }
}

// MARK: - Privacy / File PII inspection

/// Settings panel for outbound file-attachment PII inspection. Bouclier
/// does not modify text prompts — only attachments (images, PDFs,
/// audio) are scanned and stripped of PII before forwarding. This
/// scopes the trust surface to "files Bouclier rewrote", which is
/// unambiguously user-attached content rather than fields like `user`
/// or `metadata.user_id` that some upstream LLM APIs read for abuse
/// monitoring.
struct PrivacySettingsView: View {
    @ObservedObject var proxyManager: ProxyManager

    /// Whether image / PDF / audio attachments in outbound LLM requests
    /// get scanned and rewritten when they contain PII.
    @AppStorage("multimodalInspectionEnabled") private var multimodalInspectionEnabled: Bool = false
    /// Days to retain redaction audit entries. Mirrors the cleanup
    /// window in `StorageManager.cleanup()`; surfaced here so users can
    /// see what the retention is (the value itself is informational).
    @AppStorage("piiAuditRetentionDays") private var auditRetentionDays: Int = 30

    @State private var auditCounts: [String: Int] = [:]

    var body: some View {
        Form {
            Section {
                Toggle("Inspect images, PDFs, and audio in outbound attachments", isOn: $multimodalInspectionEnabled)
                Button("Export redaction report…") {
                    exportRedactionReport()
                }
                .disabled(!multimodalInspectionEnabled)
                .help("Generate a PDF summarising attachment-redaction activity. Hand to a compliance officer or attach to an audit binder.")
            } header: {
                Text("File PII inspection (beta)")
            } footer: {
                Text("Runs Apple's Vision OCR on every image, PDFKit on every PDF, and on-device Apple Speech on every audio clip attached to an outbound prompt (OpenAI, Anthropic, Gemini, plus Files-API uploads). When PII or faces appear inside an attachment, the attachment is replaced with a descriptive placeholder so the model still answers but never sees the cleartext. Encrypted PDFs and unreadable audio are stripped because they can't be inspected. Text prompts are never modified — only attachments. All inspection runs on-device; nothing about your attachments leaves your Mac.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section {
                if auditCounts.isEmpty {
                    Text("No attachment redactions in the last \(auditRetentionDays) days.")
                        .foregroundStyle(.secondary)
                        .font(.callout)
                } else {
                    ForEach(auditCounts.sorted(by: { $0.value > $1.value }), id: \.key) { type, count in
                        HStack {
                            Text(humanLabel(type))
                            Spacer()
                            Text("\(count)")
                                .monospacedDigit()
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                Text("Audit (last \(auditRetentionDays) days)")
            } footer: {
                Text("Counts per entity type detected inside outbound attachments. Bouclier.ai never logs the redacted values themselves, only the type and a hash.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding()
        .onAppear { refreshAudit() }
        .onChange(of: multimodalInspectionEnabled) { _, _ in refreshAudit() }
    }

    private func exportRedactionReport() {
        guard let storage = proxyManager.storage else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.pdf]
        panel.nameFieldStringValue = "Bouclier-Redaction-Report-\(Self.fileDateFormatter.string(from: Date())).pdf"
        if panel.runModal() == .OK, let url = panel.url {
            let pdf = RedactionReport.renderPDF(
                storage: storage,
                windowDays: auditRetentionDays,
                generatedAt: Date()
            )
            try? pdf.write(to: url)
            NSWorkspace.shared.activateFileViewerSelecting([url])
        }
    }

    private static let fileDateFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd"
        return f
    }()

    private func refreshAudit() {
        auditCounts = proxyManager.storage?.piiRedactionCounts(days: auditRetentionDays) ?? [:]
    }

    private func humanLabel(_ type: String) -> String {
        switch type {
        case "EMAIL": return "Email addresses"
        case "IBAN": return "IBAN account numbers"
        case "CREDIT_CARD": return "Credit cards"
        case "US_SSN": return "US Social Security numbers"
        case "IPV4": return "IPv4 addresses"
        case "IPV6": return "IPv6 addresses"
        case "AWS_ACCESS_KEY": return "AWS access keys"
        case "JWT": return "JWT tokens"
        case "FR_SIRET": return "French SIRET (establishment)"
        case "FR_SIREN": return "French SIREN (company)"
        case "FR_NIR": return "French NIR (social security)"
        case "UK_NHS": return "UK NHS numbers"
        case "UK_NINO": return "UK National Insurance numbers"
        case "UK_POSTCODE": return "UK postcodes"
        case "US_NPI": return "US National Provider IDs"
        default: return type
        }
    }
}

// MARK: - Secrets (secret keeper)

/// Settings panel for the secret keeper. The agent/LLM only ever holds
/// an opaque placeholder; Bouclier swaps in the real value (from the
/// Keychain) at egress, bound to the rule's allowlisted host, and blocks
/// exfil/plaintext tripwires. See `docs/secret-injection.md`.
struct SecretsSettingsView: View {
    @ObservedObject var proxyManager: ProxyManager

    /// Drives `FeatureFlags.secretInjection` via UserDefaults (the flag's
    /// resolution order reads `<key>Enabled`).
    @AppStorage("secretInjectionEnabled") private var secretInjectionEnabled: Bool = false

    @State private var rules: [SecretRule] = []
    @State private var newName: String = ""
    @State private var newValue: String = ""
    @State private var newHosts: String = ""
    @State private var newEnvVar: String = ""
    @State private var newAgentAccess: Bool = true
    @AppStorage(SecretGenerator.commandKey) private var genCommand: String = SecretGenerator.defaultCommand
    @State private var addError: String?

    var body: some View {
        Form {
            if !proxyManager.secretKeeperHealthy {
                Section {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "exclamationmark.octagon.fill")
                            .foregroundStyle(.red)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Secret keeper disabled by a safety self-test")
                                .font(.callout.weight(.semibold))
                            Text("A startup integrity check failed, so secret injection is off and all traffic is forwarded untouched. This protects your LLM connections. To retry, quit and relaunch Bouclier; if it persists, please report it — it shouldn't happen.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            }

            Section {
                // The secret keeper only does anything while protection is
                // actually running. Without this, a user could flip the
                // toggle on, add secrets, and believe they're protected while
                // the gateway is off — the worst failure mode for a security
                // product. Surface it inline with a one-click fix.
                if !proxyManager.isRunning {
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.orange)
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Protection is off — secrets aren't protected yet")
                                .font(.callout.weight(.semibold))
                            Text("Managed secrets are only scrubbed while the gateway is running.")
                                .font(.caption).foregroundStyle(.secondary)
                            Button("Turn on Protection") { proxyManager.enableStandard() }
                                .buttonStyle(.borderedProminent)
                                .controlSize(.small)
                        }
                    }
                }
                Toggle("Protect managed secrets from the model", isOn: $secretInjectionEnabled)
                    .disabled(!proxyManager.secretKeeperHealthy || !proxyManager.isRunning)
                    .onChange(of: secretInjectionEnabled) { _, _ in reArmProxy() }
                HStack(spacing: 16) {
                    Label("\(proxyManager.stats.secretsScrubbed) scrubbed", systemImage: "eraser.fill")
                        .foregroundStyle(.secondary)
                    // "injected" only happens in extreme mode.
                    if ProxyMode.current == .extreme {
                        Label("\(proxyManager.stats.secretsInjected) injected", systemImage: "key.fill")
                            .foregroundStyle(.secondary)
                    }
                    Label("\(proxyManager.stats.secretsBlocked) blocked", systemImage: "hand.raised.fill")
                        .foregroundStyle(proxyManager.stats.secretsBlocked > 0 ? .red : .secondary)
                }
                .font(.caption)
                .monospacedDigit()
            } header: {
                Text("Secret keeper (beta)")
            } footer: {
                Text("Keeps your real credentials out of the model. In Standard mode a managed secret is scrubbed to a placeholder before the request reaches the model provider and restored in the response, so your local tools still work while the vendor never sees it. Bind a secret to a host to also inject it into that third party in Extreme mode. Secrets live in your macOS Keychain and never leave this Mac.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section {
                if rules.isEmpty {
                    Text("No managed secrets yet. Add one below.")
                        .foregroundStyle(.secondary)
                        .font(.callout)
                } else {
                    ForEach(rules, id: \.name) { rule in
                        SecretRow(rule: rule, onCopy: { copyPlaceholder(rule) }, onDelete: { delete(rule) }, onToggleAccess: { toggleAccess(rule) })
                    }
                }
            } header: {
                Text("Managed secrets")
            } footer: {
                Text("A secret's `$ENV_VAR` appears in shells you open after adding it — open a new terminal to pick it up. Use the placeholder verbatim in your agent's config or tool call. Binding a host (extreme mode) makes Bouclier intercept it; a certificate-pinned tool may reject that — remove the secret to undo. Your LLM providers are never blocked for authenticating normally.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section {
                TextField("Name (lowercase, e.g. stripe)", text: $newName)
                    .textFieldStyle(.roundedBorder)
                HStack(spacing: 6) {
                    SecureField("Secret value", text: $newValue)
                        .textFieldStyle(.roundedBorder)
                    Button("Generate") {
                        if let v = SecretGenerator.generate() { newValue = v }
                    }
                    .help("Generate a random value (\(genCommand))")
                }
                TextField("Generator command", text: $genCommand)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.caption, design: .monospaced))
                TextField("Allowed hosts — optional (e.g. api.stripe.com). Blank = scrub-only.", text: $newHosts)
                    .textFieldStyle(.roundedBorder)
                TextField("Env var name — optional (default \(newName.isEmpty ? "NAME" : newName.trimmedLowercasedName.uppercased())), e.g. STRIPE_KEY", text: $newEnvVar)
                    .textFieldStyle(.roundedBorder)
                Toggle("Let an AI agent use this via MCP (value never shown to the model)", isOn: $newAgentAccess)
                if let addError {
                    Text(addError)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                Button("Add secret") { add() }
                    .disabled(newName.isEmpty || newValue.isEmpty)
                if !newName.isEmpty {
                    Text("Placeholder: \(SecretRule.placeholder(for: newName.trimmedLowercasedName))")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            } header: {
                Text("Add a secret")
            } footer: {
                Text("The value is written to the Keychain and never shown again. Name must be lowercase letters, digits, or underscores.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding()
        .onAppear { reload() }
    }

    private func reload() {
        rules = SecretStore.shared.rules().sorted { $0.name < $1.name }
    }

    private func add() {
        let name = newName.trimmedLowercasedName
        guard SecretRule.isValidName(name) else {
            addError = "Name must be lowercase letters, digits, or underscores."
            return
        }
        guard SecretRule.isValidValue(newValue) else {
            addError = "Secret value is empty, too long, or contains line breaks."
            return
        }
        let rawHosts = newHosts
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        // Hosts are OPTIONAL. With no host the secret is "scrub-only"
        // (standard mode): scrubbed out of model-provider requests and
        // restored in the response, never injected into a third party.
        // With a host it's also injectable in extreme mode.
        // Surface rejected hosts rather than silently dropping them.
        let invalid = rawHosts.filter { SecretRule.validatedHost($0) == nil }
        guard invalid.isEmpty else {
            addError = "Can't bind to: \(invalid.joined(separator: ", ")). Use a public domain (no localhost, raw IPs, or metadata endpoints)."
            return
        }
        let envVar = newEnvVar.trimmingCharacters(in: .whitespaces)
        if !envVar.isEmpty, !SecretRule.isValidEnvVar(envVar) {
            addError = "Env var name must start with a letter or _ and contain only letters, digits, and _."
            return
        }
        guard SecretStore.shared.addSecret(name: name, value: newValue, allowedHosts: rawHosts, agentAccess: newAgentAccess, envVar: envVar.isEmpty ? nil : envVar) else {
            addError = "Couldn't save the secret. Check the name, value, hosts, and env var name."
            return
        }
        addError = nil
        newName = ""; newValue = ""; newHosts = ""; newEnvVar = ""; newAgentAccess = true
        reload()
        reArmProxy()
    }

    private func delete(_ rule: SecretRule) {
        SecretStore.shared.removeSecret(name: rule.name)
        reload()
        reArmProxy()
    }

    private func toggleAccess(_ rule: SecretRule) {
        SecretStore.shared.setAgentAccess(name: rule.name, !rule.agentAccess)
        reload()
    }

    private func copyPlaceholder(_ rule: SecretRule) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(rule.placeholder, forType: .string)
    }

    /// Rewrite the system PAC so newly bound hosts are routed through the
    /// proxy (and removed ones stop being intercepted).
    ///
    /// Two safety properties: (1) no-op unless the proxy is already
    /// running, so toggling secrets never *enables* a proxy the user
    /// hasn't turned on — we only refresh an already-armed PAC, which is
    /// idempotent. (2) Runs off the main thread because `networksetup`
    /// shells out and could otherwise stall the Settings UI; the result
    /// is intentionally ignored (a failed refresh leaves the prior
    /// working PAC in place rather than breaking connectivity).
    private func reArmProxy() {
        guard proxyManager.isRunning else { return }
        let port = proxyManager.port
        DispatchQueue.global(qos: .utility).async {
            _ = SystemProxy.enable(port: port)
        }
    }
}

private struct SecretRow: View {
    let rule: SecretRule
    let onCopy: () -> Void
    let onDelete: () -> Void

    let onToggleAccess: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(rule.name)
                    .font(.callout.weight(.medium))
                Text(rule.placeholder)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
                HStack(spacing: 6) {
                    Text(rule.isScrubOnly ? "scrub-only" : rule.allowedHosts.joined(separator: ", "))
                    Text("·")
                    Text("$\(rule.environmentVariable)")
                    Text("·")
                    Text(rule.agentAccess ? "agent-usable" : "locked")
                        .foregroundStyle(rule.agentAccess ? Color.secondary : Color.orange)
                }
                .font(.caption2)
                .foregroundStyle(.tertiary)
            }
            Spacer()
            Button {
                onToggleAccess()
            } label: {
                Image(systemName: rule.agentAccess ? "person.fill" : "lock.fill")
            }
            .buttonStyle(.borderless)
            .help(rule.agentAccess ? "Agent (MCP) access on — click to lock" : "Locked — click to allow agent (MCP) access")
            Button {
                onCopy()
            } label: {
                Image(systemName: "doc.on.doc")
            }
            .buttonStyle(.borderless)
            .help("Copy placeholder")
            Button(role: .destructive) {
                onDelete()
            } label: {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
            .help("Delete secret")
        }
        .padding(.vertical, 2)
    }
}

private extension String {
    /// Normalised secret-rule name: trimmed + lowercased.
    var trimmedLowercasedName: String {
        trimmingCharacters(in: .whitespaces).lowercased()
    }
}

struct GeneralSettingsView: View {
    @ObservedObject var proxyManager: ProxyManager
    @AppStorage("proxyPort") private var port: Int = 8484
    @AppStorage("launchAtLogin") private var launchAtLogin: Bool = false
    @AppStorage("showNotifications") private var showNotifications: Bool = true
    @AppStorage("quietMode") private var quietMode: Bool = true
    /// Auto-write proxy + CA env vars into `~/.zshenv`, `~/.bashrc`,
    /// fish config, and launchctl. On by default — without it, Node /
    /// Python CLIs (Claude Code, Cursor, openai) silently bypass the
    /// proxy. Off-switch is here as an escape hatch for users with
    /// custom corporate proxies that conflict.
    @AppStorage(ShellEnvInjector.autoConfigureKey) private var autoConfigureShell: Bool = true
    @State private var showResetConfirm = false
    @State private var showResetProxiesConfirm = false

    var body: some View {
        Form {
            Section("Proxy") {
                TextField("Port", value: $port, format: .number)
                    .help("Requires proxy restart to take effect")
                Toggle("Launch at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, newValue in
                        ProxyManager.setLaunchAtLogin(newValue)
                    }
            }
            Section {
                Toggle("Capture CLI tools (Claude Code, Cursor, Python, Node)", isOn: $autoConfigureShell)
                    .onChange(of: autoConfigureShell) { _, newValue in
                        if newValue {
                            ShellEnvInjector.apply(
                                proxyPort: proxyManager.port,
                                caCertPath: proxyManager.ca.caCertFilePath
                            )
                        } else {
                            ShellEnvInjector.remove()
                        }
                    }
            } header: {
                Text("CLI capture")
            } footer: {
                Text("Bouclier writes `HTTPS_PROXY` and `NODE_EXTRA_CA_CERTS` into your shell startup files and the launchctl session so command-line AI tools route through the proxy. Without this, only GUI apps (ChatGPT, Claude Desktop) are protected — Claude Code and other CLIs bypass interception.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section("Notifications") {
                Toggle("Show block notifications", isOn: $showNotifications)
                Toggle("Quiet mode (no sounds)", isOn: $quietMode)
                    .disabled(!showNotifications)
            }
            Section {
                Button("Reset session stats", role: .destructive) {
                    showResetConfirm = true
                }
                .confirmationDialog(
                    "Reset stats?",
                    isPresented: $showResetConfirm,
                    titleVisibility: .visible
                ) {
                    Button("Reset", role: .destructive) { proxyManager.stats.reset() }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text("Clears the menu-bar counters (scanned / blocked / redacted / media). The audit log and on-disk stats are untouched.")
                }
            } header: {
                Text("Diagnostics")
            } footer: {
                Text("Resets are local to this session — the audit database keeps the history.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section {
                Button("Reset all proxy settings", role: .destructive) {
                    showResetProxiesConfirm = true
                }
                .confirmationDialog(
                    "Reset all proxy settings?",
                    isPresented: $showResetProxiesConfirm,
                    titleVisibility: .visible
                ) {
                    Button("Reset", role: .destructive) { proxyManager.resetAllProxies() }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text("Clears every proxy artifact Bouclier may have left on this Mac — PAC settings on every network service, launchctl session env, the crash watchdog, and the shell startup blocks. Protection turns off until you re-enable it from the Protection tab.")
                }
            } header: {
                Text("Proxy recovery")
            } footer: {
                Text("Use this if an unclean shutdown left CLI tools or your browser unable to reach LLM APIs. Open a new terminal afterwards so it picks up the cleared shell env.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}

struct ProtectionSettingsView: View {
    @ObservedObject var proxyManager: ProxyManager
    @State private var showUninstallConfirm = false
    @AppStorage(ProxyMode.userDefaultsKey) private var modeRaw: String = ProxyMode.compileDefault.rawValue
    @AppStorage("secretInjectionEnabled") private var secretInjectionEnabled: Bool = false
    /// Extreme mode is hidden by default — hold ⌥ Option to reveal it. It's
    /// experimental and can alter system network configuration.
    @State private var optionHeld = false
    @State private var flagsMonitor: Any?
    @State private var showExtremeConfirm = false

    private var extremeVisible: Bool { optionHeld || modeRaw == ProxyMode.extreme.rawValue }

    /// Intercepts selection so Extreme is never applied until the user
    /// confirms the experimental warning; Standard applies immediately.
    private var modeSelection: Binding<String> {
        Binding(
            get: { modeRaw },
            set: { new in
                if new == ProxyMode.extreme.rawValue {
                    if modeRaw != ProxyMode.extreme.rawValue { showExtremeConfirm = true }
                } else {
                    modeRaw = ProxyMode.standard.rawValue
                    proxyManager.selectMode(.standard)
                }
            }
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Proxy Mode")
                .font(.headline)
            Picker("Mode", selection: modeSelection) {
                Text("Standard — no CA, secrets only").tag(ProxyMode.standard.rawValue)
                if extremeVisible {
                    Text("Extreme — full interception (experimental)").tag(ProxyMode.extreme.rawValue)
                }
            }
            .pickerStyle(.radioGroup)
            .labelsHidden()

            if !extremeVisible {
                Text("Hold ⌥ Option to reveal Extreme mode.")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }

            Text(modeRaw == ProxyMode.standard.rawValue
                 ? "Routes your agents through a local gateway via ANTHROPIC_BASE_URL — no certificate to install. Protects the LLM channel: your managed secrets are scrubbed before the model sees them and restored in the response. Injection filtering and file PII stripping are off in this mode."
                 : "Installs a trusted root CA and intercepts all AI TLS traffic. Adds injection filtering, file PII stripping, and third-party secret injection on top of the secrets sandwich.")
                .font(.callout)
                .foregroundStyle(.secondary)

            Divider()

            Text("Protection Status")
                .font(.headline)

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                if modeRaw == ProxyMode.standard.rawValue {
                    // Standard mode uses no CA / extension / TLS interception —
                    // show what's actually true rather than three permanently
                    // "off" extreme-mode rows.
                    StatusRow(label: "Gateway", active: proxyManager.isRunning,
                              detail: proxyManager.isRunning ? "Listening on port \(proxyManager.port)" : "Stopped")
                    StatusRow(label: "Certificate", active: true,
                              detail: "Not needed in standard mode")
                    StatusRow(label: "Secret keeper", active: secretInjectionEnabled,
                              detail: secretInjectionEnabled ? "On" : "Off")
                } else {
                    StatusRow(label: "CA Certificate", active: proxyManager.caInstalled,
                              detail: proxyManager.caInstalled ? "Installed & Trusted" : "Not installed")
                    StatusRow(label: "TLS Proxy", active: proxyManager.isRunning,
                              detail: proxyManager.isRunning ? "Port \(proxyManager.port)" : "Stopped")
                    StatusRow(label: "System Extension", active: proxyManager.extensionActive,
                              detail: proxyManager.extensionActive ? "Capturing all AI traffic" : "Not active")
                }
            }
            .font(.callout)

            // Detection (ML + self-test) + intercepted-domain list are
            // extreme-mode concepts — injection filtering only runs there.
            if modeRaw == ProxyMode.extreme.rawValue {
                Divider()

                Text("Detection")
                    .font(.headline)
                DetectionStatusView(proxyManager: proxyManager)

                Divider()

                Text("Intercepted Domains")
                    .font(.headline)
                Text("Bouclier.ai only inspects traffic to these AI API domains. All other traffic is unaffected.")
                    .foregroundStyle(.secondary)
                    .font(.callout)

                ScrollView {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(Array(SystemProxy.interceptedDomains).sorted(), id: \.self) { domain in
                            Text(domain)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .frame(maxHeight: 100)
            }

            Spacer()

            if proxyManager.ca.caCertFilePath != nil {
                Divider()
                Text("CLI Tools")
                    .font(.headline)
                HStack(spacing: 8) {
                    Image(systemName: ShellEnvInjector.isEnabled ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(ShellEnvInjector.isEnabled ? .green : .orange)
                        .font(.callout)
                    Text(ShellEnvInjector.isEnabled
                         ? "Claude Code, Cursor, Python, Node — all captured. Open a new terminal to pick up the change."
                         : "CLI capture is off — Settings → General to re-enable.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }

            if ManagedConfig.isManaged {
                Divider()
                HStack(spacing: 6) {
                    Image(systemName: "building.2")
                        .foregroundStyle(.blue)
                    Text("Managed by your organization")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            HStack {
                if modeRaw == ProxyMode.standard.rawValue {
                    // Standard (no CA): a simple enable/disable.
                    if proxyManager.isRunning {
                        Label("Protection active", systemImage: "checkmark.shield.fill")
                            .foregroundStyle(.green)
                            .font(.callout)
                        Spacer()
                        Button("Disable", role: .destructive) { proxyManager.disableStandard() }
                    } else {
                        Button("Enable Protection") { proxyManager.enableStandard() }
                            .buttonStyle(.borderedProminent)
                    }
                } else if !proxyManager.caInstalled {
                    Button("Enable Protection") { proxyManager.setup() }
                        .buttonStyle(.borderedProminent)
                } else {
                    Button("Uninstall Everything", role: .destructive) {
                        showUninstallConfirm = true
                    }
                    .disabled(ManagedConfig.preventUninstall)
                    .help(ManagedConfig.preventUninstall ? "Uninstall is disabled by your organization" : "")
                    .alert("Uninstall Bouclier.ai?", isPresented: $showUninstallConfirm) {
                        Button("Cancel", role: .cancel) {}
                        Button("Uninstall", role: .destructive) {
                            proxyManager.uninstall()
                        }
                    } message: {
                        Text("This will remove the CA certificate, disable the System Extension, and stop the proxy. You can reinstall anytime.")
                    }
                }
            }
        }
        .padding()
        .onAppear {
            optionHeld = NSEvent.modifierFlags.contains(.option)
            flagsMonitor = NSEvent.addLocalMonitorForEvents(matching: .flagsChanged) { event in
                optionHeld = event.modifierFlags.contains(.option)
                return event
            }
        }
        .onDisappear {
            if let m = flagsMonitor { NSEvent.removeMonitor(m) }
            flagsMonitor = nil
        }
        .alert("Enable Extreme mode?", isPresented: $showExtremeConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Enable Extreme mode", role: .destructive) {
                modeRaw = ProxyMode.extreme.rawValue
                proxyManager.selectMode(.extreme)
            }
        } message: {
            Text("Experimental — use at your own risk. Extreme mode installs a trusted root certificate and reroutes your system's network traffic to inspect all AI connections. This can interfere with other apps, break certificate-pinned tools, conflict with corporate proxies, and may require manual cleanup. Only enable it if you understand these risks.")
        }
    }
}

private struct StatusRow: View {
    let label: String
    let active: Bool
    let detail: String

    var body: some View {
        GridRow {
            Label(label, systemImage: active ? "checkmark.circle.fill" : "xmark.circle")
                .foregroundStyle(active ? .green : .secondary)
            Text(detail)
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(label): \(detail)")
    }
}

struct LogsView: View {
    @ObservedObject var proxyManager: ProxyManager

    var body: some View {
        VStack(alignment: .leading) {
            HStack {
                Text("Recent Activity")
                    .font(.headline)
                Spacer()
                Text("\(proxyManager.logs.count) entries")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Button("Clear") { proxyManager.clearLogs() }
                    .buttonStyle(.borderless)
            }

            if proxyManager.logs.isEmpty {
                ContentUnavailableView {
                    Label("No Activity", systemImage: "doc.text")
                } description: {
                    Text("Logs will appear here when the proxy processes requests.")
                }
            } else {
                List(proxyManager.logs) { entry in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: entry.blocked ? "exclamationmark.shield.fill" : "checkmark.shield")
                            .foregroundStyle(entry.blocked ? .red : .green)
                            .font(.caption)
                            .frame(width: 16)
                            .accessibilityLabel(entry.blocked ? "Blocked" : "Passed")
                        VStack(alignment: .leading, spacing: 2) {
                            Text(entry.message)
                                .font(.callout)
                                .lineLimit(3)
                            Text(entry.timestamp, style: .time)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                    }
                }
                .listStyle(.plain)
            }
        }
        .padding()
    }
}

struct AboutView: View {
    @ObservedObject var updater: AutoUpdater
    let patternCount: Int

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.checkered")
                .font(.system(size: 48))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)

            HStack(spacing: 8) {
                Text("Bouclier.ai")
                    .font(.title.bold())
                Text("BETA")
                    .font(.system(size: 10, weight: .semibold))
                    .tracking(0.6)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.orange.opacity(0.15), in: RoundedRectangle(cornerRadius: 4))
                    .foregroundStyle(.orange)
            }

            Text("Stop prompt injections. Stop PII from leaking through your attachments.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Text("Version \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—")")
                .font(.caption)
                .foregroundStyle(.tertiary)

            Text("\(patternCount) detection patterns active")
                .font(.caption)
                .foregroundStyle(.tertiary)

            Button("Check for Updates...") { updater.checkForUpdates() }
                .disabled(!updater.canCheckForUpdates)

            Divider().frame(width: 200)

            // Defensive disclaimer mirroring the website Terms. Surfaced
            // here so users in regulated environments can't miss it.
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.caption)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Experimental software")
                        .font(.caption.weight(.semibold))
                    Text("Not intended for production or regulated workloads. Detection is best-effort.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(8)
            .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
            .frame(maxWidth: 320)

            HStack(spacing: 12) {
                Button("Terms") {
                    if let url = URL(string: "https://www.bouclier.ai/terms") {
                        NSWorkspace.shared.open(url)
                    }
                }
                .buttonStyle(.link)
                Button("Privacy") {
                    if let url = URL(string: "https://www.bouclier.ai/privacy") {
                        NSWorkspace.shared.open(url)
                    }
                }
                .buttonStyle(.link)
            }

            Divider().frame(width: 200)

            Text("Built with Llama")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.primary)

            Text("Uses Meta Llama Prompt Guard 2 for on-device prompt attack detection.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 300)

            Text("All detection runs locally.\nNo data ever leaves your machine.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 300)

            Spacer()
        }
        .padding(.top, 40)
    }
}
