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

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Protection Status")
                .font(.headline)

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                StatusRow(label: "CA Certificate", active: proxyManager.caInstalled,
                          detail: proxyManager.caInstalled ? "Installed & Trusted" : "Not installed")
                StatusRow(label: "TLS Proxy", active: proxyManager.isRunning,
                          detail: proxyManager.isRunning ? "Port \(proxyManager.port)" : "Stopped")
                StatusRow(label: "System Extension", active: proxyManager.extensionActive,
                          detail: proxyManager.extensionActive ? "Capturing all AI traffic" : "Not active")
            }
            .font(.callout)

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
                if !proxyManager.caInstalled {
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
