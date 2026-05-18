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

// MARK: - Privacy / PII redaction

/// Settings panel for the upstream PII redaction feature. Exposes the
/// toggle, the preview-before-send opt-in, and a per-entity-type audit
/// summary computed from the GRDB `pii_redactions` table. The summary
/// shows counts only; cleartext is never displayed or stored.
struct PrivacySettingsView: View {
    @ObservedObject var proxyManager: ProxyManager

    /// User-facing override for `FeatureFlags.piiRedaction`. Ships off
    /// by default; users opt in while the detector set matures.
    @AppStorage("piiRedactionEnabled") private var piiRedactionEnabled: Bool = false
    /// Show the preview modal before forwarding any prompt that contains
    /// detected PII. Recommended-on for the first sessions so users build
    /// confidence in what gets redacted; can be turned off once trusted.
    @AppStorage("piiPreviewBeforeSend") private var previewBeforeSend: Bool = true
    /// Whether image attachments in multimodal LLM requests get OCR'd
    /// for PII before forwarding. Off by default in v0.4.0 to mirror
    /// the text-PII toggle's opt-in posture.
    @AppStorage("multimodalInspectionEnabled") private var multimodalInspectionEnabled: Bool = false
    /// Days to retain redaction audit entries. Mirrors the cleanup
    /// window in `StorageManager.cleanup()`; surfaced here so users can
    /// see what the retention is (the value itself is informational).
    @AppStorage("piiAuditRetentionDays") private var auditRetentionDays: Int = 30

    @State private var auditCounts: [String: Int] = [:]
    @State private var allowDomainsText: String = ""
    @State private var denyDomainsText: String = ""

    var body: some View {
        Form {
            Section {
                Toggle("Strip PII from outbound prompts", isOn: $piiRedactionEnabled)
                Toggle("Preview redactions before sending", isOn: $previewBeforeSend)
                    .disabled(!piiRedactionEnabled)
                Button("Export redaction report…") {
                    exportRedactionReport()
                }
                .disabled(!piiRedactionEnabled)
                .help("Generate a PDF summarising redaction activity. Hand to a compliance officer or attach to an audit binder.")
            } header: {
                Text("PII redaction (beta)")
            } footer: {
                Text("Replaces detected PII (emails, IBANs, NHS numbers, etc.) with reversible placeholders before the prompt leaves your Mac. The model's response is reversed locally so you see normal text. All detection runs on-device — nothing about your PII is sent to Bouclier.ai or any third party.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section {
                Toggle("Inspect images, PDFs, and audio in outbound multimodal prompts", isOn: $multimodalInspectionEnabled)
            } header: {
                Text("Media inspection (beta)")
            } footer: {
                Text("Runs Apple's Vision OCR on every image, PDFKit on every PDF, and on-device Apple Speech on every audio clip attached to an outbound prompt (OpenAI, Anthropic, Gemini, plus Files-API uploads). When PII or faces appear inside an attachment, the attachment is replaced with a descriptive placeholder so the model still answers but never sees the cleartext. Encrypted PDFs and unreadable audio are stripped because they can't be inspected. Nothing about your attachments leaves your Mac.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section {
                TextEditor(text: $allowDomainsText)
                    .font(.system(.callout, design: .monospaced))
                    .frame(minHeight: 44)
                    .overlay(allowDomainsText.isEmpty ? placeholder("openai.com, anthropic.com") : nil, alignment: .topLeading)
                    .disabled(!piiRedactionEnabled)
                    .onChange(of: allowDomainsText) { _, new in
                        PIIPolicy.saveUserList(parseDomains(new), forKey: PIIPolicy.allowDomainsKey)
                    }
            } header: {
                Text("Allow only these hosts")
            } footer: {
                Text("Leave blank to redact for every host. Suffix-matches: 'openai.com' matches api.openai.com, eu.api.openai.com, etc.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section {
                TextEditor(text: $denyDomainsText)
                    .font(.system(.callout, design: .monospaced))
                    .frame(minHeight: 44)
                    .overlay(denyDomainsText.isEmpty ? placeholder("llm.internal, embeddings.acme.io") : nil, alignment: .topLeading)
                    .disabled(!piiRedactionEnabled)
                    .onChange(of: denyDomainsText) { _, new in
                        PIIPolicy.saveUserList(parseDomains(new), forKey: PIIPolicy.denyDomainsKey)
                    }
            } header: {
                Text("Never redact for these hosts")
            } footer: {
                Text("Use this for internal LLM gateways that already enforce compliance, or for endpoints where redaction would break the request (embeddings destroy the semantic vector). Always wins over the allow list.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section {
                if auditCounts.isEmpty {
                    Text("No PII redactions in the last \(auditRetentionDays) days.")
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
                Text("Counts per entity type. Bouclier.ai never logs the redacted values themselves, only the type and position.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .padding()
        .onAppear {
            refreshAudit()
            loadDomainsText()
        }
        .onChange(of: piiRedactionEnabled) { _, _ in refreshAudit() }
    }

    private func loadDomainsText() {
        if let raw = UserDefaults.standard.string(forKey: PIIPolicy.allowDomainsKey),
           let data = raw.data(using: .utf8),
           let arr = try? JSONDecoder().decode([String].self, from: data) {
            allowDomainsText = arr.joined(separator: "\n")
        }
        if let raw = UserDefaults.standard.string(forKey: PIIPolicy.denyDomainsKey),
           let data = raw.data(using: .utf8),
           let arr = try? JSONDecoder().decode([String].self, from: data) {
            denyDomainsText = arr.joined(separator: "\n")
        }
    }

    private func parseDomains(_ text: String) -> [String] {
        text
            .replacingOccurrences(of: ",", with: "\n")
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            .filter { !$0.isEmpty }
    }

    private func placeholder(_ text: String) -> some View {
        Text(text)
            .foregroundStyle(.tertiary)
            .padding(.horizontal, 5)
            .padding(.vertical, 8)
            .allowsHitTesting(false)
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
    @State private var showResetConfirm = false

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
                Text("Add to ~/.zshrc for Python/Node.js coverage:")
                    .foregroundStyle(.secondary)
                    .font(.callout)
                HStack(spacing: 8) {
                    Text("eval $(bouclier-ai-env)")
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(6)
                        .background(.quaternary)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                    Button(action: {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString("eval $(bouclier-ai-env)", forType: .string)
                    }) {
                        Image(systemName: "doc.on.doc")
                            .font(.caption)
                    }
                    .buttonStyle(.borderless)
                    .help("Copy to clipboard")
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

            Text("Stop prompt injections. Stop PII from leaking to LLMs.")
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
