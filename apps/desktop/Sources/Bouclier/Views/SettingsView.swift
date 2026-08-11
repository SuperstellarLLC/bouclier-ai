import BouclierCore
import SwiftUI

struct SettingsView: View {
    @ObservedObject var proxyManager: ProxyManager
    @ObservedObject var updater: AutoUpdater

    var body: some View {
        // Tab order follows user task frequency: a first-time user wants
        // to know "is it on" (Protection). Operational knobs (General,
        // Logs) and About come after.
        TabView {
            ProtectionSettingsView(proxyManager: proxyManager)
                .tabItem { Label("Protection", systemImage: "shield.checkered") }

            GeneralSettingsView(proxyManager: proxyManager)
                .tabItem { Label("General", systemImage: "gear") }

            LogsView(proxyManager: proxyManager)
                .tabItem { Label("Logs", systemImage: "doc.text") }

            AboutView(updater: updater)
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .frame(width: 540, height: 420)
    }
}

// Attachment PII inspection had its own Settings tab here (a toggle for
// scanning images/PDFs/audio, a redaction audit, and a PDF export). It's
// removed — the toggle had been non-functional since extreme mode's
// removal: MultimodalPIIInspector has no caller outside that path, so
// the toggle changed a UserDefaults flag nothing read. The underlying
// utilities (RedactionReport, StorageManager.piiRedactionCounts) are
// left in place, dormant, alongside the rest of the detection engine.


struct GeneralSettingsView: View {
    @ObservedObject var proxyManager: ProxyManager
    @AppStorage("proxyPort") private var port: Int = 8484
    @AppStorage("launchAtLogin") private var launchAtLogin: Bool = false
    @AppStorage("showNotifications") private var showNotifications: Bool = true
    @AppStorage("quietMode") private var quietMode: Bool = true
    /// The one setting that records request content — the block explainer.
    /// Off by default; local-only. Key matches the gateway's read.
    @AppStorage("captureBlockSamplesEnabled") private var captureBlockSamples: Bool = false
    @State private var sampleRefresh = 0
    /// Auto-write proxy + CA env vars into `~/.zshenv`, `~/.bashrc`,
    /// fish config, and launchctl. On by default — without it, Node /
    /// Python CLIs (Claude Code, Cursor, openai) silently bypass the
    /// proxy. Off-switch is here as an escape hatch for users with
    /// custom corporate proxies that conflict.
    @AppStorage(ShellEnvInjector.autoConfigureKey) private var autoConfigureShell: Bool = true
    @State private var showResetConfirm = false
    @State private var showResetProxiesConfirm = false
    @State private var cliInstalled = CLIInstaller.isInstalled()
    @State private var cliInstallError: String?
    @State private var mcpCommandCopied = false

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
                Toggle("Capture CLI tools (Claude Code, Python, Node SDKs)", isOn: $autoConfigureShell)
                    .onChange(of: autoConfigureShell) { _, newValue in
                        if newValue {
                            ShellEnvInjector.applyStandard(gatewayPort: proxyManager.port)
                        } else {
                            ShellEnvInjector.remove()
                        }
                    }
            } header: {
                Text("CLI capture")
            } footer: {
                Text("Bouclier writes `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` into your shell startup files and the launchctl session so command-line AI tools route through the gateway. Without this, tools that don't already have those variables set bypass Bouclier and talk to the provider directly. Only processes that read these variables are inspected — an app with its own backend (e.g. Cursor's agent) or a hard-coded base URL is not.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section {
                if cliInstalled {
                    Label("Installed at \(CLIInstaller.symlinkPath)", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                } else {
                    Button("Install `bouclier` command") {
                        installCLI()
                    }
                    if let cliInstallError {
                        Text(cliInstallError)
                            .font(.caption)
                            .foregroundStyle(.red)
                    }
                }
                Button(mcpCommandCopied ? "Copied" : "Copy Claude Code MCP command") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(
                        "claude mcp add bouclier -- \(CLIInstaller.mcpBinaryPath)",
                        forType: .string
                    )
                    mcpCommandCopied = true
                }
            } header: {
                Text("Agent command-line access")
            } footer: {
                Text("Puts `bouclier` on PATH (macOS will ask you to approve it — same as any app installing a helper tool) so Bash-driven agents can call `bouclier status` directly. Paste the MCP command into a terminal once to register the Bouclier MCP server with Claude Code.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section("Notifications") {
                Toggle("Show block notifications", isOn: $showNotifications)
                Toggle("Quiet mode (no sounds)", isOn: $quietMode)
                    .disabled(!showNotifications)
            }
            Section {
                Toggle("Capture blocked content for tuning", isOn: $captureBlockSamples)
                if captureBlockSamples {
                    let n = sampleRefresh >= 0 ? BlockSampleStore.count : 0
                    HStack {
                        Text("\(n) block\(n == 1 ? "" : "s") captured")
                            .font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button("Reveal in Finder") {
                            NSWorkspace.shared.activateFileViewerSelecting([BlockSampleStore.fileURL])
                        }
                        .disabled(n == 0)
                        Button("Clear") {
                            BlockSampleStore.clear()
                            sampleRefresh += 1
                        }
                        .disabled(n == 0)
                    }
                }
            } header: {
                Text("Block explainer")
            } footer: {
                Text("When a request is blocked, save the offending untrusted span, the per-signal breakdown, and the passage the on-device classifier reacted to most — to a local file (block-samples.jsonl) so you can see why it blocked and tune. This is the only setting that records request content; it stays on this Mac and is never transmitted. Off by default.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
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
                    Text("Clears the menu-bar counters (requests inspected / injections blocked). The audit log and on-disk stats are untouched.")
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

    private func installCLI() {
        cliInstallError = nil
        Task.detached(priority: .userInitiated) {
            do {
                try CLIInstaller.install()
                await MainActor.run {
                    cliInstalled = CLIInstaller.isInstalled()
                }
            } catch {
                await MainActor.run {
                    cliInstallError = error.localizedDescription
                }
            }
        }
    }
}

struct ProtectionSettingsView: View {
    @ObservedObject var proxyManager: ProxyManager
    @State private var showUninstallConfirm = false
    /// Bumped to force a re-read of the (UserDefaults-backed) allowlist
    /// count after the operator re-arms it.
    @State private var allowlistRefresh = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("How Protection Works")
                .font(.headline)
            Text("Routes your agents through a local gateway via ANTHROPIC_BASE_URL — no certificate to install. Every request is inspected on-device for prompt-injection in untrusted tool output; a request is forwarded byte-for-byte or refused, never rewritten.")
                .font(.callout)
                .foregroundStyle(.secondary)

            Divider()

            Text("Protection Status")
                .font(.headline)

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                StatusRow(label: "Gateway", active: proxyManager.isRunning,
                          detail: proxyManager.isRunning ? "Listening on port \(proxyManager.port)" : "Stopped")
                StatusRow(label: "Certificate", active: true,
                          detail: "Not needed")
                StatusRow(label: "Patterns", active: proxyManager.patternCount > 0,
                          detail: "\(proxyManager.patternCount) loaded")
            }
            .font(.callout)

            Spacer()

            if proxyManager.isRunning {
                Divider()
                Text("CLI Tools")
                    .font(.headline)
                HStack(spacing: 8) {
                    Image(systemName: ShellEnvInjector.isEnabled ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(ShellEnvInjector.isEnabled ? .green : .orange)
                        .font(.callout)
                    Text(ShellEnvInjector.isEnabled
                         ? "Command-line tools that read ANTHROPIC_BASE_URL / OPENAI_BASE_URL (Claude Code, the openai/anthropic SDKs) route through the gateway. Open a new terminal to pick up the change."
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
                if proxyManager.protectionActive {
                    Label("Protection active", systemImage: "checkmark.shield.fill")
                        .foregroundStyle(.green)
                        .font(.callout)
                    Spacer()
                    Button("Disable", role: .destructive) { proxyManager.disableStandard() }
                        .help("Traffic keeps flowing through the gateway, uninspected — active agent sessions are not interrupted")
                } else {
                    if proxyManager.isRunning {
                        Label("Passthrough — protection off", systemImage: "shield.slash")
                            .foregroundStyle(.secondary)
                            .font(.callout)
                        Spacer()
                    }
                    Button("Enable Protection") { proxyManager.enableStandard() }
                        .buttonStyle(.borderedProminent)
                }
            }

            // Released-span allowlist: surfaced only when non-empty, with a
            // one-click re-arm. This is the counterweight to the "Unblock"
            // action — a visible reminder that some spans are being
            // forwarded past the detector, and the way to undo it.
            let releasedCount = allowlistRefresh >= 0 ? proxyManager.allowlistedSpanCount : 0
            if releasedCount > 0 {
                Divider()
                HStack(spacing: 6) {
                    Image(systemName: "shield.slash")
                        .foregroundStyle(.orange)
                    Text("\(releasedCount) released span\(releasedCount == 1 ? "" : "s") forwarded past the detector")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Spacer()
                    Button("Re-arm all") {
                        proxyManager.clearAllowlist()
                        allowlistRefresh += 1
                    }
                    .font(.caption)
                    .help("Stop forwarding all released spans — the detector will block them again")
                }
            }

            Button("Uninstall Everything…", role: .destructive) {
                showUninstallConfirm = true
            }
            .buttonStyle(.link)
            .disabled(ManagedConfig.preventUninstall)
            .help(ManagedConfig.preventUninstall ? "Uninstall is disabled by your organization" : "")
            .alert("Uninstall Bouclier.ai?", isPresented: $showUninstallConfirm) {
                Button("Cancel", role: .cancel) {}
                Button("Uninstall", role: .destructive) {
                    proxyManager.uninstall()
                }
            } message: {
                Text("This will stop the gateway and remove everything Bouclier configured on this Mac. You can reinstall anytime.")
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

            Text("Catches prompt injection in untrusted tool output.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Text("Version \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—")")
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

            Text("Your traffic never leaves your machine to be inspected.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 300)

            Spacer()
        }
        .padding(.top, 40)
    }
}
