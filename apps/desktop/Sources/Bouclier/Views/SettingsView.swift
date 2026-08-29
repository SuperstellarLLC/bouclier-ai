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
        .frame(width: 560, height: 520)
    }
}

private struct ConfigurationNoticeView: View {
    let notice: ConfigurationNotice

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: notice.kind == .success
                  ? "checkmark.circle.fill"
                  : "exclamationmark.triangle.fill")
            VStack(alignment: .leading, spacing: 2) {
                Text(notice.title).font(.caption.weight(.semibold))
                Text(notice.message).font(.caption)
            }
        }
        .foregroundStyle(notice.kind == .success ? Color.green : Color.orange)
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .combine)
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
    /// Auto-write provider base URLs into `~/.zshenv`, `~/.bashrc`,
    /// fish config, and launchctl. On by default — without it, Node /
    /// Python CLIs (Claude Code, openai, anthropic) silently bypass the
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
                if let managedPort = ManagedConfig.port {
                    LabeledContent("Port", value: "\(managedPort)")
                    Text("Managed by your organization")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else {
                    TextField("Port", value: $port, format: .number)
                        .help("Takes effect the next time the gateway starts")
                        .disabled(proxyManager.configurationMutationLocked)
                        .onChange(of: port) { _, _ in
                            proxyManager.clearSuccessfulConfigurationCleanupNotice()
                        }
                    if !ManagedConfigValidator.validPortRange.contains(port) {
                        Text("Choose a port from 1024 to 65535. Bouclier will use 8484 until this is corrected.")
                            .font(.caption)
                            .foregroundStyle(.red)
                    } else if let boundPort = proxyManager.boundPort, boundPort != port {
                        Text("Currently listening on \(boundPort). The new port takes effect after Bouclier restarts.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Toggle("Launch at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, newValue in
                        if !proxyManager.setLaunchAtLoginEnabled(newValue) {
                            launchAtLogin = UserDefaults.standard.bool(
                                forKey: ProxyManager.launchAtLoginKey
                            )
                        }
                    }
                    .disabled(
                        proxyManager.managedContinuityLockActive
                            || proxyManager.configurationMutationLocked
                    )
            }
            Section {
                Toggle("Capture CLI tools (Claude Code, Python, Node SDKs)", isOn: $autoConfigureShell)
                    .onChange(of: autoConfigureShell) { _, newValue in
                        if !proxyManager.setCLICaptureEnabled(newValue) {
                            autoConfigureShell = ShellEnvInjector.isEnabled
                        }
                    }
                    .disabled(
                        proxyManager.managedContinuityLockActive
                            || proxyManager.configurationMutationLocked
                    )
                if let issue = proxyManager.cliCaptureHealthIssue {
                    Label(issue, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            } header: {
                Text("CLI capture")
            } footer: {
                Text(proxyManager.managedContinuityLockActive
                    ? "CLI capture is required while your organization prevents protection from being disabled. Bouclier supplies `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` through shell startup files and the launchctl session, but preserves a custom value already set by you or your organization. Only processes that use Bouclier's values are inspected — an app with its own backend or a hard-coded base URL is not."
                    : "Bouclier supplies `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` through your shell startup files and the launchctl session so compatible command-line AI tools route through the gateway. A custom value already set by you or your organization is preserved and continues to bypass Bouclier. Apps with their own backend (for example Cursor's agent) or a hard-coded base URL are not inspected.")
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
                Button(mcpCommandCopied ? "Copied" : "Copy Claude Code MCP status command") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(
                        CLIInstaller.mcpRegistrationCommand(),
                        forType: .string
                    )
                    mcpCommandCopied = true
                }
            } header: {
                Text("Agent command-line access")
            } footer: {
                Text("Puts `bouclier` on PATH (macOS will ask you to approve it — same as any app installing a helper tool) so Bash-driven agents can call `bouclier status` directly. The MCP command registers one read-only `bouclier_status` tool with Claude Code; it cannot change settings or read request content.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section("Notifications") {
                Toggle("Show block notifications", isOn: $showNotifications)
                    .onChange(of: showNotifications) { _, enabled in
                        if enabled { proxyManager.requestBlockNotificationAuthorizationIfNeeded() }
                    }
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
                Text("When a request is blocked, save the offending untrusted span, the per-signal breakdown, and the passage the on-device classifier reacted to most — to a local file (block-samples.jsonl) so you can see why it blocked and tune. This is the only setting that records request content; it stays on this Mac unless you choose to report a specific block as a false positive, which sends a redacted copy — after you review exactly what's sent. Off by default.")
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
                    Text("Clears the menu-bar counters (requests inspected / detector-blocked requests). The audit log and on-disk stats are untouched.")
                }
            } header: {
                Text("Diagnostics")
            } footer: {
                Text("Resets are local to this session — the audit database keeps the history.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section {
                Button("Reset HTTP/HTTPS & PAC…", role: .destructive) {
                    showResetProxiesConfirm = true
                }
                .disabled(
                    proxyManager.configurationMutationLocked
                        || (proxyManager.protectionActive && ManagedConfig.preventDisable)
                )
                .help(proxyManager.configurationMutationLocked
                      ? "Configuration cleanup is already in progress"
                      : (proxyManager.protectionActive && ManagedConfig.preventDisable
                         ? "Disabling protection is prevented by your organization"
                         : ""))
                .confirmationDialog(
                    "Reset HTTP/HTTPS and PAC settings?",
                    isPresented: $showResetProxiesConfirm,
                    titleVisibility: .visible
                ) {
                    Button("Reset Web Proxies", role: .destructive) {
                        Task { await proxyManager.resetAllProxies() }
                    }
                    Button("Cancel", role: .cancel) {}
                } message: {
                    Text("This recovery action turns off automatic PAC configuration and manual HTTP/HTTPS web proxies on every macOS network service — including corporate or personal settings Bouclier did not create. SOCKS, FTP, and proxy auto-discovery/WPAD settings are not changed. It also removes Bouclier's session routing, watchdog, shell blocks, and retired certificate/extension state. You may need to reconfigure unrelated web proxies afterward. Any step that cannot be verified is reported so you can retry safely.")
                }
                if proxyManager.configurationCleanupInProgress {
                    ProgressView("Cleaning Bouclier configuration…")
                        .font(.caption)
                }
                if proxyManager.legacyMigrationInProgress,
                   proxyManager.migrationCleanupNotice == nil
                {
                    ProgressView("Checking retired Bouclier configuration…")
                        .font(.caption)
                }
                if let notice = proxyManager.configurationCleanupNotice {
                    ConfigurationNoticeView(notice: notice)
                }
                if let notice = proxyManager.migrationCleanupNotice {
                    ConfigurationNoticeView(notice: notice)
                }
            } header: {
                Text("Proxy recovery")
            } footer: {
                Text("Use this if an unclean shutdown left CLI tools or HTTP/HTTPS traffic unable to reach LLM APIs. Open a new terminal afterwards so it picks up the cleared shell env.")
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
    @AppStorage("injectionBlockEnabled") private var userBlockingEnabled = false
    @State private var showConfigurationRemovalConfirm = false
    /// Bumped to force a re-read of the (UserDefaults-backed) allowlist
    /// count after the operator re-arms it.
    @State private var allowlistRefresh = 0

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
            Text("How Protection Works")
                .font(.headline)
            Text("Routes compatible agents through a local gateway via ANTHROPIC_BASE_URL / OPENAI_BASE_URL — no certificate to install. Untrusted tool output is inspected on-device; findings are either monitored or blocked according to the action below. Within the hard 64 MiB transport cap, supported bodies are fully inspected up to 8 MiB; larger bodies receive a bounded 24-window sample. Model-visible request-body bytes are forwarded unchanged or refused; proxy framing headers are normalized.")
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
                StatusRow(
                    label: "Patterns",
                    active: proxyManager.patternTierHealthy,
                    detail: proxyManager.patternTierHealthy
                        ? "\(proxyManager.patternCount) loaded"
                        : "\(proxyManager.patternCount) emergency patterns only — reinstall"
                )
                StatusRow(
                    label: "On-device ML",
                    active: proxyManager.mlTierActive,
                    detail: proxyManager.mlTierActive
                        ? "Prompt Guard 2 active"
                        : (proxyManager.mlTierUnavailable ? "Unavailable — pattern tier only" : "Loading…")
                )
            }
            .font(.callout)

            Divider()

            Text("When Suspicious Content Is Found")
                .font(.headline)
            Picker("Finding action", selection: blockingBinding) {
                Text("Monitor").tag(false)
                Text("Block").tag(true)
            }
            .pickerStyle(.segmented)
            .disabled(
                managedBlockingEnabled != nil
                    || proxyManager.configurationMutationLocked
            )
            .help(findingActionHelp)

            HStack(alignment: .top, spacing: 8) {
                Image(systemName: findingActionIcon)
                    .foregroundStyle(findingActionTint)
                Text(findingActionDescription)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            if proxyManager.isRunning {
                Divider()
                Text("CLI Tools")
                    .font(.headline)
                HStack(spacing: 8) {
                    Image(systemName: proxyManager.cliCaptureHealthy ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                        .foregroundStyle(proxyManager.cliCaptureHealthy ? .green : .orange)
                        .font(.callout)
                    Text(proxyManager.cliCaptureHealthIssue
                         ?? (ShellEnvInjector.isEnabled
                         ? "Automatic base-URL setup is installed. Open a new terminal; compatible tools route through the gateway unless their environment already supplies a custom ANTHROPIC_BASE_URL or OPENAI_BASE_URL, which Bouclier preserves."
                         : "CLI capture is off — Settings → General to re-enable."))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }

            if ManagedConfig.isManaged {
                Divider()
                HStack(spacing: 6) {
                    Image(systemName: "building.2")
                        .foregroundStyle(.blue)
                    Text("Your organization manages some settings. Managed finding actions apply after protection is enabled; the profile does not activate capture by itself.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            HStack {
                if proxyManager.protectionActive {
                    Label(protectionStatusText, systemImage: protectionStatusIcon)
                        .foregroundStyle(protectionState == .operational ? Color.green : Color.orange)
                        .font(.callout)
                    Spacer()
                    Button("Disable", role: .destructive) { proxyManager.disableStandard() }
                        .help("Traffic keeps flowing through the gateway, uninspected — active agent sessions are not interrupted")
                        .disabled(
                            ManagedConfig.preventDisable
                                || proxyManager.configurationMutationLocked
                        )
                } else {
                    if proxyManager.isRunning {
                        Label("Passthrough — protection off", systemImage: "shield.slash")
                            .foregroundStyle(.secondary)
                            .font(.callout)
                        Spacer()
                    }
                    Button("Enable Protection") { proxyManager.enableStandard() }
                        .buttonStyle(.borderedProminent)
                        .disabled(proxyManager.configurationMutationLocked)
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
                    .disabled(proxyManager.configurationMutationLocked)
                }
            }

            Button("Remove Bouclier Configuration…", role: .destructive) {
                showConfigurationRemovalConfirm = true
            }
            .buttonStyle(.link)
            .disabled(configurationRemovalDisabled)
            .help(configurationRemovalHelp)
            .alert("Remove Bouclier configuration?", isPresented: $showConfigurationRemovalConfirm) {
                Button("Cancel", role: .cancel) {}
                Button("Remove Configuration", role: .destructive) {
                    Task { await proxyManager.removeConfiguration() }
                }
            } message: {
                Text("Bouclier will stop the gateway, turn off launch at login, and attempt to remove its shell, narrowly owned legacy PAC URL, certificate, and retired extension configuration. Unrelated manual or corporate proxies remain unchanged. The app and audit history remain. Any step that cannot be verified is reported so you can retry safely.")
            }
            if proxyManager.configurationCleanupInProgress {
                ProgressView("Removing Bouclier configuration…")
                    .font(.caption)
            }
            if proxyManager.legacyMigrationInProgress,
               proxyManager.migrationCleanupNotice == nil
            {
                ProgressView("Checking retired Bouclier configuration…")
                    .font(.caption)
            }
            if let notice = proxyManager.configurationCleanupNotice {
                ConfigurationNoticeView(notice: notice)
            }
            if let notice = proxyManager.migrationCleanupNotice {
                ConfigurationNoticeView(notice: notice)
            }
            }
            .padding()
        }
    }

    private var managedBlockingEnabled: Bool? {
        FeatureFlags.managedInjectionBlock
    }

    private var configurationRemovalDisabled: Bool {
        proxyManager.configurationMutationLocked
            || ManagedConfig.preventConfigurationRemoval
            || (ManagedConfig.preventDisable && proxyManager.protectionActive)
    }

    private var configurationRemovalHelp: String {
        if proxyManager.configurationMutationLocked {
            return "Configuration cleanup is already in progress"
        }
        if ManagedConfig.preventConfigurationRemoval {
            return "Configuration removal is disabled by your organization"
        }
        if ManagedConfig.preventDisable && proxyManager.protectionActive {
            return "Disable protection is locked by your organization"
        }
        return ""
    }

    private var blockingEnabled: Bool {
        managedBlockingEnabled ?? userBlockingEnabled
    }

    private var detectorDisabledByPolicy: Bool {
        proxyManager.protectionActive && !proxyManager.detectorEnabled
    }

    private var findingActionIcon: String {
        switch protectionState {
        case .operational:
            return blockingEnabled ? "hand.raised.fill" : "eye.fill"
        case .requested, .degraded:
            return "exclamationmark.shield.fill"
        case .off:
            return "slider.horizontal.3"
        }
    }

    private var findingActionTint: Color {
        switch protectionState {
        case .operational:
            return blockingEnabled ? .orange : .blue
        case .requested, .degraded:
            return .orange
        case .off:
            return .secondary
        }
    }

    private var findingActionDescription: String {
        protectionState.findingActionDescription(
            blockingEnabled: blockingEnabled,
            detectorDisabledByPolicy: detectorDisabledByPolicy
        )
    }

    private var findingActionHelp: String {
        if managedBlockingEnabled != nil {
            return "This setting is managed by your organization"
        }
        if proxyManager.configurationMutationLocked {
            return "Configuration cleanup is in progress"
        }
        return protectionState == .operational
            ? "Applies immediately; no restart required"
            : "Saves this action; it applies when protection is operational"
    }

    private var protectionState: DesktopProtectionState {
        .resolve(
            protectionActive: proxyManager.protectionActive,
            gatewayRunning: proxyManager.isRunning,
            detectionEngineDegraded: proxyManager.detectionEngineDegraded
        )
    }

    private var protectionStatusText: String {
        switch protectionState {
        case .operational:
            return "Protection active for routed traffic"
        case .degraded:
            return "Protection degraded for routed traffic"
        case .requested:
            return "Protection requested — gateway not running"
        case .off:
            return "Protection off"
        }
    }

    private var protectionStatusIcon: String {
        protectionState == .operational
            ? "checkmark.shield.fill"
            : "exclamationmark.shield.fill"
    }

    private var blockingBinding: Binding<Bool> {
        Binding(
            get: { blockingEnabled },
            set: { value in
                guard managedBlockingEnabled == nil,
                      !proxyManager.configurationMutationLocked
                else { return }
                userBlockingEnabled = value
                if value { proxyManager.requestBlockNotificationAuthorizationIfNeeded() }
            }
        )
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

            Text("Built with Llama · Meta Prompt Guard 2 runs on-device")
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Text("Version \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—")")
                .font(.caption)
                .foregroundStyle(.tertiary)

            Button("Check for Updates...") { updater.checkForUpdates() }
                .disabled(!updater.canCheckForUpdates)

            Divider().frame(width: 200)

            // Safety disclaimer mirroring the website Terms without narrowing
            // the rights granted by the project's open-source licences.
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.caption)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Experimental, pre-1.0 software")
                        .font(.caption.weight(.semibold))
                    Text("Detection is best-effort. Validate it for your risks and use defence in depth.")
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
                if let noticeURL = Bundle.main.url(
                    forResource: "THIRD-PARTY-NOTICES",
                    withExtension: "txt",
                    subdirectory: "LICENSES"
                ) {
                    Button("Licenses & notices") {
                        NSWorkspace.shared.open(noticeURL.deletingLastPathComponent())
                    }
                        .buttonStyle(.link)
                }
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
