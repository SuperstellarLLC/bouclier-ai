import SwiftUI

/// The menu-bar panel. Designed to answer one question in under a second —
/// "is my AI traffic protected?" — with a calm hero + master switch, then
/// surface the headline feature (Secret Keeper) and a glanceable activity
/// line. Configuration and diagnostics live in Settings, not here.
struct MenuBarView: View {
    @ObservedObject var proxyManager: ProxyManager
    @ObservedObject var updater: AutoUpdater
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            hero

            if let error = proxyManager.errorMessage {
                errorBanner(error).padding(.top, 10)
            }

            sectionDivider
            secretKeeperSection

            if proxyManager.isRunning {
                sectionDivider
                activitySection
            }

            sectionDivider
            footer
        }
        .padding(12)
        .frame(width: 320)
        .animation(.easeInOut(duration: 0.2), value: proxyManager.isRunning)
        .animation(.easeInOut(duration: 0.2), value: proxyManager.errorMessage)
        .animation(.easeInOut(duration: 0.2), value: proxyManager.logs.first?.id)
    }

    private var sectionDivider: some View {
        Divider().padding(.vertical, 10)
    }

    // MARK: - Hero

    private var hero: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: heroIcon)
                .font(.system(size: 26))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(heroTint)
                .contentTransition(.symbolEffect(.replace))
                .frame(width: 30)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(heroTitle)
                        .font(.headline)
                        .contentTransition(.opacity)
                    Text("BETA")
                        .font(.system(size: 9, weight: .semibold))
                        .tracking(0.5)
                        .padding(.horizontal, 5).padding(.vertical, 2)
                        .background(Color.orange.opacity(0.15), in: RoundedRectangle(cornerRadius: 4))
                        .foregroundStyle(.orange)
                        .accessibilityHidden(true)
                }
                Text(heroSubtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 8)

            Toggle("", isOn: protectionBinding)
                .toggleStyle(.switch)
                .labelsHidden()
                .help(proxyManager.isRunning ? "Pause protection" : "Turn on protection")
                .accessibilityLabel("Protection")
        }
    }

    /// On = enable via the configured mode; off = pause. Hides all the
    /// mode/CA branching behind one switch.
    private var protectionBinding: Binding<Bool> {
        Binding(
            get: { proxyManager.isRunning },
            set: { on in
                if on {
                    switch ProxyMode.current {
                    case .standard: proxyManager.enableStandard()
                    case .extreme: proxyManager.caInstalled ? proxyManager.start() : proxyManager.setup()
                    }
                } else {
                    if ProxyMode.current == .standard { proxyManager.disableStandard() } else { proxyManager.stop() }
                }
            }
        )
    }

    private var heroIcon: String {
        if proxyManager.errorMessage != nil { return "exclamationmark.shield.fill" }
        return proxyManager.isRunning ? "checkmark.shield.fill" : "shield.slash"
    }

    private var heroTint: Color {
        if proxyManager.errorMessage != nil { return .red }
        return proxyManager.isRunning ? .green : .secondary
    }

    private var heroTitle: String {
        if proxyManager.errorMessage != nil { return "Needs attention" }
        return proxyManager.isRunning ? "Protected" : "Off"
    }

    private var heroSubtitle: String {
        if proxyManager.errorMessage != nil { return "Protection couldn't start — see below." }
        return proxyManager.isRunning
            ? "Your AI traffic is protected. Agents use your secrets without ever seeing them."
            : "Turn on to protect your AI traffic and secrets."
    }

    private func errorBanner(_ error: String) -> some View {
        HStack(alignment: .top, spacing: 6) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red).font(.caption)
            Text(error).font(.caption2).foregroundStyle(.red)
            Spacer(minLength: 0)
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.red.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
        .accessibilityElement(children: .combine)
    }

    // MARK: - Secret Keeper (the headline feature)

    private var secretKeeperSection: some View {
        Button(action: { openSettingsWindow() }) {
            HStack(spacing: 12) {
                Image(systemName: "key.fill")
                    .foregroundStyle(.secondary)
                    .frame(width: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Secret Keeper").font(.subheadline.weight(.semibold))
                    Text(secretKeeperSubtitle).font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                if agentSecretCount > 0 {
                    Text("\(agentSecretCount)")
                        .font(.caption.weight(.semibold).monospacedDigit())
                        .padding(.horizontal, 7).padding(.vertical, 2)
                        .background(Color.secondary.opacity(0.15), in: Capsule())
                }
                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var secretKeeperSubtitle: String {
        agentSecretCount > 0
            ? "\(agentSecretCount) secret\(agentSecretCount == 1 ? "" : "s") ready for your agent to use"
            : "Add a secret so your agent can use it without seeing it"
    }

    private var agentSecretCount: Int {
        SecretStore.shared.rules().filter { $0.agentAccess }.count
    }

    // MARK: - Activity

    @ViewBuilder
    private var activitySection: some View {
        let recents = Array(proxyManager.logs.prefix(3))
        Text("Activity").font(.caption.weight(.semibold)).foregroundStyle(.secondary)

        if proxyManager.stats.requestsScanned == 0 && recents.isEmpty {
            HStack(spacing: 6) {
                Image(systemName: "checkmark.circle").font(.caption).foregroundStyle(.secondary)
                Text("Watching your AI traffic — nothing to report yet.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(.top, 4)
        } else {
            Text(activitySummary).font(.callout).padding(.top, 2)
            if !recents.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(recents) { entry in
                        HStack(alignment: .top, spacing: 6) {
                            Text(relativeTime(entry.timestamp))
                                .font(.caption2.monospacedDigit())
                                .foregroundStyle(.tertiary)
                                .frame(width: 26, alignment: .leading)
                            if entry.blocked {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .font(.caption2).foregroundStyle(.orange)
                            }
                            Text(entry.message)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Spacer(minLength: 0)
                        }
                    }
                }
                .padding(.top, 6)
                MenuActionRow(title: "See all activity", systemImage: "list.bullet.rectangle") { openLogFile() }
                    .padding(.top, 2)
            }
        }
    }

    private var activitySummary: String {
        let n = proxyManager.stats.requestsScanned
        let threats = proxyManager.stats.injectionsBlocked + proxyManager.stats.secretsBlocked
        let base = "\(n) request\(n == 1 ? "" : "s") inspected"
        return threats > 0 ? "\(base) · \(threats) blocked" : "\(base) · all clear"
    }

    private func relativeTime(_ date: Date) -> String {
        let s = Int(max(0, Date().timeIntervalSince(date)))
        if s < 60 { return "now" }
        if s < 3600 { return "\(s / 60)m" }
        if s < 86400 { return "\(s / 3600)h" }
        return "\(s / 86400)d"
    }

    // MARK: - Footer

    private var footer: some View {
        VStack(alignment: .leading, spacing: 1) {
            MenuActionRow(title: "Settings…", systemImage: "gear", shortcut: ",") { openSettingsWindow() }
            MenuActionRow(title: "Check for Updates…", systemImage: "arrow.triangle.2.circlepath",
                          disabled: !updater.canCheckForUpdates) { updater.checkForUpdates() }
            MenuActionRow(title: "Export Diagnostics…", systemImage: "square.and.arrow.up") { exportDiagnostics() }
            MenuActionRow(title: "Quit Bouclier.ai", systemImage: "power", shortcut: "q") {
                proxyManager.stop()
                NSApplication.shared.terminate(nil)
            }
            HStack {
                Spacer()
                Button(action: { if updater.canCheckForUpdates { updater.checkForUpdates() } }) {
                    Text("v\(appVersion)").font(.caption2).foregroundStyle(.tertiary)
                }
                .buttonStyle(.plain)
                .disabled(!updater.canCheckForUpdates)
                .help(updater.canCheckForUpdates ? "Check for updates" : "Version \(appVersion)")
            }
            .padding(.top, 4)
        }
    }

    // MARK: - Actions

    private func openSettingsWindow() {
        NSApp.activate(ignoringOtherApps: true)
        openSettings()
    }

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
    }

    private func exportDiagnostics() {
        Task { @MainActor in
            let snapshot = await Metrics.shared.snapshot()
            let storage = try? StorageManager()
            let daily = storage?.statsHistory(days: 30) ?? []
            let logs = storage?.recentLogs(limit: 200) ?? []
            let bundle = DiagnosticsExport.buildBundle(
                metricsSnapshot: snapshot,
                dailyStats: daily,
                recentLogs: logs,
                patternsLoaded: proxyManager.patternsLoadedCount,
                patternsSHA256Prefix: proxyManager.patternsSHA256Prefix,
                allowedHosts: SystemProxy.interceptedDomains
            )

            let panel = NSSavePanel()
            panel.allowedContentTypes = [.json]
            let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
            panel.nameFieldStringValue = "bouclier-ai-diagnostics-\(stamp).json"
            panel.title = "Save Diagnostics Bundle"
            panel.message = "Contains scan metrics, pattern hit counts, and 30 days of aggregated stats. No request bodies or URLs."

            NSApp.activate(ignoringOtherApps: true)
            guard panel.runModal() == .OK, let url = panel.url else { return }
            do {
                let data = try DiagnosticsExport.encode(bundle)
                try data.write(to: url, options: .atomic)
                NSWorkspace.shared.selectFile(url.path, inFileViewerRootedAtPath: url.deletingLastPathComponent().path)
            } catch {
                let alert = NSAlert()
                alert.messageText = "Could not save diagnostics bundle"
                alert.informativeText = error.localizedDescription
                alert.runModal()
            }
        }
    }

    private func openLogFile() {
        let logDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first!.appendingPathComponent("ai.bouclier.app", isDirectory: true)
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)
        let logFile = logDir.appendingPathComponent("bouclier-ai.log")
        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd HH:mm:ss"
        var content = "BOUCLIER.AI ACTIVITY LOG\nGenerated: \(df.string(from: Date()))\n"
        content += String(repeating: "=", count: 80) + "\n\n"
        for entry in proxyManager.logs {
            content += "[\(df.string(from: entry.timestamp))] [\(entry.blocked ? "BLOCKED" : "OK")] \(entry.message)\n"
        }
        try? content.write(to: logFile, atomically: true, encoding: .utf8)
        NSWorkspace.shared.open(logFile)
    }
}

// MARK: - Reusable hoverable action row

struct MenuActionRow: View {
    let title: String
    let systemImage: String
    var disabled: Bool = false
    var shortcut: KeyEquivalent? = nil
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                Image(systemName: systemImage).frame(width: 18).foregroundStyle(.secondary)
                Text(title)
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 8).padding(.vertical, 5)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(hovering && !disabled ? Color.primary.opacity(0.06) : .clear,
                        in: RoundedRectangle(cornerRadius: 6))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .onHover { hovering = $0 }
        .modifier(OptionalShortcut(key: shortcut))
    }
}

private struct OptionalShortcut: ViewModifier {
    let key: KeyEquivalent?
    func body(content: Content) -> some View {
        if let key { content.keyboardShortcut(key) } else { content }
    }
}

// MARK: - Detection status (relocated from the menu into Settings → Protection)

/// On-device ML detection status + the synthetic self-test. This is
/// diagnostics, not daily status — it belongs in Settings, and only applies
/// in extreme mode where injection filtering actually runs.
struct DetectionStatusView: View {
    @ObservedObject var proxyManager: ProxyManager
    @State private var mlErrorCopied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button(action: copyMLError) {
                HStack(spacing: 6) {
                    Image(systemName: mlIcon)
                        .foregroundStyle(mlColor)
                        .contentTransition(.symbolEffect(.replace))
                    Text(mlText).foregroundStyle(.secondary)
                    Spacer()
                    if proxyManager.mlClassifierError != nil {
                        Image(systemName: mlErrorCopied ? "checkmark" : "doc.on.doc")
                            .foregroundStyle(.tertiary)
                    }
                }
                .font(.callout)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .disabled(proxyManager.mlClassifierError == nil)
            .help(proxyManager.mlClassifierError ?? "")

            HStack(spacing: 10) {
                Button("Run detection test") { proxyManager.runSelfTest() }
                if let result = proxyManager.selfTestResult {
                    SelfTestBanner(result: result)
                        .transition(.opacity.combined(with: .move(edge: .leading)))
                }
            }
            .animation(.easeInOut(duration: 0.25), value: proxyManager.selfTestResult)
        }
    }

    private var mlIcon: String {
        if proxyManager.mlClassifierActive { return "brain.head.profile.fill" }
        if proxyManager.mlClassifierError != nil { return "exclamationmark.brain" }
        return "brain.head.profile"
    }

    private var mlColor: Color {
        if proxyManager.mlClassifierActive { return .purple }
        if proxyManager.mlClassifierError != nil { return .orange }
        return .gray
    }

    private var mlText: String {
        if proxyManager.mlClassifierActive { return "Advanced on-device detection active" }
        if proxyManager.mlClassifierError != nil { return "Basic detection — on-device model unavailable" }
        return "Basic detection (advanced model loading…)"
    }

    private func copyMLError() {
        guard let error = proxyManager.mlClassifierError else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(error, forType: .string)
        mlErrorCopied = true
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(1.5))
            mlErrorCopied = false
        }
    }
}

/// Transient banner surfaced after "Run detection test".
struct SelfTestBanner: View {
    let result: SelfTestResult

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: result.passed ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                .foregroundStyle(result.passed ? .green : .red)
                .font(.callout)
            VStack(alignment: .leading, spacing: 1) {
                Text(result.headline)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(result.passed ? .green : .red)
                Text(result.detail)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
    }
}
