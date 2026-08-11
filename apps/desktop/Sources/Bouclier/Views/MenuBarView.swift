import SwiftUI

/// The menu-bar panel. Designed to answer one question in under a second —
/// "is my AI traffic protected?" — with a calm hero + master switch, then
/// surface the firewall status and a glanceable activity line.
/// Configuration and diagnostics live in Settings, not here.
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
            firewallSection

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
        .animation(.easeInOut(duration: 0.2), value: proxyManager.protectionActive)
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
                .help(proxyManager.protectionActive
                    ? "Pause protection (traffic keeps flowing, uninspected)"
                    : "Turn on protection")
                .accessibilityLabel("Protection")
        }
    }

    /// On = enable protection; off = pause. Keys off `protectionActive`,
    /// not `isRunning` — pausing leaves the gateway relaying (passthrough)
    /// so active agent sessions keep working, and the switch must reflect
    /// the protection state, not the listener.
    private var protectionBinding: Binding<Bool> {
        Binding(
            get: { proxyManager.protectionActive },
            set: { on in
                if on { proxyManager.enableStandard() } else { proxyManager.disableStandard() }
            }
        )
    }

    private var heroIcon: String {
        if proxyManager.errorMessage != nil { return "exclamationmark.shield.fill" }
        return proxyManager.protectionActive ? "checkmark.shield.fill" : "shield.slash"
    }

    private var heroTint: Color {
        if proxyManager.errorMessage != nil { return .red }
        return proxyManager.protectionActive ? .green : .secondary
    }

    private var heroTitle: String {
        if proxyManager.errorMessage != nil { return "Needs attention" }
        return proxyManager.protectionActive ? "Protected" : "Off"
    }

    private var heroSubtitle: String {
        if proxyManager.errorMessage != nil { return "Protection couldn't start — see below." }
        if proxyManager.protectionActive {
            return "Your AI traffic is inspected for prompt injection in untrusted tool output."
        }
        return proxyManager.isRunning
            ? "Passthrough: traffic flows uninspected so active sessions keep working. Turn on to inspect."
            : "Turn on to inspect your AI traffic for prompt injection."
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

    // MARK: - Firewall

    private var firewallSection: some View {
        Button(action: { openSettingsWindow() }) {
            HStack(spacing: 12) {
                Image(systemName: "shield.lefthalf.filled")
                    .foregroundStyle(.secondary)
                    .frame(width: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Injection firewall").font(.subheadline.weight(.semibold))
                    Text(firewallSubtitle).font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Image(systemName: "chevron.right").font(.caption2).foregroundStyle(.tertiary)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    private var firewallSubtitle: String {
        let n = proxyManager.patternCount
        guard n > 0 else { return "Loading detection patterns…" }
        let mode = FeatureFlags.injectionBlock ? "enforcing" : "monitoring"
        let ml = proxyManager.mlTierActive ? " + ML" : ""
        return "\(n) patterns\(ml) · \(mode)"
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
                            // Recover a false positive without waiting for
                            // the notification: release this exact span so
                            // the gateway forwards it on the next resume.
                            if let fp = entry.spanFingerprint, !fp.isEmpty {
                                Button("Unblock") { proxyManager.allowlistSpan(fp) }
                                    .font(.caption2)
                                    .buttonStyle(.link)
                                    .help("Forward this flagged content from now on (re-arm in Settings)")
                            }
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
        let blocked = proxyManager.stats.injectionsBlocked
        let base = "\(n) request\(n == 1 ? "" : "s") inspected"
        return blocked > 0 ? "\(base) · \(blocked) blocked" : "\(base) · all clear"
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

