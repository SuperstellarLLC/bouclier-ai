import SwiftUI

/// Separates the user's persisted protection intent from an operational
/// listener. Shared by the menu and Settings so neither surface can describe
/// a merely requested state as active protection.
enum DesktopProtectionState: Equatable {
    case off(gatewayRunning: Bool)
    case requested
    case degraded
    case operational

    static func resolve(
        protectionActive: Bool,
        gatewayRunning: Bool,
        detectionEngineDegraded: Bool
    ) -> Self {
        guard protectionActive else { return .off(gatewayRunning: gatewayRunning) }
        guard gatewayRunning else { return .requested }
        return detectionEngineDegraded ? .degraded : .operational
    }

    /// Explain the selected finding action without presenting configuration as
    /// live enforcement. Only an operational gateway may use present-tense
    /// Monitoring/Blocking copy; every other state says what is selected and
    /// why it is not currently an operational action.
    func findingActionDescription(
        blockingEnabled: Bool,
        detectorDisabledByPolicy: Bool
    ) -> String {
        let selectedAction = blockingEnabled ? "Block" : "Monitor"

        switch self {
        case .off(let gatewayRunning):
            if gatewayRunning {
                return "\(selectedAction) is selected, but protection is off. The gateway is in passthrough, so routed traffic is relayed without inspection and no finding action is currently applied."
            }
            return "\(selectedAction) is selected, but protection is off and the gateway is stopped. No finding action is currently applied."
        case .requested:
            return "\(selectedAction) is selected, but the gateway is not listening yet. Traffic is not protected, and the finding action will not apply until startup completes."
        case .degraded:
            if detectorDisabledByPolicy {
                return "Injection detection is disabled by managed policy. Routed traffic is relayed without injection inspection, so the selected finding action is not currently applied."
            }
            return "\(selectedAction) is selected, but protection is degraded. Review Protection Status before relying on this finding action."
        case .operational:
            return blockingEnabled
                ? "Blocking: Bouclier refuses detector findings and encoded bodies it cannot safely inspect. Supported bodies are fully inspected up to 8 MiB; larger bodies receive a bounded 24-window sample, so a clean or inconclusive sample is forwarded with a partial-coverage notice. A fingerprinted detector finding can use Unblock; encoded bodies require Monitoring or an uncompressed request. The hard 64 MiB transport cap applies in either mode."
                : "Monitoring: Bouclier records suspicious content, but allows model-visible request-body content through unchanged. Your work cannot be interrupted by a detection."
        }
    }
}

/// Pure presentation seam for the always-visible menu-bar item. Keeping this
/// next to `DesktopProtectionState` prevents the compact icon from drifting
/// from the more detailed panel and makes the complete state table testable.
struct DesktopMenuBarPresentation: Equatable {
    let iconName: String
    let accessibilityLabel: String

    static func resolve(
        state: DesktopProtectionState,
        blockingEnabled: Bool,
        errorMessage: String?
    ) -> Self {
        if let errorMessage {
            return Self(
                iconName: "exclamationmark.shield.fill",
                accessibilityLabel: "Bouclier.ai — needs attention: \(errorMessage)"
            )
        }

        switch state {
        case .off(let gatewayRunning):
            return Self(
                iconName: "shield.slash",
                accessibilityLabel: gatewayRunning
                    ? "Bouclier.ai — protection off, gateway passthrough"
                    : "Bouclier.ai — protection off"
            )
        case .requested:
            return Self(
                iconName: "exclamationmark.shield.fill",
                accessibilityLabel: "Bouclier.ai — protection requested but gateway is not running"
            )
        case .degraded:
            return Self(
                iconName: "exclamationmark.shield.fill",
                accessibilityLabel: "Bouclier.ai — protection degraded; open Bouclier for details"
            )
        case .operational:
            return Self(
                iconName: blockingEnabled ? "checkmark.shield.fill" : "eye.fill",
                accessibilityLabel: blockingEnabled
                    ? "Bouclier.ai — blocking suspicious requests"
                    : "Bouclier.ai — monitoring suspicious requests"
            )
        }
    }
}

/// The menu-bar panel. Designed to answer one question in under a second —
/// "is my AI traffic protected?" — with a calm hero + master switch, then
/// surface the firewall status and a glanceable activity line.
/// Configuration and diagnostics live in Settings, not here.
struct MenuBarView: View {
    @ObservedObject var proxyManager: ProxyManager
    @ObservedObject var updater: AutoUpdater
    @AppStorage("injectionBlockEnabled") private var userBlockingEnabled = false
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
                    ? (ManagedConfig.preventDisable
                       ? "Disabling protection is prevented by your organization"
                       : (proxyManager.configurationMutationLocked
                          ? "Configuration cleanup is in progress"
                          : "Pause protection (traffic keeps flowing, uninspected)"))
                    : (proxyManager.configurationMutationLocked
                       ? "Configuration cleanup is in progress"
                       : "Turn on protection"))
                .accessibilityLabel("Protection")
                .disabled(
                    proxyManager.configurationMutationLocked
                        || (proxyManager.protectionActive && ManagedConfig.preventDisable)
                )
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
                guard !proxyManager.configurationMutationLocked else { return }
                if on { proxyManager.enableStandard() } else { proxyManager.disableStandard() }
            }
        )
    }

    private var heroIcon: String {
        DesktopMenuBarPresentation.resolve(
            state: protectionState,
            blockingEnabled: blockingEnabled,
            errorMessage: proxyManager.errorMessage
        ).iconName
    }

    private var heroTint: Color {
        if proxyManager.errorMessage != nil { return .red }
        switch protectionState {
        case .requested, .degraded:
            return .orange
        case .off:
            return .secondary
        case .operational:
            return blockingEnabled ? .green : .blue
        }
    }

    private var heroTitle: String {
        if proxyManager.errorMessage != nil { return "Needs attention" }
        switch protectionState {
        case .off:
            return "Off"
        case .requested:
            return "Protection requested"
        case .degraded:
            return "Degraded"
        case .operational:
            return blockingEnabled ? "Blocking" : "Monitoring"
        }
    }

    private var heroSubtitle: String {
        if proxyManager.errorMessage != nil { return "An operation needs attention — see details below." }
        switch protectionState {
        case .requested:
            return "The gateway is not listening yet. Traffic is not protected until startup completes."
        case .degraded:
            if !proxyManager.detectorEnabled {
                return "Injection detection is disabled by managed policy; routed traffic is relayed without injection inspection."
            }
            if !proxyManager.patternTierHealthy {
                return "Only \(proxyManager.patternCount) emergency patterns loaded; reinstall before relying on protection."
            }
            if proxyManager.mlTierUnavailable {
                return "The pattern tier is active, but on-device ML failed to load; reinstall or check Logs."
            }
            return "The detection engine is degraded; review Logs before relying on protection."
        case .operational:
            return blockingEnabled
                ? "Routed detector findings are refused; between 8 MiB and the hard 64 MiB cap, only 24 windows are sampled and a clean or inconclusive sample passes."
                : "Routed findings are logged, but model-visible request-body content is allowed through unchanged."
        case .off(let gatewayRunning):
            return gatewayRunning
                ? "Passthrough: traffic flows uninspected so active sessions keep working. Turn on to inspect."
                : "Turn on to inspect your AI traffic for prompt injection."
        }
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
        switch protectionState {
        case .off(let gatewayRunning):
            return gatewayRunning
                ? "Gateway passthrough · protection off"
                : "Protection off"
        case .requested:
            return "Gateway starting · protection not active"
        case .degraded:
            guard n > 0 else { return "Detection unavailable · protection degraded" }
            if !proxyManager.patternTierHealthy {
                return "\(n) emergency patterns only · protection degraded"
            }
            let ml = proxyManager.mlTierUnavailable ? " · ML unavailable" : ""
            return "\(n) patterns\(ml) · protection degraded"
        case .operational:
            break
        }
        guard n > 0 else { return "Loading detection patterns…" }
        let mode = blockingEnabled ? "blocking" : "monitoring"
        let ml = proxyManager.mlTierActive
            ? " + ML"
            : (proxyManager.mlTierUnavailable ? " · ML unavailable" : " · ML loading")
        return "\(n) patterns\(ml) · \(mode)"
    }

    // MARK: - Activity

    @ViewBuilder
    private var activitySection: some View {
        let recents = Array(proxyManager.logs.prefix(3))
        Text("Activity").font(.caption.weight(.semibold)).foregroundStyle(.secondary)

        if case .off = protectionState {
            HStack(spacing: 6) {
                Image(systemName: "shield.slash").font(.caption).foregroundStyle(.secondary)
                Text("Gateway passthrough — current traffic is not inspected.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(.top, 4)
        } else if !proxyManager.detectorEnabled {
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.shield.fill").font(.caption).foregroundStyle(.orange)
                Text("Injection detection is disabled by managed policy — current traffic is not inspected.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .padding(.top, 4)
        } else if proxyManager.stats.requestsScanned == 0,
           proxyManager.stats.requestsSkippedInspection == 0,
           proxyManager.stats.injectionFindingsFlagged == 0,
           proxyManager.stats.injectionsBlocked == 0,
           proxyManager.stats.requestsBlockedByInspectionLimit == 0,
           recents.isEmpty {
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
                                Button("Report") { proxyManager.reportFalsePositive(fingerprint: fp) }
                                    .font(.caption2)
                                    .buttonStyle(.link)
                                    .help("Report this as a false positive — you'll review exactly what's sent before it leaves your Mac")
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
        let limitBlocked = proxyManager.stats.requestsBlockedByInspectionLimit
        let flagged = proxyManager.stats.injectionFindingsFlagged
        let skipped = proxyManager.stats.requestsSkippedInspection
        let base = "\(n) request\(n == 1 ? "" : "s") inspected"
        var details: [String] = []
        if blocked > 0 { details.append("\(blocked) blocked") }
        if limitBlocked > 0 { details.append("\(limitBlocked) refused uninspected") }
        if flagged > 0 { details.append("\(flagged) finding\(flagged == 1 ? "" : "s") allowed") }
        if skipped > 0 { details.append("\(skipped) not inspected") }
        return details.isEmpty ? "\(base) · all clear" : ([base] + details).joined(separator: " · ")
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
            MenuActionRow(
                title: managedActiveLock ? "Quit prevented by your organization" : "Quit Bouclier.ai",
                systemImage: "power",
                disabled: managedActiveLock,
                shortcut: "q"
            ) {
                // AppDelegate performs the transient passthrough handoff.
                // Calling stop() here first clears liveGatewayPort and
                // defeats that continuity path, breaking live agent sessions.
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

    private var blockingEnabled: Bool {
        FeatureFlags.managedInjectionBlock ?? userBlockingEnabled
    }

    private var protectionState: DesktopProtectionState {
        .resolve(
            protectionActive: proxyManager.protectionActive,
            gatewayRunning: proxyManager.isRunning,
            detectionEngineDegraded: proxyManager.detectionEngineDegraded
        )
    }

    private var managedActiveLock: Bool {
        proxyManager.protectionActive && ManagedConfig.preventDisable
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
                allowedHosts: SystemProxy.diagnosticAllowedHosts
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
