import SwiftUI

struct MenuBarView: View {
    @ObservedObject var proxyManager: ProxyManager
    @ObservedObject var updater: AutoUpdater
    @Environment(\.openSettings) private var openSettings
    @State private var mlErrorCopied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Circle()
                    .fill(statusColor)
                    .frame(width: 10, height: 10)
                    .animation(.easeInOut(duration: 0.25), value: statusColor)
                    .accessibilityLabel(statusAccessibilityLabel)
                Text("Bouclier.ai")
                    .font(.headline)
                Text("BETA")
                    .font(.system(size: 9, weight: .semibold))
                    .tracking(0.5)
                    .padding(.horizontal, 5)
                    .padding(.vertical, 2)
                    .background(Color.orange.opacity(0.15), in: RoundedRectangle(cornerRadius: 4))
                    .foregroundStyle(.orange)
                    .accessibilityLabel("Beta release")
                Spacer()
                Text(statusText)
                    .font(.caption)
                    .foregroundStyle(proxyManager.errorMessage != nil ? .red : .secondary)
                    .contentTransition(.opacity)
                    .animation(.easeInOut(duration: 0.25), value: statusText)
            }

            if let error = proxyManager.errorMessage {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .font(.caption)
                    Text(error)
                        .font(.caption2)
                        .foregroundStyle(.red)
                }
                .padding(8)
                .background(.red.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .accessibilityElement(children: .combine)
                .transition(.move(edge: .top).combined(with: .opacity))
            }

            if proxyManager.isRunning {
                Divider()

                HStack {
                    StatBadge(value: "\(proxyManager.stats.requestsScanned)", label: "Scanned", icon: "magnifyingglass", color: .blue)
                    Spacer()
                    StatBadge(
                        value: "\(proxyManager.stats.injectionsBlocked)",
                        label: "Blocked",
                        icon: "shield.slash",
                        color: proxyManager.stats.injectionsBlocked > 0 ? .red : .green
                    )
                    Spacer()
                    StatBadge(
                        value: "\(proxyManager.stats.piiRedacted)",
                        label: "Redacted",
                        icon: "eye.slash.fill",
                        color: proxyManager.stats.piiRedacted > 0 ? .purple : .secondary
                    )
                    Spacer()
                    StatBadge(
                        value: "\(proxyManager.stats.mediaBlocked)",
                        label: "Media",
                        icon: "photo.fill",
                        color: proxyManager.stats.mediaBlocked > 0 ? .purple : .secondary
                    )
                }

                PIIRedactionRow(proxyManager: proxyManager)

                // ML classifier status — small inline badge so users
                // can see whether the on-device fused detection layer
                // is active. Three states:
                //   - active  → fused detection running (regex + ML)
                //   - failed  → classifier wouldn't load; click the badge
                //               to copy the raw error to the clipboard so
                //               it can be pasted into bug reports (tooltip
                //               alone forces a screenshot)
                //   - loading → still warming up (usually <1s)
                Button(action: copyMLErrorToClipboard) {
                    HStack(spacing: 6) {
                        Image(systemName: mlBadgeIcon)
                            .foregroundStyle(mlBadgeColor)
                            .font(.caption)
                            .contentTransition(.symbolEffect(.replace))
                        Text(mlBadgeText)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                            .multilineTextAlignment(.leading)
                        Spacer()
                        if proxyManager.mlClassifierError != nil {
                            Image(systemName: mlErrorCopied ? "checkmark" : "doc.on.doc")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                                .contentTransition(.symbolEffect(.replace))
                        }
                    }
                }
                .buttonStyle(.plain)
                .disabled(proxyManager.mlClassifierError == nil)
                .padding(8)
                .background(mlBadgeColor.opacity(0.06))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .help(proxyManager.mlClassifierError ?? "")
                .animation(.easeInOut(duration: 0.35), value: proxyManager.mlClassifierActive)
                .animation(.easeInOut(duration: 0.35), value: proxyManager.mlClassifierError)

                if proxyManager.stats.injectionsBlocked == 0 && proxyManager.stats.requestsScanned > 0 {
                    HStack(spacing: 6) {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                            .font(.caption)
                        Text("No threats detected")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    .padding(8)
                    .background(.green.opacity(0.06))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .transition(.opacity.combined(with: .scale(scale: 0.96, anchor: .top)))
                } else if let lastBlocked = proxyManager.logs.first(where: { $0.blocked }) {
                    Button(action: { openLogFile() }) {
                        HStack(spacing: 6) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                                .font(.caption)
                            Text(lastBlocked.message)
                                .font(.caption2)
                                .lineLimit(2)
                                .foregroundStyle(.secondary)
                            Spacer()
                            Image(systemName: "arrow.up.right.square")
                                .font(.caption2)
                                .foregroundStyle(.tertiary)
                        }
                    }
                    .buttonStyle(.plain)
                    .padding(8)
                    .background(.orange.opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                    .transition(.opacity.combined(with: .move(edge: .top)))
                    .id(lastBlocked.id)
                }

                // Self-test: runs a known injection through the active
                // detector so the user gets an immediate "yes, it works"
                // confirmation without waiting for real traffic.
                Button(action: { proxyManager.runSelfTest() }) {
                    Label("Run detection test", systemImage: "testtube.2")
                        .font(.caption)
                }
                .buttonStyle(.plain)
                .padding(.vertical, 4)
                .padding(.horizontal, 8)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(.blue.opacity(0.06))
                .clipShape(RoundedRectangle(cornerRadius: 6))
                .help("Send a synthetic injection through the scanner and show the verdict")

                if let result = proxyManager.selfTestResult {
                    SelfTestBanner(result: result)
                        .transition(.opacity.combined(with: .move(edge: .top)))
                }
            }

            Divider()

            if !proxyManager.caInstalled {
                Button(action: { proxyManager.setup() }) {
                    Label("Enable Protection", systemImage: "lock.shield")
                }
            } else if proxyManager.isRunning {
                Button(action: { proxyManager.stop() }) {
                    Label("Stop Protection", systemImage: "stop.fill")
                }
                .keyboardShortcut("s")

                Button(action: { proxyManager.stats.reset() }) {
                    Label("Reset Stats", systemImage: "arrow.counterclockwise")
                }
            } else {
                Button(action: { proxyManager.start() }) {
                    Label("Start Protection", systemImage: "play.fill")
                }
                .keyboardShortcut("s")
            }

            Divider()

            Button(action: { updater.checkForUpdates() }) {
                Label("Check for Updates...", systemImage: "arrow.triangle.2.circlepath")
            }
            .disabled(!updater.canCheckForUpdates)

            Button(action: { exportDiagnostics() }) {
                Label("Export Diagnostics…", systemImage: "square.and.arrow.up")
            }
            .help("Save a redacted diagnostics bundle for support handoff")

            Button(action: {
                NSApp.activate(ignoringOtherApps: true)
                openSettings()
            }) {
                Label("Settings...", systemImage: "gear")
            }
            .keyboardShortcut(",")

            Button("Quit Bouclier.ai") {
                proxyManager.stop()
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q")

            // Subtle version stamp so users can verify a Sparkle update
            // landed without digging into Settings → About. Clickable to
            // trigger a manual update check when Sparkle allows it.
            HStack(spacing: 4) {
                Spacer()
                Button(action: { if updater.canCheckForUpdates { updater.checkForUpdates() } }) {
                    Text("v\(appVersion)")
                        .font(.caption2)
                        .foregroundStyle(.tertiary)
                }
                .buttonStyle(.plain)
                .disabled(!updater.canCheckForUpdates)
                .help(updater.canCheckForUpdates ? "Check for updates" : "Version \(appVersion)")
            }
        }
        .padding()
        .frame(width: 300)
        .animation(.spring(response: 0.35, dampingFraction: 0.85), value: proxyManager.isRunning)
        .animation(.spring(response: 0.35, dampingFraction: 0.85), value: proxyManager.errorMessage)
        .animation(.spring(response: 0.35, dampingFraction: 0.85), value: proxyManager.selfTestResult)
        .animation(.spring(response: 0.35, dampingFraction: 0.85), value: proxyManager.logs.first?.id)
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
        let logDir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first!.appendingPathComponent("ai.bouclier.app", isDirectory: true)
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)

        let logFile = logDir.appendingPathComponent("bouclier-ai.log")
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"

        var content = "BOUCLIER.AI SCAN LOG\n"
        content += "Generated: \(dateFormatter.string(from: Date()))\n"
        content += String(repeating: "=", count: 80) + "\n\n"

        for entry in proxyManager.logs {
            let icon = entry.blocked ? "BLOCKED" : "OK"
            let time = dateFormatter.string(from: entry.timestamp)
            content += "[\(time)] [\(icon)] \(entry.message)\n"
        }

        try? content.write(to: logFile, atomically: true, encoding: .utf8)
        NSWorkspace.shared.open(logFile)
    }

    private var statusColor: Color {
        if proxyManager.errorMessage != nil { return .red }
        if proxyManager.isRunning { return .green }
        if !proxyManager.caInstalled { return .orange }
        return .secondary
    }

    private var statusText: String {
        if proxyManager.errorMessage != nil { return "Error" }
        if proxyManager.isRunning { return "Active" }
        if !proxyManager.caInstalled { return "Setup Required" }
        return "Stopped"
    }

    private var statusAccessibilityLabel: String {
        "Protection status: \(statusText)"
    }

    private var mlBadgeIcon: String {
        if proxyManager.mlClassifierActive { return "brain.head.profile.fill" }
        if proxyManager.mlClassifierError != nil { return "exclamationmark.brain" }
        return "brain.head.profile"
    }

    private var mlBadgeColor: Color {
        if proxyManager.mlClassifierActive { return .purple }
        if proxyManager.mlClassifierError != nil { return .orange }
        return .gray
    }

    private var mlBadgeText: String {
        if proxyManager.mlClassifierActive { return "Fused detection active (regex + on-device ML)" }
        if proxyManager.mlClassifierError != nil { return "Regex detection only — ML model unavailable" }
        return "Regex detection (ML classifier loading…)"
    }

    private var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
    }

    private func copyMLErrorToClipboard() {
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

struct StatBadge: View {
    let value: String
    let label: String
    let icon: String
    let color: Color

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .foregroundStyle(color)
                .font(.caption)
            VStack(alignment: .leading, spacing: 1) {
                Text(value)
                    .font(.system(.body, design: .monospaced).bold())
                    .contentTransition(.numericText())
                    .animation(.spring(response: 0.3, dampingFraction: 0.7), value: value)
                Text(label)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(label)")
    }
}

/// Transient banner surfaced after the user taps "Run detection test".
/// Auto-dismisses from ProxyManager; this view just renders whichever
/// result is currently published.
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
                    .lineLimit(2)
            }
            Spacer()
            Text(String(format: "%.2f", result.fusedScore))
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
        }
        .padding(8)
        .background((result.passed ? Color.green : Color.red).opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Self-test result: \(result.headline). \(result.detail).")
    }
}
