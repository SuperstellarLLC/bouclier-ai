import SwiftUI

struct MenuBarView: View {
    @ObservedObject var proxyManager: ProxyManager
    @ObservedObject var updater: AutoUpdater
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Circle()
                    .fill(statusColor)
                    .frame(width: 10, height: 10)
                    .accessibilityLabel(statusAccessibilityLabel)
                Text("Bouclier.ai")
                    .font(.headline)
                Spacer()
                Text(statusText)
                    .font(.caption)
                    .foregroundStyle(proxyManager.errorMessage != nil ? .red : .secondary)
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
                }

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
        }
        .padding()
        .frame(width: 280)
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
            panel.nameFieldStringValue = "bouclier-diagnostics-\(stamp).json"
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
        ).first!.appendingPathComponent("com.bouclier.Bouclier", isDirectory: true)
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)

        let logFile = logDir.appendingPathComponent("bouclier.log")
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
                Text(label)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(value) \(label)")
    }
}
