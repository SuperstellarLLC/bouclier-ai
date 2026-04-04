import SwiftUI

struct MenuBarView: View {
    @ObservedObject var proxyManager: ProxyManager
    @ObservedObject var updater: AutoUpdater

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Circle()
                    .fill(statusColor)
                    .frame(width: 10, height: 10)
                Text("Ilvarion")
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

                if let lastBlocked = proxyManager.logs.first(where: { $0.blocked && $0.message.contains("Blocked") }) {
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

            Button(action: {
                NSApp.activate(ignoringOtherApps: true)
                NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
            }) {
                Label("Settings...", systemImage: "gear")
            }
            .keyboardShortcut(",")

            Button("Quit Ilvarion") {
                proxyManager.stop()
                NSApplication.shared.terminate(nil)
            }
            .keyboardShortcut("q")
        }
        .padding()
        .frame(width: 280)
    }

    private func openLogFile() {
        let logDir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first!.appendingPathComponent("com.ilvarion.Ilvarion", isDirectory: true)
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)

        let logFile = logDir.appendingPathComponent("ilvarion.log")
        let dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd HH:mm:ss"

        var content = "ILVARION SCAN LOG\n"
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
        return .secondary
    }

    private var statusText: String {
        if proxyManager.errorMessage != nil { return "Error" }
        if proxyManager.isRunning { return "Active" }
        if !proxyManager.caInstalled { return "Not Configured" }
        return "Stopped"
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
    }
}
