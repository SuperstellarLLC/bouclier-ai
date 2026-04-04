import SwiftUI

struct MenuBarView: View {
    @ObservedObject var proxyManager: ProxyManager

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Header
            HStack {
                Circle()
                    .fill(proxyManager.isRunning ? Color.green : Color.secondary)
                    .frame(width: 10, height: 10)
                Text("Ilvarion")
                    .font(.headline)
                Spacer()
                Text(proxyManager.isRunning ? "Active" : "Stopped")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if proxyManager.isRunning {
                Divider()

                // Stats
                HStack {
                    StatBadge(
                        value: "\(proxyManager.stats.requestsScanned)",
                        label: "Scanned",
                        icon: "magnifyingglass",
                        color: .blue
                    )
                    Spacer()
                    StatBadge(
                        value: "\(proxyManager.stats.injectionsBlocked)",
                        label: "Blocked",
                        icon: "shield.slash",
                        color: proxyManager.stats.injectionsBlocked > 0 ? .red : .green
                    )
                }

                // Last blocked (if any)
                if let lastBlocked = proxyManager.logs.first(where: { $0.blocked }) {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                            .font(.caption)
                        Text(lastBlocked.message)
                            .font(.caption2)
                            .lineLimit(2)
                            .foregroundStyle(.secondary)
                    }
                    .padding(8)
                    .background(.orange.opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                }

                Text("localhost:\(proxyManager.port)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundStyle(.secondary)
            }

            Divider()

            // Actions
            Button(action: {
                if proxyManager.isRunning { proxyManager.stop() }
                else { proxyManager.start() }
            }) {
                Label(
                    proxyManager.isRunning ? "Stop Proxy" : "Start Proxy",
                    systemImage: proxyManager.isRunning ? "stop.fill" : "play.fill"
                )
            }
            .keyboardShortcut("s")

            if proxyManager.isRunning {
                Button(action: { proxyManager.stats.reset() }) {
                    Label("Reset Stats", systemImage: "arrow.counterclockwise")
                }
            }

            Divider()

            SettingsLink {
                Label("Settings…", systemImage: "gear")
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
