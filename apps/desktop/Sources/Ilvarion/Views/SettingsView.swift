import SwiftUI

struct SettingsView: View {
    @ObservedObject var proxyManager: ProxyManager

    var body: some View {
        TabView {
            GeneralSettingsView(proxyManager: proxyManager)
                .tabItem { Label("General", systemImage: "gear") }

            ConnectionSettingsView(proxyManager: proxyManager)
                .tabItem { Label("Connection", systemImage: "network") }

            LogsView(proxyManager: proxyManager)
                .tabItem { Label("Logs", systemImage: "doc.text") }

            AboutView()
                .tabItem { Label("About", systemImage: "info.circle") }
        }
        .frame(width: 520, height: 400)
    }
}

struct GeneralSettingsView: View {
    @ObservedObject var proxyManager: ProxyManager
    @AppStorage("proxyPort") private var port: Int = 8484
    @AppStorage("launchAtLogin") private var launchAtLogin: Bool = false
    @AppStorage("showNotifications") private var showNotifications: Bool = true
    @AppStorage("quietMode") private var quietMode: Bool = false

    var body: some View {
        Form {
            Section("Proxy") {
                TextField("Port", value: $port, format: .number)
                Toggle("Start proxy on launch", isOn: $launchAtLogin)
            }
            Section("Notifications") {
                Toggle("Show block notifications", isOn: $showNotifications)
                Toggle("Quiet mode (no sounds)", isOn: $quietMode)
                    .disabled(!showNotifications)
            }
        }
        .formStyle(.grouped)
        .padding()
    }
}

struct ConnectionSettingsView: View {
    @ObservedObject var proxyManager: ProxyManager

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("SDK Configuration")
                .font(.headline)
            Text("Set these environment variables to route AI traffic through Ilvarion:")
                .foregroundStyle(.secondary)
                .font(.callout)

            VStack(alignment: .leading, spacing: 8) {
                ConfigRow(
                    label: "OpenAI",
                    value: "OPENAI_BASE_URL=http://localhost:\(proxyManager.port)/openai/v1",
                    copyPrefix: "export "
                )
                ConfigRow(
                    label: "Anthropic",
                    value: "ANTHROPIC_BASE_URL=http://localhost:\(proxyManager.port)/anthropic",
                    copyPrefix: "export "
                )
                ConfigRow(
                    label: "Mistral",
                    value: "MISTRAL_API_URL=http://localhost:\(proxyManager.port)/mistral",
                    copyPrefix: "export "
                )
            }

            Divider()

            Text("MCP Server Wrapping")
                .font(.headline)
            Text("Wrap your MCP servers with the ilvarion-mcp-wrapper binary to scan tool results.")
                .foregroundStyle(.secondary)
                .font(.callout)

            Text("""
            {
              "command": "ilvarion-mcp-wrapper",
              "args": ["npx", "-y", "@your/mcp-server"]
            }
            """)
            .font(.system(.caption, design: .monospaced))
            .padding(8)
            .background(.quaternary)
            .clipShape(RoundedRectangle(cornerRadius: 6))
            .textSelection(.enabled)

            Spacer()
        }
        .padding()
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
    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.checkered")
                .font(.system(size: 48))
                .foregroundStyle(.tint)

            Text("Ilvarion")
                .font(.title.bold())

            Text("Prompt Injection Firewall")
                .font(.callout)
                .foregroundStyle(.secondary)

            Text("Version \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.1.0")")
                .font(.caption)
                .foregroundStyle(.tertiary)

            Divider()
                .frame(width: 200)

            Text("All detection runs locally. No data ever leaves your machine.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 300)

            Spacer()
        }
        .padding(.top, 40)
    }
}
