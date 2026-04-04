import SwiftUI

struct SettingsView: View {
    @ObservedObject var proxyManager: ProxyManager

    var body: some View {
        TabView {
            GeneralSettingsView(proxyManager: proxyManager)
                .tabItem { Label("General", systemImage: "gear") }

            ProtectionSettingsView(proxyManager: proxyManager)
                .tabItem { Label("Protection", systemImage: "shield.checkered") }

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
                    .help("Requires proxy restart to take effect")
                Toggle("Launch at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, newValue in
                        ProxyManager.setLaunchAtLogin(newValue)
                    }
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

struct ProtectionSettingsView: View {
    @ObservedObject var proxyManager: ProxyManager

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Protection Status")
                .font(.headline)

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                GridRow {
                    Label("CA Certificate", systemImage: proxyManager.caInstalled ? "checkmark.circle.fill" : "xmark.circle")
                        .foregroundStyle(proxyManager.caInstalled ? .green : .secondary)
                    Text(proxyManager.caInstalled ? "Installed & Trusted" : "Not installed")
                        .foregroundStyle(.secondary)
                }
                GridRow {
                    Label("System Proxy", systemImage: proxyManager.systemProxyEnabled ? "checkmark.circle.fill" : "xmark.circle")
                        .foregroundStyle(proxyManager.systemProxyEnabled ? .green : .secondary)
                    Text(proxyManager.systemProxyEnabled ? "Enabled (AI domains only)" : "Not configured")
                        .foregroundStyle(.secondary)
                }
                GridRow {
                    Label("Proxy Server", systemImage: proxyManager.isRunning ? "checkmark.circle.fill" : "xmark.circle")
                        .foregroundStyle(proxyManager.isRunning ? .green : .secondary)
                    Text(proxyManager.isRunning ? "Running on port \(proxyManager.port)" : "Stopped")
                        .foregroundStyle(.secondary)
                }
            }
            .font(.callout)

            Divider()

            Text("Intercepted Domains")
                .font(.headline)
            Text("Ilvarion only inspects traffic to these AI API domains. All other traffic is unaffected.")
                .foregroundStyle(.secondary)
                .font(.callout)

            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(SystemProxy.interceptedDomains, id: \.self) { domain in
                        Text(domain)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .frame(maxHeight: 100)

            Spacer()

            HStack {
                if !proxyManager.caInstalled {
                    Button("Enable Protection") { proxyManager.setup() }
                        .buttonStyle(.borderedProminent)
                } else {
                    Button("Remove Certificate & Proxy", role: .destructive) {
                        proxyManager.uninstall()
                    }
                }
            }
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

            Divider().frame(width: 200)

            Text("All detection runs locally.\nNo data ever leaves your machine.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 300)

            Spacer()
        }
        .padding(.top, 40)
    }
}
