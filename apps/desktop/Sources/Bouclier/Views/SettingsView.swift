import SwiftUI

struct SettingsView: View {
    @ObservedObject var proxyManager: ProxyManager
    @ObservedObject var updater: AutoUpdater

    var body: some View {
        TabView {
            GeneralSettingsView(proxyManager: proxyManager)
                .tabItem { Label("General", systemImage: "gear") }

            ProtectionSettingsView(proxyManager: proxyManager)
                .tabItem { Label("Protection", systemImage: "shield.checkered") }

            LogsView(proxyManager: proxyManager)
                .tabItem { Label("Logs", systemImage: "doc.text") }

            AboutView(updater: updater, patternCount: proxyManager.patternsLoadedCount)
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
    @State private var showUninstallConfirm = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Protection Status")
                .font(.headline)

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 8) {
                StatusRow(label: "CA Certificate", active: proxyManager.caInstalled,
                          detail: proxyManager.caInstalled ? "Installed & Trusted" : "Not installed")
                StatusRow(label: "TLS Proxy", active: proxyManager.isRunning,
                          detail: proxyManager.isRunning ? "Port \(proxyManager.port)" : "Stopped")
                StatusRow(label: "System Extension", active: proxyManager.extensionActive,
                          detail: proxyManager.extensionActive ? "Capturing all AI traffic" : "Not active")
            }
            .font(.callout)

            Divider()

            Text("Intercepted Domains")
                .font(.headline)
            Text("Bouclier.ai only inspects traffic to these AI API domains. All other traffic is unaffected.")
                .foregroundStyle(.secondary)
                .font(.callout)

            ScrollView {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(SystemProxy.interceptedDomains).sorted(), id: \.self) { domain in
                        Text(domain)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .frame(maxHeight: 100)

            Spacer()

            if let certPath = proxyManager.ca.caCertFilePath {
                Divider()
                Text("CLI Tools")
                    .font(.headline)
                Text("Add to ~/.zshrc for Python/Node.js coverage:")
                    .foregroundStyle(.secondary)
                    .font(.callout)
                HStack(spacing: 8) {
                    Text("eval $(bouclier-env)")
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .padding(6)
                        .background(.quaternary)
                        .clipShape(RoundedRectangle(cornerRadius: 4))
                    Button(action: {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString("eval $(bouclier-env)", forType: .string)
                    }) {
                        Image(systemName: "doc.on.doc")
                            .font(.caption)
                    }
                    .buttonStyle(.borderless)
                    .help("Copy to clipboard")
                }
            }

            if ManagedConfig.isManaged {
                Divider()
                HStack(spacing: 6) {
                    Image(systemName: "building.2")
                        .foregroundStyle(.blue)
                    Text("Managed by your organization")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            HStack {
                if !proxyManager.caInstalled {
                    Button("Enable Protection") { proxyManager.setup() }
                        .buttonStyle(.borderedProminent)
                } else {
                    Button("Uninstall Everything", role: .destructive) {
                        showUninstallConfirm = true
                    }
                    .disabled(ManagedConfig.preventUninstall)
                    .help(ManagedConfig.preventUninstall ? "Uninstall is disabled by your organization" : "")
                    .alert("Uninstall Bouclier.ai?", isPresented: $showUninstallConfirm) {
                        Button("Cancel", role: .cancel) {}
                        Button("Uninstall", role: .destructive) {
                            proxyManager.uninstall()
                        }
                    } message: {
                        Text("This will remove the CA certificate, disable the System Extension, and stop the proxy. You can reinstall anytime.")
                    }
                }
            }
        }
        .padding()
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
    let patternCount: Int

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: "shield.checkered")
                .font(.system(size: 48))
                .foregroundStyle(.tint)
                .accessibilityHidden(true)

            Text("Bouclier.ai")
                .font(.title.bold())

            Text("Prompt Injection Firewall")
                .font(.callout)
                .foregroundStyle(.secondary)

            Text("Version \(Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.2.0")")
                .font(.caption)
                .foregroundStyle(.tertiary)

            Text("\(patternCount) detection patterns active")
                .font(.caption)
                .foregroundStyle(.tertiary)

            Button("Check for Updates...") { updater.checkForUpdates() }
                .disabled(!updater.canCheckForUpdates)

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
