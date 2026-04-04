import Foundation
import ServiceManagement
import SwiftUI
import UserNotifications

@MainActor
final class ProxyManager: ObservableObject {
    @Published var isRunning = false
    @Published var caInstalled = false
    @Published var systemProxyEnabled = false
    @Published var errorMessage: String?
    @Published var stats = ProxyStats()
    @Published var logs: [LogEntry] = []

    var port: Int {
        UserDefaults.standard.object(forKey: "proxyPort") as? Int ?? 8484
    }

    private var httpProxy: HTTPProxy?
    private let ca = CertificateAuthority()
    private let patternManager = PatternManager(onChange: {
        print("[ilvarion] Pattern update detected — new connections will use updated patterns")
    })
    private var storage: StorageManager?

    func initializeStorage() {
        guard storage == nil else { return }
        storage = try? StorageManager()
        caInstalled = ca.isInstalled

        if UserDefaults.standard.bool(forKey: "launchAtLogin") && !isRunning && caInstalled {
            start()
        }
    }

    /// Full setup: install CA (prompts admin) + enable system proxy + start listening.
    func setup() {
        errorMessage = nil

        // Step 1: Install CA certificate (prompts admin password)
        if !ca.isInstalled {
            let success = ca.installCA()
            caInstalled = success
            if !success {
                errorMessage = "CA certificate installation was cancelled. Ilvarion needs a trusted certificate to inspect HTTPS traffic."
                return
            }
            log("CA certificate installed and trusted", blocked: false)
        }

        // Step 2: Start the proxy
        start()

        // Step 3: Configure system proxy
        if SystemProxy.enable(port: port) {
            systemProxyEnabled = true
            log("System proxy configured — AI traffic is now routed through Ilvarion", blocked: false)
        } else {
            log("Could not configure system proxy automatically. You may need to set it manually in System Settings > Network.", blocked: true)
        }
    }

    func start() {
        guard !isRunning else { return }
        errorMessage = nil

        let proxy = HTTPProxy(port: UInt16(port), filter: patternManager.filter, ca: ca)
        httpProxy = proxy

        proxy.start(
            onReady: { [weak self] in
                Task { @MainActor in
                    self?.isRunning = true
                    self?.errorMessage = nil
                    self?.log("Proxy listening on localhost:\(self?.port ?? 0)", blocked: false)
                }
            },
            onFailed: { [weak self] error in
                Task { @MainActor in
                    self?.isRunning = false
                    let msg = Self.friendlyError(error)
                    self?.errorMessage = msg
                    self?.log("Proxy failed: \(msg)", blocked: true)
                }
            },
            onRequest: { [weak self] requestLog in
                Task { @MainActor in
                    self?.handleRequestLog(requestLog)
                }
            }
        )
    }

    func stop() {
        httpProxy?.stop()
        httpProxy = nil
        isRunning = false
        errorMessage = nil

        // Disable system proxy
        if SystemProxy.disable() {
            systemProxyEnabled = false
        }
        log("Proxy stopped", blocked: false)
    }

    /// Remove CA certificate and all proxy config.
    func uninstall() {
        stop()
        ca.uninstallCA()
        caInstalled = false
        log("CA certificate removed", blocked: false)
    }

    func clearLogs() {
        logs.removeAll()
    }

    // MARK: - Launch at Login

    static func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            print("[ilvarion] Launch at login error: \(error.localizedDescription)")
        }
    }

    // MARK: - Private

    private func handleRequestLog(_ requestLog: RequestLog) {
        stats.requestsScanned += 1

        if requestLog.detected {
            stats.injectionsBlocked += requestLog.matchCount
            log(
                "Blocked \(requestLog.matchCount) injection(s) → \(requestLog.targetHost): \(requestLog.patternNames.joined(separator: ", "))",
                blocked: true
            )
            sendBlockNotification(count: requestLog.matchCount, target: requestLog.targetHost)
        }

        storage?.recordScan(
            source: "api-proxy",
            targetHost: requestLog.targetHost,
            detected: requestLog.detected,
            matchCount: requestLog.matchCount,
            patternIds: requestLog.patternNames,
            severity: requestLog.detected ? "high" : nil,
            requestSize: requestLog.bodySize
        )
    }

    private func log(_ message: String, blocked: Bool) {
        let entry = LogEntry(message: message, blocked: blocked)
        logs.insert(entry, at: 0)
        if logs.count > 500 {
            logs.removeLast(logs.count - 500)
        }
    }

    private func sendBlockNotification(count: Int, target: String) {
        guard UserDefaults.standard.object(forKey: "showNotifications") as? Bool ?? true else { return }

        let content = UNMutableNotificationContent()
        content.title = "Injection Blocked"
        content.body = "Blocked \(count) injection\(count > 1 ? "s" : "") in request to \(target)"
        content.sound = UserDefaults.standard.bool(forKey: "quietMode") ? nil : .default

        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    private static func friendlyError(_ error: Error) -> String {
        let desc = error.localizedDescription
        if desc.contains("Address already in use") || desc.contains("48") {
            return "Port is already in use. Change the port in Settings or close the other app."
        }
        if desc.contains("Permission denied") || desc.contains("13") {
            return "Permission denied. Ports below 1024 require admin privileges."
        }
        return desc
    }
}

struct ProxyStats {
    var requestsScanned: Int = 0
    var injectionsBlocked: Int = 0

    mutating func reset() {
        requestsScanned = 0
        injectionsBlocked = 0
    }
}

struct LogEntry: Identifiable {
    let id = UUID()
    let timestamp = Date()
    let message: String
    let blocked: Bool
}
