import Foundation
import NIOCore
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

    private var tlsProxy: TLSProxy?
    private var proxyChannel: Channel?
    private let ca = CertificateAuthority()
    private let patternManager = PatternManager(onChange: {
        print("[ilvarion] Patterns updated — active on new connections")
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

    /// Full setup: install CA + start proxy + configure system proxy.
    func setup() {
        errorMessage = nil

        if !ca.isInstalled {
            let success = ca.installCA()
            caInstalled = success
            if !success {
                errorMessage = "CA installation was cancelled. Ilvarion needs a trusted certificate to inspect HTTPS traffic."
                return
            }
            log("CA certificate installed and trusted", blocked: false)
        }

        start()

        if SystemProxy.enable(port: port) {
            systemProxyEnabled = true
            log("System proxy configured for AI domains", blocked: false)
        } else {
            log("System proxy could not be configured automatically", blocked: true)
        }

        // Export CA path for CLI helper
        if let certPath = ca.caCertFilePath {
            log("CLI: eval $(ilvarion-env) — or add to ~/.zshrc", blocked: false)
            log("CA cert: \(certPath)", blocked: false)
        }
    }

    func start() {
        guard !isRunning else { return }
        errorMessage = nil

        let proxy = TLSProxy(
            port: port,
            ca: ca,
            filter: patternManager.filter,
            onRequest: { [weak self] requestLog in
                Task { @MainActor in
                    self?.handleRequestLog(requestLog)
                }
            }
        )
        tlsProxy = proxy

        Task {
            do {
                let channel = try await proxy.start()
                proxyChannel = channel
                isRunning = true
                log("TLS proxy listening on 127.0.0.1:\(port)", blocked: false)
            } catch {
                isRunning = false
                let msg = Self.friendlyError(error)
                errorMessage = msg
                log("Proxy failed: \(msg)", blocked: true)
            }
        }
    }

    func stop() {
        proxyChannel?.close(promise: nil)
        proxyChannel = nil
        tlsProxy?.shutdown()
        tlsProxy = nil
        isRunning = false
        errorMessage = nil

        if SystemProxy.disable() {
            systemProxyEnabled = false
        }
        log("Proxy stopped", blocked: false)
    }

    func uninstall() {
        stop()
        ca.uninstallCA()
        caInstalled = false
        log("CA certificate removed", blocked: false)
    }

    func clearLogs() { logs.removeAll() }

    // MARK: - Launch at Login

    static func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        } catch {
            print("[ilvarion] Launch at login error: \(error)")
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
            source: "tls-proxy",
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
        if logs.count > 500 { logs.removeLast(logs.count - 500) }
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
        let desc = "\(error)"
        if desc.contains("Address already in use") || desc.contains("bind") {
            return "Port is already in use. Change the port in Settings or close the other app."
        }
        if desc.contains("Permission denied") {
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
