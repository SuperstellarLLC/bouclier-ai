import Foundation
import NIOCore
import ServiceManagement
import SwiftUI
import UserNotifications

@MainActor
final class ProxyManager: ObservableObject {
    @Published var isRunning = false
    @Published var caInstalled = false
    @Published var extensionActive = false
    @Published var errorMessage: String?
    @Published var stats = ProxyStats()
    @Published var logs: [LogEntry] = []

    var port: Int {
        let p = UserDefaults.standard.object(forKey: "proxyPort") as? Int ?? 8484
        return (1...65535).contains(p) ? p : 8484
    }

    private var tlsProxy: TLSProxy?
    private var proxyChannel: Channel?
    let ca = CertificateAuthority()
    let extensionManager = ExtensionManager()
    private let patternManager = PatternManager(onChange: {
        print("[ilvarion] Patterns updated")
    })
    private var storage: StorageManager?

    init() {
        // Register crash cleanup — disable system proxy if we die unexpectedly
        registerCleanupHandlers()
    }

    func initializeStorage() {
        guard storage == nil else { return }
        storage = try? StorageManager()
        caInstalled = ca.isInstalled

        Task {
            await extensionManager.checkStatus()
            extensionActive = extensionManager.proxyEnabled
        }

        if UserDefaults.standard.bool(forKey: "launchAtLogin") && !isRunning && caInstalled {
            start()
        }
    }

    func setup() {
        errorMessage = nil

        if !ca.isInstalled {
            let success = ca.installCA()
            caInstalled = success
            if !success {
                errorMessage = "CA installation was cancelled."
                return
            }
            log("CA certificate installed and trusted", blocked: false)
        }

        start()

        extensionManager.installExtension { [weak self] success in
            guard let self, success else { return }
            Task { @MainActor in
                let enabled = await self.extensionManager.enableProxy()
                self.extensionActive = enabled
                if enabled {
                    self.log("System Extension active — all AI traffic intercepted", blocked: false)
                }

                if SystemProxy.enable(port: self.port) {
                    self.log("System proxy PAC configured as fallback", blocked: false)
                }

                if let certPath = self.ca.caCertFilePath {
                    self.log("CLI: eval $(ilvarion-env)", blocked: false)
                }
            }
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

        Task.detached { [weak self] in
            guard let self else { return }
            do {
                let channel = try await proxy.start()
                await MainActor.run {
                    self.proxyChannel = channel
                    self.isRunning = true
                    self.log("TLS proxy listening on 127.0.0.1:\(self.port)", blocked: false)
                }
            } catch {
                await MainActor.run {
                    self.isRunning = false
                    let msg = Self.friendlyError(error)
                    self.errorMessage = msg
                    self.log("Proxy failed: \(msg)", blocked: true)
                }
            }
        }
    }

    func stop() {
        // Close channel first (non-blocking)
        proxyChannel?.close(mode: .all, promise: nil)
        proxyChannel = nil

        // Shutdown NIO on a background thread to avoid deadlock
        let proxy = tlsProxy
        tlsProxy = nil
        Task.detached {
            proxy?.shutdown()
        }

        isRunning = false
        errorMessage = nil

        Task {
            await extensionManager.disableProxy()
            await MainActor.run { extensionActive = false }
        }
        _ = SystemProxy.disable()

        log("Proxy stopped", blocked: false)
    }

    func uninstall() {
        stop()
        extensionManager.removeExtension()
        ca.uninstallCA()
        caInstalled = false
        extensionActive = false
        log("Ilvarion fully uninstalled", blocked: false)
    }

    func clearLogs() { logs.removeAll() }

    static func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        } catch {}
    }

    // MARK: - Crash Recovery

    private nonisolated func registerCleanupHandlers() {
        // Disable system proxy on SIGTERM (e.g., force quit from Activity Monitor)
        signal(SIGTERM) { _ in
            _ = SystemProxy.disable()
            exit(0)
        }

        // Disable on normal exit
        atexit {
            _ = SystemProxy.disable()
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
        content.body = "Blocked \(count) injection\(count > 1 ? "s" : "") → \(target)"
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
    mutating func reset() { requestsScanned = 0; injectionsBlocked = 0 }
}

struct LogEntry: Identifiable {
    let id = UUID()
    let timestamp = Date()
    let message: String
    let blocked: Bool
}
