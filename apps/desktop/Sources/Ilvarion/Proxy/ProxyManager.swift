import Foundation
import SwiftUI

/// Manages the proxy server lifecycle, stats, and log entries.
@MainActor
final class ProxyManager: ObservableObject {
    @Published var isRunning = false
    @Published var stats = ProxyStats()
    @Published var logs: [LogEntry] = []

    var port: Int {
        UserDefaults.standard.object(forKey: "proxyPort") as? Int ?? 8484
    }

    private var httpProxy: HTTPProxy?
    private let filter = InjectionFilter()
    private var storage: StorageManager?

    func initializeStorage() {
        guard storage == nil else { return }
        storage = try? StorageManager()
    }

    func start() {
        guard !isRunning else { return }

        let proxy = HTTPProxy(port: UInt16(port), filter: filter)
        httpProxy = proxy

        proxy.start(
            onReady: { [weak self] in
                Task { @MainActor in
                    self?.isRunning = true
                    self?.log("Proxy started on localhost:\(self?.port ?? 0)", blocked: false)
                }
            },
            onFailed: { [weak self] error in
                Task { @MainActor in
                    self?.isRunning = false
                    self?.log("Proxy failed: \(error.localizedDescription)", blocked: true)
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
        log("Proxy stopped", blocked: false)
    }

    func clearLogs() {
        logs.removeAll()
    }

    private func handleRequestLog(_ requestLog: RequestLog) {
        stats.requestsScanned += 1

        if requestLog.detected {
            stats.injectionsBlocked += requestLog.matchCount
            log(
                "Blocked \(requestLog.matchCount) injection(s) in \(requestLog.method) \(requestLog.path) → \(requestLog.targetHost): \(requestLog.patternNames.joined(separator: ", "))",
                blocked: true
            )
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
