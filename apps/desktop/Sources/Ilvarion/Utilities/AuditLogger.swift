import Foundation
import os.log

/// Structured audit logging for enterprise compliance.
///
/// Three output channels:
/// 1. os_log (always) — visible in Console.app and collected by MDM (Jamf, etc.)
/// 2. SQLite (always) — local scan_logs table via StorageManager
/// 3. Webhook (optional) — POST JSON to a SIEM endpoint (Splunk, Datadog, etc.)
///
/// Log format (JSON):
/// ```json
/// {
///   "timestamp": "2026-04-04T14:30:00Z",
///   "event": "injection_blocked",
///   "host": "api.openai.com",
///   "matchCount": 2,
///   "patterns": ["role-001", "exfil-001"],
///   "severity": "critical",
///   "bodySize": 4096,
///   "appVersion": "0.1.0"
/// }
/// ```
final class AuditLogger: Sendable {
    static let shared = AuditLogger()

    private let osLog = OSLog(subsystem: "com.ilvarion.app", category: "audit")
    private let encoder = JSONEncoder()
    private let webhookSession = URLSession(configuration: .ephemeral)

    private init() {
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = .sortedKeys
    }

    /// Log an injection detection event.
    func logDetection(host: String, matchCount: Int, patterns: [String], severity: String, bodySize: Int) {
        let entry = AuditEntry(
            timestamp: Date(),
            event: "injection_blocked",
            host: host,
            matchCount: matchCount,
            patterns: patterns,
            severity: severity,
            bodySize: bodySize,
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
        )

        // 1. os_log (always — collected by MDM tools like Jamf)
        if let json = try? encoder.encode(entry), let str = String(data: json, encoding: .utf8) {
            os_log(.default, log: osLog, "%{public}@", str)
        }

        // 2. Webhook (if configured via MDM or settings)
        if let urlString = ManagedConfig.webhookURL ?? UserDefaults.standard.string(forKey: "webhookURL"),
           let url = URL(string: urlString),
           let json = try? encoder.encode(entry)
        {
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue("Ilvarion/\(entry.appVersion)", forHTTPHeaderField: "User-Agent")
            request.httpBody = json
            request.timeoutInterval = 5

            webhookSession.dataTask(with: request).resume()
        }
    }

    /// Log a proxy lifecycle event (started, stopped, error).
    func logEvent(_ event: String, detail: String? = nil) {
        let message = detail != nil ? "\(event): \(detail!)" : event
        os_log(.default, log: osLog, "%{public}@", message)
    }
}

// MARK: - Audit Entry

private struct AuditEntry: Codable, Sendable {
    let timestamp: Date
    let event: String
    let host: String
    let matchCount: Int
    let patterns: [String]
    let severity: String
    let bodySize: Int
    let appVersion: String
}
