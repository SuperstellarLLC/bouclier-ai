import Foundation

/// Generates a single-file diagnostics bundle suitable for handing to
/// support or enterprise security teams during triage.
///
/// The bundle is a JSON document containing:
///   - `meta`        : app/version/os fingerprint (no user identifiers)
///   - `metrics`     : `MetricsSnapshot` from the in-process registry
///   - `dailyStats`  : rolling 30-day requests/injections per day
///   - `recentEvents`: last N scan-log rows with pattern/severity only
///                     (no request bodies, no URIs, no hosts beyond the
///                     built-in allowlist)
///
/// Privacy: the diagnostics bundle never contains request payloads,
/// URLs, headers, or any user identifier. It is safe to attach to a
/// support ticket or share with enterprise SOC.
enum DiagnosticsExport {
    struct Bundle: Codable {
        let meta: Meta
        let metrics: MetricsSnapshot
        let dailyStats: [DailyStatEntry]
        let recentEvents: [EventEntry]

        struct Meta: Codable {
            let appVersion: String
            let bundleIdentifier: String
            let osVersion: String
            let generatedAt: Date
            let patternsLoaded: Int
            let patternsSHA256Prefix: String?
        }

        struct DailyStatEntry: Codable {
            let date: String
            let requestsScanned: Int
            let injectionsBlocked: Int
        }

        struct EventEntry: Codable {
            let timestamp: String
            let source: String
            let targetHost: String?
            let detected: Bool
            let matchCount: Int
            let patternIds: [String]
            let severity: String?
        }
    }

    /// Build a diagnostics bundle. All parameters are injected so the
    /// function is pure and trivially testable.
    static func buildBundle(
        metricsSnapshot: MetricsSnapshot,
        dailyStats: [DailyStatsRow],
        recentLogs: [ScanLogRow],
        patternsLoaded: Int,
        patternsSHA256Prefix: String?,
        allowedHosts: Set<String>,
        now: Date = Date()
    ) -> Bundle {
        let meta = Bundle.Meta(
            appVersion: Self.appVersion(),
            bundleIdentifier: Bundle.bundleIdentifier(),
            osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            generatedAt: now,
            patternsLoaded: patternsLoaded,
            patternsSHA256Prefix: patternsSHA256Prefix
        )

        let daily = dailyStats.map {
            Bundle.DailyStatEntry(
                date: $0.date,
                requestsScanned: $0.requestsScanned,
                injectionsBlocked: $0.injectionsBlocked
            )
        }

        let events = recentLogs.map { row -> Bundle.EventEntry in
            // Only include the target host if it's on the allowlist.
            // Anything else must have been a misconfigured request and
            // should not be disclosed in a diagnostics bundle.
            let safeHost = row.targetHost.flatMap { allowedHosts.contains($0) ? $0 : nil }
            let ids = row.patternIds.flatMap { Self.decodePatternIds($0) } ?? []
            return Bundle.EventEntry(
                timestamp: row.timestamp,
                source: row.source,
                targetHost: safeHost,
                detected: row.detected != 0,
                matchCount: row.matchCount,
                patternIds: ids,
                severity: row.severity
            )
        }

        return Bundle(
            meta: meta,
            metrics: metricsSnapshot,
            dailyStats: daily,
            recentEvents: events
        )
    }

    /// Serialize a bundle as pretty-printed JSON.
    static func encode(_ bundle: Bundle) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(bundle)
    }

    /// Write a bundle to disk and return the URL. Caller is responsible
    /// for revealing or sharing the file.
    static func write(_ bundle: Bundle, to directory: URL) throws -> URL {
        let stamp = ISO8601DateFormatter().string(from: bundle.meta.generatedAt)
            .replacingOccurrences(of: ":", with: "-")
        let url = directory.appendingPathComponent("bouclier-ai-diagnostics-\(stamp).json")
        let data = try encode(bundle)
        try data.write(to: url, options: .atomic)
        return url
    }

    // MARK: - Private

    private static func decodePatternIds(_ json: String) -> [String]? {
        guard let data = json.data(using: .utf8) else { return nil }
        return try? JSONDecoder().decode([String].self, from: data)
    }

    private static func appVersion() -> String {
        Foundation.Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
    }
}

private extension DiagnosticsExport.Bundle {
    static func bundleIdentifier() -> String {
        Foundation.Bundle.main.bundleIdentifier ?? "ai.bouclier.app"
    }
}
