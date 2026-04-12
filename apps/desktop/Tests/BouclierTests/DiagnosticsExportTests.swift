import Foundation
import Testing
@testable import Bouclier

@Suite("DiagnosticsExport")
struct DiagnosticsExportTests {
    private func makeMetricsSnapshot() -> MetricsSnapshot {
        MetricsSnapshot(
            uptimeSeconds: 3600,
            requestsTotal: 42,
            requestsBlocked: 3,
            requestsRewritten: 3,
            requestsOversized: 1,
            bytesScanned: 12345,
            sseFramesScanned: 100,
            sseStreamsBlocked: 1,
            hitsByCategory: ["role-hijack": 2, "credential-leak": 1],
            hitsBySeverity: ["critical": 2, "high": 1],
            blocksByHost: ["api.openai.com": 3],
            latency: LatencySnapshot(
                bucketsMs: [1, 5, 10, 25, 50, 100, 250, 500, 1000, .greatestFiniteMagnitude],
                counts: [0, 0, 5, 15, 20, 2, 0, 0, 0, 0],
                sumMs: 930,
                count: 42
            )
        )
    }

    @Test("Builds bundle from collected inputs")
    func buildsBundle() {
        let snap = makeMetricsSnapshot()
        let daily = [
            DailyStatsRow(date: "2026-04-05", requestsScanned: 42, injectionsBlocked: 3),
            DailyStatsRow(date: "2026-04-04", requestsScanned: 50, injectionsBlocked: 2),
        ]
        let logs = [
            ScanLogRow(
                id: 1,
                timestamp: "2026-04-05T12:00:00Z",
                source: "api-proxy",
                targetHost: "api.openai.com",
                detected: 1,
                matchCount: 2,
                patternIds: #"["role-001","exfil-001"]"#,
                severity: "critical",
                requestSize: 1024,
                mlScore: nil,
                entropyAnomaly: 0,
                fusedScore: 0,
                mlAvailable: 0
            ),
        ]

        let bundle = DiagnosticsExport.buildBundle(
            metricsSnapshot: snap,
            dailyStats: daily,
            recentLogs: logs,
            patternsLoaded: 161,
            patternsSHA256Prefix: "abcdef12",
            allowedHosts: ["api.openai.com", "api.anthropic.com"]
        )

        #expect(bundle.meta.patternsLoaded == 161)
        #expect(bundle.meta.patternsSHA256Prefix == "abcdef12")
        #expect(bundle.metrics.requestsTotal == 42)
        #expect(bundle.dailyStats.count == 2)
        #expect(bundle.recentEvents.count == 1)
        #expect(bundle.recentEvents[0].patternIds == ["role-001", "exfil-001"])
        #expect(bundle.recentEvents[0].targetHost == "api.openai.com")
        #expect(bundle.recentEvents[0].detected)
    }

    @Test("Strips target host when it's not on the allowlist")
    func stripsUnlistedHost() {
        let snap = makeMetricsSnapshot()
        let logs = [
            ScanLogRow(
                id: 1,
                timestamp: "2026-04-05T12:00:00Z",
                source: "api-proxy",
                targetHost: "evil.attacker.com",
                detected: 1,
                matchCount: 1,
                patternIds: #"["role-001"]"#,
                severity: "critical",
                requestSize: 512,
                mlScore: nil,
                entropyAnomaly: 0,
                fusedScore: 0,
                mlAvailable: 0
            ),
        ]

        let bundle = DiagnosticsExport.buildBundle(
            metricsSnapshot: snap,
            dailyStats: [],
            recentLogs: logs,
            patternsLoaded: 161,
            patternsSHA256Prefix: nil,
            allowedHosts: ["api.openai.com"]
        )

        #expect(bundle.recentEvents[0].targetHost == nil)
    }

    @Test("Decodes malformed patternIds JSON safely")
    func decodesMalformedIds() {
        let snap = makeMetricsSnapshot()
        let logs = [
            ScanLogRow(
                id: 1,
                timestamp: "2026-04-05T12:00:00Z",
                source: "api-proxy",
                targetHost: "api.openai.com",
                detected: 0,
                matchCount: 0,
                patternIds: "not json",
                severity: nil,
                requestSize: nil,
                mlScore: nil,
                entropyAnomaly: 0,
                fusedScore: 0,
                mlAvailable: 0
            ),
        ]

        let bundle = DiagnosticsExport.buildBundle(
            metricsSnapshot: snap,
            dailyStats: [],
            recentLogs: logs,
            patternsLoaded: 161,
            patternsSHA256Prefix: nil,
            allowedHosts: ["api.openai.com"]
        )

        #expect(bundle.recentEvents[0].patternIds.isEmpty)
    }

    @Test("Encodes bundle to stable JSON")
    func encodes() throws {
        let snap = makeMetricsSnapshot()
        let bundle = DiagnosticsExport.buildBundle(
            metricsSnapshot: snap,
            dailyStats: [],
            recentLogs: [],
            patternsLoaded: 161,
            patternsSHA256Prefix: nil,
            allowedHosts: []
        )
        let data = try DiagnosticsExport.encode(bundle)
        let string = String(data: data, encoding: .utf8) ?? ""
        #expect(string.contains("requestsTotal"))
        #expect(string.contains("hitsByCategory"))
        // JSON should not contain any raw request bodies or user input.
        #expect(!string.contains("prompt"))
    }

    @Test("Writes bundle file to disk")
    func writesToDisk() throws {
        let snap = makeMetricsSnapshot()
        let bundle = DiagnosticsExport.buildBundle(
            metricsSnapshot: snap,
            dailyStats: [],
            recentLogs: [],
            patternsLoaded: 161,
            patternsSHA256Prefix: nil,
            allowedHosts: []
        )
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("bouclier-ai-diag-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let url = try DiagnosticsExport.write(bundle, to: tmp)
        #expect(FileManager.default.fileExists(atPath: url.path))
        #expect(url.lastPathComponent.hasPrefix("bouclier-ai-diagnostics-"))
        #expect(url.pathExtension == "json")
    }
}
