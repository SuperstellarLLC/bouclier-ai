import Foundation
import Testing
@testable import Bouclier

@Suite("Metrics")
struct MetricsTests {
    @Test("Records per-category and per-severity counts")
    func recordsHitBreakdown() async {
        let metrics = Metrics()
        await metrics.recordRequest(
            host: "api.openai.com",
            bodySize: 1024,
            scanDurationSeconds: 0.012,
            detected: true,
            rewritten: true,
            oversized: false,
            categories: ["role-hijack", "data-exfiltration"],
            severities: ["critical"]
        )
        await metrics.recordRequest(
            host: "api.openai.com",
            bodySize: 512,
            scanDurationSeconds: 0.004,
            detected: true,
            rewritten: false,
            oversized: false,
            categories: ["role-hijack"],
            severities: ["high"]
        )

        let snap = await metrics.snapshot()
        #expect(snap.requestsTotal == 2)
        #expect(snap.requestsBlocked == 2)
        #expect(snap.requestsRewritten == 1)
        #expect(snap.hitsByCategory["role-hijack"] == 2)
        #expect(snap.hitsByCategory["data-exfiltration"] == 1)
        #expect(snap.hitsBySeverity["critical"] == 1)
        #expect(snap.hitsBySeverity["high"] == 1)
        #expect(snap.blocksByHost["api.openai.com"] == 2)
        #expect(snap.bytesScanned == 1536)
    }

    @Test("Tracks oversized requests separately")
    func tracksOversized() async {
        let metrics = Metrics()
        await metrics.recordRequest(
            host: "api.anthropic.com",
            bodySize: 50_000_000,
            scanDurationSeconds: 0,
            detected: false,
            rewritten: false,
            oversized: true,
            categories: [],
            severities: []
        )
        let snap = await metrics.snapshot()
        #expect(snap.requestsOversized == 1)
        #expect(snap.requestsBlocked == 0)
    }

    @Test("SSE frame counter tracks blocked streams")
    func tracksSSE() async {
        let metrics = Metrics()
        await metrics.recordSSEFrame(blocked: false)
        await metrics.recordSSEFrame(blocked: false)
        await metrics.recordSSEFrame(blocked: true)
        let snap = await metrics.snapshot()
        #expect(snap.sseFramesScanned == 3)
        #expect(snap.sseStreamsBlocked == 1)
    }

    @Test("Latency histogram buckets increment correctly")
    func latencyBuckets() async {
        let metrics = Metrics()
        let durations: [TimeInterval] = [0.0005, 0.004, 0.009, 0.024, 0.050, 0.120, 0.600, 2.0]
        for d in durations {
            await metrics.recordRequest(
                host: "api.openai.com",
                bodySize: 0,
                scanDurationSeconds: d,
                detected: false,
                rewritten: false,
                oversized: false,
                categories: [],
                severities: []
            )
        }
        let snap = await metrics.snapshot()
        #expect(snap.latency.count == UInt64(durations.count))
        #expect(snap.latency.p50Ms != nil)
        #expect(snap.latency.p95Ms != nil)
        #expect(snap.latency.p99Ms != nil)
        // sum ≈ 2807.5 ms (0.5 + 4 + 9 + 24 + 50 + 120 + 600 + 2000)
        #expect(snap.latency.sumMs > 2800 && snap.latency.sumMs < 2810)
    }

    @Test("Snapshot encodes to valid JSON")
    func snapshotEncodes() async throws {
        let metrics = Metrics()
        await metrics.recordRequest(
            host: "api.openai.com",
            bodySize: 123,
            scanDurationSeconds: 0.015,
            detected: true,
            rewritten: true,
            oversized: false,
            categories: ["role-hijack"],
            severities: ["critical"]
        )
        let snap = await metrics.snapshot()
        let data = try JSONEncoder().encode(snap)
        #expect(data.count > 0)
        let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(obj?["requestsTotal"] as? Int == 1)
    }

    @Test("Reset clears state")
    func resetsState() async {
        let metrics = Metrics()
        await metrics.recordRequest(
            host: "api.openai.com", bodySize: 0, scanDurationSeconds: 0,
            detected: true, rewritten: false, oversized: false,
            categories: ["x"], severities: ["critical"]
        )
        await metrics.reset()
        let snap = await metrics.snapshot()
        #expect(snap.requestsTotal == 0)
        #expect(snap.hitsByCategory.isEmpty)
    }
}
