import Foundation

/// Thread-safe in-process metrics registry. Exposes counters,
/// per-category/severity tallies, a rolling latency histogram, and
/// a JSON snapshot surfaced in the diagnostics bundle (`DiagnosticsExport`).
/// Fed from the request funnel (`ProxyManager.handleRequestLog`).
///
/// Design:
/// - Actor-isolated so every mutation happens on the metrics serial queue
///   without blocking the proxy event loop.
/// - No external dependencies; snapshot is a plain `[String: Any]`-like
///   value encoded through `MetricsSnapshot` for type-safe JSON.
/// - Latency buckets match the Prometheus default (ms): 1, 5, 10, 25,
///   50, 100, 250, 500, 1000, +Inf. AI traffic clusters around 20-60ms
///   of scan time so this range gives useful detail without over-bucketing.
actor Metrics {
    static let shared = Metrics()

    init() {}

    // MARK: - State

    private(set) var startedAt = Date()
    private(set) var requestsTotal: UInt64 = 0
    private(set) var requestsBlocked: UInt64 = 0
    private(set) var requestsRewritten: UInt64 = 0
    private(set) var requestsOversized: UInt64 = 0
    private(set) var bytesScanned: UInt64 = 0
    private(set) var sseFramesScanned: UInt64 = 0
    private(set) var sseStreamsBlocked: UInt64 = 0

    /// Hits per detection category (role-hijack, credential-leak, …).
    private var hitsByCategory: [String: UInt64] = [:]
    /// Hits per severity level.
    private var hitsBySeverity: [String: UInt64] = [:]
    /// Hits per host (api.openai.com, …).
    private var blocksByHost: [String: UInt64] = [:]

    /// Histogram bucket upper bounds in milliseconds. The final bucket
    /// (`.greatestFiniteMagnitude`) is the +Inf tail — we use a finite
    /// sentinel so snapshots round-trip through standard JSON encoders.
    private static let latencyBucketsMs: [Double] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, .greatestFiniteMagnitude]
    private var latencyBuckets: [UInt64] = Array(repeating: 0, count: latencyBucketsMs.count)
    private var latencySumMs: Double = 0
    private var latencyCount: UInt64 = 0

    // MARK: - Public API

    func recordRequest(
        host: String,
        bodySize: Int,
        scanDurationSeconds: TimeInterval,
        detected: Bool,
        rewritten: Bool,
        oversized: Bool,
        categories: [String],
        severities: [String]
    ) {
        requestsTotal += 1
        bytesScanned += UInt64(max(0, bodySize))
        if detected { requestsBlocked += 1 }
        if rewritten { requestsRewritten += 1 }
        if oversized { requestsOversized += 1 }

        if detected {
            blocksByHost[host, default: 0] += 1
        }

        for cat in categories {
            hitsByCategory[cat, default: 0] += 1
        }
        for sev in severities {
            hitsBySeverity[sev, default: 0] += 1
        }

        recordLatency(scanDurationSeconds)
    }

    func recordSSEFrame(blocked: Bool) {
        sseFramesScanned += 1
        if blocked { sseStreamsBlocked += 1 }
    }

    func snapshot() -> MetricsSnapshot {
        MetricsSnapshot(
            uptimeSeconds: Date().timeIntervalSince(startedAt),
            requestsTotal: requestsTotal,
            requestsBlocked: requestsBlocked,
            requestsRewritten: requestsRewritten,
            requestsOversized: requestsOversized,
            bytesScanned: bytesScanned,
            sseFramesScanned: sseFramesScanned,
            sseStreamsBlocked: sseStreamsBlocked,
            hitsByCategory: hitsByCategory,
            hitsBySeverity: hitsBySeverity,
            blocksByHost: blocksByHost,
            latency: LatencySnapshot(
                bucketsMs: Self.latencyBucketsMs,
                counts: latencyBuckets,
                sumMs: latencySumMs,
                count: latencyCount
            )
        )
    }

    /// Reset state. Used by tests. (The diagnostics export snapshots
    /// without resetting, so counters persist across exports.)
    func reset() {
        startedAt = Date()
        requestsTotal = 0
        requestsBlocked = 0
        requestsRewritten = 0
        requestsOversized = 0
        bytesScanned = 0
        sseFramesScanned = 0
        sseStreamsBlocked = 0
        hitsByCategory.removeAll()
        hitsBySeverity.removeAll()
        blocksByHost.removeAll()
        latencyBuckets = Array(repeating: 0, count: Self.latencyBucketsMs.count)
        latencySumMs = 0
        latencyCount = 0
    }

    // MARK: - Private

    private func recordLatency(_ seconds: TimeInterval) {
        let ms = seconds * 1000
        latencySumMs += ms
        latencyCount += 1
        // Cumulative histogram: increment every bucket at or above the value
        for (i, bucket) in Self.latencyBucketsMs.enumerated() where ms <= bucket {
            latencyBuckets[i] += 1
        }
    }
}

// MARK: - Request mapping

extension Metrics {
    /// The request-scoped inputs a completed scan contributes to the
    /// registry, derived purely from a `RequestLog`. Kept as a separate
    /// value so the wiring (`RequestLog` → metric dimensions) is
    /// unit-testable without touching the shared actor.
    struct RequestSample: Sendable {
        let host: String
        let bodySize: Int
        let scanDurationSeconds: TimeInterval
        let detected: Bool
        let rewritten: Bool
        let oversized: Bool
        let categories: [String]
        let severities: [String]
    }

    /// Map a finished scan record to its metric contribution.
    static func sample(for log: RequestLog) -> RequestSample {
        RequestSample(
            host: log.targetHost,
            bodySize: log.bodySize,
            scanDurationSeconds: log.scanDurationSeconds,
            detected: log.detected,
            // The gateway relays the request byte-for-byte on the injection
            // path — only the multimodal path rewrites (stripped/redacted
            // attachments), so a rewrite means multimodal findings existed.
            rewritten: !(log.multimodal?.findings.isEmpty ?? true),
            // The oversize-reject path never reaches this funnel, so it is
            // counted elsewhere; a scanned request is never "oversized" here.
            oversized: false,
            categories: log.categories,
            severities: log.severities
        )
    }

    /// Record a mapped `RequestSample` — one value instead of eight args.
    func record(_ sample: RequestSample) {
        recordRequest(
            host: sample.host,
            bodySize: sample.bodySize,
            scanDurationSeconds: sample.scanDurationSeconds,
            detected: sample.detected,
            rewritten: sample.rewritten,
            oversized: sample.oversized,
            categories: sample.categories,
            severities: sample.severities
        )
    }
}

// MARK: - Snapshot types

struct MetricsSnapshot: Codable, Sendable {
    let uptimeSeconds: TimeInterval
    let requestsTotal: UInt64
    let requestsBlocked: UInt64
    let requestsRewritten: UInt64
    let requestsOversized: UInt64
    let bytesScanned: UInt64
    let sseFramesScanned: UInt64
    let sseStreamsBlocked: UInt64
    let hitsByCategory: [String: UInt64]
    let hitsBySeverity: [String: UInt64]
    let blocksByHost: [String: UInt64]
    let latency: LatencySnapshot
}

struct LatencySnapshot: Codable, Sendable {
    let bucketsMs: [Double]
    let counts: [UInt64]
    let sumMs: Double
    let count: UInt64

    var p50Ms: Double? { percentile(0.5) }
    var p95Ms: Double? { percentile(0.95) }
    var p99Ms: Double? { percentile(0.99) }

    private func percentile(_ p: Double) -> Double? {
        guard count > 0 else { return nil }
        let target = Double(count) * p
        var running: UInt64 = 0
        for (i, c) in counts.enumerated() {
            running += c
            if Double(running) >= target { return bucketsMs[i] }
        }
        return bucketsMs.last
    }
}
