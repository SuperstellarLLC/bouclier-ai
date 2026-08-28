import Foundation

// MARK: - Request Log

enum InjectionScanSkipReason: String, Sendable {
    case protectionDisabled = "protection-disabled"
    case engineUnavailable = "engine-unavailable"
    case oversized = "oversized"
    case unsupportedContentEncoding = "unsupported-content-encoding"
}

struct RequestLog: Sendable {
    let timestamp: Date
    let targetHost: String
    let detected: Bool
    let matchCount: Int
    let patternNames: [String]
    let bodySize: Int
    // Fused scoring telemetry — populated by InjectionFilter.scan().
    // mlScore is nil when the classifier wasn't consulted; mlAvailable
    // distinguishes "ML cleared this" from "ML never ran".
    let mlScore: Float?
    let entropyAnomaly: Double
    let fusedScore: Double
    let mlAvailable: Bool
    /// A detector finding that was deliberately forwarded (monitor mode,
    /// below the enforcement threshold, or operator release). Separate from
    /// `detected`, which means the request was actually refused.
    let injectionFlagged: Bool
    /// True only when the injection gate/engine inspected this request.
    /// Passthrough and limit skips must not inflate "requests inspected" or
    /// bytes-scanned telemetry.
    let inspectionPerformed: Bool
    let scanSkippedReason: InjectionScanSkipReason?
    /// Detection categories and severities that fired on this request,
    /// aggregated across findings. Feed the diagnostics metrics registry's
    /// per-category / per-severity tallies. Empty when nothing matched.
    let categories: [String]
    let severities: [String]
    /// Time spent scanning this request, in seconds. Feeds the metrics
    /// latency histogram. Zero for requests that skipped inspection (no
    /// untrusted content, or the engine wasn't ready).
    let scanDurationSeconds: TimeInterval
    /// Multimodal scan report. Nil when multimodal inspection didn't
    /// run for this request (feature off, etc.); empty findings when
    /// it ran and the attachments were clean.
    let multimodal: MultimodalPIIInspector.Report?

    /// Salted fingerprint of the untrusted span that drove a block, when
    /// this request was refused. Lets the UI offer "release this span"
    /// (add to `SpanAllowlist`) so a persistent false positive can be
    /// recovered from. Nil for non-block logs and ML/entropy blocks that
    /// left no fingerprint.
    let spanFingerprint: String?

    /// JSON path of the untrusted span that drove a block (e.g.
    /// `messages[2].content[0].tool_result`) — structural metadata, never
    /// the span's content. Surfaced in the block notification so the
    /// operator can locate the offending span without the adversarial text
    /// being broadcast. Nil for non-block logs.
    let locator: String?

    init(
        timestamp: Date,
        targetHost: String,
        detected: Bool,
        matchCount: Int,
        patternNames: [String],
        bodySize: Int,
        mlScore: Float?,
        entropyAnomaly: Double,
        fusedScore: Double,
        mlAvailable: Bool,
        multimodal: MultimodalPIIInspector.Report? = nil,
        spanFingerprint: String? = nil,
        locator: String? = nil,
        categories: [String] = [],
        severities: [String] = [],
        scanDurationSeconds: TimeInterval = 0,
        injectionFlagged: Bool = false,
        inspectionPerformed: Bool = true,
        scanSkippedReason: InjectionScanSkipReason? = nil
    ) {
        self.timestamp = timestamp
        self.targetHost = targetHost
        self.detected = detected
        self.matchCount = matchCount
        self.patternNames = patternNames
        self.bodySize = bodySize
        self.mlScore = mlScore
        self.entropyAnomaly = entropyAnomaly
        self.fusedScore = fusedScore
        self.mlAvailable = mlAvailable
        self.injectionFlagged = injectionFlagged
        self.inspectionPerformed = inspectionPerformed
        self.scanSkippedReason = scanSkippedReason
        self.categories = categories
        self.severities = severities
        self.scanDurationSeconds = scanDurationSeconds
        self.multimodal = multimodal
        self.spanFingerprint = spanFingerprint
        self.locator = locator
    }
}
