import Foundation
import NIOCore
import NIOHTTP1

/// Pure, testable helpers for inspecting an intercepted HTTP request.
///
/// `HTTPInspectionHandler` in `TLSProxy.swift` composes these with NIO
/// plumbing; unit tests exercise this type directly with no network or
/// channel setup needed.
enum HTTPRequestInspector {
    /// Maximum buffered request body, in bytes. A single request
    /// larger than this is rejected at the proxy to protect the event
    /// loop from OOM and slow-loris uploads. Sized to fit typical
    /// multimodal payloads — OpenAI vision images and Anthropic PDF
    /// documents routinely exceed 10 MB once base64-encoded, and
    /// Files API multipart uploads sit in the 5–50 MB range. Bodies
    /// past this cap are rejected with 413; true streaming inspection
    /// of larger uploads is out of scope here.
    static let maxBodyBytes = 64 * 1024 * 1024

    /// Maximum number of bytes buffered while waiting for the end of a
    /// CONNECT request line + headers. 8 KiB is well above any legitimate
    /// CONNECT header block and prevents slow-loris style buffer growth.
    static let maxConnectHeaderBytes = 8 * 1024

    /// Content-Type media types whose bodies we actually scan. Scanning
    /// binary uploads (images, audio, multipart form boundaries) wastes
    /// CPU and can trip false positives on byte sequences that happen
    /// to look like regex matches.
    static let scannableMediaPrefixes: [String] = [
        "application/json",
        "application/x-ndjson",
        "application/ld+json",
        "text/",
    ]

    /// Result of a full-request scan.
    struct InspectionResult: Sendable {
        /// True if the filter found at least one match anywhere (URI or body).
        let detected: Bool
        /// Count of distinct matches (URI + body combined).
        let matchCount: Int
        /// Names of patterns that matched. Deduplicated.
        let patternNames: [String]
        /// Categories that matched. Deduplicated.
        let categories: [String]
        /// Severities that matched. Deduplicated.
        let severities: [String]
        /// Body bytes after redaction. Equal to the input body when nothing
        /// was detected or when the body is non-scannable.
        let sanitizedBody: ByteBuffer
        /// True if the body was skipped because its content type is not
        /// scannable (binary upload, multipart form, etc.).
        let bodyScanSkipped: Bool
        /// True iff the body bytes were actually rewritten by the
        /// injection scanner (i.e. an injection pattern matched inside
        /// the body and the placeholder substitution ran). This is
        /// strictly narrower than `detected`, which also fires on
        /// URI-only matches that don't touch body bytes. Downstream
        /// passes (PII redaction, multimodal inspection) gate on this
        /// rather than on `detected` so URI-injection requests don't
        /// silently bypass body scanning.
        let bodyRewritten: Bool
        /// True if the request was rejected for exceeding `maxBodyBytes`.
        let rejectedOversize: Bool
        /// Highest ML maliciousness score across URI + body scans, or
        /// `nil` if the classifier wasn't consulted on either.
        let mlScore: Float?
        /// Highest entropy anomaly score across URI + body scans.
        let entropyAnomaly: Double
        /// Highest fused score across URI + body scans. The body is the
        /// long-form content that usually drives the decision; we take
        /// the max so a strong URI signal isn't lost.
        let fusedScore: Double
        /// True if the ML classifier ran on at least one of the
        /// URI/body scans. Used by the audit log to distinguish
        /// "ML cleared it" from "ML never ran".
        let mlAvailable: Bool
    }

    /// Result of a PII redaction pass on the post-injection-sanitized body.
    /// Returned separately from `InspectionResult` so the TLS handler can
    /// retain the per-connection session and apply reversal on the
    /// response without threading it through the inspection contract.
    struct PIIPass: Sendable {
        /// Body after PII tokens have been substituted in. Equal to the
        /// input when no PII was detected or when redaction is disabled.
        let body: ByteBuffer
        /// Per-redaction audit entries (type + offsets, never cleartext).
        let audit: [PIIRedactor.AuditEntry]
    }

    /// Result of a multimodal (image / PDF / audio) inspection pass.
    /// Returned alongside the text-PII pass so the TLS handler can
    /// audit + notify per blocked media item.
    struct MultimodalPass: Sendable {
        /// Body after flagged media have been replaced with text
        /// placeholders. Equal to the input when no media was flagged
        /// or when multimodal inspection is disabled.
        let body: ByteBuffer
        /// The full inspector report — surfaces image count and
        /// per-finding metadata for the audit log + notification UI.
        let report: MultimodalPIIInspector.Report
    }

    /// Wall-clock ceiling on `applyMultimodalInspection`. Beyond this
    /// the inspector is cancelled and the original body is forwarded
    /// with an `unscannable.timedOut`-style audit entry. Bounded so
    /// a single pathological request (50-page scanned PDF + 60-second
    /// audio + 18 images) can't blow past LLM-client read timeouts
    /// (Anthropic / OpenAI SDKs default to 60-120 s, beyond which the
    /// client times out and the user sees a confusing error).
    static let multimodalInspectionBudgetSeconds: Double = 30

    /// Run the multimodal inspector over a request body. Composed by
    /// the TLS handler after `inspect()` and the text PII pass.
    /// Idempotent and safe to call when
    /// `FeatureFlags.multimodalInspection` is off (returns the input
    /// unchanged with an empty report). Handles two body shapes:
    ///
    /// * JSON envelopes with base64-embedded media (OpenAI / Anthropic /
    ///   Gemini chat bodies). Routes via MultimodalPIIInspector +
    ///   MultimodalRewriter.
    /// * multipart/form-data uploads (OpenAI / Anthropic Files API,
    ///   transcription endpoints). Routes via MultipartMediaScanner.
    static func applyMultimodalInspection(
        body: ByteBuffer,
        contentType: String,
        method: HTTPMethod,
        allocator: ByteBufferAllocator
    ) async -> MultimodalPass {
        let empty = MultimodalPass(
            body: body,
            report: MultimodalPIIInspector.Report(imagesScanned: 0, pdfsScanned: 0, audioScanned: 0, findings: [], latencyMs: 0)
        )
        guard FeatureFlags.multimodalInspection else { return empty }
        guard body.readableBytes > 0,
              method != .GET, method != .HEAD, method != .DELETE,
              method != .OPTIONS, method != .CONNECT, method != .TRACE
        else { return empty }
        // Single-copy `Data` from the ByteBuffer rather than
        // `getBytes` → `[UInt8]` → `Data(_)` which copies twice. On a
        // 64 MB body this saves a full allocation per request.
        let bodyData = Data(body.readableBytesView)

        // Race the inspector against the wall-clock budget. If
        // inspection takes too long (pathological PDF / audio) we
        // forward the original body untouched rather than holding
        // the client connection open past its read timeout — failing
        // open with a loud log line is better UX than failing
        // closed-with-timeout in the v0.4.x band. A future MDM key
        // can flip this to fail-closed for regulated deployments.
        let ct = contentType.lowercased()
        return await withTimeoutOrFallback(seconds: multimodalInspectionBudgetSeconds, fallback: empty) {
            if ct.hasPrefix("multipart/") {
                if let result = await MultipartMediaScanner.inspect(body: bodyData, contentType: contentType) {
                    if result.report.findings.isEmpty {
                        return MultimodalPass(body: body, report: result.report)
                    }
                    var buf = allocator.buffer(capacity: result.body.count)
                    buf.writeBytes(result.body)
                    return MultimodalPass(body: buf, report: result.report)
                }
                return empty
            }
            guard shouldScanBody(contentType: contentType, method: method) else { return empty }
            let report = await MultimodalPIIInspector.inspect(body: bodyData)
            guard !report.findings.isEmpty else {
                return MultimodalPass(body: body, report: report)
            }
            let rewritten = MultimodalRewriter.stripFlaggedImages(from: bodyData, report: report)
            var buf = allocator.buffer(capacity: rewritten.count)
            buf.writeBytes(rewritten)
            return MultimodalPass(body: buf, report: report)
        }
    }

    /// Race an async operation against a wall-clock deadline. Returns
    /// the fallback value when the deadline expires before the work
    /// finishes; the work's task is cancelled so any Vision / Speech /
    /// PDFKit task in flight propagates `Task.isCancelled` and bails
    /// out. Logs a single line on timeout so an operator can see the
    /// drop in the proxy log without parsing the stats.
    private static func withTimeoutOrFallback<T: Sendable>(
        seconds: Double,
        fallback: T,
        operation: @escaping @Sendable () async -> T
    ) async -> T {
        await withTaskGroup(of: T?.self) { group in
            group.addTask {
                await operation()
            }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return nil  // sentinel: deadline expired
            }
            defer { group.cancelAll() }
            guard let first = await group.next() else { return fallback }
            if let value = first {
                return value
            }
            print("[bouclier.ai] multimodal inspection exceeded \(seconds)s budget — forwarding unchanged")
            return fallback
        }
    }

    /// Run the PII redactor over a sanitized request body. Composed by
    /// the TLS handler *after* `inspect()` so injection-blocked bodies
    /// never reach the PII pass. Idempotent and safe to call when
    /// `FeatureFlags.piiRedaction` is off (returns the input unchanged).
    static func applyPIIRedaction(
        body: ByteBuffer,
        contentType: String,
        method: HTTPMethod,
        redactor: PIIRedactor,
        session: PIISession,
        allocator: ByteBufferAllocator
    ) async -> PIIPass {
        guard FeatureFlags.piiRedaction else {
            return PIIPass(body: body, audit: [])
        }
        guard shouldScanBody(contentType: contentType, method: method),
              body.readableBytes > 0,
              let text = body.getString(at: body.readerIndex, length: body.readableBytes)
        else {
            return PIIPass(body: body, audit: [])
        }
        let (redacted, audit) = await redactor.redact(text, with: session)
        if audit.isEmpty {
            return PIIPass(body: body, audit: [])
        }
        var buf = allocator.buffer(capacity: redacted.utf8.count)
        buf.writeString(redacted)
        return PIIPass(body: buf, audit: audit)
    }

    /// Inspect a complete HTTP request. Returns nil only if the request
    /// must be dropped entirely (oversized body).
    static func inspect(
        head: HTTPRequestHead,
        body: ByteBuffer,
        filter: InjectionFilter,
        allocator: ByteBufferAllocator
    ) -> InspectionResult {
        let bodySize = body.readableBytes

        if bodySize > maxBodyBytes {
            return InspectionResult(
                detected: false,
                matchCount: 0,
                patternNames: [],
                categories: [],
                severities: [],
                sanitizedBody: body,
                bodyScanSkipped: true,
                bodyRewritten: false,
                rejectedOversize: true,
                mlScore: nil,
                entropyAnomaly: 0,
                fusedScore: 0,
                mlAvailable: false
            )
        }

        // Scan the request URI — injection vectors hide in query
        // parameters (e.g. ?q=ignore+previous+instructions). Decode URL
        // encoding first so `+` and `%20` become real spaces that the
        // regex patterns can match against. Can be disabled via the
        // `uriScanning` feature flag for legacy deployments.
        let uriScan: FilterResult
        if FeatureFlags.uriScanning {
            uriScan = filter.scan(decodeURI(head.uri))
        } else {
            uriScan = FilterResult(matchCount: 0, patternNames: [], sanitized: "")
        }

        let contentType = head.headers.first(name: "Content-Type") ?? ""
        let scannable = shouldScanBody(contentType: contentType, method: head.method)

        guard scannable, bodySize > 0,
              let bodyString = body.getString(at: body.readerIndex, length: bodySize)
        else {
            return InspectionResult(
                detected: uriScan.detected,
                matchCount: uriScan.matchCount,
                patternNames: uriScan.patternNames,
                categories: uriScan.categories,
                severities: uriScan.severities,
                sanitizedBody: body,
                bodyScanSkipped: !scannable,
                bodyRewritten: false,
                rejectedOversize: false,
                mlScore: uriScan.mlScore,
                entropyAnomaly: uriScan.entropyAnomaly,
                fusedScore: uriScan.fusedScore,
                mlAvailable: uriScan.mlAvailable
            )
        }

        let bodyScan = filter.scan(bodyString)

        let detected = uriScan.detected || bodyScan.detected
        let matchCount = uriScan.matchCount + bodyScan.matchCount
        let names = Array(Set(uriScan.patternNames + bodyScan.patternNames))
        let categories = Array(Set(uriScan.categories + bodyScan.categories))
        let severities = Array(Set(uriScan.severities + bodyScan.severities))

        // Take the max of each fused-scoring signal across URI + body
        // scans. The body usually dominates, but we don't want a high
        // URI score to disappear.
        let mlScore = combinedMax(uriScan.mlScore, bodyScan.mlScore)
        let entropyAnomaly = max(uriScan.entropyAnomaly, bodyScan.entropyAnomaly)
        let fusedScore = max(uriScan.fusedScore, bodyScan.fusedScore)
        let mlAvailable = uriScan.mlAvailable || bodyScan.mlAvailable

        let sanitized: ByteBuffer
        if bodyScan.detected {
            var buf = allocator.buffer(capacity: bodyScan.sanitized.utf8.count)
            buf.writeString(bodyScan.sanitized)
            sanitized = buf
        } else {
            sanitized = body
        }

        return InspectionResult(
            detected: detected,
            matchCount: matchCount,
            patternNames: names,
            categories: categories,
            severities: severities,
            sanitizedBody: sanitized,
            bodyScanSkipped: false,
            bodyRewritten: bodyScan.detected,
            rejectedOversize: false,
            mlScore: mlScore,
            entropyAnomaly: entropyAnomaly,
            fusedScore: fusedScore,
            mlAvailable: mlAvailable
        )
    }

    /// Max of two optional Floats. Treats `nil` as "no signal" so a
    /// real value always wins over the absence of one.
    private static func combinedMax(_ a: Float?, _ b: Float?) -> Float? {
        switch (a, b) {
        case (nil, nil): return nil
        case (let x?, nil): return x
        case (nil, let y?): return y
        case (let x?, let y?): return max(x, y)
        }
    }

    /// Decide whether to scan the body based on method + Content-Type.
    /// GET/HEAD/DELETE requests rarely carry scan-worthy bodies.
    static func shouldScanBody(contentType: String, method: HTTPMethod) -> Bool {
        switch method {
        case .GET, .HEAD, .DELETE, .OPTIONS, .CONNECT, .TRACE:
            return false
        default:
            break
        }
        if contentType.isEmpty { return true } // be conservative
        let lower = contentType.lowercased()
        return scannableMediaPrefixes.contains(where: { lower.hasPrefix($0) })
    }

    /// Decode `+` → space and percent-escapes so query parameters can be
    /// scanned in their decoded form. Falls back to the raw string when
    /// percent-decoding fails so we still scan something.
    static func decodeURI(_ uri: String) -> String {
        let plus = uri.replacingOccurrences(of: "+", with: " ")
        return plus.removingPercentEncoding ?? plus
    }

    /// Parse and validate a CONNECT target of the form `host:port`.
    ///
    /// Rejects:
    /// - empty or missing host
    /// - embedded CR/LF (header-injection attempts)
    /// - whitespace, control, or null characters
    /// - ports outside 1…65535
    ///
    /// Returns the parsed host and port on success, nil on failure.
    static func parseConnectTarget(_ target: String) -> (host: String, port: Int)? {
        guard !target.isEmpty, target.count <= 253 + 6 else { return nil }

        // Reject control characters (CR/LF injection, null bytes).
        for scalar in target.unicodeScalars {
            if scalar.value < 0x21 || scalar.value == 0x7F { return nil }
        }

        let parts = target.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2 else { return nil }

        // Delegate full RFC 1123 validation (label length, leading/trailing
        // hyphen, lowercasing) to the shared validator.
        guard let host = ManagedConfigValidator.validatedHostname(String(parts[0])) else {
            return nil
        }

        guard let port = Int(parts[1]), (1...65535).contains(port) else { return nil }
        return (host, port)
    }
}
