import Foundation
import NIOCore
import NIOHTTP1

/// Pure, testable helpers for inspecting an intercepted HTTP request.
///
/// `HTTPInspectionHandler` in `TLSProxy.swift` composes these with NIO
/// plumbing; unit tests exercise this type directly with no network or
/// channel setup needed.
enum HTTPRequestInspector {
    /// Maximum buffered request body, in bytes. A single request larger
    /// than this is rejected at the proxy to protect the event loop from
    /// OOM / slow-loris uploads. AI chat payloads are well under 1 MB in
    /// practice; we keep generous headroom for long document-grounded
    /// prompts while still bounding the blast radius.
    static let maxBodyBytes = 10 * 1024 * 1024

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

    /// Run the multimodal inspector over a request body. Composed by
    /// the TLS handler after `inspect()` and the text PII pass.
    /// Idempotent and safe to call when
    /// `FeatureFlags.multimodalInspection` is off (returns the input
    /// unchanged with an empty report).
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
        guard shouldScanBody(contentType: contentType, method: method),
              body.readableBytes > 0
        else { return empty }
        // Snapshot the body to a Data so JSONSerialization can chew on
        // it. ByteBuffer's `getBytes` returns nil only on a malformed
        // index range, which we never construct.
        guard let bytes = body.getBytes(at: body.readerIndex, length: body.readableBytes) else {
            return empty
        }
        let bodyData = Data(bytes)
        let report = await MultimodalPIIInspector.inspect(body: bodyData)
        guard !report.findings.isEmpty else {
            return MultimodalPass(body: body, report: report)
        }
        let rewritten = MultimodalRewriter.stripFlaggedImages(from: bodyData, report: report)
        var buf = allocator.buffer(capacity: rewritten.count)
        buf.writeBytes(rewritten)
        return MultimodalPass(body: buf, report: report)
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
