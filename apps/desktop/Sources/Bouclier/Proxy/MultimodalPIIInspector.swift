import Foundation

/// Glues the multimodal image extractor and the Vision-backed scanner
/// together so the proxy can call one entry point.
///
/// Per-image work runs concurrently inside a `TaskGroup` so a prompt
/// with N images takes roughly the wall-clock of the slowest scan,
/// not N × per-image. Output is one `Finding` per detected entity
/// (text PII or face), tagged with the JSON path of the image it
/// came from — the preview-modal renderer uses that path to render
/// each image's findings under its own header.
enum MultimodalPIIInspector {
    /// One PII finding tied back to a specific image inside the body.
    ///
    /// **`cleartextValue` invariant** — for `textPII` findings this
    /// carries the raw matched string (e.g. an email address or an
    /// IBAN). It MUST NOT be logged, persisted, surfaced via
    /// `os_log`, or included in any string interpolation that
    /// crosses a process boundary. The audit log table records
    /// only the entity type and a SHA-256 hash prefix, never this
    /// value. Renamed from `value` to make the contract explicit.
    struct Finding: Sendable, CustomStringConvertible {
        /// JSON path to the base64 *leaf* field inside the image
        /// shape (`image_url.url`, `source.data`, `inlineData.data`).
        /// Used by audit logs.
        let imagePath: [MultimodalImageExtractor.Image.PathComponent]
        /// JSON path to the *content block* surrounding the image
        /// (one level above `image_url` / `source` / `inlineData`).
        /// Used by the rewriter to swap the entire content block for
        /// a text placeholder.
        let contentBlockPath: [MultimodalImageExtractor.Image.PathComponent]
        let mediaType: String
        let provider: MultimodalImageExtractor.Image.Provider
        let category: Category
        /// Cleartext of the detected entity — see invariant above.
        let cleartextValue: String

        /// Render the finding without the cleartext. Anyone who
        /// `print`s or `os_log`s a Finding gets a redacted summary,
        /// not the raw value.
        var description: String {
            "Finding(category: \(category), mediaType: \(mediaType), provider: \(provider))"
        }

        enum Category: Sendable, Equatable {
            case textPII(type: String)
            case face(confidence: Float)
            /// Attachment was rejected without inspection — encrypted
            /// PDF, document past page cap, malformed file. Treated
            /// the same as a real finding by the rewriter so the
            /// content block gets stripped instead of forwarded.
            case unscannable(reason: PDFPIIScanner.ScanResult.UnscannableReason)
            /// Audio attachment was rejected without inspection —
            /// authorisation denied, format unsupported, too long.
            case unscannableAudio(reason: AudioPIIScanner.ScanResult.UnscannableReason)
        }
    }

    /// Aggregated scan report. `findings` is empty when nothing of
    /// interest was found. Per-media counts let the menu-bar UI
    /// distinguish "5 images, 1 PDF, 0 audio" without scanning the
    /// findings list.
    struct Report: Sendable {
        let imagesScanned: Int
        let pdfsScanned: Int
        let audioScanned: Int
        let findings: [Finding]
        let latencyMs: Double
    }

    /// Scan an audio attachment. Mirrors the PDF helper above but
    /// routes through `AudioPIIScanner` (SFSpeechRecognizer on-device).
    private static func audioFindings(for image: MultimodalImageExtractor.Image) async -> [Finding] {
        guard let result = try? await AudioPIIScanner.shared.scan(
            audioData: image.data, mediaType: image.mediaType
        ) else { return [] }
        var out: [Finding] = []
        if let reason = result.unscannable {
            out.append(Finding(
                imagePath: image.path,
                contentBlockPath: image.contentBlockPath,
                mediaType: image.mediaType,
                provider: image.provider,
                category: .unscannableAudio(reason: reason),
                cleartextValue: reason.rawValue
            ))
            return out
        }
        for det in result.piiDetections {
            out.append(Finding(
                imagePath: image.path,
                contentBlockPath: image.contentBlockPath,
                mediaType: image.mediaType,
                provider: image.provider,
                category: .textPII(type: det.type),
                cleartextValue: det.value
            ))
        }
        return out
    }

    /// Hard ceiling on images we'll scan per request. A prompt with
    /// 100 attached images is overwhelmingly accidental abuse (an
    /// SDK loop, a script generating fan-out) — once we're past this
    /// we abort the scan and pass through, on the theory that letting
    /// the legitimate request go through is better than the proxy
    /// OOMing.
    static let maxImagesPerRequest = 20

    /// Maximum number of Vision passes running concurrently. Each
    /// pass holds 80–150 MB peak; with `maxImagesPerRequest = 20` we
    /// could see ~3 GB peak without a throttle. The current cap
    /// matches typical M-series E-core count and keeps peak RSS
    /// under ~600 MB on the worst-case 20-image request.
    static let maxConcurrentScans = 4

    /// Inspect an outbound multimodal body. Always returns — errors
    /// from the Vision pipeline are swallowed and surface as an empty
    /// findings list so the proxy can always decide to forward.
    static func inspect(body: Data) async -> Report {
        let start = CFAbsoluteTimeGetCurrent()
        let images = MultimodalImageExtractor.extract(from: body)
        guard !images.isEmpty else {
            return Report(imagesScanned: 0, pdfsScanned: 0, audioScanned: 0,
                          findings: [], latencyMs: 0)
        }
        let imageCount = images.filter { $0.isImage }.count
        let pdfCount = images.filter { $0.isPDF }.count
        let audioCount = images.filter { $0.isAudio }.count
        // Cap the request — see `maxImagesPerRequest`. The proxy still
        // forwards the body unmodified (because we return an empty
        // findings list), so the user's prompt isn't dropped; we just
        // refuse to spend our Vision budget on an obvious fan-out.
        guard images.count <= maxImagesPerRequest else {
            return Report(imagesScanned: 0, pdfsScanned: 0, audioScanned: 0,
                          findings: [], latencyMs: 0)
        }

        let throttle = maxConcurrentScans
        let findings = await withTaskGroup(of: [Finding].self) { group -> [Finding] in
            var inFlight = 0
            var idx = 0
            // Prime the group up to the concurrency cap.
            while idx < images.count, inFlight < throttle {
                let image = images[idx]
                group.addTask { await Self.findings(for: image) }
                idx += 1
                inFlight += 1
            }
            var collected: [Finding] = []
            // Each finishing child task slot frees one in-flight unit;
            // we top up from `images` until they're all dispatched.
            while let chunk = await group.next() {
                collected.append(contentsOf: chunk)
                inFlight -= 1
                if idx < images.count {
                    let image = images[idx]
                    group.addTask { await Self.findings(for: image) }
                    idx += 1
                    inFlight += 1
                }
            }
            return collected
        }

        return Report(
            imagesScanned: imageCount,
            pdfsScanned: pdfCount,
            audioScanned: audioCount,
            findings: findings,
            latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000
        )
    }

    private static func findings(for image: MultimodalImageExtractor.Image) async -> [Finding] {
        // Route by media type. Images go through Vision OCR + face
        // detection. PDFs go through PDFKit text-layer + Vision OCR
        // fallback on scanned pages. Audio goes through SFSpeechRecognizer.
        // All paths end up producing PIIScanner detections that we map
        // into Finding instances on the same contentBlockPath, so the
        // rewriter doesn't care which pipeline produced them.
        if image.isAudio {
            return await audioFindings(for: image)
        }
        if image.isPDF {
            guard let pdfResult = try? await PDFPIIScanner.shared.scan(pdfData: image.data) else {
                return []
            }
            var out: [Finding] = []
            // Unscannable PDFs (encrypted, oversize, malformed) surface
            // as a synthetic finding so the rewriter still strips the
            // content. Silent pass-through of an un-inspected document
            // is a fail-open bug.
            if let reason = pdfResult.unscannable {
                out.append(Finding(
                    imagePath: image.path,
                    contentBlockPath: image.contentBlockPath,
                    mediaType: image.mediaType,
                    provider: image.provider,
                    category: .unscannable(reason: reason),
                    cleartextValue: reason.rawValue
                ))
                return out
            }
            for det in pdfResult.piiDetections {
                out.append(Finding(
                    imagePath: image.path,
                    contentBlockPath: image.contentBlockPath,
                    mediaType: image.mediaType,
                    provider: image.provider,
                    category: .textPII(type: det.type),
                    cleartextValue: det.value
                ))
            }
            for face in pdfResult.faces {
                out.append(Finding(
                    imagePath: image.path,
                    contentBlockPath: image.contentBlockPath,
                    mediaType: image.mediaType,
                    provider: image.provider,
                    category: .face(confidence: face.confidence),
                    cleartextValue: "face"
                ))
            }
            return out
        }
        guard let result = try? await MediaPIIScanner.shared.scan(imageData: image.data) else {
            return []
        }
        var out: [Finding] = []
        for det in result.piiDetections {
            out.append(Finding(
                imagePath: image.path,
                contentBlockPath: image.contentBlockPath,
                mediaType: image.mediaType,
                provider: image.provider,
                category: .textPII(type: det.type),
                cleartextValue: det.value
            ))
        }
        for face in result.faces {
            // Don't encode pixel coordinates into the value string —
            // the placeholder renderer counts faces from `category`
            // alone, and surfacing coordinates would leak more about
            // an image than the audit-log invariant ("type + offsets
            // only, never cleartext") allows.
            out.append(Finding(
                imagePath: image.path,
                contentBlockPath: image.contentBlockPath,
                mediaType: image.mediaType,
                provider: image.provider,
                category: .face(confidence: face.confidence),
                cleartextValue: "face"
            ))
        }
        return out
    }
}
