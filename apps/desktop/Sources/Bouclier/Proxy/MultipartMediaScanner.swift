import Foundation

/// Scans a `multipart/form-data` request body for PII in file parts
/// and rewrites the body, replacing flagged file parts with text
/// parts that explain what was blocked.
///
/// Phase 4 scope: file uploads to LLM-provider Files APIs (OpenAI's
/// `POST /v1/files`, Anthropic's `POST /v1/files`, the OpenAI
/// `audio/transcriptions` and `audio/translations` endpoints).
/// Each file part's Content-Type is the routing key:
///
/// * `image/*` → MediaPIIScanner
/// * `application/pdf` → PDFPIIScanner
/// * `audio/*` → AudioPIIScanner
/// * anything else → passed through unmodified
///
/// The non-file parts (purpose, model, language, etc.) ride through
/// untouched. On the no-findings path we return the original body
/// bytes — byte-for-byte, so any upstream HMAC-of-body or content-
/// hash trace ID survives.
enum MultipartMediaScanner {
    struct InspectResult: Sendable {
        /// The rewritten body. Equal to the input bytes when no part
        /// had findings.
        let body: Data
        /// Aggregated inspector report so the caller can log, count,
        /// and notify on findings.
        let report: MultimodalPIIInspector.Report
    }

    /// Inspect a multipart body. Returns nil if the body isn't
    /// parseable as multipart (lets the caller fall back to whatever
    /// it would have done before).
    static func inspect(body: Data, contentType: String) async -> InspectResult? {
        guard let boundary = MultipartParser.boundary(from: contentType),
              let parts = MultipartParser.parse(body: body, contentType: contentType)
        else { return nil }

        // Identify file parts that need inspection. Routing dispatches
        // on Content-Type first; for `application/octet-stream` (the
        // default `curl -F file=@x` and `python requests.post(files=...)`
        // emit for everything without a `--mime-type` override), we
        // sniff the first 16 bytes for known magic numbers — without
        // this fallback, a PDF uploaded as octet-stream would silently
        // bypass inspection and break the "every file scanned" claim.
        var fileScans: [(partIndex: Int, scanType: ScanType)] = []
        for (idx, part) in parts.enumerated() {
            guard part.filename != nil else { continue }
            let ct = part.contentType.lowercased()
            if ct.hasPrefix("image/") {
                fileScans.append((idx, .image))
            } else if ct.hasPrefix("application/pdf") {
                fileScans.append((idx, .pdf))
            } else if ct.hasPrefix("audio/") {
                fileScans.append((idx, .audio))
            } else if ct.hasPrefix("application/octet-stream") || ct.hasPrefix("text/plain") {
                let prefix = part.bodyData(in: body).prefix(16)
                if let inferred = sniffMediaType(prefix) {
                    fileScans.append((idx, inferred))
                }
            }
        }
        guard !fileScans.isEmpty else {
            return InspectResult(
                body: body,
                report: MultimodalPIIInspector.Report(
                    imagesScanned: 0, pdfsScanned: 0, audioScanned: 0,
                    findings: [], latencyMs: 0
                )
            )
        }

        let start = CFAbsoluteTimeGetCurrent()
        var imageCount = 0, pdfCount = 0, audioCount = 0
        var allFindings: [PartFinding] = []

        // Reuse the same 4-concurrency throttle as MultimodalPIIInspector
        // so a multipart with 20 images can't spike RAM past the budget.
        let throttle = MultimodalPIIInspector.maxConcurrentScans
        await withTaskGroup(of: PartFinding?.self) { group -> Void in
            var iter = fileScans.makeIterator()
            var inFlight = 0
            func dispatch(_ next: (partIndex: Int, scanType: ScanType)?) {
                guard let next else { return }
                let part = parts[next.partIndex]
                let bodyData = part.bodyData(in: body)
                let mediaType = part.contentType
                let scanType = next.scanType
                let partIdx = next.partIndex
                group.addTask {
                    let finds = await scan(bodyData: bodyData, mediaType: mediaType, scanType: scanType)
                    return PartFinding(partIndex: partIdx, scanType: scanType, findings: finds)
                }
                inFlight += 1
            }
            for _ in 0..<throttle {
                dispatch(iter.next())
            }
            for await result in group {
                inFlight -= 1
                if let result {
                    switch result.scanType {
                    case .image: imageCount += 1
                    case .pdf: pdfCount += 1
                    case .audio: audioCount += 1
                    }
                    allFindings.append(result)
                }
                dispatch(iter.next())
            }
            _ = inFlight
        }

        let flatFindings = allFindings.flatMap { partFinding -> [MultimodalPIIInspector.Finding] in
            partFinding.findings.map { f in
                // Use a synthetic JSON path of `[.key("multipart-part-<idx>")]`
                // so the rewriter (text-PII / image-side) won't mistake
                // it for a real JSON envelope. The multipart rewriter
                // below keys off the part index directly.
                MultimodalPIIInspector.Finding(
                    imagePath: [.key("multipart-part-\(partFinding.partIndex)")],
                    contentBlockPath: [.key("multipart-part-\(partFinding.partIndex)")],
                    mediaType: f.mediaType,
                    provider: .unknown,
                    category: f.category,
                    cleartextValue: f.cleartextValue
                )
            }
        }

        // Build the rewritten body if any findings exist.
        let rewritten: Data
        if flatFindings.isEmpty {
            rewritten = body  // byte-stable on the clean path
        } else {
            let dirtyIndices = Set(allFindings
                .filter { !$0.findings.isEmpty }
                .map { $0.partIndex })
            let placeholderByIndex = Dictionary(
                uniqueKeysWithValues: allFindings
                    .filter { dirtyIndices.contains($0.partIndex) }
                    .map { ($0.partIndex, placeholder(for: $0.findings)) }
            )
            rewritten = rebuild(body: body, parts: parts, boundary: boundary,
                                dirty: dirtyIndices, placeholders: placeholderByIndex)
        }

        return InspectResult(
            body: rewritten,
            report: MultimodalPIIInspector.Report(
                imagesScanned: imageCount,
                pdfsScanned: pdfCount,
                audioScanned: audioCount,
                findings: flatFindings,
                latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000
            )
        )
    }

    // MARK: - Internals

    enum ScanType: Sendable {
        case image, pdf, audio
    }

    /// Magic-byte sniffer for the most common file shapes a user
    /// might upload as `application/octet-stream` or `text/plain`.
    /// Returns nil for unknown types — the part rides through
    /// unchanged. Deliberately conservative: false positives here
    /// route real-world files to the wrong scanner, which then
    /// returns `.unsupportedFormat` and the rewriter still strips
    /// them — annoying but not unsafe.
    static func sniffMediaType(_ prefix: Data) -> ScanType? {
        let b = Array(prefix)
        if b.count >= 4 && b[0] == 0x25 && b[1] == 0x50 && b[2] == 0x44 && b[3] == 0x46 {
            return .pdf  // "%PDF"
        }
        if b.count >= 8 && b[0] == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47 {
            return .image  // PNG
        }
        if b.count >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF {
            return .image  // JPEG
        }
        if b.count >= 4 && b[0] == 0x47 && b[1] == 0x49 && b[2] == 0x46 && b[3] == 0x38 {
            return .image  // GIF87a / GIF89a
        }
        if b.count >= 12 && b[0] == 0x52 && b[1] == 0x49 && b[2] == 0x46 && b[3] == 0x46
            && b[8] == 0x57 && b[9] == 0x45 && b[10] == 0x42 && b[11] == 0x50 {
            return .image  // RIFF…WEBP
        }
        // ID3 tag or MPEG audio frame sync
        if b.count >= 3 && b[0] == 0x49 && b[1] == 0x44 && b[2] == 0x33 {
            return .audio  // ID3 (mp3)
        }
        if b.count >= 2 && b[0] == 0xFF && (b[1] & 0xE0) == 0xE0 {
            return .audio  // MPEG frame sync
        }
        // ISO BMFF (mp4 / m4a / mov) — `ftyp` at byte 4
        if b.count >= 8 && b[4] == 0x66 && b[5] == 0x74 && b[6] == 0x79 && b[7] == 0x70 {
            // M4A vs MP4 vs HEIC — the brand at bytes 8..12 distinguishes.
            // For routing we treat any ftyp as image if brand starts
            // with "heic"/"heix"/"hevc"/"avif", audio if "M4A "/"M4B ",
            // otherwise audio (most user uploads of mp4 to LLMs are
            // audio recordings; video isn't in scope for Phase 4).
            if b.count >= 12 {
                let brand = String(bytes: b[8..<min(12, b.count)], encoding: .ascii) ?? ""
                if brand.hasPrefix("heic") || brand.hasPrefix("heix")
                    || brand.hasPrefix("hevc") || brand.hasPrefix("avif") {
                    return .image
                }
            }
            return .audio
        }
        return nil
    }

    /// Sanitise an attacker-supplied multipart part name before we
    /// re-emit it inside a synthesised Content-Disposition header.
    /// RFC 7578 §4.2 says clients SHOULD percent-encode; many don't,
    /// and a name like `file"\r\nX-Injected: yes` smuggled through
    /// verbatim would corrupt the rewritten multipart envelope.
    /// Strip everything that isn't a conservative ASCII identifier
    /// char — losing fidelity on weird names is fine; preserving
    /// safety is the bar.
    static func sanitisePartName(_ raw: String) -> String {
        let allowed = raw.unicodeScalars.filter { scalar in
            let v = scalar.value
            return (v >= 0x30 && v <= 0x39)  // 0-9
                || (v >= 0x41 && v <= 0x5A)  // A-Z
                || (v >= 0x61 && v <= 0x7A)  // a-z
                || v == 0x5F || v == 0x2D || v == 0x2E  // _ - .
        }
        let s = String(String.UnicodeScalarView(allowed))
        return s.isEmpty ? "file" : s
    }

    /// One file part's scan output (raw, pre-flattened).
    private struct PartFinding: Sendable {
        let partIndex: Int
        let scanType: ScanType
        let findings: [MultimodalPIIInspector.Finding]
    }

    private static func scan(
        bodyData: Data, mediaType: String, scanType: ScanType
    ) async -> [MultimodalPIIInspector.Finding] {
        switch scanType {
        case .image:
            guard let result = try? await MediaPIIScanner.shared.scan(imageData: bodyData) else { return [] }
            var out: [MultimodalPIIInspector.Finding] = []
            for det in result.piiDetections {
                out.append(MultimodalPIIInspector.Finding(
                    imagePath: [], contentBlockPath: [],
                    mediaType: mediaType, provider: .unknown,
                    category: .textPII(type: det.type), cleartextValue: det.value
                ))
            }
            for face in result.faces {
                out.append(MultimodalPIIInspector.Finding(
                    imagePath: [], contentBlockPath: [],
                    mediaType: mediaType, provider: .unknown,
                    category: .face(confidence: face.confidence), cleartextValue: "face"
                ))
            }
            return out
        case .pdf:
            guard let result = try? await PDFPIIScanner.shared.scan(pdfData: bodyData) else { return [] }
            if let reason = result.unscannable {
                return [MultimodalPIIInspector.Finding(
                    imagePath: [], contentBlockPath: [],
                    mediaType: mediaType, provider: .unknown,
                    category: .unscannable(reason: reason), cleartextValue: reason.rawValue
                )]
            }
            var out: [MultimodalPIIInspector.Finding] = []
            for det in result.piiDetections {
                out.append(MultimodalPIIInspector.Finding(
                    imagePath: [], contentBlockPath: [],
                    mediaType: mediaType, provider: .unknown,
                    category: .textPII(type: det.type), cleartextValue: det.value
                ))
            }
            for face in result.faces {
                out.append(MultimodalPIIInspector.Finding(
                    imagePath: [], contentBlockPath: [],
                    mediaType: mediaType, provider: .unknown,
                    category: .face(confidence: face.confidence), cleartextValue: "face"
                ))
            }
            return out
        case .audio:
            guard let result = try? await AudioPIIScanner.shared.scan(audioData: bodyData, mediaType: mediaType) else { return [] }
            if let reason = result.unscannable {
                return [MultimodalPIIInspector.Finding(
                    imagePath: [], contentBlockPath: [],
                    mediaType: mediaType, provider: .unknown,
                    category: .unscannableAudio(reason: reason), cleartextValue: reason.rawValue
                )]
            }
            return result.piiDetections.map { det in
                MultimodalPIIInspector.Finding(
                    imagePath: [], contentBlockPath: [],
                    mediaType: mediaType, provider: .unknown,
                    category: .textPII(type: det.type), cleartextValue: det.value
                )
            }
        }
    }

    /// Build the placeholder text content that replaces a stripped
    /// file part's bytes. Mirrors `MultimodalRewriter.summarize` in
    /// shape AND the JSON-path placeholder's media-type labelling
    /// (so a stripped PDF says "PDF", not the generic "attachment"
    /// that earlier multipart placeholders used).
    private static func placeholder(for findings: [MultimodalPIIInspector.Finding]) -> String {
        let summary = MultimodalRewriter.summarizePublic(findings)
        let allPDF = findings.allSatisfy { $0.mediaType.lowercased().hasPrefix("application/pdf") }
        let allImage = findings.allSatisfy { $0.mediaType.lowercased().hasPrefix("image/") }
        let allAudio = findings.allSatisfy { $0.mediaType.lowercased().hasPrefix("audio/") }
        let label = allPDF ? "PDF"
            : allImage ? "image"
            : allAudio ? "audio clip"
            : "attachment"
        return "[Bouclier blocked an uploaded \(label) — \(summary)]"
    }

    /// Reassemble the multipart body, replacing flagged file parts
    /// with a text/plain part of the same `name`. Untouched parts
    /// are copied verbatim from the original byte buffer so we don't
    /// risk corrupting clean bytes in the rewrite.
    private static func rebuild(
        body source: Data,
        parts: [MultipartParser.Part],
        boundary: String,
        dirty: Set<Int>,
        placeholders: [Int: String]
    ) -> Data {
        var out = Data()
        let crlf = Data("\r\n".utf8)
        for (idx, part) in parts.enumerated() {
            out.append(Data("--\(boundary)".utf8))
            out.append(crlf)
            if dirty.contains(idx) {
                // P0 fix: sanitise the part name before re-emitting
                // it inside a synthesised header. A name carrying
                // CRLF / quote / boundary bytes would otherwise smuggle
                // headers and split the multipart.
                let name = sanitisePartName(part.name ?? "file")
                let placeholder = placeholders[idx] ?? "[Bouclier blocked an attachment]"
                out.append(Data("Content-Disposition: form-data; name=\"\(name)\"".utf8))
                out.append(crlf)
                out.append(Data("Content-Type: text/plain; charset=utf-8".utf8))
                out.append(crlf)
                out.append(crlf)
                out.append(Data(placeholder.utf8))
                out.append(crlf)
            } else {
                // Preserve original headers + body verbatim.
                for (name, value) in part.headers.sorted(by: { $0.key < $1.key }) {
                    out.append(Data("\(name): \(value)".utf8))
                    out.append(crlf)
                }
                out.append(crlf)
                out.append(part.bodyData(in: source))
                out.append(crlf)
            }
        }
        out.append(Data("--\(boundary)--\r\n".utf8))
        return out
    }
}
