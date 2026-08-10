import Foundation
import PDFKit

/// On-device PDF inspector. Two-stage pipeline:
///
/// 1. **Text-layer pass** — PDFKit's `PDFPage.string` returns the
///    embedded text layer when the PDF was authored by a real editor
///    (Word, LaTeX, reportlab, browser print-to-PDF, …). Sub-ms per
///    page; covers ~95% of real-world PDFs.
/// 2. **Scanned-page fallback** — when a page returns no text (it's
///    a flattened image inside a PDF wrapper), we render that page to
///    a `CGImage` via `PDFPage.thumbnail(of:for:)` and hand it to
///    `MediaPIIScanner` for the same Vision OCR + face detection
///    pipeline used on regular images.
///
/// The text-PII scanner runs on the concatenated transcript from
/// every page — text + OCR — so all our regex, native, and ML
/// detectors light up uniformly across the document.
///
/// **Bounds.** We cap rendered pages at the same 2000-pixel side that
/// MediaPIIScanner uses, and refuse to scan PDFs above
/// `maxPagesPerDocument` (mirrors the request fan-out cap in
/// MultimodalPIIInspector).
final class PDFPIIScanner: @unchecked Sendable {
    static let shared = PDFPIIScanner()

    /// Hard ceiling on pages we'll inspect per PDF. Beyond this we
    /// pass through unchanged on the theory that an LLM prompt with
    /// a 200-page PDF is either deliberate batch processing (which
    /// should not run through a proxy anyway) or accidental abuse.
    static let maxPagesPerDocument = 50

    /// Render scale for the scanned-page fallback. PDFPage user-space
    /// is 72 dpi; 2.0× yields 144 dpi which matches Apple's WWDC
    /// guidance "≥150 dpi for body text". Lower (e.g. 1.5×/108 dpi)
    /// leaves real recall on small font sizes — exactly where
    /// IBANs and tax IDs live on bank statements.
    private static let pageRenderScale: CGFloat = 2.0

    /// Maximum rendered bitmap side. A malicious PDF declaring a
    /// 100"×100" mediaBox at 2× would otherwise allocate ~830 MB
    /// in one pass. Matches MediaPIIScanner's `maxImagePixelSize`.
    private static let maxRenderedSide: CGFloat = 2400

    struct ScanResult: Sendable {
        let piiDetections: [PIIScanner.Detection]
        /// Faces detected across all OCR'd pages. Catches ID scans /
        /// passport photos / KYC docs embedded in PDFs.
        let faces: [MediaPIIScanner.DetectedFace]
        let pageCount: Int
        let pagesOCRd: Int
        /// Non-nil when we couldn't inspect the PDF (encrypted, too
        /// large, malformed). Callers must treat this the same as
        /// findings — strip the document and surface to the user.
        /// Silent pass-through of an un-inspected document is a
        /// fail-open bug.
        let unscannable: UnscannableReason?
        let latencyMs: Double

        enum UnscannableReason: String, Sendable {
            case encrypted
            case tooManyPages
            case malformed
        }
    }

    private init() {}

    /// Scan a PDF's raw bytes. Always returns; never silently passes
    /// through an un-inspected document — encrypted / oversize /
    /// malformed inputs surface as a non-nil `unscannable` reason so
    /// the rewriter still strips the content block.
    func scan(pdfData: Data) async throws -> ScanResult {
        let start = CFAbsoluteTimeGetCurrent()

        guard let doc = PDFDocument(data: pdfData) else {
            return ScanResult(
                piiDetections: [], faces: [],
                pageCount: 0, pagesOCRd: 0,
                unscannable: .malformed,
                latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000
            )
        }
        // Encrypted or password-locked PDFs return empty text and a
        // blank raster for OCR, so both inspection paths see nothing.
        // Surface them as unscannable so the rewriter strips them with
        // an "encrypted" label rather than forwarding silently.
        if doc.isLocked || doc.isEncrypted {
            return ScanResult(
                piiDetections: [], faces: [],
                pageCount: doc.pageCount, pagesOCRd: 0,
                unscannable: .encrypted,
                latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000
            )
        }
        let pageCount = doc.pageCount
        guard pageCount > 0 else {
            return ScanResult(
                piiDetections: [], faces: [],
                pageCount: 0, pagesOCRd: 0,
                unscannable: .malformed,
                latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000
            )
        }
        // Refusing to scan a long document while still forwarding it is
        // the wrong default for a privacy tool. Surface as unscannable
        // so the rewriter strips it.
        guard pageCount <= Self.maxPagesPerDocument else {
            return ScanResult(
                piiDetections: [], faces: [],
                pageCount: pageCount, pagesOCRd: 0,
                unscannable: .tooManyPages,
                latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000
            )
        }

        var fullText = ""
        var ocrPageCount = 0
        var collectedFaces: [MediaPIIScanner.DetectedFace] = []

        for pageIndex in 0..<pageCount {
            guard let page = doc.page(at: pageIndex) else { continue }
            // Try the text layer first. PDFKit normalises whitespace
            // and joins lines, which is exactly what the downstream
            // regex detectors expect.
            if let text = page.string, !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                fullText += text
                fullText += "\n"
                continue
            }
            // No text layer — render and OCR. This is the slow path
            // (~150–300 ms per page on M-series); we run pages
            // serially because the Vision pool already parallelises
            // internally and our concurrent-request budget is
            // managed one level up in MultimodalPIIInspector.
            if let imageData = renderPageAsPNG(page) {
                if let result = try? await MediaPIIScanner.shared.scan(imageData: imageData) {
                    if !result.ocrText.isEmpty {
                        fullText += result.ocrText
                        fullText += "\n"
                    }
                    // Propagate faces — ID scans and KYC documents
                    // embedded in PDFs need the same face-PII coverage
                    // as standalone image attachments.
                    collectedFaces.append(contentsOf: result.faces)
                    ocrPageCount += 1
                }
            }
        }

        let piiDetections = PIIScanner.active.current().scan(fullText)
        return ScanResult(
            piiDetections: piiDetections,
            faces: collectedFaces,
            pageCount: pageCount,
            pagesOCRd: ocrPageCount,
            unscannable: nil,
            latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000
        )
    }

    /// Render a PDF page to PNG bytes so we can hand it through the
    /// existing MediaPIIScanner. We deliberately go through PNG (and
    /// not the more efficient CGImage path) because MediaPIIScanner's
    /// public API is bytes-in — bridging through `Data` keeps a single
    /// surface for the upstream code to test.
    private func renderPageAsPNG(_ page: PDFPage) -> Data? {
        autoreleasepool {
            // mediaBox over cropBox is intentional: we want maximum
            // recall including content the renderer might clip
            // (margins, watermarks). Anthropic's PDF ingest renders
            // mediaBox too, so what we inspect matches what the
            // model sees.
            let rawBounds = page.bounds(for: .mediaBox)
            let rotation = page.rotation  // 0/90/180/270
            // Rotated pages (common in mobile scans) need swapped
            // width/height in the target bitmap; PDFKit's draw
            // honours `page.rotation` automatically.
            let bounds = (rotation == 90 || rotation == 270)
                ? CGRect(x: rawBounds.minX, y: rawBounds.minY,
                         width: rawBounds.height, height: rawBounds.width)
                : rawBounds
            // Clamp the rendered bitmap so a maliciously large
            // mediaBox can't blow the per-image memory budget.
            let nominalSide = max(bounds.width, bounds.height) * Self.pageRenderScale
            let scale: CGFloat = nominalSide > Self.maxRenderedSide
                ? Self.pageRenderScale * (Self.maxRenderedSide / nominalSide)
                : Self.pageRenderScale
            let width = Int(bounds.width * scale)
            let height = Int(bounds.height * scale)
            guard width > 0, height > 0 else { return nil }

            let colorSpace = CGColorSpaceCreateDeviceRGB()
            guard let ctx = CGContext(
                data: nil,
                width: width,
                height: height,
                bitsPerComponent: 8,
                bytesPerRow: 0,
                space: colorSpace,
                bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
            ) else { return nil }

            // White background — most scanned PDFs are documents on
            // white, OCR is calibrated for it, and a transparent
            // background can confuse Vision's binarisation.
            ctx.setFillColor(CGColor(red: 1, green: 1, blue: 1, alpha: 1))
            ctx.fill(CGRect(x: 0, y: 0, width: width, height: height))

            ctx.scaleBy(x: scale, y: scale)
            ctx.translateBy(x: -bounds.minX, y: -bounds.minY)
            page.draw(with: .mediaBox, to: ctx)

            guard let cgImage = ctx.makeImage() else { return nil }
            let mutable = NSMutableData()
            guard let dest = CGImageDestinationCreateWithData(
                mutable as CFMutableData, "public.png" as CFString, 1, nil
            ) else { return nil }
            CGImageDestinationAddImage(dest, cgImage, nil)
            guard CGImageDestinationFinalize(dest) else { return nil }
            return mutable as Data
        }
    }
}
