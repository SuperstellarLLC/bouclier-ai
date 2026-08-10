import CoreGraphics
import Foundation
import ImageIO
@preconcurrency import Vision

/// On-device image PII scanner backed by Apple's Vision framework.
///
/// Two passes per image:
///
/// 1. **OCR** via `VNRecognizeTextRequest` (`.accurate`, language
///    autodetect) — extracts every readable text observation and its
///    bounding rectangle.
/// 2. **Face detection** via `VNDetectFaceRectanglesRequest`
///    (`.revision3`, the current high-recall variant) — faces count as
///    PII under GDPR Art. 4.
///
/// The OCR text is then fed into the existing `PIIScanner` so the same
/// regex + native + ML detector pipeline that powers text PII
/// inspection lights up for images. Face rectangles surface as
/// synthetic `FACE` entities so the preview modal can list them.
///
/// **Concurrency.** `VNImageRequestHandler.perform(_:)` is documented
/// as safe to call concurrently across handlers; we therefore expose a
/// nonisolated async API and never share a handler between calls.
/// `VNRequest` subclasses are not `Sendable` in Swift 6 strict mode, so
/// each `scan` call constructs fresh request objects — cheap (~µs) and
/// avoids any cross-actor reasoning.
///
/// **Latency budget.** WWDC 2024 + community benchmarks put
/// `VNRecognizeTextRequest(.accurate)` at 50–250 ms on a 1024×1024
/// image on M-series. Face detection adds another 20–60 ms.
/// `scan` runs both in parallel via a `TaskGroup`.
///
/// **Memory.** Vision allocates its own buffers; we don't keep the
/// `CGImage` alive once the requests finish. For very large images
/// (>16 MP) we downscale to a 4096-pixel bounding box before handing
/// them to Vision — Apple's docs note that OCR accuracy plateaus well
/// before that resolution and the memory cliff above it is steep.
final class MediaPIIScanner: @unchecked Sendable {
    /// Process-wide shared instance. Stateless — exists only so we
    /// don't re-pay the (cheap) request-construction cost per call.
    static let shared = MediaPIIScanner()

    /// One detected face, normalised to pixel coordinates in the
    /// original image. Used by the preview modal to count faces and
    /// (in a future release) by the redactor to blur regions.
    struct DetectedFace: Sendable, Equatable {
        let pixelRect: CGRect
        let confidence: Float
    }

    /// Result of scanning a single image.
    struct ImageScanResult: Sendable {
        /// PII detections found inside the OCR'd text.
        let piiDetections: [PIIScanner.Detection]
        /// Faces detected in the image (high-confidence only).
        let faces: [DetectedFace]
        /// Full OCR transcript (recorded for the audit log but never
        /// transmitted off-device).
        let ocrText: String
        /// Wall-clock latency in ms, for telemetry.
        let latencyMs: Double
    }

    /// Downscale anything past this max pixel size on the long edge
    /// before handing the image to Vision. Community + Apple guidance
    /// converges around 2000 px: above ~3000 px OCR accuracy plateaus
    /// while memory cliffs upward. Tracked in the "memory" research
    /// notes for v0.4.0.
    private static let maxImagePixelSize: Int = 2000

    /// Hard upper bound on declared image dimensions (long edge × short
    /// edge) before we even attempt a thumbnail decode. Defends against
    /// the classic "decompression bomb" — a tiny PNG/JPEG that declares
    /// 100k × 100k dimensions and forces a multi-GB intermediate
    /// allocation. 50 megapixels covers every legitimate camera /
    /// screenshot users will paste into an LLM (8K screens are
    /// ~33 MP). Above that, the rewriter strips the attachment and
    /// surfaces an "unscannable" finding instead.
    private static let maxImagePixelArea: Int = 50_000_000

    /// Face-detection confidence floor. Revision 3 has a low false-
    /// positive rate so 0.5 is safe in practice; raised for
    /// preview-modal noise reduction would be a UX call.
    private static let faceConfidenceThreshold: Float = 0.5

    private init() {}

    /// Scan an image's raw bytes. Returns an empty result if the
    /// bytes don't decode as an image (corrupted input, unsupported
    /// codec). Errors thrown by Vision are wrapped and re-thrown so
    /// the caller can degrade gracefully.
    func scan(imageData: Data) async throws -> ImageScanResult {
        let start = CFAbsoluteTimeGetCurrent()

        // Decode + read EXIF orientation in one pass so the rest of
        // the pipeline has both. Without orientation, Vision treats
        // every CGImage as `.up` and silently fails on portrait phone
        // photos — the #1 Vision-framework footgun in production.
        guard let decoded = decodeImage(from: imageData) else {
            return ImageScanResult(
                piiDetections: [], faces: [], ocrText: "",
                latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000
            )
        }

        // Both passes share the same handler — a single perform() with
        // two requests halves the wall-clock vs running them in
        // separate handlers. WWDC '24 explicitly recommends this.
        let (ocrText, faces) = try await runVision(
            on: decoded.image,
            orientation: decoded.orientation
        )
        let piiDetections = PIIScanner.active.current().scan(ocrText)

        return ImageScanResult(
            piiDetections: piiDetections,
            faces: faces,
            ocrText: ocrText,
            latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000
        )
    }

    // MARK: - Decoding

    /// Decoded image + its EXIF orientation. Orientation lives on the
    /// CGImageSource, not the CGImage itself, so we have to read it
    /// before the source goes out of scope.
    private struct DecodedImage {
        let image: CGImage
        let orientation: CGImagePropertyOrientation
    }

    private func decodeImage(from data: Data) -> DecodedImage? {
        autoreleasepool {
            guard let source = CGImageSourceCreateWithData(data as CFData, nil),
                  CGImageSourceGetStatus(source) == .statusComplete
            else { return nil }

            // Read metadata first — pixel dimensions, EXIF orientation
            // — without decoding the pixel buffer. A decompression-bomb
            // image declares enormous dimensions but ships only a few
            // KB of data; reading the dimensions cheaply tells us to
            // reject before allocating anything large.
            let props = (CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any]) ?? [:]
            if let w = props[kCGImagePropertyPixelWidth] as? Int,
               let h = props[kCGImagePropertyPixelHeight] as? Int,
               w > 0, h > 0,
               w.multipliedReportingOverflow(by: h).overflow
                || w * h > Self.maxImagePixelArea
            {
                return nil
            }

            let orientationRaw = (props[kCGImagePropertyOrientation] as? UInt32) ?? 1
            let orientation = CGImagePropertyOrientation(rawValue: orientationRaw) ?? .up

            // Use CGImageSourceCreateThumbnailAtIndex which is the
            // documented cheap-downscale path (no CGContext redraw,
            // no Lanczos cycle on the CPU). When the image is already
            // smaller than the cap, kCGImageSourceCreateThumbnailFromImageIfAbsent
            // still returns the full image at native resolution.
            let opts: [CFString: Any] = [
                kCGImageSourceCreateThumbnailFromImageAlways: true,
                kCGImageSourceCreateThumbnailWithTransform: false, // we pass orientation explicitly
                kCGImageSourceThumbnailMaxPixelSize: Self.maxImagePixelSize,
                kCGImageSourceShouldCache: false,
            ]
            guard let image = CGImageSourceCreateThumbnailAtIndex(source, 0, opts as CFDictionary) else {
                return nil
            }
            return DecodedImage(image: image, orientation: orientation)
        }
    }

    // MARK: - Vision passes

    /// Run OCR + face detection in a single perform() call. Returns
    /// the joined OCR transcript and the converted face list. Errors
    /// from Vision propagate to the caller.
    private func runVision(
        on image: CGImage,
        orientation: CGImagePropertyOrientation
    ) async throws -> (ocrText: String, faces: [DetectedFace]) {
        let width = CGFloat(image.width)
        let height = CGFloat(image.height)

        return try await withCheckedThrowingContinuation { continuation in
            // Hop off the cooperative thread pool — VNImageRequestHandler.perform
            // is sync + GCD-internal and can starve Swift concurrency
            // ("Swift Concurrency Waits for No One" — saagarjha.com).
            DispatchQueue.global(qos: .userInitiated).async {
                autoreleasepool {
                    do {
                        let ocr = VNRecognizeTextRequest()
                        ocr.recognitionLevel = .accurate
                        ocr.usesLanguageCorrection = true
                        ocr.automaticallyDetectsLanguage = true
                        ocr.revision = VNRecognizeTextRequestRevision3

                        let face = VNDetectFaceRectanglesRequest()
                        face.revision = VNDetectFaceRectanglesRequestRevision3

                        let handler = VNImageRequestHandler(
                            cgImage: image,
                            orientation: orientation,
                            options: [:]
                        )
                        try handler.perform([ocr, face])

                        let text = (ocr.results ?? []).compactMap {
                            $0.topCandidates(1).first?.string
                        }.joined(separator: "\n")

                        let faces: [DetectedFace] = (face.results ?? []).compactMap { obs in
                            guard obs.confidence >= Self.faceConfidenceThreshold else { return nil }
                            let r = obs.boundingBox
                            return DetectedFace(
                                pixelRect: CGRect(
                                    x: r.minX * width,
                                    y: (1 - r.maxY) * height,
                                    width: r.width * width,
                                    height: r.height * height
                                ),
                                confidence: obs.confidence
                            )
                        }
                        continuation.resume(returning: (text, faces))
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            }
        }
    }
}
