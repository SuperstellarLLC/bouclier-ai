import AVFoundation
import Foundation
@preconcurrency import Speech

/// On-device audio PII scanner backed by Apple's Speech framework.
///
/// **What it does.** Decodes a base64 audio blob extracted from an
/// outbound multimodal request (OpenAI's `input_audio` content block,
/// Gemini's `inlineData` with an `audio/*` mime type), runs
/// `SFSpeechRecognizer` with `requiresOnDeviceRecognition = true` so
/// nothing leaves the Mac, hands the resulting transcript to the
/// existing `PIIScanner` pipeline, and reports any detections.
///
/// **What it deliberately doesn't do.** Speech-to-speech redaction is
/// genuinely hard (you can't surgically erase PII from voice without
/// re-synthesis that destroys the original cadence and identity). The
/// downstream `MultimodalRewriter` strips the entire audio leaf when
/// any PII is found — the model gets a text placeholder explaining
/// what was caught.
///
/// **Authorisation.** Speech recognition requires the user to grant
/// permission once (via `SFSpeechRecognizer.requestAuthorization`).
/// `NSSpeechRecognitionUsageDescription` must be in `Info.plist`. We
/// degrade to "unscannable" with reason `.notAuthorised` rather than
/// silently bypassing — the proxy's job is to never let an
/// un-inspected attachment through.
///
/// **Test injection.** The class accepts a `recogniserFactory` closure
/// at init so tests can stub the recogniser without touching the
/// real Speech framework (which fails closed in headless test envs).
final class AudioPIIScanner: @unchecked Sendable {
    static let shared = AudioPIIScanner()

    /// Maximum audio duration we'll transcribe in a single pass.
    /// `SFSpeechRecognizer`'s file-based request is documented to
    /// handle up to ~1 minute reliably; longer files chunk poorly.
    /// Anything past this cap is treated as unscannable — the
    /// rewriter still strips it.
    static let maxDurationSeconds: TimeInterval = 60

    /// Result of transcribing + scanning one audio blob.
    struct ScanResult: Sendable {
        let piiDetections: [PIIScanner.Detection]
        /// Full transcript (used by the audit log; never transmitted
        /// off-device).
        let transcript: String
        /// Detected audio duration in seconds.
        let durationSeconds: TimeInterval
        /// Non-nil when we couldn't inspect — caller treats this the
        /// same as findings and strips the attachment.
        let unscannable: UnscannableReason?
        let latencyMs: Double

        enum UnscannableReason: String, Sendable {
            case notAuthorised
            case unsupportedFormat
            case tooLong
            case malformed
            case recogniserUnavailable
        }
    }

    /// Pluggable transcriber so tests can stub Apple Speech.
    typealias Transcriber = @Sendable (URL) async throws -> String

    private let transcribe: Transcriber

    init(transcribe: Transcriber? = nil) {
        // Default to the real Speech-framework-backed transcriber;
        // tests pass their own closure.
        self.transcribe = transcribe ?? AudioPIIScanner.defaultTranscriber
    }

    /// Scan one audio payload. Always returns; never silently passes
    /// an un-inspected attachment through. Writes the bytes to a
    /// temp file because SFSpeechRecognizer's file recogniser is the
    /// only path that supports `requiresOnDeviceRecognition`.
    func scan(audioData: Data, mediaType: String) async throws -> ScanResult {
        let start = CFAbsoluteTimeGetCurrent()

        guard !audioData.isEmpty else {
            return ScanResult(piiDetections: [], transcript: "", durationSeconds: 0,
                              unscannable: .malformed,
                              latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000)
        }

        // Reject unknown audio formats up-front rather than coerce to
        // .m4a — silently mis-extending a non-decodable container
        // leaves a temp file on disk and confuses the failure message
        // the user sees in the rewriter placeholder.
        guard let ext = Self.fileExtension(for: mediaType) else {
            return ScanResult(piiDetections: [], transcript: "", durationSeconds: 0,
                              unscannable: .unsupportedFormat,
                              latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000)
        }
        let tmpURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("bouclier-audio-\(UUID().uuidString)")
            .appendingPathExtension(ext)
        defer { try? FileManager.default.removeItem(at: tmpURL) }

        do {
            try audioData.write(to: tmpURL, options: [.atomic])
        } catch {
            return ScanResult(piiDetections: [], transcript: "", durationSeconds: 0,
                              unscannable: .malformed,
                              latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000)
        }

        // Read duration via AVFoundation so we can refuse oversize
        // inputs before paying for transcription.
        let duration = await Self.duration(of: tmpURL)
        guard duration > 0 else {
            return ScanResult(piiDetections: [], transcript: "", durationSeconds: 0,
                              unscannable: .unsupportedFormat,
                              latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000)
        }
        guard duration <= Self.maxDurationSeconds else {
            return ScanResult(piiDetections: [], transcript: "", durationSeconds: duration,
                              unscannable: .tooLong,
                              latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000)
        }

        do {
            let transcript = try await transcribe(tmpURL)
            let piiDetections = PIIScanner.active.current().scan(transcript)
            return ScanResult(
                piiDetections: piiDetections,
                transcript: transcript,
                durationSeconds: duration,
                unscannable: nil,
                latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000
            )
        } catch let err as TranscriberError {
            return ScanResult(
                piiDetections: [], transcript: "", durationSeconds: duration,
                unscannable: err.reason,
                latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000
            )
        } catch {
            // Anything else from a custom transcriber stub →
            // recogniserUnavailable so the rewriter still strips.
            return ScanResult(
                piiDetections: [], transcript: "", durationSeconds: duration,
                unscannable: .recogniserUnavailable,
                latencyMs: (CFAbsoluteTimeGetCurrent() - start) * 1000
            )
        }
    }

    // MARK: - Defaults

    enum TranscriberError: Error, Sendable {
        case notAuthorised
        case recogniserUnavailable
        case noSpeech
        case timedOut

        var reason: ScanResult.UnscannableReason {
            switch self {
            case .notAuthorised: return .notAuthorised
            case .recogniserUnavailable: return .recogniserUnavailable
            case .noSpeech: return .recogniserUnavailable
            case .timedOut: return .recogniserUnavailable
            }
        }
    }

    /// Wall-clock ceiling on a single recogniser task, including the
    /// time the Speech XPC service spends queuing. Set to 2× the
    /// audio-duration cap so any task that hasn't reported a final
    /// result by then is treated as hung.
    private static let recogniserWallClockTimeoutSeconds: Double = 120

    /// The real Speech-framework-backed transcriber. Returns the
    /// concatenated final transcript. Errors map to TranscriberError
    /// cases the outer scan() turns into unscannable reasons.
    ///
    /// **Resilience.** Three independent failure modes get a tight
    /// answer rather than a silent hang:
    /// - Cancellation from the parent task → SFSpeechRecognitionTask
    ///   gets cancel() called via withTaskCancellationHandler so we
    ///   don't leak a recogniser task + the temp file the caller
    ///   wants to delete.
    /// - Silent / no-speech audio (Speech framework can fire the
    ///   callback with `(nil, nil)` or never fire `isFinal`) →
    ///   surfaces as `.noSpeech` so the rewriter still strips.
    /// - Wall-clock hang past 2× the duration cap → surfaces as
    ///   `.timedOut`. The XPC service occasionally never wakes up;
    ///   without this the proxy's request would deadlock forever.
    @Sendable static func defaultTranscriber(url: URL) async throws -> String {
        let authStatus = await Self.requestAuthorization()
        guard authStatus == .authorized else { throw TranscriberError.notAuthorised }

        guard let recogniser = SFSpeechRecognizer(locale: Locale.current)
            ?? SFSpeechRecognizer(locale: Locale(identifier: "en-US")),
              recogniser.isAvailable,
              recogniser.supportsOnDeviceRecognition
        else { throw TranscriberError.recogniserUnavailable }

        let request = SFSpeechURLRecognitionRequest(url: url)
        request.requiresOnDeviceRecognition = true
        request.shouldReportPartialResults = false

        // Race the recogniser callback against a wall-clock deadline.
        // The first to resolve wins; the other is cancelled.
        return try await withThrowingTaskGroup(of: String.self) { group in
            let taskBox = TaskBox()

            group.addTask { @Sendable in
                try await withTaskCancellationHandler {
                    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<String, Error>) in
                        var resumed = false
                        let recogniserTask = recogniser.recognitionTask(with: request) { result, err in
                            guard !resumed else { return }
                            if let err {
                                resumed = true
                                continuation.resume(throwing: err)
                                return
                            }
                            // Apple's docs allow (nil, nil) and "callback
                            // never called again" for silent/no-speech audio.
                            // The wall-clock timer in the sibling task is
                            // what saves us in those cases, but if we ever
                            // do get the no-op final result, end here.
                            if let result, result.isFinal {
                                resumed = true
                                continuation.resume(returning: result.bestTranscription.formattedString)
                                return
                            }
                            if result == nil {
                                resumed = true
                                continuation.resume(throwing: TranscriberError.noSpeech)
                            }
                        }
                        taskBox.store(recogniserTask)
                    }
                } onCancel: {
                    taskBox.cancelStored()
                }
            }
            group.addTask { @Sendable in
                try await Task.sleep(nanoseconds: UInt64(recogniserWallClockTimeoutSeconds * 1_000_000_000))
                throw TranscriberError.timedOut
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else {
                throw TranscriberError.recogniserUnavailable
            }
            return first
        }
    }

    /// Small reference box so the cancellation handler can reach the
    /// SFSpeechRecognitionTask created inside the continuation. We
    /// can't capture it directly because the closure escapes before
    /// the task is created.
    private final class TaskBox: @unchecked Sendable {
        private let lock = NSLock()
        private var task: SFSpeechRecognitionTask?
        func store(_ task: SFSpeechRecognitionTask) {
            lock.lock(); defer { lock.unlock() }
            self.task = task
        }
        func cancelStored() {
            lock.lock(); defer { lock.unlock() }
            task?.cancel()
        }
    }

    private static func requestAuthorization() async -> SFSpeechRecognizerAuthorizationStatus {
        let current = SFSpeechRecognizer.authorizationStatus()
        if current != .notDetermined { return current }
        return await withCheckedContinuation { continuation in
            SFSpeechRecognizer.requestAuthorization { status in
                continuation.resume(returning: status)
            }
        }
    }

    /// Read the audio's duration via AVFoundation. Returns 0 when the
    /// file isn't a supported audio container.
    private static func duration(of url: URL) async -> TimeInterval {
        let asset = AVURLAsset(url: url)
        do {
            let dur = try await asset.load(.duration)
            let seconds = CMTimeGetSeconds(dur)
            return seconds.isFinite ? seconds : 0
        } catch {
            return 0
        }
    }

    /// IANA media type → file extension. Speech framework's decoder
    /// dispatches on extension, not on file magic. Returns nil for
    /// formats AVFoundation can't reliably decode (webm/opus on macOS
    /// for instance) so the caller can surface `.unsupportedFormat`
    /// instead of writing a temp file with a misleading extension.
    private static func fileExtension(for mediaType: String) -> String? {
        let canonical = mediaType.lowercased()
            .split(separator: ";").first.map(String.init)?
            .trimmingCharacters(in: .whitespaces) ?? ""
        switch canonical {
        case "audio/mpeg", "audio/mp3": return "mp3"
        case "audio/mp4", "audio/m4a", "audio/x-m4a": return "m4a"
        case "audio/wav", "audio/x-wav", "audio/wave": return "wav"
        case "audio/flac", "audio/x-flac": return "flac"
        case "audio/aac": return "aac"
        case "audio/aiff", "audio/x-aiff": return "aiff"
        default:
            // webm/opus, ogg/vorbis, ogg/opus — AVFoundation's support
            // is partial and version-dependent. Refuse rather than
            // write a temp file with a misleading extension.
            return nil
        }
    }
}
