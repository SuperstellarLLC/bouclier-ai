import CoreML
import Foundation
import Tokenizers

/// On-device prompt-injection classifier backed by Meta's Prompt Guard 2
/// (86M-param mDeBERTa, binary BENIGN/MALICIOUS) compiled to CoreML.
///
/// All inference runs locally on Apple Neural Engine — no network calls,
/// no telemetry. The classifier is intentionally optional: if the
/// `.mlpackage` or tokenizer files are missing from the bundle the
/// `init()` throws and the rest of the proxy continues running on
/// regex-only detection.
final class MLClassifier: @unchecked Sendable {
    // MARK: - Public types

    enum ClassifierError: Error, CustomStringConvertible {
        case modelNotFound
        case tokenizerNotFound
        case predictionFailed(String)
        case invalidOutput

        var description: String {
            switch self {
            case .modelNotFound:
                return "PromptGuard2.mlpackage not found in app bundle"
            case .tokenizerNotFound:
                return "PromptGuardTokenizer folder not found in app bundle"
            case .predictionFailed(let detail):
                return "CoreML prediction failed: \(detail)"
            case .invalidOutput:
                return "CoreML model returned an unexpected output shape"
            }
        }
    }

    /// Result of a single classification call.
    struct Classification: Sendable {
        /// Probability the input is a prompt injection / jailbreak (0–1).
        let maliciousScore: Float
        /// Probability the input is benign (0–1). Always `1 - maliciousScore`.
        let benignScore: Float
        /// Wall-clock latency in milliseconds, useful for telemetry / tuning.
        let latencyMs: Double
    }

    // MARK: - Configuration

    /// Fixed sequence length the CoreML model was traced with. Must match
    /// the value used in `scripts/convert-promptguard.py`. Neural Engine
    /// strongly prefers fixed shapes, so we pad/truncate every input.
    private static let sequenceLength = 512

    // MARK: - Stored state

    private let model: MLModel
    private let tokenizer: any Tokenizer

    // MARK: - Init

    /// Loads the bundled CoreML model and tokenizer. Throws if either is
    /// missing so the caller can fall back to regex-only mode without
    /// crashing the app.
    ///
    /// Async because swift-transformers' tokenizer loader is async — the
    /// load happens once at app startup, so the caller should `await`
    /// this from a Task during the proxy's initialization sequence.
    init() async throws {
        // Locate the compiled CoreML model. Xcode compiles `.mlpackage`
        // resources into `.mlmodelc` at build time; in SwiftPM dev builds
        // the raw `.mlpackage` is also accepted. Resources live in the
        // SPM-generated module bundle (`Bouclier_Bouclier.bundle`), not
        // at `Bundle.main`'s root — looking in `Bundle.main` silently
        // returns nil and the classifier never loads.
        let modelURL: URL
        if let compiled = Bundle.module.url(forResource: "PromptGuard2", withExtension: "mlmodelc") {
            modelURL = compiled
        } else if let raw = Bundle.module.url(forResource: "PromptGuard2", withExtension: "mlpackage") {
            modelURL = raw
        } else {
            throw ClassifierError.modelNotFound
        }

        let config = MLModelConfiguration()
        // `.all` lets CoreML pick the best engine — Neural Engine when
        // shapes are static (which they are), CPU otherwise. We do not
        // pin to `.cpuAndNeuralEngine` because that fails ungracefully
        // on Intel Macs and older hardware.
        config.computeUnits = .all
        self.model = try MLModel(contentsOf: modelURL, configuration: config)

        // Load the tokenizer from a bundled folder containing
        // tokenizer.json + tokenizer_config.json + special_tokens_map.json,
        // populated by the convert-promptguard.py script.
        guard let tokenizerDir = Bundle.module.url(
            forResource: "PromptGuardTokenizer",
            withExtension: nil
        ) else {
            throw ClassifierError.tokenizerNotFound
        }
        self.tokenizer = try await AutoTokenizer.from(modelFolder: tokenizerDir)
    }

    // MARK: - Inference

    /// Classify a single string. Thread-safe — `MLModel.prediction(from:)`
    /// is documented as safe to call concurrently.
    func classify(_ text: String) throws -> Classification {
        let start = CFAbsoluteTimeGetCurrent()

        // 1. Tokenize. swift-transformers returns the encoded ids; we
        //    derive a matching attention mask manually because the
        //    `Tokenizer` protocol doesn't expose one directly.
        let rawIds = tokenizer.encode(text: text)
        let truncated = Array(rawIds.prefix(Self.sequenceLength))
        let attendedCount = truncated.count

        // 2. Pad to fixed length. Pad token id is taken from the
        //    tokenizer when available, falling back to 0 (the standard
        //    DeBERTa pad id).
        let padId: Int = 0
        var paddedIds = truncated
        if paddedIds.count < Self.sequenceLength {
            paddedIds.append(contentsOf: repeatElement(padId, count: Self.sequenceLength - paddedIds.count))
        }

        // 3. Build MLMultiArray inputs. CoreML wants Int32 here.
        let inputIds = try MLMultiArray(
            shape: [1, NSNumber(value: Self.sequenceLength)],
            dataType: .int32
        )
        let attentionMask = try MLMultiArray(
            shape: [1, NSNumber(value: Self.sequenceLength)],
            dataType: .int32
        )
        for i in 0..<Self.sequenceLength {
            inputIds[i] = NSNumber(value: Int32(paddedIds[i]))
            attentionMask[i] = NSNumber(value: Int32(i < attendedCount ? 1 : 0))
        }

        // 4. Run the model.
        let input = try MLDictionaryFeatureProvider(dictionary: [
            "input_ids": MLFeatureValue(multiArray: inputIds),
            "attention_mask": MLFeatureValue(multiArray: attentionMask),
        ])
        let output: MLFeatureProvider
        do {
            output = try model.prediction(from: input)
        } catch {
            throw ClassifierError.predictionFailed(String(describing: error))
        }

        guard let logits = output.featureValue(for: "logits")?.multiArrayValue,
              logits.count >= 2 else {
            throw ClassifierError.invalidOutput
        }

        // 5. Numerically-stable softmax over [BENIGN, MALICIOUS].
        let benignLogit = logits[0].floatValue
        let maliciousLogit = logits[1].floatValue
        let maxLogit = max(benignLogit, maliciousLogit)
        let expBenign = expf(benignLogit - maxLogit)
        let expMalicious = expf(maliciousLogit - maxLogit)
        let sum = expBenign + expMalicious

        let elapsedMs = (CFAbsoluteTimeGetCurrent() - start) * 1000
        return Classification(
            maliciousScore: expMalicious / sum,
            benignScore: expBenign / sum,
            latencyMs: elapsedMs
        )
    }

}
