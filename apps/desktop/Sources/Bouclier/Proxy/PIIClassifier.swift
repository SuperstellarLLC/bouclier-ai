import CoreML
import Foundation
import Tokenizers

/// On-device PII NER classifier backed by Piiranha v1
/// (iiiorg/piiranha-v1-detect-personal-information, ~280 MB mDeBERTa-v3)
/// compiled to CoreML and run on the Apple Neural Engine.
///
/// Architecture mirrors `MLClassifier` line-for-line; the difference is
/// model shape: token classification (per-subword IOB2 tags) instead
/// of sequence classification (single benign/malicious score). The
/// classifier therefore takes responsibility for:
///   1. Tokenising the input.
///   2. Padding/truncating to a fixed seq length.
///   3. Running CoreML inference.
///   4. Decoding per-token argmax logits.
///   5. Collapsing IOB2 (`B-X` / `I-X` / `O`) tag runs into spans.
///   6. Mapping subword spans back to character offsets in the original
///      input — the hard part, because Piiranha's SentencePiece
///      tokenizer doesn't expose offsets directly.
///   7. Mapping Piiranha's label slugs to our `PIIEntityType` slugs.
///
/// **Bundling.** Model + tokenizer + label map are produced by
/// `apps/desktop/scripts/convert-piiranha.py`. They live in
/// `Sources/Bouclier/Resources/` next to PromptGuard2's bundle. The
/// classifier throws `.modelNotFound` if any of the three artifacts is
/// missing — `PatternManager` swallows that and continues on a
/// regex-only PII path, identical to how MLClassifier degrades.
final class PIIClassifier: @unchecked Sendable {
    // MARK: - Types

    enum ClassifierError: Error, CustomStringConvertible {
        case modelNotFound
        case tokenizerNotFound
        case labelMapNotFound
        case labelMapInvalid(String)
        case predictionFailed(String)
        case invalidOutput

        var description: String {
            switch self {
            case .modelNotFound:
                return "Piiranha.mlpackage not found in app bundle"
            case .tokenizerNotFound:
                return "PiiranhaTokenizer folder not found in app bundle"
            case .labelMapNotFound:
                return "piiranha-labels.json not found in app bundle"
            case .labelMapInvalid(let detail):
                return "piiranha-labels.json malformed: \(detail)"
            case .predictionFailed(let detail):
                return "CoreML prediction failed: \(detail)"
            case .invalidOutput:
                return "CoreML model returned an unexpected output shape"
            }
        }
    }

    // MARK: - Configuration

    /// Fixed sequence length the CoreML model is traced with. Must match
    /// `SEQ_LENGTH` in `convert-piiranha.py`. mDeBERTa-v3 + Piiranha
    /// uses 256 (longer prompts truncate; almost all chat-completion
    /// content fits comfortably).
    private static let sequenceLength = 256

    /// Drop predicted spans whose mean per-token softmax probability is
    /// below this threshold. Calibrated low because IOB2 single-token
    /// spans are common and Piiranha is well-calibrated at threshold
    /// 0.5 on AI4Privacy — we keep some headroom for OOD chat text.
    private static let minSpanProbability: Float = 0.55

    /// Subword surface for word-initial tokens in SentencePiece. mDeBERTa
    /// uses the standard `▁` (U+2581) marker.
    private static let spmSpaceMarker: Character = "\u{2581}"

    // MARK: - State

    private let model: MLModel
    private let tokenizer: any Tokenizer
    private let idToLabel: [Int: String]

    // MARK: - Init

    /// Loads the bundled CoreML model, tokenizer, and label map. Async
    /// because swift-transformers' loader is async; called once at
    /// startup from a background task.
    init() async throws {
        // ── 1. Locate the CoreML model. Same compile-and-cache flow as
        // MLClassifier so dev builds (`swift run`, .mlpackage only) and
        // release builds (.mlmodelc precompiled) both work.
        let modelURL: URL
        if let compiled = BouclierResources.url(forResource: "Piiranha", withExtension: "mlmodelc") {
            modelURL = compiled
        } else if let raw = BouclierResources.url(forResource: "Piiranha", withExtension: "mlpackage") {
            modelURL = try Self.compiledCopy(of: raw)
        } else {
            throw ClassifierError.modelNotFound
        }

        let config = MLModelConfiguration()
        config.computeUnits = .all
        self.model = try MLModel(contentsOf: modelURL, configuration: config)

        // ── 2. Tokenizer folder.
        guard let tokenizerDir = BouclierResources.url(
            forResource: "PiiranhaTokenizer",
            withExtension: nil
        ) else {
            throw ClassifierError.tokenizerNotFound
        }
        self.tokenizer = try await AutoTokenizer.from(modelFolder: tokenizerDir)

        // ── 3. Label map. Produced by convert-piiranha.py from
        // `model.config.id2label`. JSON keys are stringified ints.
        guard let labelMapURL = BouclierResources.url(
            forResource: "piiranha-labels",
            withExtension: "json"
        ) else {
            throw ClassifierError.labelMapNotFound
        }
        self.idToLabel = try Self.loadLabelMap(from: labelMapURL)
    }

    /// Compile a raw `.mlpackage` to a release/version-aware cached copy.
    private static func compiledCopy(of rawPackage: URL) throws -> URL {
        try CompiledModelCache.compiledCopy(
            of: rawPackage,
            modelName: "Piiranha"
        )
    }

    private static func loadLabelMap(from url: URL) throws -> [Int: String] {
        let data = try Data(contentsOf: url)
        guard let raw = try JSONSerialization.jsonObject(with: data) as? [String: String] else {
            throw ClassifierError.labelMapInvalid("not a {string: string} object")
        }
        var out: [Int: String] = [:]
        for (key, value) in raw {
            guard let id = Int(key) else {
                throw ClassifierError.labelMapInvalid("non-integer key \(key)")
            }
            out[id] = value
        }
        if out.isEmpty { throw ClassifierError.labelMapInvalid("empty map") }
        return out
    }

    // MARK: - Inference

    /// Classify a single string and return detected PII spans. Errors
    /// bubble up so the caller can degrade gracefully — a thrown error
    /// here means the ML pass produced nothing, but the regex + native
    /// passes still ran.
    func classify(_ text: String) async throws -> [PIIScanner.Detection] {
        guard !text.isEmpty else { return [] }

        // ── 1. Tokenize and pad to the model's fixed seq length.
        let rawIds = tokenizer.encode(text: text)
        let truncated = Array(rawIds.prefix(Self.sequenceLength))
        let attendedCount = truncated.count
        var paddedIds = truncated
        if paddedIds.count < Self.sequenceLength {
            paddedIds.append(contentsOf: repeatElement(0, count: Self.sequenceLength - paddedIds.count))
        }

        // ── 2. Build MLMultiArray inputs.
        let inputIds = try MLMultiArray(shape: [1, NSNumber(value: Self.sequenceLength)], dataType: .int32)
        let attentionMask = try MLMultiArray(shape: [1, NSNumber(value: Self.sequenceLength)], dataType: .int32)
        for i in 0..<Self.sequenceLength {
            inputIds[i] = NSNumber(value: Int32(paddedIds[i]))
            attentionMask[i] = NSNumber(value: Int32(i < attendedCount ? 1 : 0))
        }
        let input = try MLDictionaryFeatureProvider(dictionary: [
            "input_ids": MLFeatureValue(multiArray: inputIds),
            "attention_mask": MLFeatureValue(multiArray: attentionMask),
        ])

        // ── 3. Run the model. CoreML's prediction(from:) is async on
        // macOS 14+; the await is required even when the underlying
        // call returns synchronously for small models.
        let output: MLFeatureProvider
        do {
            output = try await model.prediction(from: input)
        } catch {
            throw ClassifierError.predictionFailed(String(describing: error))
        }

        // ── 4. Logits → per-token (label, probability).
        // Output shape: [1, seqLen, numLabels]. We argmax over the
        // last axis after a numerically-stable softmax.
        guard let logits = output.featureValue(for: "logits")?.multiArrayValue else {
            throw ClassifierError.invalidOutput
        }
        let numLabels = idToLabel.count
        guard logits.count == Self.sequenceLength * numLabels else {
            throw ClassifierError.invalidOutput
        }
        let perTokenLabels = decodeTokenLabels(
            logits: logits,
            attendedCount: attendedCount,
            numLabels: numLabels
        )

        // ── 5. Decode IOB2 → spans (token-index ranges).
        let tokenSpans = collapseIOB2(perTokenLabels)

        // ── 6. Map token spans to character offsets in the original input.
        let charSpans = mapTokensToChars(
            input: text,
            tokenIds: truncated,
            tokenSpans: tokenSpans
        )

        return charSpans
    }

    // MARK: - Decoding

    private struct TokenLabel {
        /// Predicted label slug — e.g. "B-EMAIL", "I-PERSON", "O".
        let label: String
        /// Softmax probability of the predicted label, [0,1].
        let probability: Float
    }

    /// Walk the `[seqLen × numLabels]` logits buffer, take argmax per
    /// token, and return label + softmax confidence. Skips padded
    /// positions beyond `attendedCount`.
    private func decodeTokenLabels(
        logits: MLMultiArray,
        attendedCount: Int,
        numLabels: Int
    ) -> [TokenLabel] {
        var out: [TokenLabel] = []
        out.reserveCapacity(attendedCount)
        for tokenIdx in 0..<attendedCount {
            let base = tokenIdx * numLabels
            var bestId = 0
            var bestLogit: Float = -.greatestFiniteMagnitude
            for label in 0..<numLabels {
                let v = logits[base + label].floatValue
                if v > bestLogit {
                    bestLogit = v
                    bestId = label
                }
            }
            // Numerically-stable softmax over this token's row.
            var sumExp: Float = 0
            for label in 0..<numLabels {
                sumExp += expf(logits[base + label].floatValue - bestLogit)
            }
            let prob = sumExp > 0 ? 1.0 / sumExp : 0
            let labelSlug = idToLabel[bestId] ?? "O"
            out.append(TokenLabel(label: labelSlug, probability: prob))
        }
        return out
    }

    /// One IOB2 span in token-index space, with its average probability.
    private struct TokenSpan {
        let labelBase: String  // "EMAIL", "PERSON", … (B-/I- stripped)
        let firstToken: Int    // inclusive
        let lastToken: Int     // inclusive
        let meanProbability: Float
    }

    /// Collapse `[B-X, I-X, I-X, O, B-Y, …]` into contiguous spans.
    private func collapseIOB2(_ tokens: [TokenLabel]) -> [TokenSpan] {
        var spans: [TokenSpan] = []
        var current: (base: String, start: Int, probs: [Float])?

        func flush(endingAt last: Int) {
            guard let c = current else { return }
            let mean = c.probs.reduce(0, +) / Float(c.probs.count)
            if mean >= Self.minSpanProbability {
                spans.append(TokenSpan(
                    labelBase: c.base, firstToken: c.start, lastToken: last,
                    meanProbability: mean
                ))
            }
            current = nil
        }

        for (idx, tok) in tokens.enumerated() {
            if tok.label == "O" {
                flush(endingAt: idx - 1)
                continue
            }
            let parts = tok.label.split(separator: "-", maxSplits: 1)
            guard parts.count == 2 else {
                flush(endingAt: idx - 1)
                continue
            }
            let prefix = String(parts[0])
            let base = String(parts[1])
            if prefix == "B" {
                flush(endingAt: idx - 1)
                current = (base: base, start: idx, probs: [tok.probability])
            } else if prefix == "I", current?.base == base {
                current!.probs.append(tok.probability)
            } else {
                // Stray I- without matching B- — treat as new span.
                flush(endingAt: idx - 1)
                current = (base: base, start: idx, probs: [tok.probability])
            }
        }
        flush(endingAt: tokens.count - 1)
        return spans
    }

    // MARK: - Subword → character offset mapping

    /// Walk each subword's surface form forward through the original
    /// input, recording character offsets per token. SentencePiece uses
    /// `▁` to mark word-initial tokens (with a leading space); we
    /// translate that into a literal space when aligning.
    private func mapTokensToChars(
        input: String,
        tokenIds: [Int],
        tokenSpans: [TokenSpan]
    ) -> [PIIScanner.Detection] {
        guard !tokenSpans.isEmpty else { return [] }

        // Compute (start, end) UTF-16 offsets per token by decoding each
        // ID back to its surface form, normalising the `▁` marker, and
        // sliding through the input.
        let nsInput = input as NSString
        var tokenStarts: [Int] = Array(repeating: -1, count: tokenIds.count)
        var tokenEnds: [Int] = Array(repeating: -1, count: tokenIds.count)
        var cursor = 0

        for (idx, id) in tokenIds.enumerated() {
            let raw = tokenizer.decode(tokens: [id])
            // Tokenizer.decode may strip the SentencePiece marker; for
            // raw subword inspection we ask the convertor for the
            // unprocessed form when possible. Falling back: derive from
            // raw decode + heuristic re-insertion of leading space.
            var surface = raw
            if surface.first == Self.spmSpaceMarker {
                surface = " " + String(surface.dropFirst())
            }
            // Edge case: special tokens like [CLS]/[SEP] decode to empty
            // or a tag string. Skip them — their character span is zero.
            if surface.isEmpty || surface.hasPrefix("[") && surface.hasSuffix("]") {
                tokenStarts[idx] = cursor
                tokenEnds[idx] = cursor
                continue
            }

            // Find `surface` in the input starting from `cursor`. Use
            // NSString length so we stay in UTF-16 units (which is what
            // CoreML/PIIScanner offsets are in).
            let searchRange = NSRange(location: cursor, length: nsInput.length - cursor)
            let foundRange = nsInput.range(of: surface, options: [.literal], range: searchRange)
            if foundRange.location == NSNotFound {
                // Could happen with byte-level fallback tokens. Best-effort
                // synthesize a zero-width span anchored at cursor so
                // downstream IOB2 collapsing doesn't break.
                tokenStarts[idx] = cursor
                tokenEnds[idx] = cursor
                continue
            }
            tokenStarts[idx] = foundRange.location
            tokenEnds[idx] = foundRange.location + foundRange.length
            cursor = tokenEnds[idx]
        }

        // Translate IOB2 token spans into character ranges, then into
        // PIIScanner.Detection values. Skip spans that map to an empty
        // range or to a Piiranha label we don't expose.
        var detections: [PIIScanner.Detection] = []
        for span in tokenSpans {
            guard let entityType = Self.mapLabel(span.labelBase) else { continue }
            let firstIdx = max(0, span.firstToken)
            let lastIdx = min(tokenIds.count - 1, span.lastToken)
            guard firstIdx <= lastIdx else { continue }
            let start = tokenStarts[firstIdx]
            let end = tokenEnds[lastIdx]
            guard start >= 0, end > start, end <= nsInput.length else { continue }
            let value = nsInput.substring(with: NSRange(location: start, length: end - start))
            // Trim a leading space introduced by the SPM marker on the
            // first subword — the actual entity value starts at the
            // first non-whitespace character.
            let trimmedLeading = value.prefix(while: { $0 == " " }).count
            let finalStart = start + trimmedLeading
            let finalValue = String(value.dropFirst(trimmedLeading))
            guard finalValue.count > 0 else { continue }
            detections.append(
                PIIScanner.Detection(
                    type: entityType,
                    start: finalStart,
                    end: finalStart + (finalValue as NSString).length,
                    value: finalValue
                )
            )
        }
        return detections
    }

    /// Map Piiranha's label slug (post B-/I- strip) to our PIIEntityType.
    /// Returns nil to deliberately suppress: TIME (not PII), NRP
    /// (nationality/religious/political — too broad to redact safely),
    /// PASSWORD (handled with much higher precision by the secret
    /// detectors).
    private static func mapLabel(_ piiranhaLabel: String) -> String? {
        switch piiranhaLabel.uppercased() {
        case "EMAIL", "EMAILADDRESS": return "EMAIL"
        case "PHONE", "PHONENUMBER", "PHONE_NUMBER": return "PHONE"
        case "ADDRESS", "STREETADDRESS", "STREET_ADDRESS": return "ADDRESS"
        case "USERNAME": return "USERNAME"
        case "PERSON", "GIVENNAME", "SURNAME", "NAME": return "PERSON"
        case "CREDITCARDNUMBER", "CREDIT_CARD", "CREDITCARD": return "CREDIT_CARD"
        case "IP_ADDRESS", "IPADDRESS": return "IPV4"
        case "DATE_OF_BIRTH", "DATEOFBIRTH", "DOB": return "DATE_OF_BIRTH"
        case "SOCIALNUM", "SOCIAL_SECURITY_NUMBER", "SSN", "US_SSN": return "US_SSN"
        case "MEDICAL_LICENSE", "MEDICALLICENSE": return "MEDICAL_LICENSE"
        case "ID_NUM", "IDNUM", "IDCARDNUM": return "ID_NUM"
        case "DRIVERLICENSE", "DRIVER_LICENSE": return "DRIVER_LICENSE"
        case "BANK_ACCT", "BANKACCT", "ACCOUNTNUM": return "BANK_ACCOUNT"
        case "TAXNUM", "TAX_NUM": return "TAX_NUM"
        case "BUILDINGNUM", "ZIPCODE", "POSTCODE": return "ADDRESS"
        case "TIME", "NRP", "PASSWORD": return nil  // intentionally suppressed
        default: return nil
        }
    }
}
