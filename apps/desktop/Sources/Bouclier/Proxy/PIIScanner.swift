import Foundation

/// Swift port of the `@bouclier-ai/patterns` PII regex tier (Phase 1).
///
/// Detector list, validator logic, and overlap-resolution rules are kept
/// in lockstep with the TypeScript source — same offsets, same precedence,
/// same false-positive suppression. Cross-platform parity matters because
/// the site playground (TS) and the desktop proxy (Swift) must reach
/// identical conclusions about a given payload.
///
/// Phase 2 (Piiranha mDeBERTa on CoreML) will plug into this scanner as
/// an optional second signal, mirroring `MLClassifier`'s relationship
/// to `InjectionFilter`.
final class PIIScanner: @unchecked Sendable {
    /// A single PII span found in the input.
    struct Detection: Sendable, Equatable {
        let type: String
        let start: Int   // UTF-16 offset (NSRegularExpression natively)
        let end: Int
        let value: String
    }

    /// One detector: a compiled regex + the matching validator hook.
    private struct Detector {
        let type: String
        let regex: NSRegularExpression
        let validate: (@Sendable (String) -> Bool)?
        let contextOk: (@Sendable (String, NSRange) -> Bool)?
    }

    private let detectors: [Detector]

    init() {
        self.detectors = Self.buildDetectors()
    }

    /// Scan a string for PII. Returns non-overlapping detections in
    /// input order.
    func scan(_ content: String) -> [Detection] {
        guard !content.isEmpty else { return [] }
        let nsContent = content as NSString
        let fullRange = NSRange(location: 0, length: nsContent.length)

        struct Raw {
            let d: Detection
            let rank: Int
        }
        var raw: [Raw] = []
        for (rank, det) in detectors.enumerated() {
            det.regex.enumerateMatches(in: content, range: fullRange) { result, _, _ in
                guard let result, result.range.length > 0 else { return }
                let value = nsContent.substring(with: result.range)
                if let validate = det.validate, !validate(value) { return }
                if let contextOk = det.contextOk, !contextOk(content, result.range) { return }
                let det = Detection(
                    type: det.type,
                    start: result.range.location,
                    end: result.range.location + result.range.length,
                    value: value
                )
                raw.append(Raw(d: det, rank: rank))
            }
        }

        raw.sort { a, b in
            if a.d.start != b.d.start { return a.d.start < b.d.start }
            if a.rank != b.rank { return a.rank < b.rank }
            // Longest span at the same start/rank wins so we don't leak
            // an un-redacted tail. Documented invariant — see R1 in the
            // S-tier review (scanner.ts:45 dead-code fix).
            return a.d.end > b.d.end
        }

        var out: [Detection] = []
        var lastEnd = -1
        for item in raw where item.d.start >= lastEnd {
            out.append(item.d)
            lastEnd = item.d.end
        }
        return out
    }

    // MARK: - Detector list (mirrors PII_DETECTORS in TS)

    private static func buildDetectors() -> [Detector] {
        func re(_ pattern: String, _ flags: NSRegularExpression.Options = []) -> NSRegularExpression {
            try! NSRegularExpression(pattern: pattern, options: flags)
        }

        return [
            // High-precision first.
            Detector(
                type: "JWT",
                regex: re(#"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"#),
                validate: PIIValidators.isPlausibleJWT,
                contextOk: nil
            ),
            Detector(
                type: "AWS_ACCESS_KEY",
                regex: re(#"\b(?:AKIA|ASIA|AIDA|AGPA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b"#),
                validate: nil, contextOk: nil
            ),
            Detector(
                type: "EMAIL",
                regex: re(#"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b"#),
                validate: nil, contextOk: nil
            ),
            Detector(
                type: "IBAN",
                regex: re(#"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b"#),
                validate: PIIValidators.ibanMod97,
                contextOk: nil
            ),
            Detector(
                type: "FR_NIR",
                regex: re(#"\b[12][ ]?\d{2}[ ]?\d{2}[ ]?[0-9AB]\d[ ]?\d{3}[ ]?\d{3}[ ]?\d{2}\b"#),
                validate: PIIValidators.isPlausibleNIR,
                contextOk: nil
            ),
            Detector(
                type: "FR_SIRET",
                regex: re(#"\b\d{3}[ ]?\d{3}[ ]?\d{3}[ ]?\d{5}\b"#),
                validate: PIIValidators.isPlausibleSIRET,
                contextOk: nil
            ),
            Detector(
                type: "CREDIT_CARD",
                regex: re(#"\b\d(?:[ -]?\d){12,18}\b"#),
                validate: PIIValidators.luhn,
                contextOk: PIIValidators.creditCardContextOk
            ),
            Detector(
                type: "UK_NHS",
                regex: re(#"\b\d{3}[ -]\d{3}[ -]\d{4}\b"#),
                validate: PIIValidators.isPlausibleNHS,
                contextOk: nil
            ),
            Detector(
                type: "US_NPI",
                regex: re(#"\b\d{10}\b"#),
                validate: PIIValidators.isPlausibleNPI,
                contextOk: nil
            ),
            Detector(
                type: "FR_SIREN",
                regex: re(#"\b\d{3}[ ]?\d{3}[ ]?\d{3}\b"#),
                validate: PIIValidators.isPlausibleSIREN,
                contextOk: nil
            ),
            Detector(
                type: "US_SSN",
                regex: re(#"\b\d{3}-?\d{2}-?\d{4}\b"#),
                validate: PIIValidators.isPlausibleSSN,
                contextOk: nil
            ),
            Detector(
                type: "UK_NINO",
                regex: re(#"\b[A-Z]{2}[ ]?\d{2}[ ]?\d{2}[ ]?\d{2}[ ]?[A-D]\b"#),
                validate: PIIValidators.isPlausibleNINO,
                contextOk: nil
            ),
            Detector(
                type: "UK_POSTCODE",
                regex: re(#"\b[A-PR-UWYZ][A-Z0-9]{1,3}[ ]?\d[A-Z]{2}\b"#, [.caseInsensitive]),
                validate: PIIValidators.isPlausibleUKPostcode,
                contextOk: nil
            ),
            Detector(
                type: "IPV6",
                regex: re(
                    #"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{0,4}\b"#
                ),
                validate: PIIValidators.isPlausibleIPv6,
                contextOk: nil
            ),
            Detector(
                type: "IPV4",
                regex: re(#"\b(?:\d{1,3}\.){3}\d{1,3}\b"#),
                validate: PIIValidators.isPlausibleIPv4,
                contextOk: nil
            ),
        ]
    }
}
