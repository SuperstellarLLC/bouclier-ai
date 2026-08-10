import Foundation

/// Wraps `NSDataDetector` to surface PHONE and ADDRESS spans that regex
/// would either miss (international phone formats, multi-line postal
/// addresses) or over-flag (`12.34.56.78` shaped numbers).
///
/// `NSDataDetector` is a heavyweight construct — its initialiser
/// JIT-compiles internal state — but instances are documented as safe
/// for concurrent reads. We keep one per process, lazily constructed
/// the first time the proxy scans a payload.
///
/// Date detection is intentionally **excluded** from the default
/// configuration: every "May 17, 2026" in a log line would otherwise
/// surface as DATE_OF_BIRTH, which is the wrong frame. Date-of-birth
/// recall is delegated to the ML tier (Piiranha) which uses
/// surrounding context to disambiguate.
final class PIINativeDetector: @unchecked Sendable {
    /// Single shared instance — NSDataDetector compilation isn't free.
    static let shared = PIINativeDetector()

    private let detector: NSDataDetector

    private init() {
        // `phoneNumber | address` is what we want today. URLs are not
        // PII per se (they're often public), and dates need contextual
        // disambiguation we don't yet do.
        let types: NSTextCheckingResult.CheckingType = [.phoneNumber, .address]
        self.detector = try! NSDataDetector(types: types.rawValue)
    }

    /// Scan `content` for native PHONE and ADDRESS spans. Returns
    /// detections compatible with `PIIScanner.Detection` (NSRange is
    /// converted into character offsets / value substring).
    func scan(_ content: String) -> [PIIScanner.Detection] {
        guard !content.isEmpty else { return [] }
        let nsContent = content as NSString
        let fullRange = NSRange(location: 0, length: nsContent.length)
        var detections: [PIIScanner.Detection] = []

        detector.enumerateMatches(in: content, range: fullRange) { result, _, _ in
            guard let result, result.range.length > 0 else { return }
            let value = nsContent.substring(with: result.range)
            let type = Self.entityType(for: result.resultType)
            guard let type else { return }
            detections.append(
                PIIScanner.Detection(
                    type: type,
                    start: result.range.location,
                    end: result.range.location + result.range.length,
                    value: value
                )
            )
        }
        return detections
    }

    /// Map an NSTextCheckingResult type to our PIIEntityType slug.
    /// Returns nil for types we deliberately don't redact (URLs,
    /// transit info, dates without context).
    private static func entityType(for resultType: NSTextCheckingResult.CheckingType) -> String? {
        if resultType.contains(.phoneNumber) { return "PHONE" }
        if resultType.contains(.address) { return "ADDRESS" }
        return nil
    }
}
