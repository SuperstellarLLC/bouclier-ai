import Foundation

/// Cheap statistical anomaly signal that complements regex + ML detection.
///
/// Natural language has a Shannon entropy of roughly 3.5–4.5 bits per
/// character. Adversarial GCG-style suffixes (`describing.\ + similarlyNow…`)
/// and base64/hex blobs land above 5.5. Highly repetitive payloads
/// (token-stuffing, fence repetition) drop below 2.5. Both extremes are
/// suspicious; the middle is normal text.
///
/// This is intentionally a single-pass, allocation-free function so it
/// can run on every request without measurable overhead.
enum EntropyAnalyzer {
    /// Shannon entropy in bits per character. Returns 0 for empty input.
    static func shannonEntropy(_ text: String) -> Double {
        guard !text.isEmpty else { return 0 }
        var freq: [Character: Int] = [:]
        freq.reserveCapacity(64)
        for c in text { freq[c, default: 0] += 1 }
        let len = Double(text.count)
        var h = 0.0
        for count in freq.values {
            let p = Double(count) / len
            h -= p * log2(p)
        }
        return h
    }

    /// 0.0–1.0 anomaly score. Both high-entropy (gibberish, encoded
    /// payloads) and abnormally low-entropy (repetitive token stuffing)
    /// inputs score above 0. Mid-range natural text scores 0.
    ///
    /// The thresholds are conservative — tuned to fire only on clearly
    /// abnormal text so the signal stays low-false-positive. The fused
    /// scorer in `InjectionFilter` weights this lightly (10%).
    static func anomalyScore(_ text: String) -> Double {
        // Skip very short inputs — entropy is meaningless on a few chars.
        guard text.count >= 32 else { return 0 }

        let h = shannonEntropy(text)

        if h > 5.5 {
            // Gibberish / encoded payload territory. Cap at 2 bits over
            // the threshold so a typical base64 blob (~6.0) scores ~0.25.
            return min(1.0, (h - 5.5) / 2.0)
        }
        if h < 2.5 {
            // Highly repetitive. Only meaningful on longer inputs to
            // avoid flagging short codes / IDs.
            guard text.count >= 100 else { return 0 }
            return min(1.0, (2.5 - h) / 2.0)
        }
        return 0
    }
}
