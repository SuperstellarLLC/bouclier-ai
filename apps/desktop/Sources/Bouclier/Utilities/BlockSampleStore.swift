import BouclierCore
import Foundation

/// One captured block, written only when the operator opts in.
///
/// This is the one place in Bouclier that records request *content* — the
/// offending untrusted span — so it exists to answer the question the
/// score alone can't: *why* did this block? It carries the per-signal
/// breakdown and, for an ML-driven block, the single passage the
/// classifier reacted to most strongly (`topWindow`), which is the only
/// way to explain a neural score that otherwise arrives as a bare number.
struct BlockSample: Codable, Sendable {
    let timestamp: String
    let targetHost: String
    let locator: String
    /// Truncated copy of the offending untrusted span. Capped; never the
    /// whole request. This is content — the reason capture is opt-in.
    let spanExcerpt: String
    let spanLength: Int
    let fusedScore: Double
    let mlScore: Float?
    let entropyAnomaly: Double
    let matchCount: Int
    let patternNames: [String]
    /// Benign-context multiplier applied to the ML signal (1.0 = none).
    /// Explains at a glance why dampening did or didn't rescue the span.
    let benignMultiplier: Double
    /// Highest-scoring ~window of the span under the classifier, when ML
    /// was the driver — turns "0.99 somewhere" into "this passage."
    let topWindow: String?
    let topWindowScore: Float?
    let windowsScanned: Int
    let attributionTruncated: Bool
    let fingerprint: String
}

/// Append-only, size-capped local store for captured blocks. Local file
/// only — never transmitted, never leaves the machine. Off by default;
/// the gateway only writes here when `captureBlockSamplesEnabled` is set.
enum BlockSampleStore {
    /// Cap the offending-span copy so one giant tool result can't bloat
    /// the file. The head is where injected instructions sit in practice.
    static let maxExcerptChars = 4096
    /// Keep the most recent N samples; older ones are dropped on write.
    static let maxSamples = 100

    static var fileURL: URL {
        BouclierPaths.appSupportDir.appendingPathComponent("block-samples.jsonl")
    }

    /// Append one sample, then trim to the newest `maxSamples`. Best-effort:
    /// a capture failure must never affect the block decision itself.
    static func append(_ sample: BlockSample) {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let line = try encoder.encode(sample)
            guard var text = String(data: line, encoding: .utf8) else { return }
            text += "\n"

            let url = fileURL
            var existing = (try? String(contentsOf: url, encoding: .utf8)) ?? ""
            existing += text

            // Trim to the newest maxSamples lines.
            var lines = existing.split(separator: "\n", omittingEmptySubsequences: true)
            if lines.count > maxSamples {
                lines = Array(lines.suffix(maxSamples))
            }
            let out = lines.joined(separator: "\n") + "\n"
            try out.data(using: .utf8)?.write(to: url, options: .atomic)
        } catch {
            // Swallow — capture is a debugging aid, not a correctness path.
        }
    }

    static var count: Int {
        guard let text = try? String(contentsOf: fileURL, encoding: .utf8) else { return 0 }
        return text.split(separator: "\n", omittingEmptySubsequences: true).count
    }

    static func clear() {
        try? FileManager.default.removeItem(at: fileURL)
    }
}
