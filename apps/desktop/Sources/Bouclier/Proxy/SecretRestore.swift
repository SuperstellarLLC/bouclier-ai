import Foundation

/// Pure, streaming, straddle-safe restore of placeholders → real secret
/// values in a response body — the inbound inverse of
/// `SecretRedactionPass`. The model echoes our placeholder; we put the
/// real value back before the local agent consumes it, so the agent's
/// own tool calls work while the model provider never saw the secret.
///
/// **EXACT-MATCH ONLY.** Deliberately no fuzzy / case-insensitive
/// matching: splicing a *live API key* in place of a hallucinated
/// near-token would be a security hole. A near-miss is a signal to log,
/// never something to act on. (This inverts the PII-anonymization SOTA,
/// where fuzzy recovery is a feature — for secrets it is a liability.)
///
/// Operates on **raw bytes** and never decodes UTF-8, so a multi-byte
/// character split across stream chunks can't be corrupted. Placeholders
/// are ASCII, so byte-subsequence matching is exact and boundary-safe.
///
/// Straddle safety: a placeholder may be split across two chunks
/// (`__BOUCLIER` | `_SECRET_x__`). We retain a trailing carry of
/// `maxPlaceholderLen − 1` bytes — the most a placeholder prefix can
/// occupy without completing — and only emit bytes we've confirmed
/// aren't a partial placeholder.
struct SecretRestore: Sendable {
    /// (placeholder bytes, real value bytes), longest placeholder first so
    /// a placeholder that is a prefix of another isn't clobbered.
    private let replacements: [(needle: [UInt8], value: [UInt8])]
    /// Bytes retained each chunk because they could be the start of a
    /// placeholder completed by the next chunk.
    private let holdback: Int
    private var carry: [UInt8] = []

    init(map: [(placeholder: String, value: String)]) {
        let sorted = map.sorted { $0.placeholder.utf8.count > $1.placeholder.utf8.count }
        self.replacements = sorted.map { (Array($0.placeholder.utf8), Array($0.value.utf8)) }
        let maxLen = self.replacements.map(\.needle.count).max() ?? 0
        self.holdback = max(0, maxLen - 1)
    }

    var isEmpty: Bool { replacements.isEmpty }

    /// Ingest a chunk; return the bytes safe to emit now, with all
    /// fully-arrived placeholders restored.
    mutating func ingest(_ chunk: [UInt8]) -> [UInt8] {
        carry.append(contentsOf: chunk)
        let buffer = Self.replaceAll(carry, replacements)
        if buffer.count <= holdback {
            carry = buffer
            return []
        }
        let cut = buffer.count - holdback
        let emit = Array(buffer[..<cut])
        carry = Array(buffer[cut...])
        return emit
    }

    /// Flush at stream end: restore and emit whatever remains.
    mutating func finish() -> [UInt8] {
        let out = Self.replaceAll(carry, replacements)
        carry = []
        return out
    }

    /// SINGLE left-to-right pass that, at each position, tries every needle
    /// (longest first) and on a match copies the replacement value and
    /// jumps past the matched needle — never re-scanning emitted value
    /// bytes. This is critical: a sequential per-needle pass would let a
    /// restored value that happens to contain ANOTHER rule's placeholder be
    /// rewritten by a later needle, splicing in a secret the model never
    /// emitted. One pass with jump-past makes restoration exact and
    /// order-independent across rules.
    static func replaceAll(_ input: [UInt8], _ replacements: [(needle: [UInt8], value: [UInt8])]) -> [UInt8] {
        guard !replacements.isEmpty else { return input }
        var out: [UInt8] = []
        out.reserveCapacity(input.count)
        var i = 0
        scan: while i < input.count {
            for (needle, value) in replacements where !needle.isEmpty {
                if i + needle.count <= input.count, matches(input, at: i, needle) {
                    out.append(contentsOf: value)
                    i += needle.count
                    continue scan
                }
            }
            out.append(input[i])
            i += 1
        }
        return out
    }

    private static func matches(_ h: [UInt8], at i: Int, _ needle: [UInt8]) -> Bool {
        var k = 0
        while k < needle.count {
            if h[i + k] != needle[k] { return false }
            k += 1
        }
        return true
    }
}
