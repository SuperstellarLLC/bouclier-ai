import Foundation

/// Scrubs secrets and PII from a captured span before it can be shown in
/// the report preview or sent to bouclier.ai.
///
/// This reuses the **shipped** detection engine (`PIIScanner`) rather than a
/// bespoke regex set: the same detectors that redact PII elsewhere —
/// API keys, tokens, AWS keys, JWTs, emails, credit-card / IBAN / SSN, and
/// so on — decide what to mask here. `PIIScanner.active` is a live registry
/// initialised with a default regex-based scanner, so redaction is never a
/// silent no-op even before the optional ML tier loads.
///
/// Redaction is **best effort** — it cannot know that a random string is a
/// customer's proprietary token. The real safeguard is the preview: the
/// operator sees the exact bytes below and can cancel. This step removes the
/// obvious credential/PII footguns so an accidental report doesn't exfiltrate
/// an API key from a tool result the agent happened to read.
enum ReportRedactor {
    /// Redact secrets/PII from `text` using the live PII scanner, **including
    /// the ML tier** (`scanWithML`) — so free-text PII the regexes miss
    /// (names, locations, general PII) is scrubbed too, not just structured
    /// secrets. Async and off the main actor: it runs the full scan (dozens
    /// of regexes plus a possible CoreML pass) over adversarial content, so
    /// it must never block the UI. `scanWithML` degrades to regex-only when
    /// the ML model isn't loaded, so this is always at least as strong as the
    /// sync path.
    static func redact(_ text: String) async -> String {
        apply(await PIIScanner.active.current().scanWithML(text), to: text)
    }

    /// Pure application of a detection set to text: each detected span is
    /// replaced by a `[redacted:type]` marker. Applied right-to-left so
    /// earlier UTF-16 offsets stay valid as later spans are replaced. Split
    /// out from the scan so it is unit-testable without the live registry.
    ///
    /// `scan()` already returns non-overlapping spans, but `apply` is public
    /// and independently testable, so it defends against overlap: each span's
    /// end is clamped into the not-yet-replaced region, and a partially
    /// overlapping earlier span still masks its exposed prefix rather than
    /// being dropped whole (which would leave cleartext behind).
    static func apply(_ detections: [PIIScanner.Detection], to text: String) -> String {
        guard !detections.isEmpty else { return text }
        let ns = NSMutableString(string: text)
        let sorted = detections.sorted { $0.start > $1.start }
        var lastStart = ns.length
        for d in sorted {
            let start = max(0, min(d.start, ns.length))
            let end = min(max(0, min(d.end, ns.length)), lastStart)
            guard end > start else { continue }
            let marker = "[redacted:\(d.type.lowercased())]"
            ns.replaceCharacters(in: NSRange(location: start, length: end - start), with: marker)
            lastStart = start
        }
        return ns as String
    }
}
