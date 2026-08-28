import CryptoKit
import Darwin
import Foundation

/// Gateway-side prompt-injection inspection.
///
/// This is the pass that makes Bouclier a prompt-injection firewall again
/// **without** the CA-terminating proxy and System Extension that the
/// detection engine used to hang off. The loopback gateway already sees
/// every request body in plaintext before it is re-issued upstream over
/// TLS, which is all the visibility detection ever needed; extreme mode
/// was never a prerequisite for it, only an accident of how the engine
/// was first wired.
///
/// ## Why this is not the 2026-04 filter with a new caller
///
/// The old `InjectionFilter` call sites scanned the whole request body and
/// blocked on any regex hit. That is the design that makes guardrail
/// products unusable: a developer who types *"ignore previous
/// instructions"* into their own agent, or pastes an OWASP advisory, is
/// the **principal**. Blocking the principal is a false positive by
/// construction, and it is what drove this project's own retreat from
/// text-prompt rewriting in v0.6.0.
///
/// So this pass splits the body by **provenance** before it scores
/// anything:
///
/// - `.untrusted` — content the request does not positively attribute to
///   the principal or to a supported local-file read: `tool_result` blocks
///   (Anthropic), `role: "tool"`
///   messages (OpenAI chat), `function_call_output` items (OpenAI
///   Responses). This is where indirect prompt injection actually lands
///   for an agent — a poisoned web page, a hostile README, a malicious
///   MCP tool result. Instructions have no business being here, so a
///   detection is actionable: Monitor records it and Blocking may refuse it.
/// - `.principal` — the operator's own prompt and system text. Scanned
///   for telemetry so the activity log stays useful, but **never blocked
///   in normal mode and never rewritten**. Managed strict policy may elect
///   to refuse it and accepts that availability tradeoff.
///
/// That provenance split is the honest version of "state of the art" for
/// a local detector in 2026: the field's consensus (CaMeL, Meta's Agents
/// Rule of Two, MCP Colors) is that the load-bearing control is knowing
/// which request spans are classified as untrusted and constraining what they
/// can reach —
/// not a cleverer classifier. Detection here is defence in depth on the
/// untrusted leg, not a claim to have solved prompt injection.
///
/// ## Integrity discipline
///
/// Mirrors `SecretRedactionPass`: a cheap, independent `hasTrigger` gate
/// runs first, so traffic with no untrusted spans is provably untouched
/// and a bug in the scoring path cannot corrupt an ordinary chat request.
///
/// Pure and channel-free so it is unit-testable without a socket.
enum InjectionInspectionPass {

    // MARK: - Types

    /// Where a span of text came from, which decides what we may do about it.
    enum Origin: String, Sendable {
        /// Tool output and retrieved documents without an eligible, positively
        /// attributed local-read provenance. This is a request-local
        /// classification, not proof that no person in the session authored it.
        case untrusted
        /// The operator's own prompt / system text.
        case principal
        /// A `tool_result` positively attributed to a local read of the
        /// current workspace (the `Read`/`NotebookRead` tool on a non-vendored
        /// path). Bouclier does not track file taint or origin history across
        /// requests, so this label is not proof of authorship. Treated like
        /// `principal` — scanned and
        /// flagged, never blocked unless `strict`. Only assigned when
        /// provenance tiering is on and the source tool + path clear the bar;
        /// anything unattributable stays `.untrusted`.
        case authored
    }

    /// A contiguous piece of request text with known provenance.
    struct Span: Sendable, Equatable {
        let text: String
        let origin: Origin
        /// Human-readable JSON location, e.g. `messages[3].content[0].tool_result`.
        /// Shown in the activity log so a block is explainable.
        let locator: String
        /// The complete logical source span. Long values are scanned in
        /// overlapping windows, but every window shares one fingerprint so
        /// releasing that source cannot be defeated by a duplicate match in
        /// its neighbouring overlap.
        let fingerprintBasis: String

        init(text: String, origin: Origin, locator: String, fingerprintBasis: String? = nil) {
            self.text = text
            self.origin = origin
            self.locator = locator
            self.fingerprintBasis = fingerprintBasis ?? text
        }
    }

    /// One detection against one span.
    struct Finding: Sendable {
        let origin: Origin
        let locator: String
        let patternNames: [String]
        let categories: [String]
        let severities: [String]
        let matchCount: Int
        let fusedScore: Double
        let mlScore: Float?
        let entropyAnomaly: Double
        /// Salted fingerprint of the scanned span. Stable across resumes
        /// of the same conversation (the offending tool result is the same
        /// bytes each turn), so the operator can release exactly this span
        /// via the allowlist. Empty for principal spans (never blocked).
        let fingerprint: String
        /// True when this untrusted span crossed the block bar but was
        /// forwarded anyway because its fingerprint is on the allowlist.
        /// Recorded so the activity log can say "released, not blocked".
        let allowlisted: Bool
        /// True only when this finding contributed to the final block
        /// decision after score threshold, strict-policy, and allowlist
        /// handling. Refusal/log attribution must key off this value rather
        /// than merely choosing the first untrusted match.
        let causedBlock: Bool
    }

    enum Decision: String, Sendable {
        /// Nothing fired. Forward untouched.
        case allow
        /// Something fired, but only on principal text (or below the block
        /// bar on untrusted text). Forward untouched, record it.
        case flag
        /// A finding crossed its applicable enforcement policy (untrusted
        /// threshold, or principal/authored under strict mode). Refuse.
        case block
    }

    struct Outcome: Sendable {
        let decision: Decision
        let findings: [Finding]
        /// Highest fused score across all spans, for the activity log.
        let topScore: Double
        /// True if the on-device classifier contributed to any span.
        let mlAvailable: Bool
        /// Spans actually scanned — used by tests and diagnostics.
        let scannedSpanCount: Int
        /// Scanned spans whose provenance is genuinely untrusted. Response
        /// correlation must use this, not total span count: principal-only or
        /// canonical authored input cannot complete the injected-action
        /// trifecta.
        let untrustedSpanCount: Int

        static let clean = Outcome(
            decision: .allow, findings: [], topScore: 0,
            mlAvailable: false, scannedSpanCount: 0, untrustedSpanCount: 0
        )

        var blockedFinding: Finding? {
            guard decision == .block else { return nil }
            return findings.first { $0.causedBlock }
        }

        /// Fingerprint of the untrusted span that drove a block, for the
        /// "release this span" affordance. Nil when nothing blocked.
        var blockedFingerprint: String? {
            guard let fp = blockedFinding?.fingerprint, !fp.isEmpty else { return nil }
            return fp
        }
    }

    /// Salted SHA-256 fingerprint (hex) of a scanned span. Machine-local
    /// via `salt`; stable for identical span bytes, so a release taken from
    /// a block matches the same span on the next resume of a conversation.
    /// See `SpanAllowlist`.
    static func spanFingerprint(_ text: String, salt: Data) -> String {
        var hasher = SHA256()
        hasher.update(data: salt)
        hasher.update(data: Data(text.utf8))
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// Build a captured block sample for the offending untrusted span —
    /// the opt-in block explainer. Re-extracts spans from the body, finds
    /// the one that drove the block (by locator), and pairs an excerpt of
    /// it with the per-signal breakdown and — when ML was the driver — the
    /// passage the classifier reacted to most. Off the hot path: only
    /// called on a block when capture is enabled. Returns nil if the
    /// blocking span can't be recovered.
    static func explain(
        body: Data,
        filter: InjectionFilter,
        outcome: Outcome,
        salt: Data,
        targetHost: String,
        timestamp: String
    ) -> BlockSample? {
        guard let blocked = outcome.blockedFinding,
              blocked.origin == .untrusted,
              !blocked.fingerprint.isEmpty else { return nil }
        let spans = body.count <= maxScanBytes
            ? extractSpans(body: body)
            : extractSpans(
                body: body,
                trustAuthoredReads: false,
                bodyLimit: HTTPRequestInspector.maxBodyBytes
            )
        let span = spans.first { $0.origin == .untrusted && $0.locator == blocked.locator }
            ?? spans.first { $0.origin == .untrusted }
        guard let span else { return nil }

        let excerpt = span.text.count > BlockSampleStore.maxExcerptChars
            ? String(span.text.prefix(BlockSampleStore.maxExcerptChars))
            : span.text
        let attribution = filter.attributeTopWindow(span.text)

        return BlockSample(
            timestamp: timestamp,
            targetHost: targetHost,
            locator: blocked.locator,
            spanExcerpt: excerpt,
            spanLength: span.text.count,
            fusedScore: blocked.fusedScore,
            mlScore: blocked.mlScore,
            entropyAnomaly: blocked.entropyAnomaly,
            matchCount: blocked.matchCount,
            patternNames: blocked.patternNames,
            benignMultiplier: filter.benignMultiplier(for: span.text),
            topWindow: attribution?.window,
            topWindowScore: attribution?.score,
            windowsScanned: attribution?.windowsScanned ?? 0,
            attributionTruncated: attribution?.truncated ?? false,
            fingerprint: blocked.fingerprint
        )
    }

    // MARK: - Tuning

    /// Bodies above this skip full inspection and follow the configured
    /// monitor/block coverage-limit policy. Eight MiB covers the serialized
    /// envelope of a typical 1M-token text session while still keeping JSON
    /// parsing and detector allocations far below the 64 MiB transport cap.
    static let maxScanBytes = 8 * 1024 * 1024

    /// Maximum size of one detector invocation. Longer logical spans are
    /// covered from beginning to end with bounded overlapping windows.
    static let maxSpanScanChars = 64 * 1024

    /// Carries a pattern that straddles a window boundary into at least one
    /// complete detector invocation. The request-wide byte ceiling bounds
    /// the total number of windows (at most ~140 for an 8 MiB body).
    // Shipped signatures allow up to ~2,048 characters between their anchor
    // terms. Keep twice that distance so the complete expression lands in a
    // neighbouring window even at the least favourable boundary.
    static let spanScanOverlapChars = 4 * 1024

    /// CoreML is the expensive tier. Regex and entropy cover every detector
    /// window, while ML is sampled evenly across very long conversations so a
    /// multi-megabyte history cannot trigger hundreds of synchronous model
    /// invocations. Small/ordinary requests still run ML on every span.
    static let maxMLWindowsPerRequest = 24

    static func mlSampleIndices(spanCount: Int) -> Set<Int> {
        guard spanCount > 0 else { return [] }
        guard spanCount > maxMLWindowsPerRequest else { return Set(0..<spanCount) }
        guard maxMLWindowsPerRequest > 1 else { return [0] }

        var result = Set<Int>()
        for sample in 0..<maxMLWindowsPerRequest {
            result.insert(sample * (spanCount - 1) / (maxMLWindowsPerRequest - 1))
        }
        return result
    }

    /// Fused score at which an *untrusted* span is refused.
    ///
    /// The score is dampened: a match inside a benign context (an OWASP/CVE
    /// reference, a "how to detect…" tutorial, a fenced code block, a
    /// quoted advisory) has its severity weight multiplied down, so the
    /// legitimate tool output an agent reads all day doesn't trip the
    /// filter. An *undampened* critical pattern drives the regex signal to
    /// 1.0 and short-circuits the fused score to 1.0 (well past 0.60), so
    /// real injections still block; a dampened one falls below the bar and
    /// is flagged-and-forwarded instead. This mirrors the TS scorer the
    /// benchmark measures (block at 0.60) — see scorer.ts.
    static let untrustedBlockThreshold: Double = 0.60

    // MARK: - Cheap trigger gate

    /// Markers that indicate the body carries model-visible content that
    /// did not come from the operator. Substring search over raw bytes —
    /// no JSON parse, no regex — so ordinary chat traffic pays almost
    /// nothing.
    private static let untrustedMarkers: [[UInt8]] = [
        Array("tool_result".utf8),          // Anthropic content block
        Array("function_call_output".utf8), // OpenAI Responses
        // Retrieved / attached content that `extractSpans` ALSO treats as
        // untrusted. Without these the cheap gate would skip a request
        // whose ONLY untrusted span is a document/search_result block or a
        // <document> RAG wrapper — extractSpans would never run and the
        // poisoned span would be forwarded uninspected. Each marker is part
        // of the wire format extractSpans keys on, so the gate can't miss a
        // shape the parser handles.
        Array("\"document\"".utf8),         // Anthropic `document` block type value
        Array("search_result".utf8),        // `search_result` block type + <search_result[s]> wrapper
        Array("<document".utf8),            // <document> / <documents> RAG wrapper
    ]

    /// True if the body plausibly contains an untrusted span. When this is
    /// false the inspection pass does not run at all and the request is
    /// forwarded with its model-visible body bytes unchanged.
    ///
    /// Conservative in the safe direction: a false positive here costs one
    /// JSON parse, a false negative is impossible for the untrusted shapes
    /// `extractSpans` supports because each marker is part of the wire
    /// format itself — the gate and the parser cover the same set.
    ///
    /// Takes raw bytes rather than `Data` so the gateway can run it
    /// straight off the NIO `ByteBuffer` — the whole point of the gate is
    /// that clean traffic pays almost nothing, and copying every request
    /// body into a `Data` just to decide not to scan it would undo that.
    static func hasTrigger(bytes raw: UnsafeRawBufferPointer) -> Bool {
        guard !raw.isEmpty, raw.count <= maxScanBytes else { return false }
        guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return false }
        if hasRawUntrustedMarker(base, raw.count) { return true }

        // A supported marker may itself be JSON Unicode-escaped (including
        // a key such as `t\u0079pe`). Decode only this uncommon slow path and
        // ask the authoritative extractor; ordinary traffic remains a cheap
        // raw-byte scan.
        if containsBytes(base, raw.count, Array("\\u".utf8)) {
            let body = Data(bytes: base, count: raw.count)
            return extractSpans(body: body).contains { $0.origin == .untrusted }
        }
        return false
    }

    /// Bounded structural plausibility check for a body too large to parse or
    /// run through regexes. The caller already enforces the gateway's 64 MiB
    /// body ceiling. In Blocking mode an actual supported raw or
    /// JSON-Unicode-escaped marker fails closed; Monitoring mode logs the skip
    /// and forwards. This lexical pass runs on the gateway's bounded worker
    /// pool, never on the NIO event loop.
    static func hasPlausibleUntrustedMarker(bytes raw: UnsafeRawBufferPointer) -> Bool {
        guard !raw.isEmpty,
              let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return false }
        // Tool/document type and role pairs are by far the common case and
        // can usually be decided near the beginning of the envelope.
        if hasStructuredUntrustedPair(base, raw.count) { return true }
        // Explicit RAG wrappers are supported wherever they appear inside a
        // principal string. Accept literal and genuine `\uXXXX` encodings of
        // those exact markers, not an unrelated escape elsewhere in a large
        // conversation.
        if containsASCIIInsensitiveAllowingJSONUnicodeEscapes(
            base, raw.count, Array("<document".utf8)
        ) || containsASCIIInsensitiveAllowingJSONUnicodeEscapes(
            base, raw.count, Array("<search_result".utf8)
        ) {
            return true
        }
        // The bounded lexer above decodes escapes only inside the short
        // structural key/value tokens it compares. A literal `\u` in an
        // ordinary tool result is not itself an untrusted-content shape.
        return false
    }

    /// Lightweight JSON lexical check for direct string key/value pairs such
    /// as `"type" : "tool_result"` and `"role" : "tool"`. It never builds a
    /// JSON tree and retains at most 64 bytes per token, so work and memory are
    /// bounded by the already-buffered request size. False positives from a
    /// principal merely mentioning `tool_result` are avoided.
    private static func hasStructuredUntrustedPair(
        _ bytes: UnsafePointer<UInt8>, _ count: Int
    ) -> Bool {
        var i = 0
        while i < count {
            guard bytes[i] == UInt8(ascii: "\"") else { i += 1; continue }
            let keyToken = jsonASCIIString(bytes, count, startingAt: i)
            i = max(i + 1, keyToken.end)
            guard let key = keyToken.value, key == "type" || key == "role" else { continue }

            var cursor = keyToken.end
            while cursor < count, isJSONWhitespace(bytes[cursor]) { cursor += 1 }
            guard cursor < count, bytes[cursor] == UInt8(ascii: ":") else { continue }
            cursor += 1
            while cursor < count, isJSONWhitespace(bytes[cursor]) { cursor += 1 }
            guard cursor < count, bytes[cursor] == UInt8(ascii: "\"") else { continue }
            let valueToken = jsonASCIIString(bytes, count, startingAt: cursor)
            guard let value = valueToken.value else { continue }
            if key == "role", value == "tool" { return true }
            if key == "type",
               ["tool_result", "function_call_output", "document", "search_result"].contains(value) {
                return true
            }
        }
        return false
    }

    private static func jsonASCIIString(
        _ bytes: UnsafePointer<UInt8>, _ count: Int, startingAt quote: Int
    ) -> (value: String?, end: Int) {
        var decoded: [UInt8] = []
        decoded.reserveCapacity(32)
        var tooLong = false
        @inline(__always) func appendDecoded(_ byte: UInt8) {
            if decoded.count < 64 {
                decoded.append(byte)
            } else {
                tooLong = true
            }
        }
        var i = quote + 1
        while i < count {
            let byte = bytes[i]
            if byte == UInt8(ascii: "\"") {
                let value = tooLong ? nil : String(bytes: decoded, encoding: .utf8)?.lowercased()
                return (value, i + 1)
            }
            if byte == UInt8(ascii: "\\") {
                guard i + 1 < count else { return (nil, count) }
                let escaped = bytes[i + 1]
                if escaped == UInt8(ascii: "u"),
                   let scalar = jsonUnicodeEscape(bytes, count, slashAt: i) {
                    // Supported wire keys and values are ASCII. Preserve an
                    // out-of-range scalar as an invalid UTF-8 sentinel so it
                    // cannot accidentally collapse two token fragments.
                    appendDecoded(scalar <= 0x7F ? UInt8(scalar) : 0xFF)
                    i += 6
                    continue
                }
                let simple: UInt8
                switch escaped {
                case UInt8(ascii: "\""): simple = UInt8(ascii: "\"")
                case UInt8(ascii: "\\"): simple = UInt8(ascii: "\\")
                case UInt8(ascii: "/"): simple = UInt8(ascii: "/")
                case UInt8(ascii: "b"): simple = 0x08
                case UInt8(ascii: "f"): simple = 0x0C
                case UInt8(ascii: "n"): simple = 0x0A
                case UInt8(ascii: "r"): simple = 0x0D
                case UInt8(ascii: "t"): simple = 0x09
                default: return (nil, min(count, i + 2))
                }
                appendDecoded(simple)
                i += 2
                continue
            }
            appendDecoded(byte)
            i += 1
        }
        return (nil, count)
    }

    private static func jsonUnicodeEscape(
        _ bytes: UnsafePointer<UInt8>, _ count: Int, slashAt index: Int
    ) -> UInt16? {
        guard index + 5 < count,
              bytes[index] == UInt8(ascii: "\\"),
              bytes[index + 1] == UInt8(ascii: "u") else { return nil }
        var value: UInt16 = 0
        for offset in 2...5 {
            let nibble: UInt16
            switch bytes[index + offset] {
            case UInt8(ascii: "0")...UInt8(ascii: "9"):
                nibble = UInt16(bytes[index + offset] - UInt8(ascii: "0"))
            case UInt8(ascii: "a")...UInt8(ascii: "f"):
                nibble = UInt16(bytes[index + offset] - UInt8(ascii: "a") + 10)
            case UInt8(ascii: "A")...UInt8(ascii: "F"):
                nibble = UInt16(bytes[index + offset] - UInt8(ascii: "A") + 10)
            default:
                return nil
            }
            value = value &* 16 &+ nibble
        }
        return value
    }

    /// Search for one ASCII marker while accepting JSON's `\uXXXX` spelling
    /// for any of its characters. Work is O(body * marker length), with the
    /// only callers using 9- and 14-byte markers; it allocates nothing and
    /// never treats an unrelated escape as evidence.
    private static func containsASCIIInsensitiveAllowingJSONUnicodeEscapes(
        _ hay: UnsafePointer<UInt8>, _ count: Int, _ marker: [UInt8]
    ) -> Bool {
        @inline(__always) func folded(_ byte: UInt8) -> UInt8 {
            (65...90).contains(byte) ? byte + 32 : byte
        }
        guard !marker.isEmpty else { return true }
        var start = 0
        while start < count {
            var cursor = start
            var matched = 0
            while matched < marker.count, cursor < count {
                let scalar: UInt16
                if hay[cursor] == UInt8(ascii: "\\"),
                   let escaped = jsonUnicodeEscape(hay, count, slashAt: cursor) {
                    scalar = escaped
                    cursor += 6
                } else {
                    scalar = UInt16(hay[cursor])
                    cursor += 1
                }
                guard scalar <= 0x7F,
                      folded(UInt8(scalar)) == folded(marker[matched]) else { break }
                matched += 1
            }
            if matched == marker.count { return true }
            start += 1
        }
        return false
    }

    @inline(__always)
    private static func isJSONWhitespace(_ byte: UInt8) -> Bool {
        byte == 0x20 || byte == 0x09 || byte == 0x0A || byte == 0x0D
    }

    private static func hasRawUntrustedMarker(
        _ base: UnsafePointer<UInt8>, _ count: Int
    ) -> Bool {
        for marker in untrustedMarkers {
            if containsASCIIInsensitive(base, count, marker) { return true }
        }

        // JSON whitespace is unrestricted, so match the role key/value as
        // independent tokens rather than relying on one serialized layout.
        if containsASCIIInsensitive(base, count, Array("\"role\"".utf8)),
           containsASCIIInsensitive(base, count, Array("\"tool\"".utf8)) {
            return true
        }
        return false
    }

    /// `Data` convenience — used by the tests and any caller that already
    /// holds a contiguous buffer.
    static func hasTrigger(body: Data) -> Bool {
        body.withUnsafeBytes { hasTrigger(bytes: $0) }
    }

    /// Plain forward substring search. `Data.range(of:)` bridges through
    /// Foundation and allocates; this runs on the hot request path.
    private static func containsBytes(_ hay: UnsafePointer<UInt8>, _ n: Int, _ needle: [UInt8]) -> Bool {
        let m = needle.count
        guard m > 0, n >= m else { return false }
        let first = needle[0]
        var i = 0
        let last = n - m
        while i <= last {
            if hay[i] == first {
                var k = 1
                while k < m, hay[i + k] == needle[k] { k += 1 }
                if k == m { return true }
            }
            i += 1
        }
        return false
    }

    /// ASCII case-insensitive raw-byte search. JSON structural bytes and all
    /// supported trigger tokens are ASCII; bytes outside A...Z are compared
    /// exactly, so this cannot corrupt or reinterpret UTF-8.
    private static func containsASCIIInsensitive(
        _ hay: UnsafePointer<UInt8>, _ n: Int, _ needle: [UInt8]
    ) -> Bool {
        @inline(__always) func folded(_ byte: UInt8) -> UInt8 {
            (65...90).contains(byte) ? byte + 32 : byte
        }
        let m = needle.count
        guard m > 0, n >= m else { return false }
        var i = 0
        let last = n - m
        while i <= last {
            var k = 0
            while k < m, folded(hay[i + k]) == folded(needle[k]) { k += 1 }
            if k == m { return true }
            i += 1
        }
        return false
    }

    // MARK: - Span extraction

    /// Pull model-visible text out of an Anthropic or OpenAI request body,
    /// tagged by provenance. Unknown shapes yield no spans, which means
    /// "forward untouched" — we never guess at provenance.
    static func extractSpans(body: Data, trustAuthoredReads: Bool = false) -> [Span] {
        extractSpans(
            body: body,
            trustAuthoredReads: trustAuthoredReads,
            bodyLimit: maxScanBytes
        )
    }

    /// Same structural extractor with an explicit caller-owned byte bound.
    /// The gateway uses this only on its fixed-width worker pool for bodies
    /// above the fast-path ceiling; ordinary callers stay on `maxScanBytes`.
    private static func extractSpans(
        body: Data,
        trustAuthoredReads: Bool,
        bodyLimit: Int
    ) -> [Span] {
        guard !body.isEmpty, body.count <= bodyLimit,
              let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any]
        else { return [] }

        var spans: [Span] = []

        // Anthropic Messages + OpenAI Chat Completions both use `messages`.
        if let messages = root["messages"] as? [Any] {
            // Provenance tiering: map each tool_use so a tool_result can be
            // attributed to the tool that produced it. When tiering is off
            // this stays empty and every tool_result stays `.untrusted`.
            let toolUses = trustAuthoredReads ? indexToolUses(messages) : [:]
            // The session's workspace root(s), for the `.authored` allowlist.
            // Read only from principal text (see `workspaceRoots`) so attacker
            // tool content can't declare a trusted root.
            let roots = trustAuthoredReads ? workspaceRoots(from: root) : []
            for (i, raw) in messages.enumerated() {
                guard let msg = raw as? [String: Any] else { continue }
                let role = (msg["role"] as? String)?.lowercased()

                // OpenAI chat: a whole message with role "tool" is output.
                if role == "tool" {
                    appendText(msg["content"], origin: .untrusted,
                               locator: "messages[\(i)].content", into: &spans)
                    continue
                }

                let origin: Origin = .principal
                switch msg["content"] {
                case let s as String:
                    append(s, origin: origin, locator: "messages[\(i)].content", into: &spans)
                case let blocks as [Any]:
                    for (j, rawBlock) in blocks.enumerated() {
                        guard let block = rawBlock as? [String: Any] else { continue }
                        let type = (block["type"] as? String)?.lowercased()
                        let base = "messages[\(i)].content[\(j)]"
                        // Anthropic: tool_result is the untrusted leg — unless
                        // it's a trusted local read (see `toolResultOrigin`).
                        if type == "tool_result" {
                            appendText(block["content"],
                                       origin: toolResultOrigin(block, toolUses: toolUses, workspaceRoots: roots),
                                       locator: "\(base).tool_result", into: &spans)
                        } else if type == "document" || type == "search_result" {
                            // Attached/retrieved content is untrusted no
                            // matter who attached it — a malicious PDF or a
                            // poisoned search result is exactly the indirect
                            // injection surface. Text may live in `content`,
                            // `source.data`, `source.content`, or `title`.
                            let label = type ?? "document"
                            appendText(block["content"], origin: .untrusted,
                                       locator: "\(base).\(label)", into: &spans)
                            if let source = block["source"] as? [String: Any] {
                                if let data = source["data"] as? String {
                                    append(data, origin: .untrusted,
                                           locator: "\(base).\(label).source", into: &spans)
                                }
                                appendText(source["content"], origin: .untrusted,
                                           locator: "\(base).\(label).source", into: &spans)
                            }
                            if let title = block["title"] as? String {
                                append(title, origin: .untrusted,
                                       locator: "\(base).\(label).title", into: &spans)
                            }
                        } else if type == "text", let t = block["text"] as? String {
                            append(t, origin: origin, locator: "\(base).text", into: &spans)
                        }
                    }
                default:
                    break
                }
            }
        }

        // OpenAI Responses API: `input` items, `function_call_output`.
        if let input = root["input"] as? [Any] {
            for (i, raw) in input.enumerated() {
                guard let item = raw as? [String: Any] else { continue }
                let base = "input[\(i)]"
                if (item["type"] as? String)?.lowercased() == "function_call_output" {
                    appendText(item["output"], origin: .untrusted,
                               locator: "\(base).output", into: &spans)
                } else {
                    appendText(item["content"], origin: .principal,
                               locator: "\(base).content", into: &spans)
                }
            }
        }

        // System prompt is principal text on both providers.
        appendText(root["system"], origin: .principal, locator: "system", into: &spans)
        appendText(root["instructions"], origin: .principal, locator: "instructions", into: &spans)

        return spans
    }

    // MARK: - Provenance tiering

    /// Tools whose output can be linked to an eligible local-file read.
    static let authoredReadTools: Set<String> = ["Read", "NotebookRead"]

    /// Path fragments where *external* content lands — never trusted even
    /// through a local read: poisoned dependencies, downloads, temp dirs,
    /// build output, VCS internals.
    private static let untrustedPathFragments = [
        "/node_modules/", "/vendor/", "/.venv/", "/venv/", "/site-packages/",
        "/dist/", "/build/", "/.next/", "/.cache/", "/downloads/",
        "/tmp/", "/private/tmp/", "/var/tmp/", "/var/folders/", "/.git/",
    ]

    /// Provenance of a `tool_result`, from the tool that produced it.
    /// Returns `.authored` ONLY when the content can be positively attributed
    /// to an eligible path in the current workspace — a local read
    /// (`Read`/`NotebookRead`)
    /// of an absolute path that is outside the vendored/download/temp denylist
    /// AND *under* a known canonical session workspace root. Web,
    /// search, shell, external MCP, unknown tools, unreadable inputs, and reads
    /// outside the workspace all stay `.untrusted`: unattributable provenance
    /// is never trusted.
    static func provenance(
        ofToolName name: String, input: [String: Any]?, workspaceRoots: [String] = []
    ) -> Origin {
        guard authoredReadTools.contains(name) else { return .untrusted }
        let rawPath = (input?["file_path"] ?? input?["notebook_path"]) as? String
        // Only vouch for an ABSOLUTE path we can classify. A relative path
        // (e.g. `node_modules/evil/x.md`) wouldn't contain the slash-delimited
        // denylist fragments and would otherwise slip through as authored.
        guard let rawPath, let path = canonicalFilePath(rawPath) else { return .untrusted }
        let denylistPath = path.lowercased()
        if untrustedPathFragments.contains(where: denylistPath.contains) { return .untrusted }
        // Allowlist: a read is trusted only if it lives UNDER a canonical
        // workspace root positively declared by the client's recognized
        // system metadata envelope.
        // Without one, provenance is incomplete and must fail closed; a bare
        // absolute path is not evidence that content is operator-authored.
        guard workspaceRoots.count == 1,
              let root = workspaceRoots.first.flatMap(canonicalWorkspaceRoot)
        else { return .untrusted }
        return path.hasPrefix(root) ? .authored : .untrusted
    }

    /// Standardize `.`/`..` and resolve every existing symlink before a path
    /// participates in either the denylist or workspace-prefix allowlist.
    /// This is intentionally internal so security regressions can pin the
    /// canonicalization itself without depending on a particular denylist.
    static func canonicalFilePath(_ rawPath: String) -> String? {
        guard rawPath.hasPrefix("/"), !rawPath.utf8.contains(0) else { return nil }

        // Resolve the complete path first, before ANY lexical cleanup. POSIX
        // applies `..` after following the preceding symlink: with
        // `link -> /outside/subdir`, `link/../secret` is `/outside/secret`,
        // not `<lexical-parent>/secret`. Standardizing first reverses that
        // order and can turn an escape into an apparently trusted path.
        var resolvedBuffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        if rawPath.withCString({ Darwin.realpath($0, &resolvedBuffer) }) != nil {
            let bytes = resolvedBuffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
            return String(decoding: bytes, as: UTF8.self)
        }

        // A successful Read should normally still exist. If it does not and
        // includes `..`, filesystem-order resolution is unknowable (an earlier
        // component may have been a symlink), so fail closed.
        if rawPath.split(separator: "/", omittingEmptySubsequences: false).contains("..") {
            return nil
        }

        let fm = FileManager.default
        let standardized = URL(fileURLWithPath: rawPath).standardizedFileURL
        var cursor = standardized
        var missingTail: [String] = []

        // `resolvingSymlinksInPath()` does not resolve an earlier symlink
        // when the final leaf no longer exists. Walk to the nearest existing
        // ancestor first, then append the missing tail. A successful Read
        // normally leaves the full path present, but this also fails safely
        // across delete/rename races between the tool read and inspection.
        while cursor.path != "/", !fm.fileExists(atPath: cursor.path) {
            // Broken symlink: `fileExists` is false, but the component still
            // carries a destination that must not retain its lexical trust.
            if let destination = try? fm.destinationOfSymbolicLink(atPath: cursor.path) {
                let destinationURL = destination.hasPrefix("/")
                    ? URL(fileURLWithPath: destination)
                    : cursor.deletingLastPathComponent().appendingPathComponent(destination)
                cursor = destinationURL.standardizedFileURL
                break
            }
            missingTail.insert(cursor.lastPathComponent, at: 0)
            cursor.deleteLastPathComponent()
        }

        var resolved = cursor.resolvingSymlinksInPath().standardizedFileURL
        for component in missingTail { resolved.appendPathComponent(component) }
        let path = resolved.standardizedFileURL.path
        guard path.hasPrefix("/") else { return nil }
        return path
    }

    private static func canonicalWorkspaceRoot(_ rawPath: String) -> String? {
        let forbidden = CharacterSet(charactersIn: "\"'<>")
        guard rawPath.rangeOfCharacter(from: forbidden) == nil,
              var path = canonicalFilePath(rawPath),
              path != "/"
        else { return nil }
        if !path.hasSuffix("/") { path += "/" }
        return path
    }

    /// Attribute a `tool_result` block to its source tool via `tool_use_id`.
    /// `.untrusted` when tiering is off (`toolUses` empty), the link is
    /// missing, or the source is not an eligible attributed local read.
    private static func toolResultOrigin(
        _ block: [String: Any],
        toolUses: [String: (name: String, input: [String: Any])],
        workspaceRoots: [String]
    ) -> Origin {
        guard let id = block["tool_use_id"] as? String,
              let src = toolUses[id] else { return .untrusted }
        return provenance(ofToolName: src.name, input: src.input, workspaceRoots: workspaceRoots)
    }

    /// Directories the `.authored` allowlist keys on — the session's working
    /// directory. Claude Code puts its cwd in a system-prompt `<env>` metadata
    /// block (`Working directory: /path`). Accept exactly one such block and
    /// exactly one directory declaration in the complete system text;
    /// duplicate, conflicting, unscoped, root-filesystem, or malformed
    /// declarations fail closed. This prevents arbitrary prose later in the
    /// system prompt from widening the allowlist. Tool content is never
    /// considered here.
    ///
    /// Returned canonicalized with a trailing slash so prefix-matching cannot
    /// leak into a sibling directory. Paths are standardized and symlinks
    /// resolved before use. Empty when no unambiguous declaration is present.
    static func workspaceRoots(from root: [String: Any]) -> [String] {
        var text: String
        switch root["system"] {
        case let s as String: text = s
        case let arr as [Any]:
            text = arr.compactMap { ($0 as? [String: Any])?["text"] as? String }.joined(separator: "\n")
        default: return []
        }
        // Never validate only a prefix: a second declaration after the bound
        // would otherwise be invisible and could turn ambiguous metadata into
        // an apparently unique trusted root.
        guard !text.isEmpty, text.count <= 16_384 else { return [] }

        let ns = text as NSString
        let completeRange = NSRange(location: 0, length: ns.length)
        let envBlocks = envBlockRegex.matches(in: text, range: completeRange)
        let declarationHints = workspaceDeclarationRegex.matches(in: text, range: completeRange)
        let declarations = workingDirRegex.matches(in: text, range: completeRange)
        guard envBlocks.count == 1,
              declarationHints.count == 1,
              declarations.count == 1,
              envBlocks[0].numberOfRanges > 1,
              declarations[0].numberOfRanges > 1
        else { return [] }

        let envRange = envBlocks[0].range(at: 1)
        let declarationRange = declarations[0].range
        guard declarationRange.location >= envRange.location,
              declarationRange.location + declarationRange.length
                <= envRange.location + envRange.length
        else { return [] }

        let rawPath = ns.substring(with: declarations[0].range(at: 1))
            .trimmingCharacters(in: .whitespaces)
        guard let path = canonicalWorkspaceRoot(rawPath) else { return [] }
        return [path]
    }

    private static let envBlockRegex = try! NSRegularExpression(
        pattern: #"<env>(.*?)</env>"#,
        options: [.caseInsensitive, .dotMatchesLineSeparators]
    )

    private static let workingDirRegex = try! NSRegularExpression(
        pattern: #"^[\t ]*working directory[\t ]*:[\t ]*(/[^\r\n]+?)[\t ]*$"#,
        options: [.caseInsensitive, .anchorsMatchLines]
    )

    /// Broader than the accepted declaration on purpose: an extra `cwd=` or
    /// alternate-form hint makes the metadata ambiguous instead of being
    /// ignored while a second declaration widens trust.
    private static let workspaceDeclarationRegex = try! NSRegularExpression(
        pattern: #"^[\t ]*(?:working directory|cwd)[\t ]*[:=][\t ]*/[^\r\n]*$"#,
        options: [.caseInsensitive, .anchorsMatchLines]
    )

    /// Index every `tool_use.id → (name, input)` in the request so a later
    /// `tool_result` can be attributed to the tool that produced it
    /// (Anthropic wire shape: tool_use in an assistant turn, tool_result in
    /// a following user turn).
    private static func indexToolUses(
        _ messages: [Any]
    ) -> [String: (name: String, input: [String: Any])] {
        var map: [String: (name: String, input: [String: Any])] = [:]
        var duplicateIDs: Set<String> = []
        for raw in messages {
            guard let msg = raw as? [String: Any],
                  let blocks = msg["content"] as? [Any] else { continue }
            for rb in blocks {
                guard let b = rb as? [String: Any],
                      (b["type"] as? String)?.lowercased() == "tool_use",
                      let id = b["id"] as? String,
                      let name = b["name"] as? String else { continue }
                // A tool_result cannot be attributed safely when the same ID
                // names more than one tool_use. Permanently poison the ID for
                // this request instead of letting the last occurrence turn an
                // external result into an apparently authored local Read.
                if map[id] != nil || duplicateIDs.contains(id) {
                    map.removeValue(forKey: id)
                    duplicateIDs.insert(id)
                    continue
                }
                map[id] = (name, b["input"] as? [String: Any] ?? [:])
            }
        }
        return map
    }

    /// Append a value that may be a bare string or an array of content
    /// blocks (Anthropic allows both for `tool_result.content` and
    /// `system`).
    private static func appendText(
        _ value: Any?, origin: Origin, locator: String, into spans: inout [Span]
    ) {
        switch value {
        case let s as String:
            append(s, origin: origin, locator: locator, into: &spans)
        case let arr as [Any]:
            for (k, element) in arr.enumerated() {
                if let s = element as? String {
                    append(s, origin: origin, locator: "\(locator)[\(k)]", into: &spans)
                } else if let block = element as? [String: Any] {
                    if let t = block["text"] as? String {
                        append(t, origin: origin, locator: "\(locator)[\(k)].text", into: &spans)
                    }
                    // Nested tool_result content arrays keep their origin.
                    if let nested = block["content"] {
                        appendText(nested, origin: origin,
                                   locator: "\(locator)[\(k)].content", into: &spans)
                    }
                }
            }
        default:
            break
        }
    }

    private static func append(_ text: String, origin: Origin, locator: String, into spans: inout [Span]) {
        guard !text.isEmpty else { return }
        appendWindowed(text, origin: origin, locator: locator, into: &spans)

        // Retrieved content embedded inside PRINCIPAL text — Anthropic's
        // own RAG guidance wraps documents in `<document>` tags, and agent
        // frameworks paste search results into a user turn the same way.
        // That content did not come from the operator, so an injection
        // hidden in it must still be caught even though the message role is
        // the user's. Surface each wrapped region as an untrusted sub-span.
        // (The whole message stays principal — scanned, never blocked — so
        // the operator's own words around the quote are never held against
        // them.) Only fires on the explicit RAG wrapper tags, so ordinary
        // prose is unaffected.
        if origin == .principal {
            for (index, region) in untrustedWrapperRegions(in: text).enumerated() {
                appendWindowed(
                    region,
                    origin: .untrusted,
                    locator: "\(locator)<doc>[\(index)]",
                    into: &spans
                )
            }
        }
    }

    /// Split one logical source into detector-sized overlapping UTF-16
    /// windows. `NSRegularExpression` and every detector range use UTF-16,
    /// so `String.count` is not a safe work bound: one extended grapheme can
    /// contain tens of thousands of combining scalars. Measuring the same
    /// units the regex engine consumes keeps one pathological grapheme from
    /// turning into a near-1 MiB invocation. The request ceiling bounds the
    /// window count, while overlap preserves boundary-crossing signatures.
    private static func appendWindowed(
        _ text: String, origin: Origin, locator: String, into spans: inout [Span]
    ) {
        let ns = text as NSString
        let utf16Length = ns.length
        guard utf16Length > maxSpanScanChars else {
            spans.append(Span(text: text, origin: origin, locator: locator))
            return
        }

        var start = 0
        var index = 0
        while start < utf16Length {
            var end = min(start + maxSpanScanChars, utf16Length)
            // Never cut a UTF-16 surrogate pair. Combining sequences may be
            // split—that is intentional and bounded—but every window stays
            // a well-formed Swift String.
            if end < utf16Length,
               UTF16.isLeadSurrogate(ns.character(at: end - 1)),
               UTF16.isTrailSurrogate(ns.character(at: end)) {
                end -= 1
            }
            let window = ns.substring(with: NSRange(location: start, length: end - start))
            spans.append(Span(
                text: window,
                origin: origin,
                locator: "\(locator)#window[\(index)]",
                fingerprintBasis: text
            ))
            guard end < utf16Length else { break }
            var next = max(start + 1, end - spanScanOverlapChars)
            if next < utf16Length,
               UTF16.isTrailSurrogate(ns.character(at: next)),
               next > 0,
               UTF16.isLeadSurrogate(ns.character(at: next - 1)) {
                next += 1
            }
            start = next
            index += 1
        }
    }

    private enum UTF16 {
        static func isLeadSurrogate(_ unit: unichar) -> Bool {
            (0xD800...0xDBFF).contains(unit)
        }

        static func isTrailSurrogate(_ unit: unichar) -> Bool {
            (0xDC00...0xDFFF).contains(unit)
        }
    }

    /// Explicit document/RAG boundary tags. Deliberately narrow — the
    /// canonical `<document>` convention and search-result wrappers — so a
    /// developer casually mentioning, say, `<context>` in chat isn't
    /// reclassified as untrusted.
    private static let documentWrapperRegexes: [NSRegularExpression] = {
        ["document", "documents", "search_result", "search_results"].compactMap {
            try? NSRegularExpression(
                pattern: "<\($0)(?:\\s[^>]*)?>([\\s\\S]*?)</\($0)>",
                options: [.caseInsensitive]
            )
        }
    }()

    /// Inner text of every `<document>…</document>` / `<search_result>…`
    /// region in `text`.
    private static func untrustedWrapperRegions(in text: String) -> [String] {
        guard text.contains("<") else { return [] }
        let ns = text as NSString
        let full = NSRange(location: 0, length: ns.length)
        var regions: [String] = []
        for re in documentWrapperRegexes {
            for m in re.matches(in: text, range: full) where m.numberOfRanges > 1 {
                let inner = ns.substring(with: m.range(at: 1))
                if !inner.isEmpty { regions.append(inner) }
            }
        }
        return regions
    }

    // MARK: - Inspection

    /// Score every span and decide. `filter` is the live fused
    /// regex+ML+entropy engine owned by `PatternManager`.
    ///
    /// - Parameter strict: when true, a detection on *principal* text also
    ///   blocks. Off by default; exposed for MDM deployments that genuinely
    ///   want to police their own users' prompts and accept the
    ///   false-positive cost.
    /// - Parameters:
    ///   - allowlisted: span fingerprints the operator has released. An
    ///     untrusted span that would block is forwarded (recorded as a
    ///     flag) when its fingerprint is in this set — the escape hatch for
    ///     a persistent false positive that would otherwise block a session
    ///     on every resume.
    ///   - salt: per-install salt for `spanFingerprint`, so a fingerprint
    ///     is machine-local. Defaults empty for tests that don't exercise
    ///     the allowlist.
    static func inspect(
        body: Data,
        filter: InjectionFilter,
        strict: Bool = false,
        allowlisted: Set<String> = [],
        salt: Data = Data(),
        trustAuthoredReads: Bool = false
    ) -> Outcome {
        let spans = extractSpans(body: body, trustAuthoredReads: trustAuthoredReads)
        return inspect(
            spans: spans,
            filter: filter,
            strict: strict,
            allowlisted: allowlisted,
            salt: salt
        )
    }

    /// Inspect an evenly distributed, bounded sample of untrusted windows in
    /// a request above the ordinary fast-path ceiling but still within the
    /// gateway's hard 64 MiB transport cap. Structural parsing runs only on
    /// the bounded gateway worker pool. The first and last untrusted windows
    /// are always included and the middle is sampled evenly; detector work is
    /// capped independently of conversation length while a long, clean
    /// tool-result history no longer becomes a permanent Blocking-mode
    /// coverage refusal. The caller must continue to record an oversized
    /// coverage skip when this sample is clean.
    static func inspectOversized(
        body: Data,
        filter: InjectionFilter,
        strict: Bool = false,
        allowlisted: Set<String> = [],
        salt: Data = Data(),
        trustAuthoredReads: Bool = false
    ) -> Outcome {
        let spans = extractSpans(
            body: body,
            trustAuthoredReads: trustAuthoredReads,
            bodyLimit: HTTPRequestInspector.maxBodyBytes
        )
        let candidates = strict ? spans : spans.filter { $0.origin == .untrusted }
        let boundedSpans = evenlySampledSpans(
            candidates,
            limit: maxOversizedDetectorWindows
        )
        return inspect(
            spans: boundedSpans,
            filter: filter,
            strict: strict,
            allowlisted: allowlisted,
            salt: salt
        )
    }

    /// At most this many 64 KiB windows are scored for an oversized body.
    /// Twenty-four matches the request-wide CoreML budget and bounds the
    /// regex/dampener/entropy tiers to roughly 1.5 Mi UTF-16 code units.
    static let maxOversizedDetectorWindows = 24

    private static func evenlySampledSpans(_ spans: [Span], limit: Int) -> [Span] {
        guard limit > 0, !spans.isEmpty else { return [] }
        guard spans.count > limit else { return spans }
        guard limit > 1 else { return [spans[spans.count - 1]] }

        var sampled: [Span] = []
        sampled.reserveCapacity(limit)
        for slot in 0..<limit {
            let index = slot * (spans.count - 1) / (limit - 1)
            sampled.append(spans[index])
        }
        return sampled
    }

    private static func inspect(
        spans: [Span],
        filter: InjectionFilter,
        strict: Bool,
        allowlisted: Set<String>,
        salt: Data
    ) -> Outcome {
        guard !spans.isEmpty else { return .clean }

        var findings: [Finding] = []
        var topScore = 0.0
        var mlAvailable = false
        var block = false
        var fingerprintsByLogicalSpan: [String: String] = [:]
        let mlIndices = mlSampleIndices(spanCount: spans.count)

        for (index, span) in spans.enumerated() {
            let result = filter.scan(span.text, includeML: mlIndices.contains(index))
            if result.mlAvailable { mlAvailable = true }
            topScore = max(topScore, result.fusedScore)

            guard result.matchCount > 0 || result.shouldBlock else { continue }

            // Fingerprint only untrusted spans — principal text is never
            // blocked, so it is never allowlistable.
            let fingerprint: String
            if span.origin == .untrusted {
                // Every detector window from one logical source shares its
                // fingerprint basis. Hash a multi-megabyte tool result once,
                // not once per matching 64 KiB window.
                let logicalLocator = span.locator.split(
                    separator: "#", maxSplits: 1, omittingEmptySubsequences: false
                ).first.map(String.init) ?? span.locator
                if let cached = fingerprintsByLogicalSpan[logicalLocator] {
                    fingerprint = cached
                } else {
                    fingerprint = spanFingerprint(span.fingerprintBasis, salt: salt)
                    fingerprintsByLogicalSpan[logicalLocator] = fingerprint
                }
            } else {
                fingerprint = ""
            }
            let wouldBlock = span.origin == .untrusted && result.fusedScore >= untrustedBlockThreshold
            let isReleased = wouldBlock && allowlisted.contains(fingerprint)
            let causedBlock: Bool
            switch span.origin {
            case .untrusted:
                causedBlock = wouldBlock && !isReleased
            case .principal, .authored:
                causedBlock = strict && result.shouldBlock
            }

            findings.append(Finding(
                origin: span.origin,
                locator: span.locator,
                patternNames: result.patternNames,
                categories: result.categories,
                severities: result.severities,
                matchCount: result.matchCount,
                fusedScore: result.fusedScore,
                mlScore: result.mlScore,
                entropyAnomaly: result.entropyAnomaly,
                fingerprint: fingerprint,
                allowlisted: isReleased,
                causedBlock: causedBlock
            ))

            switch span.origin {
            case .untrusted:
                // Score-based, so dampeners apply. (Do NOT also block on a
                // raw `critical` severity match — that would bypass
                // dampening and re-introduce the false positives on benign
                // security/tutorial/quoted content that dampening exists to
                // suppress; an undampened critical already reaches 1.0.)
                // A released (allowlisted) span is recorded but never blocks.
                if causedBlock { block = true }
            case .principal, .authored:
                // `.authored` is a trusted local read of the developer's own
                // file — treated like principal: flagged, never blocked
                // unless `strict` polices even trusted content.
                if causedBlock { block = true }
            }
        }

        let decision: Decision = block ? .block : (findings.isEmpty ? .allow : .flag)
        return Outcome(
            decision: decision,
            findings: findings,
            topScore: topScore,
            mlAvailable: mlAvailable,
            scannedSpanCount: spans.count,
            untrustedSpanCount: spans.lazy.filter { $0.origin == .untrusted }.count
        )
    }

    // MARK: - Refusal payload

    /// JSON body returned to the agent when a request is refused. Shaped
    /// like a provider error so an SDK surfaces it as an API error rather
    /// than a transport failure — the agent gets a readable reason instead
    /// of a dead socket.
    static func refusalJSON(for outcome: Outcome) -> String {
        let f = outcome.blockedFinding
        let where_ = f?.locator ?? "tool output"
        let names = (f?.patternNames ?? []).sorted().prefix(3).joined(separator: ", ")
        let detail = names.isEmpty ? "" : " Matched: \(names)."
        let message: String
        switch f?.origin {
        case .principal:
            message =
                "Bouclier.ai blocked this request because your organization's strict policy "
                + "flagged operator-authored content at \(where_).\(detail) "
                + "Strict mode applies to text you supplied; this was not classified as "
                + "untrusted tool output. See https://www.bouclier.ai/blocked"
        case .authored:
            message =
                "Bouclier.ai blocked this request because your organization's strict policy "
                + "flagged content classified as an attributed local read at \(where_).\(detail) "
                + "Strict mode enforces findings in attributed workspace content too. "
                + "See https://www.bouclier.ai/blocked"
        case .untrusted, .none:
            message =
                "Bouclier.ai blocked this request: untrusted content at \(where_) contained "
                + "instructions aimed at the model.\(detail) "
                + "The request did not positively attribute this span to principal text or an "
                + "eligible local Read/NotebookRead result. "
                + "See https://www.bouclier.ai/blocked"
        }
        let payload: [String: Any] = [
            "type": "error",
            "error": [
                "type": "bouclier_injection_blocked",
                "message": message,
                "locator": where_,
                "patterns": Array((f?.patternNames ?? []).sorted().prefix(8)),
                "score": (f?.fusedScore).map { (($0 * 100).rounded() / 100) } ?? 0,
            ],
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let s = String(data: data, encoding: .utf8)
        else {
            return #"{"type":"error","error":{"type":"bouclier_injection_blocked","message":"Blocked by Bouclier.ai"}}"#
        }
        return s
    }

    /// Provider-shaped, non-retryable coverage refusal for compressed request
    /// bodies. Bouclier does not claim a detector verdict because it never
    /// scanned decompressed model-visible content.
    static func unsupportedEncodingRefusalJSON(encoding: String) -> String {
        let message =
            "Bouclier.ai refused this request because Content-Encoding \(encoding) "
            + "is not supported by bounded inspection. No injection verdict was "
            + "produced. Send an uncompressed request, or switch to Monitoring to "
            + "forward it with a visible skip warning."
        let payload: [String: Any] = [
            "type": "error",
            "error": [
                "type": "bouclier_unsupported_content_encoding",
                "message": message,
                "content_encoding": encoding,
            ],
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let string = String(data: data, encoding: .utf8) else {
            return #"{"type":"error","error":{"type":"bouclier_unsupported_content_encoding","message":"Compressed request bodies cannot be inspected"}}"#
        }
        return string
    }
}
