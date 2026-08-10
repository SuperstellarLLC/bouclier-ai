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
/// - `.untrusted` — content the model is about to read that no human in
///   this session typed: `tool_result` blocks (Anthropic), `role: "tool"`
///   messages (OpenAI chat), `function_call_output` items (OpenAI
///   Responses). This is where indirect prompt injection actually lands
///   for an agent — a poisoned web page, a hostile README, a malicious
///   MCP tool result. Instructions have no business being here, so a
///   detection is actionable and we block.
/// - `.principal` — the operator's own prompt and system text. Scanned
///   for telemetry so the activity log stays useful, but **never blocked
///   and never rewritten**. The user is allowed to say anything to their
///   own model.
///
/// That provenance split is the honest version of "state of the art" for
/// a local detector in 2026: the field's consensus (CaMeL, Meta's Agents
/// Rule of Two, MCP Colors) is that the load-bearing control is knowing
/// which bytes are untrusted and constraining what they can reach —
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
        /// Tool output, retrieved documents — nobody in this session typed it.
        case untrusted
        /// The operator's own prompt / system text.
        case principal
    }

    /// A contiguous piece of request text with known provenance.
    struct Span: Sendable, Equatable {
        let text: String
        let origin: Origin
        /// Human-readable JSON location, e.g. `messages[3].content[0].tool_result`.
        /// Shown in the activity log so a block is explainable.
        let locator: String
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
    }

    enum Decision: String, Sendable {
        /// Nothing fired. Forward untouched.
        case allow
        /// Something fired, but only on principal text (or below the block
        /// bar on untrusted text). Forward untouched, record it.
        case flag
        /// An untrusted span carried instructions. Refuse the request.
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

        static let clean = Outcome(
            decision: .allow, findings: [], topScore: 0,
            mlAvailable: false, scannedSpanCount: 0
        )

        var blockedFinding: Finding? {
            findings.first { $0.origin == .untrusted }
        }
    }

    // MARK: - Tuning

    /// Bodies above this are forwarded without inspection. Matches the
    /// secret-scan ceiling: big bodies are vision payloads and file
    /// uploads, and we must not add latency to them.
    static let maxScanBytes = 1 * 1024 * 1024

    /// A single untrusted span longer than this is truncated before
    /// scanning. Bounds worst-case regex time on a pathological tool
    /// result; the head of a tool result is where injected instructions
    /// are placed in practice, and the tail is still covered by the
    /// separate whole-span entropy signal.
    static let maxSpanScanChars = 64 * 1024

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
        Array("\"role\":\"tool\"".utf8),    // OpenAI chat (compact)
        Array("\"role\": \"tool\"".utf8),   // OpenAI chat (pretty)
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
    /// forwarded byte-for-byte.
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
        for marker in untrustedMarkers {
            if containsBytes(base, raw.count, marker) { return true }
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

    // MARK: - Span extraction

    /// Pull model-visible text out of an Anthropic or OpenAI request body,
    /// tagged by provenance. Unknown shapes yield no spans, which means
    /// "forward untouched" — we never guess at provenance.
    static func extractSpans(body: Data) -> [Span] {
        guard !body.isEmpty, body.count <= maxScanBytes,
              let root = try? JSONSerialization.jsonObject(with: body) as? [String: Any]
        else { return [] }

        var spans: [Span] = []

        // Anthropic Messages + OpenAI Chat Completions both use `messages`.
        if let messages = root["messages"] as? [Any] {
            for (i, raw) in messages.enumerated() {
                guard let msg = raw as? [String: Any] else { continue }
                let role = msg["role"] as? String

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
                        let type = block["type"] as? String
                        let base = "messages[\(i)].content[\(j)]"
                        // Anthropic: tool_result is the untrusted leg.
                        if type == "tool_result" {
                            appendText(block["content"], origin: .untrusted,
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
                if item["type"] as? String == "function_call_output" {
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
        let clipped = text.count > maxSpanScanChars ? String(text.prefix(maxSpanScanChars)) : text
        spans.append(Span(text: clipped, origin: origin, locator: locator))

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
            for region in untrustedWrapperRegions(in: clipped) {
                append(region, origin: .untrusted, locator: "\(locator)<doc>", into: &spans)
            }
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
    ///   blocks. Off by default and off in the shipped DMG; exposed for
    ///   MDM deployments that genuinely want to police their own users'
    ///   prompts and accept the false-positive cost.
    static func inspect(body: Data, filter: InjectionFilter, strict: Bool = false) -> Outcome {
        let spans = extractSpans(body: body)
        guard !spans.isEmpty else { return .clean }

        var findings: [Finding] = []
        var topScore = 0.0
        var mlAvailable = false
        var block = false

        for span in spans {
            let result = filter.scan(span.text)
            if result.mlAvailable { mlAvailable = true }
            topScore = max(topScore, result.fusedScore)

            guard result.matchCount > 0 || result.shouldBlock else { continue }

            let finding = Finding(
                origin: span.origin,
                locator: span.locator,
                patternNames: result.patternNames,
                categories: result.categories,
                severities: result.severities,
                matchCount: result.matchCount,
                fusedScore: result.fusedScore,
                mlScore: result.mlScore,
                entropyAnomaly: result.entropyAnomaly
            )
            findings.append(finding)

            switch span.origin {
            case .untrusted:
                // Score-based, so dampeners apply. (Do NOT also block on a
                // raw `critical` severity match — that would bypass
                // dampening and re-introduce the false positives on benign
                // security/tutorial/quoted content that dampening exists to
                // suppress; an undampened critical already reaches 1.0.)
                if result.fusedScore >= untrustedBlockThreshold {
                    block = true
                }
            case .principal:
                if strict, result.shouldBlock { block = true }
            }
        }

        let decision: Decision = block ? .block : (findings.isEmpty ? .allow : .flag)
        return Outcome(
            decision: decision,
            findings: findings,
            topScore: topScore,
            mlAvailable: mlAvailable,
            scannedSpanCount: spans.count
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
        let message =
            "Bouclier.ai blocked this request: untrusted content at \(where_) contained "
            + "instructions aimed at the model.\(detail) "
            + "This is prompt injection arriving through tool output, not something you typed. "
            + "See https://www.bouclier.ai/blocked"
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
}
