import CryptoKit
import Foundation

/// Core injection detection engine.
///
/// Combines three independent signals into a fused threat score:
///   1. **Regex patterns** (~160, severity-weighted) — fast, precise on
///      known signatures.
///   2. **ML classifier** (Meta Prompt Guard 2 / mDeBERTa, optional) —
///      catches semantic and multilingual attacks regex misses. Loaded
///      lazily by `PatternManager` and may be `nil` if the bundled
///      `.mlpackage` failed to load (e.g. on Intel Macs without Neural
///      Engine).
///   3. **Shannon entropy anomaly** — cheap statistical signal for
///      gibberish/encoded payloads.
///
/// All inference runs locally; no network calls. Inputs are still
/// scanned through NSRegularExpression so the existing redaction-offset
/// machinery works unchanged.
///
/// Callers on the live request path do not construct this directly —
/// they read `InjectionFilter.active.current()`, which `PatternManager`
/// keeps pointed at the newest engine. See `ActiveInjectionFilterRegistry`.
final class InjectionFilter: @unchecked Sendable {
    /// The process-wide active filter. Mirrors `PIIScanner.active`.
    static let active = ActiveInjectionFilterRegistry()

    private let patterns: [FilterPattern]
    private let dampeners: [CompiledDampener]
    private let classifier: MLClassifier?

    /// Proximity window (UTF-16 units) within which a dampener hit reduces a
    /// pattern match's severity weight. Mirrors `DAMPENER_PROXIMITY` in
    /// `packages/patterns/src/dampeners.ts`.
    private static let dampenerProximity = 200

    /// Severity weights mirror the TS scorer (`packages/patterns/src/types.ts`).
    /// Kept in sync so the regex signal carries the same calibration on
    /// both platforms.
    private static let severityWeights: [String: Double] = [
        "low": 0.15,
        "medium": 0.35,
        "high": 0.6,
        "critical": 1.0,
    ]

    /// Block when fused score crosses this. Calibrated so that one
    /// critical regex match alone (severity 1.0 × weight 0.50 = 0.50)
    /// blocks at the threshold.
    private static let blockThreshold: Double = 0.50

    /// A single signal at this strength short-circuits the decision —
    /// "if any one signal is this confident, that's enough." This is the
    /// **ML-alone block tier**: it lets the classifier trigger a block on
    /// novel attacks the regex set has never seen, and it sits above the
    /// gateway's corroborated bar (0.60), so ML-alone must clear a higher
    /// bar than an ML+regex agreement. Crucially the ML signal is
    /// benign-context *dampened* before it is tested here (see
    /// `mlBenignMultiplier`), so quoted advisories / this project's own
    /// pattern files don't clear it while genuine injections in untrusted
    /// prose still do. ML stays load-bearing; it just loses its
    /// foothold on security content it is only *reading about*.
    private static let strongSignalThreshold: Double = 0.85

    static let redactionMessage =
        "[Possible prompt injection redacted by Bouclier.ai. See https://www.bouclier.ai/blocked for details]"

    private static let homoglyphMap: [Character: Character] = [
        "\u{0430}": "a", "\u{0435}": "e", "\u{043E}": "o",
        "\u{0440}": "p", "\u{0441}": "c", "\u{0443}": "y",
        "\u{0445}": "x", "\u{0410}": "A", "\u{0415}": "E",
        "\u{041E}": "O", "\u{0420}": "P", "\u{0421}": "C",
        "\u{03B1}": "a", "\u{03B5}": "e", "\u{03BF}": "o", "\u{03C1}": "p",
    ]

    /// Load patterns from bundled resource or fallback. The classifier
    /// can be attached later via `PatternManager` once it finishes
    /// loading on a background task.
    init(classifier: MLClassifier? = nil) {
        let set = Self.loadBundledSet()
        self.patterns = set.patterns
        self.dampeners = set.dampeners
        self.classifier = classifier
    }

    /// Initialize with externally-provided patterns and an optional ML
    /// classifier. Used by PatternManager for hot-reload and for
    /// installing the classifier after async load. Dampeners are loaded
    /// from the bundle (they are not part of the hot-reloadable user
    /// pattern override).
    init(patterns: [FilterPattern], classifier: MLClassifier? = nil) {
        self.patterns = patterns
        self.dampeners = Self.loadBundledSet().dampeners
        self.classifier = classifier
    }

    /// Initialize with explicit patterns AND dampeners. Used by the test
    /// suite so it can exercise the exact shipped dampening behaviour
    /// against a patterns.json it reads directly (the test host's
    /// `Bundle.main` is the runner, not the app, so bundle loading yields
    /// the fallback set).
    init(patterns: [FilterPattern], dampeners: [CompiledDampener], classifier: MLClassifier? = nil) {
        self.patterns = patterns
        self.dampeners = dampeners
        self.classifier = classifier
    }

    /// Number of enabled patterns currently loaded. Exposed so the
    /// diagnostics bundle and the stats dashboard can report accurate
    /// coverage figures after a hot-reload.
    var patternCount: Int { patterns.filter(\.enabled).count }

    /// All loaded patterns (enabled or not). Used by `PatternManager`
    /// to rebuild the filter with a different classifier without
    /// re-reading from disk.
    var allPatterns: [FilterPattern] { patterns }

    /// Whether the on-device ML classifier is attached and active.
    /// Useful for the diagnostics bundle and stats dashboard.
    var hasMLClassifier: Bool { classifier != nil }

    /// Scan content for prompt injections using fused regex + ML +
    /// entropy signals.
    func scan(_ content: String) -> FilterResult {
        guard !content.isEmpty else {
            return FilterResult.empty(content: content)
        }

        // ─── Signal 1: Regex over normalized + leetspeak variants ───
        let normalized = Self.normalize(content)
        let variants = content == normalized ? [content] : [content, normalized]

        var allMatches: [(range: NSRange, name: String, category: String, severity: String)] = []
        for variant in variants {
            let nsContent = variant as NSString
            for pattern in patterns where pattern.enabled {
                let regexMatches = pattern.regex.matches(
                    in: variant,
                    range: NSRange(location: 0, length: nsContent.length)
                )
                for match in regexMatches {
                    allMatches.append((match.range, pattern.name, pattern.category, pattern.severity))
                }
            }
        }

        allMatches.sort { $0.range.location < $1.range.location }
        let deduped = deduplicateOverlaps(allMatches)
        // Dampeners are found on the ORIGINAL content; a match near a
        // benign-context marker (OWASP/CVE, "tutorial", fenced code, a
        // quoted advisory) gets its severity weight multiplied down, so
        // legitimate tool output that merely *discusses* an attack doesn't
        // trip the filter. Mirrors the TS scorer the benchmark measures.
        let dampenerRanges = findDampenerRanges(in: content)
        let regexSignal = Self.computeRegexSignal(deduped, dampenerRanges: dampenerRanges)

        // ─── Signal 2: ML classifier (optional, on-device, ~10ms) ───
        // Skip on very short inputs — not enough surface for the model
        // to make a meaningful decision and the latency cost is wasted.
        var mlScore: Float? = nil
        var mlAvailable = false
        if let classifier, content.count >= 16 {
            do {
                let result = try classifier.classify(content)
                mlScore = result.maliciousScore
                mlAvailable = true
            } catch {
                // Degrade silently to regex+entropy. Logging here would
                // spam every request when the model is unavailable.
                mlScore = nil
                mlAvailable = false
            }
        }
        let mlSignalRaw = Double(mlScore ?? 0)
        // The regex tier dampens per match by offset; the ML score has no
        // offset, so apply an equivalent whole-span benign-context factor.
        // Without this, ML bypassed dampening entirely — the exact reason
        // a quoted advisory or this project's own pattern files scored ~1.0
        // and 403'd a session. Both tiers now see the same benign contexts.
        let mlBenignMultiplier = Self.mlBenignMultiplier(
            dampenerRanges: dampenerRanges,
            contentLength: (content as NSString).length
        )
        let mlSignal = mlSignalRaw * mlBenignMultiplier

        // ─── Signal 3: Entropy anomaly (near-free) ───
        let entropySignal = EntropyAnalyzer.anomalyScore(content)

        // ─── Fuse: weighted sum + max-signal short-circuit ───
        // The weighted sum rewards corroboration (regex + ML agreeing push
        // each other up); the short-circuit is the single-strong-signal
        // path — either an undampened critical regex hit or a dampened-ML
        // score clearing the higher ML-alone bar.
        let fusedWeighted =
            regexSignal * 0.50 +
            mlSignal * 0.40 +
            entropySignal * 0.10
        let strongest = max(regexSignal, mlSignal)
        let fusedScore = max(fusedWeighted, strongest >= Self.strongSignalThreshold ? strongest : 0)

        // ─── Sanitize ───
        // Three cases:
        //   a) Regex matched → redact match offsets (existing behavior)
        //   b) Only ML/entropy fired AND we should block → replace whole content
        //   c) Nothing fires → return content unchanged
        let shouldBlock = !deduped.isEmpty
            || fusedScore >= Self.blockThreshold
            || (mlSignal >= Self.strongSignalThreshold)

        let sanitized: String
        if !deduped.isEmpty {
            var s = content
            for match in deduped.reversed() {
                guard let swiftRange = Range(match.range, in: s) else { continue }
                s.replaceSubrange(swiftRange, with: Self.redactionMessage)
            }
            sanitized = s
        } else if shouldBlock {
            sanitized = Self.redactionMessage
        } else {
            sanitized = content
        }

        let patternNames = Array(Set(deduped.map(\.name)))
        let categories = Array(Set(deduped.map(\.category)))
        let severities = Array(Set(deduped.map(\.severity)))

        return FilterResult(
            matchCount: deduped.count,
            patternNames: patternNames,
            categories: categories,
            severities: severities,
            sanitized: sanitized,
            mlScore: mlScore,
            entropyAnomaly: entropySignal,
            fusedScore: fusedScore,
            mlAvailable: mlAvailable,
            shouldBlock: shouldBlock
        )
    }

    /// Severity-weighted regex signal in [0, 1]. Mirrors the TS scorer's
    /// `severityScore` factor: sum of severity weights, capped at 1, with
    /// per-match dampening applied. Single (undampened) critical → 1.0;
    /// a critical inside an OWASP/tutorial/quoted context → far lower.
    private static func computeRegexSignal(
        _ matches: [(range: NSRange, name: String, category: String, severity: String)],
        dampenerRanges: [DampenerRange]
    ) -> Double {
        var sum = 0.0
        for m in matches {
            let weight = severityWeights[m.severity] ?? 0.15
            sum += weight * dampeningMultiplier(for: m.range, ranges: dampenerRanges)
        }
        return min(1.0, sum)
    }

    /// Lowest (most aggressive) dampener multiplier among all dampener
    /// ranges within `dampenerProximity` of the match. 1.0 = no dampening.
    /// Mirrors `computeDampening` in `packages/patterns/src/scorer.ts`.
    private static func dampeningMultiplier(for range: NSRange, ranges: [DampenerRange]) -> Double {
        guard !ranges.isEmpty else { return 1.0 }
        var multiplier = 1.0
        let matchStart = range.location
        let matchEnd = range.location + range.length
        for r in ranges {
            let gap = max(0, max(r.start - matchEnd, matchStart - r.end))
            if gap <= dampenerProximity, r.dampen < multiplier {
                multiplier = r.dampen
            }
        }
        return multiplier
    }

    /// All dampener hit ranges in `content` (UTF-16 offsets, matching the
    /// pattern-match offsets). Mirrors `findDampenerRanges` in scorer.ts.
    private func findDampenerRanges(in content: String) -> [DampenerRange] {
        guard !dampeners.isEmpty else { return [] }
        let ns = content as NSString
        let full = NSRange(location: 0, length: ns.length)
        var ranges: [DampenerRange] = []
        for d in dampeners {
            for m in d.regex.matches(in: content, range: full) {
                ranges.append(DampenerRange(
                    start: m.range.location,
                    end: m.range.location + m.range.length,
                    dampen: d.dampen
                ))
            }
        }
        return ranges
    }

    /// Whole-span benign-context multiplier for the ML signal, in
    /// (0, 1]. 1.0 means "no benign context — trust ML fully."
    ///
    /// The regex tier dampens each match by how close it sits to a
    /// benign-context marker (`dampeningMultiplier`). The ML score is a
    /// single number for the whole span with no offset, so we need a
    /// span-level analogue. We reuse the same proximity notion: expand
    /// every dampener hit by `dampenerProximity` on each side (the region
    /// it makes "benign context"), union those windows, and take the
    /// fraction of the span they cover. The multiplier interpolates from
    /// 1.0 (no coverage) down to the strongest dampener present (full
    /// coverage).
    ///
    /// Consequence, by construction:
    ///   - A span saturated with markers — a security advisory, an OWASP
    ///     page, this project's own pattern files — is ~fully covered, so
    ///     ML is pulled down toward the strongest dampener and a quoted
    ///     attack no longer reads as a live one.
    ///   - A genuine injection in untrusted prose has no benign markers,
    ///     coverage 0, multiplier 1.0 — ML still blocks it alone.
    ///
    /// The adversarial case (an attacker sprinkling "according to OWASP"
    /// to buy dampening) is the same tradeoff the regex tier already
    /// accepts; provenance + the higher ML-alone bar are the backstops,
    /// and the span allowlist covers a surviving false positive.
    static func mlBenignMultiplier(dampenerRanges: [DampenerRange], contentLength: Int) -> Double {
        guard !dampenerRanges.isEmpty, contentLength > 0 else { return 1.0 }

        var windows: [(start: Int, end: Int)] = dampenerRanges.map {
            (max(0, $0.start - dampenerProximity), min(contentLength, $0.end + dampenerProximity))
        }
        windows.sort { $0.start < $1.start }

        var coveredLen = 0
        var curStart = windows[0].start
        var curEnd = windows[0].end
        for w in windows.dropFirst() {
            if w.start <= curEnd {
                curEnd = max(curEnd, w.end)
            } else {
                coveredLen += curEnd - curStart
                curStart = w.start
                curEnd = w.end
            }
        }
        coveredLen += curEnd - curStart

        let coverage = min(1.0, Double(coveredLen) / Double(contentLength))
        let minDampen = dampenerRanges.map(\.dampen).min() ?? 1.0
        return 1.0 - coverage * (1.0 - minDampen)
    }

    /// Regex-tier-only scan: pattern matches with their names and
    /// categories, no ML and no entropy. Fast (sub-millisecond over small
    /// inputs) and side-effect free, so it is safe to call on the NIO event
    /// loop — unlike `scan`, whose ML tier is a synchronous CoreML call.
    /// Used by `ResponseActionInspector`, which keys only on which category
    /// matched in a tool call's arguments.
    func scanRegexOnly(_ content: String) -> (matchCount: Int, patternNames: [String], categories: [String]) {
        guard !content.isEmpty else { return (0, [], []) }
        let normalized = Self.normalize(content)
        let variants = content == normalized ? [content] : [content, normalized]

        var allMatches: [(range: NSRange, name: String, category: String, severity: String)] = []
        for variant in variants {
            let nsContent = variant as NSString
            for pattern in patterns where pattern.enabled {
                let matches = pattern.regex.matches(
                    in: variant, range: NSRange(location: 0, length: nsContent.length)
                )
                for match in matches {
                    allMatches.append((match.range, pattern.name, pattern.category, pattern.severity))
                }
            }
        }
        allMatches.sort { $0.range.location < $1.range.location }
        let deduped = deduplicateOverlaps(allMatches)
        return (deduped.count, Array(Set(deduped.map(\.name))), Array(Set(deduped.map(\.category))))
    }

    // MARK: - Explainability (block-explainer, off the hot path)

    /// Benign-context multiplier the ML signal would receive for `text`
    /// (1.0 = no benign context, so ML is trusted fully). Exposed so the
    /// opt-in block explainer can show why dampening did or didn't rescue
    /// a span.
    func benignMultiplier(for text: String) -> Double {
        let ranges = findDampenerRanges(in: text)
        return Self.mlBenignMultiplier(dampenerRanges: ranges, contentLength: (text as NSString).length)
    }

    /// Localize which passage of `text` drives the ML score by running the
    /// classifier over overlapping windows and returning the strongest.
    ///
    /// The classifier collapses a whole span to one number with no
    /// attribution; this is the cheapest honest way to turn "0.99
    /// somewhere in 60 KB" into "this passage scored 0.99." Bounded by
    /// `maxWindows` so a pathological span can't stall the capture, and
    /// only ever called on a block when capture is enabled. Returns nil
    /// when no classifier is attached (a regex block already names its
    /// span via pattern matches).
    func attributeTopWindow(
        _ text: String,
        windowChars: Int = 1500,
        stride: Int = 1000,
        maxWindows: Int = 24
    ) -> (window: String, score: Float, windowsScanned: Int, truncated: Bool)? {
        guard let classifier else { return nil }
        let chars = Array(text)
        guard !chars.isEmpty else { return nil }

        var best: (window: String, score: Float)?
        var scanned = 0
        var start = 0
        var lastEnd = 0
        while start < chars.count, scanned < maxWindows {
            let end = min(start + windowChars, chars.count)
            let window = String(chars[start..<end])
            if let c = try? classifier.classify(window), best == nil || c.maliciousScore > best!.score {
                best = (window, c.maliciousScore)
            }
            scanned += 1
            lastEnd = end
            if end == chars.count { break }
            start += stride
        }
        guard let b = best else { return nil }
        return (b.window, b.score, scanned, lastEnd < chars.count)
    }

    private static func normalize(_ content: String) -> String {
        // NFKC normalization (fullwidth chars, compatibility decompositions)
        var result = content.precomposedStringWithCompatibilityMapping

        result = result.replacingOccurrences(
            of: "[\\u200B\\u200C\\u200D\\uFEFF\\u2060\\u00AD]",
            with: "",
            options: .regularExpression
        )

        // Single-pass homoglyph replacement
        var chars: [Character] = []
        chars.reserveCapacity(result.count)
        for c in result {
            chars.append(homoglyphMap[c] ?? c)
        }
        result = String(chars)

        return result
    }

    private func deduplicateOverlaps(
        _ matches: [(range: NSRange, name: String, category: String, severity: String)]
    ) -> [(range: NSRange, name: String, category: String, severity: String)] {
        var result: [(range: NSRange, name: String, category: String, severity: String)] = []
        var lastEnd = 0
        for match in matches {
            if match.range.location >= lastEnd {
                result.append(match)
                lastEnd = match.range.location + match.range.length
            }
        }
        return result
    }

    /// Compile a `[DampenerJSON]` into runnable dampeners, dropping any
    /// whose regex doesn't compile under ICU (fail-safe: a broken dampener
    /// just means less FP suppression, never a crash). Exposed for tests.
    static func compileDampeners(_ defs: [DampenerJSON]) -> [CompiledDampener] {
        defs.compactMap { d in
            var options: NSRegularExpression.Options = []
            if d.flags.contains("i") { options.insert(.caseInsensitive) }
            if d.flags.contains("s") { options.insert(.dotMatchesLineSeparators) }
            guard let re = try? NSRegularExpression(pattern: d.regex, options: options) else { return nil }
            return CompiledDampener(regex: re, dampen: d.dampen)
        }
    }

    private static func loadBundledSet() -> (patterns: [FilterPattern], dampeners: [CompiledDampener]) {
        guard let url = Bundle.main.url(forResource: "patterns", withExtension: "json"),
              let data = try? Data(contentsOf: url)
        else {
            print("[bouclier.ai] patterns.json not found, using fallback patterns")
            return (fallbackPatterns(), [])
        }

        let hash = SHA256.hash(data: data)
        let hashString = hash.map { String(format: "%02x", $0) }.joined()
        print("[bouclier.ai] Loaded patterns.json (SHA-256: \(hashString.prefix(16))...)")

        guard let patternSet = try? JSONDecoder().decode(PatternSetJSON.self, from: data) else {
            print("[bouclier.ai] Failed to decode patterns.json, using fallback patterns")
            return (fallbackPatterns(), [])
        }

        let compiled = patternSet.patterns.compactMap { FilterPattern(from: $0) }
        let dampeners = compileDampeners(patternSet.dampeners ?? [])
        print("[bouclier.ai] Compiled \(compiled.count)/\(patternSet.patterns.count) patterns, \(dampeners.count) dampeners")
        return (compiled, dampeners)
    }

    private static func fallbackPatterns() -> [FilterPattern] {
        let defs: [(String, String, String, String, String)] = [
            ("role-001", "System prompt override", "role-hijack", "critical",
             "(?:you\\s+are\\s+now|from\\s+now\\s+on\\s+you\\s+are|ignore\\s+(?:all\\s+)?previous\\s+instructions?|forget\\s+(?:all\\s+)?(?:your\\s+)?(?:previous\\s+)?instructions?|disregard\\s+(?:all\\s+)?(?:your\\s+)?previous\\s+(?:instructions?|directives?))"),
            ("role-002", "Jailbreak persona", "role-hijack", "critical",
             "(?:you\\s+are\\s+(?:DAN|STAN|DUDE|AIM|KEVIN|APOPHIS)|act\\s+as\\s+(?:an?\\s+)?(?:unrestricted|unfiltered|uncensored)\\s+(?:AI|model|assistant))"),
            ("delim-001", "LLM special token injection", "delimiter-attack", "high",
             "(?:<\\|(?:im_(?:start|end)|end(?:of(?:text|prompt))?|system|user|assistant)\\|>|\\[(?:INST|/INST|SYS|/SYS)\\])"),
            ("indirect-001", "Tool result manipulation", "indirect-injection", "critical",
             "(?:IMPORTANT:\\s*(?:ignore|override|disregard)|NOTE\\s+TO\\s+(?:AI|ASSISTANT|MODEL):|AI\\s+INSTRUCTION:|BEGIN\\s+(?:HIDDEN|SECRET)\\s+INSTRUCTION)"),
            ("override-003", "Constraint removal", "instruction-override", "critical",
             "(?:(?:remove|disable|bypass|ignore|override)\\s+(?:all\\s+)?(?:your\\s+)?(?:safety|security|content)\\s+(?:filters?|checks?|guidelines?|restrictions?))"),
            ("exfil-001", "System prompt extraction", "data-exfiltration", "critical",
             "(?:(?:show|tell|reveal|output|repeat)\\s+(?:me\\s+)?(?:your|the)\\s+(?:system\\s+(?:prompt|message|instructions?)|(?:initial|original|hidden)\\s+(?:prompt|instructions?)))"),
        ]

        return defs.compactMap { id, name, category, severity, regex in
            guard let compiled = try? NSRegularExpression(pattern: regex, options: [.caseInsensitive]) else {
                return nil
            }
            return FilterPattern(id: id, name: name, category: category, severity: severity, regex: compiled, enabled: true)
        }
    }
}

// MARK: - Active filter registry

/// Process-wide registry for the live `InjectionFilter`.
///
/// Same rationale as `ActivePIIScannerRegistry`: the engine is mutable
/// across the process lifetime because the CoreML classifier loads
/// asynchronously and `patterns.json` can hot-reload, but the gateway
/// handler is constructed per-connection long before either settles.
/// Threading a provider closure through the NIO pipeline would be
/// boilerplate for a swap that happens once or twice per process.
///
/// `PatternManager` owns the lifecycle and calls `install(_:)` on every
/// swap; `GatewayHandler` reads `current()` per request, so a request in
/// flight before the ML swap picks the fused engine up on the next one.
///
/// `current()` is `nil` until the engine has loaded. Callers treat nil as
/// **fail-open** — forward the request untouched — matching the v0.5.2
/// rule that Bouclier being unavailable must never break the user's
/// agent.
final class ActiveInjectionFilterRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var filter: InjectionFilter?

    func current() -> InjectionFilter? {
        lock.lock(); defer { lock.unlock() }
        return filter
    }

    func install(_ new: InjectionFilter) {
        lock.lock(); defer { lock.unlock() }
        filter = new
    }

    /// Test hook — drop the engine so a test can exercise the fail-open path.
    func reset() {
        lock.lock(); defer { lock.unlock() }
        filter = nil
    }
}

// MARK: - Types

struct FilterResult: Sendable {
    let matchCount: Int
    let patternNames: [String]
    let categories: [String]
    let severities: [String]
    let sanitized: String

    /// Probability returned by the on-device ML classifier (0–1), or
    /// `nil` if the classifier wasn't loaded or the input was too
    /// short to bother running it through.
    let mlScore: Float?

    /// Shannon-entropy anomaly score in [0, 1]. Non-zero only on
    /// inputs with abnormal character distributions.
    let entropyAnomaly: Double

    /// Combined 0–1 score from the fused regex/ML/entropy scorer.
    /// What `shouldBlock` is derived from.
    let fusedScore: Double

    /// Whether the on-device ML classifier was actually consulted for
    /// this scan. False when the input was too short to run through it
    /// or when the classifier hasn't been loaded yet (regex-only mode).
    /// Used by the audit log so dashboards can distinguish "ML cleared
    /// it" from "ML never ran".
    let mlAvailable: Bool

    /// Authoritative block decision. True when the fused score crosses
    /// the block threshold, OR any single signal short-circuits the
    /// decision (a critical regex match, or ML confidence ≥ 0.85).
    let shouldBlock: Bool

    /// Backwards-compatible alias used throughout the proxy pipeline
    /// (HTTPRequestInspector / SSEStreamInspector). Anything that
    /// triggers a block also flips `detected`.
    var detected: Bool { shouldBlock }

    init(
        matchCount: Int,
        patternNames: [String],
        categories: [String] = [],
        severities: [String] = [],
        sanitized: String,
        mlScore: Float? = nil,
        entropyAnomaly: Double = 0,
        fusedScore: Double = 0,
        mlAvailable: Bool = false,
        shouldBlock: Bool = false
    ) {
        self.matchCount = matchCount
        self.patternNames = patternNames
        self.categories = categories
        self.severities = severities
        self.sanitized = sanitized
        self.mlScore = mlScore
        self.entropyAnomaly = entropyAnomaly
        self.fusedScore = fusedScore
        self.mlAvailable = mlAvailable
        // Preserve old behavior: any regex match implicitly blocks if
        // the caller didn't pass an explicit decision.
        self.shouldBlock = shouldBlock || matchCount > 0
    }

    /// Empty result for early-exit paths (empty input, etc.).
    static func empty(content: String) -> FilterResult {
        FilterResult(
            matchCount: 0,
            patternNames: [],
            sanitized: content,
            mlScore: nil,
            entropyAnomaly: 0,
            fusedScore: 0,
            mlAvailable: false,
            shouldBlock: false
        )
    }
}

struct FilterPattern: Sendable {
    let id: String
    let name: String
    let category: String
    let severity: String
    let regex: NSRegularExpression
    let enabled: Bool

    init(id: String, name: String, category: String, severity: String, regex: NSRegularExpression, enabled: Bool) {
        self.id = id
        self.name = name
        self.category = category
        self.severity = severity
        self.regex = regex
        self.enabled = enabled
    }

    init?(from json: PatternJSON) {
        self.id = json.id
        self.name = json.name
        self.category = json.category
        self.severity = json.severity
        self.enabled = json.enabled

        var options: NSRegularExpression.Options = []
        if json.flags.contains("i") { options.insert(.caseInsensitive) }
        if json.flags.contains("s") { options.insert(.dotMatchesLineSeparators) }

        guard let compiled = try? NSRegularExpression(pattern: json.regex, options: options) else {
            return nil
        }
        self.regex = compiled
    }
}

struct PatternSetJSON: Codable, Sendable {
    let version: String
    let updatedAt: String
    let patterns: [PatternJSON]
    /// Optional so an older patterns.json (or a user override without a
    /// dampeners array) still decodes — absent ⇒ no FP suppression.
    let dampeners: [DampenerJSON]?
}

/// A false-positive dampener as shipped in patterns.json. Mirrors the
/// `Dampener` interface in `packages/patterns/src/types.ts`.
struct DampenerJSON: Codable, Sendable {
    let id: String
    let label: String
    let regex: String
    let flags: String
    let dampen: Double
}

/// A compiled dampener ready to scan content.
struct CompiledDampener: Sendable {
    let regex: NSRegularExpression
    let dampen: Double
}

/// One dampener hit's span (UTF-16 offsets) and its multiplier.
struct DampenerRange: Sendable {
    let start: Int
    let end: Int
    let dampen: Double
}

struct PatternJSON: Codable, Sendable {
    let id: String
    let name: String
    let description: String
    let category: String
    let severity: String
    let regex: String
    let flags: String
    let examples: [String]
    let enabled: Bool
}
