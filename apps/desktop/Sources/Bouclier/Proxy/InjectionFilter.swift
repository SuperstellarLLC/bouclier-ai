import CryptoKit
import Foundation

/// Core injection detection engine.
/// Loads patterns from the shared @bouclier/patterns package (JSON export)
/// and scans content using NSRegularExpression for cross-platform compatibility.
///
/// Includes Unicode normalization and heuristic scoring.
final class InjectionFilter: Sendable {
    private let patterns: [FilterPattern]

    static let redactionMessage =
        "[Possible prompt injection redacted by Bouclier.ai. See https://bouclier.ai/blocked for details]"

    private static let homoglyphMap: [Character: Character] = [
        "\u{0430}": "a", "\u{0435}": "e", "\u{043E}": "o",
        "\u{0440}": "p", "\u{0441}": "c", "\u{0443}": "y",
        "\u{0445}": "x", "\u{0410}": "A", "\u{0415}": "E",
        "\u{041E}": "O", "\u{0420}": "P", "\u{0421}": "C",
        "\u{03B1}": "a", "\u{03B5}": "e", "\u{03BF}": "o", "\u{03C1}": "p",
    ]

    /// Load patterns from bundled resource or fallback.
    init() {
        self.patterns = Self.loadAndVerifyPatterns()
    }

    /// Initialize with externally-provided patterns (used by PatternManager for hot-reload).
    init(patterns: [FilterPattern]) {
        self.patterns = patterns
    }

    /// Number of enabled patterns currently loaded. Exposed so the
    /// diagnostics bundle and the stats dashboard can report accurate
    /// coverage figures after a hot-reload.
    var patternCount: Int { patterns.filter(\.enabled).count }

    /// Scan content for prompt injections.
    func scan(_ content: String) -> FilterResult {
        guard !content.isEmpty else {
            return FilterResult(matchCount: 0, patternNames: [], sanitized: content)
        }

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

        guard !allMatches.isEmpty else {
            return FilterResult(matchCount: 0, patternNames: [], sanitized: content)
        }

        allMatches.sort { $0.range.location < $1.range.location }
        let deduped = deduplicateOverlaps(allMatches)

        // Build sanitized string from original content
        var sanitized = content
        for match in deduped.reversed() {
            guard let swiftRange = Range(match.range, in: sanitized) else { continue }
            sanitized.replaceSubrange(swiftRange, with: Self.redactionMessage)
        }

        let patternNames = Array(Set(allMatches.map(\.name)))
        let categories = Array(Set(allMatches.map(\.category)))
        let severities = Array(Set(allMatches.map(\.severity)))

        return FilterResult(
            matchCount: deduped.count,
            patternNames: patternNames,
            categories: categories,
            severities: severities,
            sanitized: sanitized
        )
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

    private static func loadAndVerifyPatterns() -> [FilterPattern] {
        guard let url = Bundle.main.url(forResource: "patterns", withExtension: "json"),
              let data = try? Data(contentsOf: url)
        else {
            print("[bouclier.ai] patterns.json not found, using fallback patterns")
            return fallbackPatterns()
        }

        let hash = SHA256.hash(data: data)
        let hashString = hash.map { String(format: "%02x", $0) }.joined()
        print("[bouclier.ai] Loaded patterns.json (SHA-256: \(hashString.prefix(16))...)")

        guard let patternSet = try? JSONDecoder().decode(PatternSetJSON.self, from: data) else {
            print("[bouclier.ai] Failed to decode patterns.json, using fallback patterns")
            return fallbackPatterns()
        }

        let compiled = patternSet.patterns.compactMap { FilterPattern(from: $0) }
        print("[bouclier.ai] Compiled \(compiled.count)/\(patternSet.patterns.count) patterns")
        return compiled
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

// MARK: - Types

struct FilterResult: Sendable {
    let matchCount: Int
    let patternNames: [String]
    let categories: [String]
    let severities: [String]
    let sanitized: String
    var detected: Bool { matchCount > 0 }

    init(
        matchCount: Int,
        patternNames: [String],
        categories: [String] = [],
        severities: [String] = [],
        sanitized: String
    ) {
        self.matchCount = matchCount
        self.patternNames = patternNames
        self.categories = categories
        self.severities = severities
        self.sanitized = sanitized
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
