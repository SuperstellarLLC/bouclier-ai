import Foundation

/// bouclier-ai-mcp-wrapper — a stdio pipe filter for MCP servers.
///
/// Usage:
///   bouclier-ai-mcp-wrapper <command> [args...]
///
/// Wraps an MCP server by spawning it as a child process, piping stdin to it,
/// intercepting its stdout, scanning JSON-RPC responses for prompt injections
/// in tool result content blocks, and forwarding sanitized output.

let redactionMessage = "[Possible prompt injection redacted by Bouclier. See https://www.bouclier.ai/blocked for details]"

// MARK: - Injection Patterns (embedded subset for standalone binary)

let injectionPatterns: [(id: String, regex: NSRegularExpression)] = {
    let defs: [(String, String)] = [
        ("role-001", "(?:you\\s+are\\s+now|from\\s+now\\s+on\\s+you\\s+are|ignore\\s+(?:all\\s+)?(?:your\\s+)?previous\\s+instructions?|forget\\s+(?:all\\s+)?(?:your\\s+)?(?:previous\\s+)?instructions?|disregard\\s+(?:all\\s+)?(?:your\\s+)?(?:previous|prior|above)\\s+(?:instructions?|directives?|rules?))"),
        ("role-002", "(?:you\\s+are\\s+(?:DAN|STAN|DUDE|AIM|KEVIN|APOPHIS)|act\\s+as\\s+(?:an?\\s+)?(?:unrestricted|unfiltered|uncensored)\\s+(?:AI|model|assistant))"),
        ("override-001", "(?:new\\s+instructions?:|(?:system|admin)\\s*(?:prompt|message)\\s*:|\\[\\s*(?:SYSTEM|INST|ADMIN)\\s*\\]|<\\s*(?:system|instruction)\\s*>)"),
        ("override-003", "(?:(?:remove|disable|bypass|ignore|override)\\s+(?:all\\s+)?(?:your\\s+)?(?:safety|security|content)\\s+(?:filters?|checks?|guidelines?|restrictions?))"),
        ("delim-001", "(?:<\\|(?:im_(?:start|end)|end(?:of(?:text|prompt))?|system|user|assistant)\\|>|\\[(?:INST|/INST|SYS|/SYS)\\])"),
        ("indirect-001", "(?:IMPORTANT:\\s*(?:ignore|override|disregard)|NOTE\\s+TO\\s+(?:AI|ASSISTANT|MODEL):|AI\\s+INSTRUCTION:|BEGIN\\s+(?:HIDDEN|SECRET)\\s+INSTRUCTION)"),
        ("exfil-001", "(?:(?:show|tell|reveal|output|repeat)\\s+(?:me\\s+)?(?:your|the)\\s+(?:system\\s+(?:prompt|message|instructions?)|(?:initial|original|hidden)\\s+(?:prompt|instructions?)))"),
        ("recurse-001", "(?:(?:if|when)\\s+(?:anyone|someone|a\\s+(?:filter|scanner))\\s+(?:asks?|tells?)\\s+(?:you\\s+)?(?:to\\s+)?(?:ignore|block|flag)\\s+this|this\\s+(?:is\\s+)?(?:not\\s+)?(?:a\\s+)?(?:prompt\\s+injection))"),
    ]

    return defs.compactMap { id, pattern in
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        return (id, regex)
    }
}()

// MARK: - Normalization (minimal, matches InjectionFilter)

func normalizeForScan(_ content: String) -> String {
    var result = content.precomposedStringWithCompatibilityMapping

    // Strip zero-width characters
    result = result.replacingOccurrences(
        of: "[\\u200B\\u200C\\u200D\\uFEFF\\u2060\\u00AD]",
        with: "",
        options: .regularExpression
    )

    // Cyrillic homoglyphs
    let homoglyphs: [Character: Character] = [
        "\u{0430}": "a", "\u{0435}": "e", "\u{043E}": "o",
        "\u{0440}": "p", "\u{0441}": "c", "\u{0443}": "y",
        "\u{0445}": "x", "\u{0410}": "A", "\u{0415}": "E",
        "\u{041E}": "O", "\u{0420}": "P", "\u{0421}": "C",
    ]

    var chars: [Character] = []
    chars.reserveCapacity(result.count)
    for c in result {
        chars.append(homoglyphs[c] ?? c)
    }
    return String(chars)
}

// MARK: - Scanner

func scanForInjections(_ text: String) -> (detected: Bool, sanitized: String, count: Int) {
    guard !text.isEmpty else { return (false, text, 0) }

    let normalized = normalizeForScan(text)
    let variants = text == normalized ? [text] : [text, normalized]

    var matches: [(range: NSRange, id: String)] = []

    for variant in variants {
        let nsText = variant as NSString
        for (id, regex) in injectionPatterns {
            let results = regex.matches(in: variant, range: NSRange(location: 0, length: nsText.length))
            for result in results {
                matches.append((result.range, id))
            }
        }
    }

    guard !matches.isEmpty else { return (false, text, 0) }

    matches.sort { $0.range.location < $1.range.location }

    // Deduplicate overlaps
    var deduped: [(range: NSRange, id: String)] = []
    var lastEnd = 0
    for match in matches {
        if match.range.location >= lastEnd {
            deduped.append(match)
            lastEnd = match.range.location + match.range.length
        }
    }

    // Replace in original text (use only first-variant offsets for safety)
    var sanitized = text
    for match in deduped.reversed() {
        guard let range = Range(match.range, in: sanitized) else { continue }
        sanitized.replaceSubrange(range, with: redactionMessage)
    }

    return (true, sanitized, deduped.count)
}

// MARK: - JSON-RPC Processing

func processJSONRPCResponse(_ data: Data) -> Data {
    guard var json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        return data
    }

    guard var result = json["result"] as? [String: Any],
          var content = result["content"] as? [[String: Any]]
    else {
        return data
    }

    var modified = false
    var totalBlocked = 0

    for i in 0..<content.count {
        if let text = content[i]["text"] as? String {
            let (detected, sanitized, count) = scanForInjections(text)
            if detected {
                content[i]["text"] = sanitized
                modified = true
                totalBlocked += count
            }
        }
    }

    guard modified else { return data }

    result["content"] = content
    json["result"] = result

    if totalBlocked > 0 {
        FileHandle.standardError.write(
            "[bouclier.ai] Blocked \(totalBlocked) injection(s) in MCP tool result\n".data(using: .utf8)!
        )
    }

    return (try? JSONSerialization.data(withJSONObject: json)) ?? data
}

// MARK: - Line Buffer

/// Accumulates partial reads and yields complete newline-delimited lines.
/// Thread-safety: only accessed from the readabilityHandler callback queue.
final class LineBuffer: @unchecked Sendable {
    private var buffer = ""

    func append(_ data: Data) -> [String] {
        guard let str = String(data: data, encoding: .utf8) else { return [] }
        buffer += str

        var lines: [String] = []
        while let newlineIndex = buffer.firstIndex(of: "\n") {
            let line = String(buffer[buffer.startIndex..<newlineIndex])
            buffer = String(buffer[buffer.index(after: newlineIndex)...])
            lines.append(line)
        }
        return lines
    }

    func flush() -> String? {
        guard !buffer.isEmpty else { return nil }
        let remaining = buffer
        buffer = ""
        return remaining
    }
}

// MARK: - Main

guard CommandLine.arguments.count > 1 else {
    FileHandle.standardError.write(
        "Usage: bouclier-ai-mcp-wrapper <command> [args...]\n".data(using: .utf8)!
    )
    exit(1)
}

let command = CommandLine.arguments[1]
let args = Array(CommandLine.arguments.dropFirst(2))

let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
process.arguments = [command] + args

let stdinPipe = Pipe()
let stdoutPipe = Pipe()

process.standardInput = stdinPipe
process.standardOutput = stdoutPipe
process.standardError = FileHandle.standardError

// Forward our stdin to child's stdin
let stdinSource = DispatchSource.makeReadSource(fileDescriptor: FileHandle.standardInput.fileDescriptor, queue: .global())
stdinSource.setEventHandler {
    let data = FileHandle.standardInput.availableData
    if data.isEmpty {
        stdinPipe.fileHandleForWriting.closeFile()
        stdinSource.cancel()
    } else {
        stdinPipe.fileHandleForWriting.write(data)
    }
}
stdinSource.resume()

// Process child's stdout with line buffering
let lineBuffer = LineBuffer()

stdoutPipe.fileHandleForReading.readabilityHandler = { handle in
    let data = handle.availableData
    guard !data.isEmpty else {
        // EOF — flush remaining buffer
        if let remaining = lineBuffer.flush() {
            processAndForward(line: remaining)
        }
        FileHandle.standardOutput.closeFile()
        return
    }

    let lines = lineBuffer.append(data)
    for line in lines {
        processAndForward(line: line)
    }
}

@Sendable func processAndForward(line: String) {
    if line.isEmpty {
        FileHandle.standardOutput.write("\n".data(using: .utf8)!)
        return
    }

    if let lineData = line.data(using: .utf8),
       (try? JSONSerialization.jsonObject(with: lineData)) != nil {
        let processed = processJSONRPCResponse(lineData)
        FileHandle.standardOutput.write(processed)
        FileHandle.standardOutput.write("\n".data(using: .utf8)!)
    } else {
        FileHandle.standardOutput.write((line + "\n").data(using: .utf8)!)
    }
}

do {
    try process.run()
} catch {
    FileHandle.standardError.write(
        "[bouclier.ai] Failed to start MCP server: \(error.localizedDescription)\n".data(using: .utf8)!
    )
    exit(1)
}

process.waitUntilExit()
exit(process.terminationStatus)
