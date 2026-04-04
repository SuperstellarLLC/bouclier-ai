import Foundation

/// ilvarion-mcp-wrapper — a stdio pipe filter for MCP servers.
///
/// Usage:
///   ilvarion-mcp-wrapper <command> [args...]
///
/// Wraps an MCP server by spawning it as a child process, piping stdin to it,
/// intercepting its stdout, scanning JSON-RPC responses for prompt injections
/// in tool result content blocks, and forwarding sanitized output.
///
/// Example MCP config:
/// ```json
/// {
///   "command": "ilvarion-mcp-wrapper",
///   "args": ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
/// }
/// ```

let redactionMessage = "[Possible prompt injection redacted by Ilvarion. See https://ilvarion.dev/blocked for details]"

// MARK: - Injection Patterns (embedded subset for standalone binary)

let injectionPatterns: [(id: String, regex: NSRegularExpression)] = {
    let defs: [(String, String)] = [
        ("role-001", "(?:you\\s+are\\s+now|from\\s+now\\s+on\\s+you\\s+are|ignore\\s+(?:all\\s+)?previous\\s+instructions?|forget\\s+(?:all\\s+)?(?:your\\s+)?(?:previous\\s+)?instructions?|disregard\\s+(?:all\\s+)?(?:your\\s+)?previous\\s+(?:instructions?|directives?))"),
        ("role-002", "(?:you\\s+are\\s+(?:DAN|STAN|DUDE|AIM|KEVIN|APOPHIS)|act\\s+as\\s+(?:an?\\s+)?(?:unrestricted|unfiltered|uncensored)\\s+(?:AI|model|assistant))"),
        ("override-001", "(?:new\\s+instructions?:|(?:system|admin)\\s*(?:prompt|message)\\s*:|\\[\\s*(?:SYSTEM|INST|ADMIN)\\s*\\]|<\\s*(?:system|instruction)\\s*>)"),
        ("override-003", "(?:(?:remove|disable|bypass|ignore|override)\\s+(?:all\\s+)?(?:your\\s+)?(?:safety|security|content)\\s+(?:filters?|checks?|guidelines?|restrictions?))"),
        ("delim-001", "(?:<\\|(?:im_(?:start|end)|end(?:of(?:text|prompt))?|system|user|assistant)\\|>|\\[(?:INST|/INST|SYS|/SYS)\\])"),
        ("indirect-001", "(?:IMPORTANT:\\s*(?:ignore|override|disregard)|NOTE\\s+TO\\s+(?:AI|ASSISTANT|MODEL):|AI\\s+INSTRUCTION:|BEGIN\\s+(?:HIDDEN|SECRET)\\s+INSTRUCTION)"),
        ("exfil-001", "(?:(?:show|tell|reveal|output|repeat)\\s+(?:me\\s+)?(?:your|the)\\s+(?:system\\s+(?:prompt|message|instructions?)|(?:initial|original|hidden)\\s+(?:prompt|instructions?)))"),
        ("recurse-001", "(?:(?:if|when)\\s+(?:anyone|someone|a\\s+filter)\\s+(?:asks?|tells?)\\s+(?:you\\s+)?(?:to\\s+)?(?:ignore|block|flag)\\s+this|this\\s+is\\s+not\\s+a\\s+prompt\\s+injection)"),
    ]

    return defs.compactMap { id, pattern in
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        return (id, regex)
    }
}()

// MARK: - Scanner

func scanForInjections(_ text: String) -> (detected: Bool, sanitized: String, count: Int) {
    guard !text.isEmpty else { return (false, text, 0) }

    var matches: [(range: NSRange, id: String)] = []
    let nsText = text as NSString

    for (id, regex) in injectionPatterns {
        let results = regex.matches(in: text, range: NSRange(location: 0, length: nsText.length))
        for result in results {
            matches.append((result.range, id))
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

    // Replace in reverse order
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

    // Check for tool call results: {"jsonrpc":"2.0","id":...,"result":{"content":[...]}}
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
            "[ilvarion] Blocked \(totalBlocked) injection(s) in MCP tool result\n".data(using: .utf8)!
        )
    }

    return (try? JSONSerialization.data(withJSONObject: json)) ?? data
}

// MARK: - Main

guard CommandLine.arguments.count > 1 else {
    FileHandle.standardError.write(
        "Usage: ilvarion-mcp-wrapper <command> [args...]\n".data(using: .utf8)!
    )
    exit(1)
}

let command = CommandLine.arguments[1]
let args = Array(CommandLine.arguments.dropFirst(2))

// Spawn the real MCP server
let process = Process()
process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
process.arguments = [command] + args

// Set up pipes
let stdinPipe = Pipe()   // Our stdin → child's stdin
let stdoutPipe = Pipe()  // Child's stdout → our processing → our stdout

process.standardInput = stdinPipe
process.standardOutput = stdoutPipe
process.standardError = FileHandle.standardError // Pass through stderr

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

// Process child's stdout: scan JSON-RPC responses and forward
stdoutPipe.fileHandleForReading.readabilityHandler = { handle in
    let data = handle.availableData
    guard !data.isEmpty else {
        FileHandle.standardOutput.closeFile()
        return
    }

    // MCP uses newline-delimited JSON
    // Process each line separately
    guard let raw = String(data: data, encoding: .utf8) else {
        FileHandle.standardOutput.write(data)
        return
    }

    let lines = raw.components(separatedBy: "\n")
    for line in lines {
        if line.isEmpty {
            FileHandle.standardOutput.write("\n".data(using: .utf8)!)
            continue
        }

        if let lineData = line.data(using: .utf8),
           (try? JSONSerialization.jsonObject(with: lineData)) != nil {
            // Valid JSON — process it
            let processed = processJSONRPCResponse(lineData)
            FileHandle.standardOutput.write(processed)
            FileHandle.standardOutput.write("\n".data(using: .utf8)!)
        } else {
            // Not JSON — pass through as-is
            FileHandle.standardOutput.write(line.data(using: .utf8)!)
            if !line.hasSuffix("\n") {
                FileHandle.standardOutput.write("\n".data(using: .utf8)!)
            }
        }
    }
}

// Launch
do {
    try process.run()
} catch {
    FileHandle.standardError.write(
        "[ilvarion] Failed to start MCP server: \(error.localizedDescription)\n".data(using: .utf8)!
    )
    exit(1)
}

process.waitUntilExit()
exit(process.terminationStatus)
