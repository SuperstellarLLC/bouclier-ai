import Foundation

/// Incremental Server-Sent Events inspector.
///
/// Upstream AI APIs (OpenAI, Anthropic, Gemini, Mistral, …) stream
/// chat completions as SSE frames. This inspector accumulates partial
/// frames as they arrive, extracts the model's `content` / `delta`
/// text, and runs it through the injection filter. When detection
/// fires, the offending frame is replaced with a redaction frame and
/// the stream is marked closed.
///
/// Design goals:
/// - **Stateful & byte-safe.** Partial frames arriving across TCP
///   boundaries are buffered until a full `\n\n`-delimited event is
///   available.
/// - **Non-blocking.** Each `ingest` call returns only the bytes that
///   can be safely forwarded downstream right now; incomplete frames
///   stay in the buffer.
/// - **Rewrite-or-truncate.** On detection the remaining stream is
///   closed with a final redaction event so the client sees a clean
///   termination rather than a stalled connection.
/// - **No NIO dependency.** Pure data-in / data-out so it can be
///   unit-tested without a channel.
final class SSEStreamInspector {
    private let filter: InjectionFilter
    private var buffer: String = ""
    private var accumulatedText: String = ""
    private(set) var detected: Bool = false
    private(set) var closed: Bool = false
    private(set) var patternNames: [String] = []

    /// Hard cap on the un-flushed SSE buffer. A misbehaving upstream
    /// that never emits an event terminator (`\n\n`) could otherwise
    /// drive arbitrary memory growth. 1 MiB is well above any
    /// legitimate single SSE event (largest in practice is a few KB
    /// of reasoning text) so this only fires on pathological input.
    static let maxBufferBytes = 1 * 1024 * 1024

    /// SSE frame returned to the caller after a final safety event is
    /// emitted. `[DONE]` mirrors OpenAI's termination sentinel.
    static let redactionFrame =
        "event: bouclier-ai.redacted\ndata: {\"error\":\"response_blocked\",\"reason\":\"\(InjectionFilter.redactionMessage)\"}\n\ndata: [DONE]\n\n"

    /// Frame emitted when the buffer cap is exceeded — distinguishes a
    /// DoS-style runaway response from an injection block in the audit
    /// trail.
    static let oversizeFrame =
        "event: bouclier-ai.oversize\ndata: {\"error\":\"sse_buffer_exceeded\"}\n\ndata: [DONE]\n\n"

    init(filter: InjectionFilter) {
        self.filter = filter
    }

    /// Feed bytes from upstream, receive bytes to forward to the client.
    /// Returns an empty string once the stream has been closed by a prior
    /// detection so the caller can tear down the connection.
    func ingest(_ chunk: String) -> String {
        if closed { return "" }

        buffer += chunk

        // Bound the unflushed buffer. A 1 MB cap is plenty for any
        // legitimate SSE event; runaway upstreams hit this before they
        // hurt the host.
        if buffer.utf8.count > Self.maxBufferBytes {
            closed = true
            buffer.removeAll(keepingCapacity: false)
            return Self.oversizeFrame
        }

        var forward = ""

        // SSE frames are separated by "\n\n" (or "\r\n\r\n"). Process any
        // complete frames and leave the trailing partial frame in the
        // buffer for the next call.
        while let sep = buffer.range(of: "\n\n") ?? buffer.range(of: "\r\n\r\n") {
            let frame = String(buffer[..<sep.lowerBound])
            buffer.removeSubrange(buffer.startIndex..<sep.upperBound)

            // Extract every `data:` field from the frame and build up a
            // running transcript of model output to scan.
            let newText = extractData(from: frame)
            if !newText.isEmpty {
                accumulatedText += newText
                accumulatedText = String(accumulatedText.suffix(4096)) // rolling window

                let result = filter.scan(accumulatedText)
                if result.detected {
                    detected = true
                    closed = true
                    patternNames = result.patternNames
                    forward += Self.redactionFrame
                    return forward
                }
            }

            // Clean frames are forwarded verbatim.
            forward += frame
            forward += "\n\n"
        }

        return forward
    }

    /// Flush any remaining partial frame at stream end. Returns the
    /// bytes that should be written before closing the client channel.
    func finish() -> String {
        if closed { return "" }

        if !buffer.isEmpty {
            let tail = buffer
            buffer.removeAll()
            let newText = extractData(from: tail)
            if !newText.isEmpty {
                accumulatedText += newText
                let result = filter.scan(accumulatedText)
                if result.detected {
                    detected = true
                    closed = true
                    patternNames = result.patternNames
                    return Self.redactionFrame
                }
            }
            return tail
        }
        return ""
    }

    /// Extract model-visible text from an SSE frame. Handles OpenAI
    /// (`choices[].delta.content`), Anthropic (`delta.text`), and falls
    /// back to the raw `data:` payload string so unknown providers still
    /// get scanned.
    private func extractData(from frame: String) -> String {
        var collected = ""
        for line in frame.split(separator: "\n", omittingEmptySubsequences: true) {
            guard line.hasPrefix("data:") else { continue }
            let payload = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
            if payload.isEmpty || payload == "[DONE]" { continue }

            // Try to extract content fields from known JSON shapes.
            if let data = payload.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            {
                if let text = Self.extractKnownText(from: json) {
                    collected += text
                    continue
                }
            }

            // Fallback: scan the raw payload string. Covers non-JSON
            // providers and malformed frames.
            collected += payload + " "
        }
        return collected
    }

    private static func extractKnownText(from json: [String: Any]) -> String? {
        // OpenAI chat completions: choices[0].delta.content
        if let choices = json["choices"] as? [[String: Any]], let first = choices.first {
            if let delta = first["delta"] as? [String: Any] {
                if let content = delta["content"] as? String { return content }
                if let reasoning = delta["reasoning"] as? String { return reasoning }
            }
            if let message = first["message"] as? [String: Any],
               let content = message["content"] as? String { return content }
            if let text = first["text"] as? String { return text }
        }

        // Anthropic streaming: delta.text
        if let delta = json["delta"] as? [String: Any] {
            if let text = delta["text"] as? String { return text }
            if let partial = delta["partial_json"] as? String { return partial }
        }

        // Gemini / Mistral style: candidates[0].content.parts[].text
        if let candidates = json["candidates"] as? [[String: Any]],
           let first = candidates.first,
           let content = first["content"] as? [String: Any],
           let parts = content["parts"] as? [[String: Any]]
        {
            return parts.compactMap { $0["text"] as? String }.joined()
        }

        return nil
    }
}
