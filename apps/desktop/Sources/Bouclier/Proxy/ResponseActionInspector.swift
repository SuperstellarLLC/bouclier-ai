import Foundation

/// Output-side injected-action detector — the response-leg half of the
/// firewall, and the piece that aims at where the field's frontier is.
///
/// Input classification is evadable and, on its own, losing: a good enough
/// attacker paraphrases past any detector. The invariant that actually
/// matters is the one the "lethal trifecta" / CaMeL / Agents-Rule-of-Two
/// literature points at — *untrusted input must not be able to turn into a
/// harmful action*. A passive gateway can't rewrite the agent's capability
/// model, but it sits on the stream, so it can do the honest observable
/// version: watch the model's **response** for an outbound tool call whose
/// arguments carry an exfiltration / dangerous-action signature, and when
/// the request that produced it contained **untrusted** content, flag the
/// trifecta completion (untrusted input → private context → egress).
///
/// This is deliberately **monitor-only and byte-faithful**: it never
/// alters the streamed response. Truncating a half-emitted tool call
/// mid-stream is its own hard, risky problem; the value here is turning an
/// otherwise-invisible event ("the model just tried to exfiltrate right
/// after reading a web page") into an auditable signal. It is defence in
/// depth on the leg the input classifier cannot see.
///
/// Pure and channel-free (like `SSEStreamInspector`) so the streaming
/// tool-call accumulation — the error-prone part — is unit-testable
/// without a socket.
final class ResponseActionInspector {
    /// One dangerous outbound action observed in the response.
    struct Finding: Sendable, Equatable {
        let toolName: String
        /// Truncated copy of the tool-call arguments that matched.
        let argExcerpt: String
        let patternNames: [String]
        let categories: [String]
        /// True when the request that produced this response also carried
        /// untrusted content — the trifecta is complete and this is the
        /// high-confidence "injected action" case.
        let trifecta: Bool
        let severity: String
    }

    private let filter: InjectionFilter
    private var requestHadUntrusted: Bool

    private var buffer = ""
    /// Accumulating tool calls keyed by their stream index, per provider
    /// shape. Anthropic keys by `content_block` index; OpenAI by
    /// `tool_calls[].index`.
    private var anthropicTools: [Int: PendingCall] = [:]
    private var openAITools: [Int: PendingCall] = [:]

    private(set) var findings: [Finding] = []
    private var reportedUpTo = 0

    /// Findings appended since the last call — lets the relay report as the
    /// stream flows without re-reporting the whole list each chunk.
    func takeNewFindings() -> [Finding] {
        guard reportedUpTo < findings.count else { return [] }
        let new = Array(findings[reportedUpTo...])
        reportedUpTo = findings.count
        return new
    }

    private struct PendingCall {
        var name: String
        var args: String
    }

    /// Categories whose presence in a tool call's *arguments* means the
    /// model is about to take a dangerous outbound action. Keyed off the
    /// shipped, benchmarked pattern set rather than a parallel regex list
    /// so the two never drift.
    static let dangerousCategories: Set<String> = [
        "data-exfiltration", "credential-leak", "sandbox-escape",
    ]
    static let maxArgExcerpt = 2048
    static let maxBufferBytes = 1 * 1024 * 1024

    /// Cheap markers that a response stream carries tool calls at all. Until
    /// one appears we don't parse frames — a plain text answer pays almost
    /// nothing, mirroring the request-side `hasTrigger` gate.
    private static let toolMarkers = ["tool_use", "input_json_delta", "tool_calls", "function_call"]
    private var engaged = false

    init(filter: InjectionFilter, requestHadUntrusted: Bool) {
        self.filter = filter
        self.requestHadUntrusted = requestHadUntrusted
    }

    /// Reset for the next request on a keep-alive connection. HTTP/1.1
    /// serializes request/response, so finalizing here is safe: response N
    /// is fully streamed before request N+1 is sent.
    func beginRequest(requestHadUntrusted: Bool) {
        finalizePending()
        buffer.removeAll(keepingCapacity: true)
        anthropicTools.removeAll(keepingCapacity: true)
        openAITools.removeAll(keepingCapacity: true)
        engaged = false
        self.requestHadUntrusted = requestHadUntrusted
    }

    /// Observe a response chunk. Observe-only — returns nothing, never
    /// alters the stream. Best-effort: any parse failure is swallowed so a
    /// malformed frame can never affect forwarding.
    func ingest(_ chunk: String) {
        buffer += chunk

        if !engaged {
            if Self.toolMarkers.contains(where: { buffer.contains($0) }) {
                engaged = true
            } else {
                // No tool markers yet — almost certainly a plain text
                // answer. Keep only a small tail (a marker could straddle a
                // chunk boundary) so a long response doesn't grow the
                // buffer, and pay nothing more until one appears.
                if buffer.utf8.count > 65_536 {
                    buffer = String(buffer.suffix(1024))
                }
                return
            }
        }

        if buffer.utf8.count > Self.maxBufferBytes {
            // Runaway upstream: stop accumulating, keep any findings so far.
            buffer.removeAll(keepingCapacity: false)
            return
        }

        while let sep = buffer.range(of: "\n\n") ?? buffer.range(of: "\r\n\r\n") {
            let frame = String(buffer[..<sep.lowerBound])
            buffer.removeSubrange(buffer.startIndex..<sep.upperBound)
            processFrame(frame)
        }
    }

    /// Stream end — finalize any tool call still open (e.g. a provider that
    /// closes on `[DONE]` without an explicit stop event).
    func finish() {
        if !buffer.isEmpty {
            let tail = buffer
            buffer.removeAll()
            processFrame(tail)
        }
        finalizePending()
    }

    // MARK: - Frame parsing

    private func processFrame(_ frame: String) {
        for line in frame.split(separator: "\n", omittingEmptySubsequences: true) {
            guard line.hasPrefix("data:") else { continue }
            let payload = line.dropFirst(5).trimmingCharacters(in: .whitespaces)
            if payload.isEmpty || payload == "[DONE]" { continue }
            guard let data = payload.data(using: .utf8),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { continue }
            routeAnthropic(json)
            routeOpenAI(json)
        }
    }

    /// Anthropic Messages streaming: tool_use opens on `content_block_start`,
    /// its input arrives as `input_json_delta.partial_json` fragments, and
    /// it closes on `content_block_stop`.
    private func routeAnthropic(_ json: [String: Any]) {
        guard let type = json["type"] as? String else { return }
        switch type {
        case "content_block_start":
            guard let index = json["index"] as? Int,
                  let block = json["content_block"] as? [String: Any],
                  block["type"] as? String == "tool_use"
            else { return }
            let name = block["name"] as? String ?? ""
            anthropicTools[index] = PendingCall(name: name, args: "")
        case "content_block_delta":
            guard let index = json["index"] as? Int,
                  let delta = json["delta"] as? [String: Any],
                  delta["type"] as? String == "input_json_delta",
                  let partial = delta["partial_json"] as? String
            else { return }
            anthropicTools[index]?.args += partial
        case "content_block_stop":
            guard let index = json["index"] as? Int, let call = anthropicTools[index] else { return }
            anthropicTools[index] = nil
            evaluate(call)
        default:
            break
        }
    }

    /// OpenAI Chat Completions streaming: `choices[].delta.tool_calls[]`
    /// carries an index, a one-time `function.name`, and `function.arguments`
    /// fragments. Finalized on `finish_reason == "tool_calls"` (or at end).
    private func routeOpenAI(_ json: [String: Any]) {
        guard let choices = json["choices"] as? [[String: Any]], let first = choices.first else { return }

        if let delta = first["delta"] as? [String: Any],
           let toolCalls = delta["tool_calls"] as? [[String: Any]] {
            for tc in toolCalls {
                let index = tc["index"] as? Int ?? 0
                var call = openAITools[index] ?? PendingCall(name: "", args: "")
                if let fn = tc["function"] as? [String: Any] {
                    if let name = fn["name"] as? String, !name.isEmpty { call.name = name }
                    if let args = fn["arguments"] as? String { call.args += args }
                }
                openAITools[index] = call
            }
        }

        if first["finish_reason"] as? String == "tool_calls" {
            finalizeOpenAI()
        }
    }

    private func finalizeOpenAI() {
        let calls = openAITools.values
        openAITools.removeAll(keepingCapacity: true)
        for call in calls { evaluate(call) }
    }

    private func finalizePending() {
        let anthro = anthropicTools.values
        anthropicTools.removeAll(keepingCapacity: true)
        for call in anthro { evaluate(call) }
        finalizeOpenAI()
    }

    // MARK: - Evaluation

    /// Scan a completed tool call's arguments for a dangerous outbound
    /// action, reusing the shipped pattern set. A match in a
    /// `dangerousCategories` category is the action signal; the trifecta
    /// flag records whether untrusted input was also present.
    private func evaluate(_ call: PendingCall) {
        guard !call.args.isEmpty else { return }
        // Regex-only: this runs on the NIO event loop, and we key solely on
        // which dangerous category matched — paying for the ML tier here
        // (a synchronous CoreML call) would stall the loop for no benefit.
        let result = filter.scanRegexOnly(call.args)
        guard result.matchCount > 0 else { return }

        let hitCategories = Set(result.categories).intersection(Self.dangerousCategories)
        guard !hitCategories.isEmpty else { return }

        let excerpt = call.args.count > Self.maxArgExcerpt
            ? String(call.args.prefix(Self.maxArgExcerpt))
            : call.args

        findings.append(Finding(
            toolName: call.name,
            argExcerpt: excerpt,
            patternNames: result.patternNames,
            categories: Array(hitCategories).sorted(),
            trifecta: requestHadUntrusted,
            // A dangerous action that completes the trifecta is critical;
            // the same action with no untrusted input in the request is
            // suspicious but may be the operator's own instruction.
            severity: requestHadUntrusted ? "critical" : "medium"
        ))
    }
}
