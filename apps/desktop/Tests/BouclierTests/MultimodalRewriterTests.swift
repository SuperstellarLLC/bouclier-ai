import Foundation
import Testing
@testable import Bouclier

@Suite("MultimodalRewriter — strip flagged images")
struct MultimodalRewriterTests {
    private func base64Fixture(_ name: String, ext: String = "png") -> String {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures")
            ?? Bundle.module.url(forResource: name, withExtension: ext)
        else {
            Issue.record("Missing fixture \(name).\(ext)")
            return ""
        }
        let data = (try? Data(contentsOf: url)) ?? Data()
        return data.base64EncodedString()
    }

    @Test("OpenAI image_url with findings becomes a text placeholder")
    func openAIRewrite() async throws {
        let b64 = base64Fixture("image-with-iban")
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"text","text":"hello"},
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(b64)"}}
        ]}]}
        """
        let bodyData = Data(body.utf8)
        let report = await MultimodalPIIInspector.inspect(body: bodyData)
        let rewritten = MultimodalRewriter.stripFlaggedImages(from: bodyData, report: report)

        let parsed = try JSONSerialization.jsonObject(with: rewritten) as! [String: Any]
        let messages = parsed["messages"] as! [[String: Any]]
        let content = messages[0]["content"] as! [[String: Any]]
        // First block (text) unchanged.
        #expect(content[0]["type"] as? String == "text")
        #expect(content[0]["text"] as? String == "hello")
        // Second block (image) replaced.
        #expect(content[1]["type"] as? String == "text")
        let placeholder = content[1]["text"] as? String ?? ""
        #expect(placeholder.contains("Bouclier blocked"))
        #expect(placeholder.lowercased().contains("iban"))
    }

    @Test("Anthropic image source with findings becomes a text placeholder")
    func anthropicRewrite() async throws {
        let b64 = base64Fixture("image-with-card")
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"image","source":{"type":"base64","media_type":"image/png","data":"\(b64)"}}
        ]}]}
        """
        let bodyData = Data(body.utf8)
        let report = await MultimodalPIIInspector.inspect(body: bodyData)
        let rewritten = MultimodalRewriter.stripFlaggedImages(from: bodyData, report: report)

        let parsed = try JSONSerialization.jsonObject(with: rewritten) as! [String: Any]
        let messages = parsed["messages"] as! [[String: Any]]
        let content = messages[0]["content"] as! [[String: Any]]
        #expect(content[0]["type"] as? String == "text")
        #expect((content[0]["text"] as? String)?.contains("credit card") == true)
        // Original `source` field should be gone.
        #expect(content[0]["source"] == nil)
    }

    @Test("Clean text-only payloads pass through unchanged")
    func cleanPayloadUnchanged() async {
        let body = #"{"messages":[{"role":"user","content":"hello"}]}"#
        let bodyData = Data(body.utf8)
        let report = await MultimodalPIIInspector.inspect(body: bodyData)
        let rewritten = MultimodalRewriter.stripFlaggedImages(from: bodyData, report: report)
        #expect(rewritten == bodyData)
    }

    @Test("Clean image (no PII detected) passes through unchanged")
    func cleanImagePassesThrough() async {
        let b64 = base64Fixture("image-blank")
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(b64)"}}
        ]}]}
        """
        let bodyData = Data(body.utf8)
        let report = await MultimodalPIIInspector.inspect(body: bodyData)
        #expect(report.findings.isEmpty)
        let rewritten = MultimodalRewriter.stripFlaggedImages(from: bodyData, report: report)
        // Bytes may not match exactly due to JSONSerialization round-trip
        // when the rewriter does mutate, but we return the original
        // when findings are empty.
        #expect(rewritten == bodyData)
    }

    @Test("Multi-image prompts strip only flagged images, leaving clean ones in place")
    func selectiveStrip() async throws {
        let dirty = base64Fixture("image-with-iban")
        let clean = base64Fixture("image-blank")
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(dirty)"}},
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(clean)"}}
        ]}]}
        """
        let bodyData = Data(body.utf8)
        let report = await MultimodalPIIInspector.inspect(body: bodyData)
        let rewritten = MultimodalRewriter.stripFlaggedImages(from: bodyData, report: report)

        let parsed = try JSONSerialization.jsonObject(with: rewritten) as! [String: Any]
        let content = (parsed["messages"] as! [[String: Any]])[0]["content"] as! [[String: Any]]
        // First (dirty) became text.
        #expect(content[0]["type"] as? String == "text")
        // Second (clean) still has image_url.
        #expect(content[1]["type"] as? String == "image_url")
    }

    @Test("Top-level JSON array bodies are still rewritten (P1 fix)")
    func arrayRootRewrite() async throws {
        // Some batched-API shapes wrap their requests in a top-level
        // array. Before the P1 fix the rewriter early-returned on
        // non-dict roots and quietly let the unredacted bytes through.
        let b64 = base64Fixture("image-with-iban")
        let body = """
        [
          {"messages":[{"role":"user","content":[
            {"type":"image_url","image_url":{"url":"data:image/png;base64,\(b64)"}}
          ]}]}
        ]
        """
        let bodyData = Data(body.utf8)
        let report = await MultimodalPIIInspector.inspect(body: bodyData)
        #expect(!report.findings.isEmpty)
        let rewritten = MultimodalRewriter.stripFlaggedImages(from: bodyData, report: report)
        let parsed = try JSONSerialization.jsonObject(with: rewritten) as! [Any]
        let firstEnvelope = parsed[0] as! [String: Any]
        let content = ((firstEnvelope["messages"] as! [[String: Any]])[0]["content"] as! [[String: Any]])
        #expect(content[0]["type"] as? String == "text",
                "P1 fix: top-level array containing a multimodal payload must rewrite the image block")
        #expect((content[0]["text"] as? String)?.contains("Bouclier blocked") == true)
    }

    @Test("Byte-identical output when no findings (no JSON round-trip)")
    func noFindingsByteStable() async {
        // P1 invariant: the rewriter must not parse + re-serialise on
        // the no-findings path. JSONSerialization round-trips would
        // reorder dict keys and break Anthropic prompt-cache hits.
        let body = #"{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}]}"#
        let bodyData = Data(body.utf8)
        let empty = MultimodalPIIInspector.Report(
            imagesScanned: 0, findings: [], latencyMs: 0
        )
        let rewritten = MultimodalRewriter.stripFlaggedImages(from: bodyData, report: empty)
        #expect(rewritten == bodyData)
    }

    @Test("Face-only findings produce a face-count placeholder")
    func faceOnlyPlaceholder() async throws {
        // The blank image fixture won't trigger faces; we synthesize a
        // report manually here to exercise the rewriter without depending
        // on Vision's face detector being able to find faces in synthetic
        // pixels.
        let b64 = base64Fixture("image-with-iban")
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(b64)"}}
        ]}]}
        """
        let bodyData = Data(body.utf8)
        let synthReport = MultimodalPIIInspector.Report(
            imagesScanned: 1,
            findings: [
                MultimodalPIIInspector.Finding(
                    imagePath: [
                        .key("messages"), .index(0),
                        .key("content"), .index(0),
                        .key("image_url"), .key("url"),
                    ],
                    contentBlockPath: [
                        .key("messages"), .index(0),
                        .key("content"), .index(0),
                    ],
                    mediaType: "image/png",
                    provider: .openai,
                    category: .face(confidence: 0.9),
                    value: "face"
                ),
            ],
            latencyMs: 1
        )
        let rewritten = MultimodalRewriter.stripFlaggedImages(from: bodyData, report: synthReport)
        let parsed = try JSONSerialization.jsonObject(with: rewritten) as! [String: Any]
        let placeholder = ((parsed["messages"] as! [[String: Any]])[0]["content"] as! [[String: Any]])[0]["text"] as? String ?? ""
        #expect(placeholder.contains("face"))
    }
}
