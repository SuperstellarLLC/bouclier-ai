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

    @Test("Encrypted PDFs get stripped with a clear placeholder message")
    func encryptedPDFStripped() async throws {
        guard let url = Bundle.module.url(forResource: "pdf-encrypted", withExtension: "pdf", subdirectory: "Fixtures")
            ?? Bundle.module.url(forResource: "pdf-encrypted", withExtension: "pdf"),
              let pdfData = try? Data(contentsOf: url)
        else {
            Issue.record("Missing pdf-encrypted fixture")
            return
        }
        let b64 = pdfData.base64EncodedString()
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"\(b64)"}}
        ]}]}
        """
        let bodyData = Data(body.utf8)
        let report = await MultimodalPIIInspector.inspect(body: bodyData)
        // Critical invariant: an unscannable PDF must surface a
        // finding so the rewriter strips it. An empty findings list
        // here would mean the encrypted PDF ships to the model
        // unchanged.
        #expect(!report.findings.isEmpty,
                "Encrypted PDF must produce a finding to trigger strip — not silently pass through")
        let rewritten = MultimodalRewriter.stripFlaggedImages(from: bodyData, report: report)
        let parsed = try JSONSerialization.jsonObject(with: rewritten) as! [String: Any]
        let content = ((parsed["messages"] as! [[String: Any]])[0]["content"] as! [[String: Any]])
        #expect(content[0]["type"] as? String == "text")
        let placeholder = content[0]["text"] as? String ?? ""
        #expect(placeholder.lowercased().contains("encrypted"))
        #expect(content[0]["source"] == nil)
    }

    @Test("Anthropic PDF document block gets stripped when text-layer PII is found")
    func anthropicPDFRewrite() async throws {
        guard let url = Bundle.module.url(forResource: "pdf-text-with-pii", withExtension: "pdf", subdirectory: "Fixtures")
            ?? Bundle.module.url(forResource: "pdf-text-with-pii", withExtension: "pdf"),
              let pdfData = try? Data(contentsOf: url)
        else {
            Issue.record("Missing pdf fixture")
            return
        }
        let b64 = pdfData.base64EncodedString()
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"text","text":"summarise this invoice"},
          {"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"\(b64)"}}
        ]}]}
        """
        let bodyData = Data(body.utf8)
        let report = await MultimodalPIIInspector.inspect(body: bodyData)
        #expect(!report.findings.isEmpty)
        let rewritten = MultimodalRewriter.stripFlaggedImages(from: bodyData, report: report)

        let parsed = try JSONSerialization.jsonObject(with: rewritten) as! [String: Any]
        let content = ((parsed["messages"] as! [[String: Any]])[0]["content"] as! [[String: Any]])
        // First block (text) unchanged.
        #expect(content[0]["type"] as? String == "text")
        // Second block (PDF) replaced — placeholder text mentions PDF.
        #expect(content[1]["type"] as? String == "text")
        let placeholder = content[1]["text"] as? String ?? ""
        #expect(placeholder.contains("PDF"))
        #expect(placeholder.contains("Bouclier blocked"))
        // Original `source` field should be gone.
        #expect(content[1]["source"] == nil)
    }

    @Test("Top-level JSON array bodies are still rewritten")
    func arrayRootRewrite() async throws {
        // Some batched-API shapes wrap their requests in a top-level
        // array. The rewriter must walk those too — early-returning
        // on non-dict roots would let unredacted bytes through.
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
                "a top-level array wrapping a multimodal payload must still rewrite the image block")
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
            imagesScanned: 0, pdfsScanned: 0, audioScanned: 0, findings: [], latencyMs: 0
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
            pdfsScanned: 0,
            audioScanned: 0,
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
                    cleartextValue: "face"
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
