import Foundation
import Testing
@testable import Bouclier

@Suite("MultimodalImageExtractor — base64 image surface")
struct MultimodalImageExtractorTests {
    /// Smallest valid PNG — 1x1 transparent pixel. Generated once,
    /// reused across tests so the assertions stay readable.
    static let onePixelPNGBase64 =
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="

    @Test("Extracts an OpenAI image_url data URL")
    func openAIImageURL() {
        let body = """
        {
          "model": "gpt-4o",
          "messages": [
            {
              "role": "user",
              "content": [
                {"type": "text", "text": "What's in this image?"},
                {"type": "image_url",
                 "image_url": {"url": "data:image/png;base64,\(Self.onePixelPNGBase64)"}}
              ]
            }
          ]
        }
        """
        let images = MultimodalImageExtractor.extract(from: Data(body.utf8))
        #expect(images.count == 1)
        #expect(images.first?.provider == .openai)
        #expect(images.first?.mediaType == "image/png")
        #expect((images.first?.data.count ?? 0) > 0)
    }

    @Test("Extracts an Anthropic base64 source")
    func anthropicSource() {
        let body = """
        {
          "model": "claude-opus-4-7",
          "messages": [
            {
              "role": "user",
              "content": [
                {"type": "text", "text": "describe"},
                {"type": "image",
                 "source": {"type": "base64",
                            "media_type": "image/png",
                            "data": "\(Self.onePixelPNGBase64)"}}
              ]
            }
          ]
        }
        """
        let images = MultimodalImageExtractor.extract(from: Data(body.utf8))
        #expect(images.count == 1)
        #expect(images.first?.provider == .anthropic)
        #expect(images.first?.mediaType == "image/png")
    }

    @Test("Extracts a Gemini inlineData payload")
    func geminiInlineData() {
        let body = """
        {
          "contents": [
            {"parts": [
                {"text": "what's this"},
                {"inlineData": {"mimeType": "image/png", "data": "\(Self.onePixelPNGBase64)"}}
            ]}
          ]
        }
        """
        let images = MultimodalImageExtractor.extract(from: Data(body.utf8))
        #expect(images.count == 1)
        #expect(images.first?.provider == .gemini)
    }

    @Test("Tolerates Gemini snake_case variant")
    func geminiSnakeCase() {
        let body = """
        {"contents":[{"parts":[{"inline_data":{"mime_type":"image/jpeg","data":"\(Self.onePixelPNGBase64)"}}]}]}
        """
        let images = MultimodalImageExtractor.extract(from: Data(body.utf8))
        #expect(images.first?.provider == .gemini)
        #expect(images.first?.mediaType == "image/jpeg")
    }

    @Test("Returns multiple images from a single multimodal prompt")
    func multipleImages() {
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(Self.onePixelPNGBase64)"}},
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(Self.onePixelPNGBase64)"}}
        ]}]}
        """
        let images = MultimodalImageExtractor.extract(from: Data(body.utf8))
        #expect(images.count == 2)
    }

    @Test("Returns empty for text-only payloads")
    func textOnly() {
        let body = """
        {"messages":[{"role":"user","content":"hello"}]}
        """
        let images = MultimodalImageExtractor.extract(from: Data(body.utf8))
        #expect(images.isEmpty)
    }

    @Test("Returns empty for malformed JSON")
    func malformedJSON() {
        let images = MultimodalImageExtractor.extract(from: Data("not json".utf8))
        #expect(images.isEmpty)
    }

    @Test("Rejects images larger than the configured cap")
    func rejectsHugePayload() {
        // Build a base64 string that decodes to maxBytesPerImage + 1
        // bytes. Decoded size = ceil(b64.length * 3 / 4).
        let oversized = String(
            repeating: "A",
            count: (MultimodalImageExtractor.maxBytesPerImage / 3 + 8) * 4 / 3 + 4
        )
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(oversized)"}}
        ]}]}
        """
        let images = MultimodalImageExtractor.extract(from: Data(body.utf8))
        #expect(images.isEmpty)
    }

    @Test("Rejects a data URL without base64 marker")
    func rejectsNonBase64DataURL() {
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png,plain-text"}}
        ]}]}
        """
        let images = MultimodalImageExtractor.extract(from: Data(body.utf8))
        #expect(images.isEmpty)
    }

    @Test("Records a JSON path that round-trips to the source field")
    func pathRoundTrips() {
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(Self.onePixelPNGBase64)"}}
        ]}]}
        """
        let image = MultimodalImageExtractor.extract(from: Data(body.utf8)).first
        #expect(image != nil)
        // Path should be: messages[0].content[0].image_url.url
        let expected: [MultimodalImageExtractor.Image.PathComponent] = [
            .key("messages"), .index(0),
            .key("content"), .index(0),
            .key("image_url"), .key("url"),
        ]
        #expect(image?.path == expected)
    }
}
