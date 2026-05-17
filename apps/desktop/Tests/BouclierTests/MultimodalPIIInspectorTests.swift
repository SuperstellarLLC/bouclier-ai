import Foundation
import Testing
@testable import Bouclier

@Suite("MultimodalPIIInspector — extractor + Vision pipeline integration")
struct MultimodalPIIInspectorTests {
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

    @Test("Text-only payloads yield an empty report")
    func textOnly() async {
        let body = #"{"messages":[{"role":"user","content":"hello"}]}"#
        let report = await MultimodalPIIInspector.inspect(body: Data(body.utf8))
        #expect(report.imagesScanned == 0)
        #expect(report.findings.isEmpty)
    }

    @Test("OpenAI image_url with an IBAN gets flagged")
    func openAIImageWithIBAN() async {
        let b64 = base64Fixture("image-with-iban")
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(b64)"}}
        ]}]}
        """
        let report = await MultimodalPIIInspector.inspect(body: Data(body.utf8))
        #expect(report.imagesScanned == 1)
        #expect(report.findings.contains(where: {
            if case .textPII(let type) = $0.category { return type == "IBAN" }
            return false
        }))
        // Path should round-trip to the image_url.url leaf.
        let expected: [MultimodalImageExtractor.Image.PathComponent] = [
            .key("messages"), .index(0), .key("content"), .index(0),
            .key("image_url"), .key("url"),
        ]
        #expect(report.findings.first?.imagePath == expected)
    }

    @Test("Anthropic base64 source with a credit card gets flagged")
    func anthropicWithCard() async {
        let b64 = base64Fixture("image-with-card")
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"image","source":{"type":"base64","media_type":"image/png","data":"\(b64)"}}
        ]}]}
        """
        let report = await MultimodalPIIInspector.inspect(body: Data(body.utf8))
        #expect(report.findings.contains(where: {
            if case .textPII(let type) = $0.category { return type == "CREDIT_CARD" }
            return false
        }))
    }

    @Test("Multiple images in one prompt run concurrently and combine findings")
    func multipleImagesScanInParallel() async {
        let iban = base64Fixture("image-with-iban")
        let card = base64Fixture("image-with-card")
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(iban)"}},
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(card)"}}
        ]}]}
        """
        let report = await MultimodalPIIInspector.inspect(body: Data(body.utf8))
        #expect(report.imagesScanned == 2)
        let types = Set(report.findings.compactMap { f -> String? in
            if case .textPII(let t) = f.category { return t }
            return nil
        })
        #expect(types.contains("IBAN"))
        #expect(types.contains("CREDIT_CARD"))
    }

    @Test("Refuses to scan obvious fan-out (>maxImagesPerRequest)")
    func refusesObviousFanout() async {
        let b64 = base64Fixture("image-blank")
        // 21 images, one above the cap. Body still well-formed.
        let items = (0..<(MultimodalPIIInspector.maxImagesPerRequest + 1)).map { _ in
            #"{"type":"image_url","image_url":{"url":"data:image/png;base64,\#(b64)"}}"#
        }.joined(separator: ",")
        let body = #"{"messages":[{"role":"user","content":[\#(items)]}]}"#
        let report = await MultimodalPIIInspector.inspect(body: Data(body.utf8))
        // Inspector refuses to spend Vision time — passes through
        // with zero findings rather than OOMing the host.
        #expect(report.findings.isEmpty)
        #expect(report.imagesScanned == 0)
    }

    @Test("Corrupted base64 data is skipped, not propagated as an error")
    func corruptedBase64() async {
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,this is not real base64=="}}
        ]}]}
        """
        let report = await MultimodalPIIInspector.inspect(body: Data(body.utf8))
        // Either zero images extracted (bad base64 → decoder refuses)
        // or one image with empty findings. Either way: no crash, no
        // findings.
        #expect(report.findings.isEmpty)
    }
}
