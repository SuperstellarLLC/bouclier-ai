import Foundation
import NIOCore
import NIOHTTP1
import Testing
@testable import Bouclier

/// End-to-end orchestrator tests covering the seam where
/// `HTTPRequestInspector.applyMultimodalInspection` runs the full
/// extract → inspect → rewrite pipeline against a real request body.
///
/// Component-level unit tests cover each stage in isolation; these
/// tests catch integration drift — e.g. a misplaced
/// `bodyScanSkipped` gate that disables the whole pass without any
/// component-level test failing.
@Suite("Multimodal integration — applyMultimodalInspection through the proxy seam", .serialized)
struct MultimodalIntegrationTests {
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

    private func fixture(_ name: String, ext: String) -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures")
            ?? Bundle.module.url(forResource: name, withExtension: ext)
        else { return Data() }
        return (try? Data(contentsOf: url)) ?? Data()
    }

    // Per-key override + defer-per-key clear so parallel suites that
    // call `FeatureFlags.clearTestOverrides()` (e.g. FeatureFlagsTests)
    // don't race with our flag state. Using clearTestOverrides() in
    // our own defer would wipe other suites' overrides too.
    private func enableMultimodal() {
        FeatureFlags.setTestOverride("multimodalInspection", true)
    }
    private func disableMultimodal() {
        FeatureFlags.setTestOverride("multimodalInspection", nil)
    }

    @Test("JSON body with a base64 image containing OCR'd PII gets rewritten")
    func jsonImageEndToEnd() async {
        enableMultimodal()
        defer { disableMultimodal() }

        let b64 = base64Fixture("image-with-iban")
        let bodyStr = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(b64)"}}
        ]}]}
        """
        let allocator = ByteBufferAllocator()
        var buf = allocator.buffer(capacity: bodyStr.utf8.count)
        buf.writeString(bodyStr)
        let pass = await HTTPRequestInspector.applyMultimodalInspection(
            body: buf,
            contentType: "application/json",
            method: .POST,
            allocator: allocator
        )
        #expect(pass.report.findings.isEmpty == false,
                "Integration: JSON-shaped image with PII must produce findings through the orchestrator")
        let outStr = pass.body.getString(at: pass.body.readerIndex, length: pass.body.readableBytes) ?? ""
        #expect(outStr.contains("Bouclier blocked"),
                "Integration: the rewritten body must carry the placeholder text")
    }

    @Test("Multipart body with a flagged file part gets rewritten")
    func multipartFileEndToEnd() async {
        enableMultimodal()
        defer { disableMultimodal() }

        let boundary = "----BoundaryIntegration"
        let pdf = fixture("pdf-text-with-pii", ext: "pdf")
        var body = Data()
        body.append(Data("--\(boundary)\r\n".utf8))
        body.append(Data("Content-Disposition: form-data; name=\"purpose\"\r\n\r\nassistants\r\n".utf8))
        body.append(Data("--\(boundary)\r\n".utf8))
        body.append(Data("Content-Disposition: form-data; name=\"file\"; filename=\"invoice.pdf\"\r\n".utf8))
        body.append(Data("Content-Type: application/pdf\r\n\r\n".utf8))
        body.append(pdf)
        body.append(Data("\r\n--\(boundary)--\r\n".utf8))

        let allocator = ByteBufferAllocator()
        var buf = allocator.buffer(capacity: body.count)
        buf.writeBytes(body)
        let pass = await HTTPRequestInspector.applyMultimodalInspection(
            body: buf,
            contentType: "multipart/form-data; boundary=\(boundary)",
            method: .POST,
            allocator: allocator
        )
        // Regression cover: a `shouldScanBody` gate that refuses
        // multipart bodies would make applyMultimodalInspection
        // return an empty pass and leak attachments unchanged.
        #expect(pass.report.pdfsScanned == 1,
                "multipart Files-API uploads must reach the multipart scanner")
        #expect(!pass.report.findings.isEmpty,
                "Integration: a flagged PDF in a Files-API upload must produce findings")
        // Verify the body bytes were actually rewritten — the file
        // part should now be text/plain.
        let rewrittenParts = MultipartParser.parse(
            body: Data(pass.body.readableBytesView),
            contentType: "multipart/form-data; boundary=\(boundary)"
        )
        let filePart = rewrittenParts?.first(where: { $0.name == "file" })
        #expect(filePart?.contentType.hasPrefix("text/plain") == true)
    }

    @Test("Feature flag off → multimodal pass is a no-op even for a flagged body")
    func featureFlagGate() async {
        // Explicitly force the flag OFF (rather than relying on the
        // compile-time default) so a parallel suite that set it true
        // and hasn't yet cleared can't race us. Defer-clear restores
        // the no-override state.
        FeatureFlags.setTestOverride("multimodalInspection", false)
        defer { FeatureFlags.setTestOverride("multimodalInspection", nil) }
        let b64 = base64Fixture("image-with-iban")
        let bodyStr = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(b64)"}}
        ]}]}
        """
        let allocator = ByteBufferAllocator()
        var buf = allocator.buffer(capacity: bodyStr.utf8.count)
        buf.writeString(bodyStr)
        let pass = await HTTPRequestInspector.applyMultimodalInspection(
            body: buf,
            contentType: "application/json",
            method: .POST,
            allocator: allocator
        )
        #expect(pass.report.findings.isEmpty,
                "With the flag off, multimodal inspection must be a no-op — no findings, no rewrite")
        #expect(pass.body.readableBytes == bodyStr.utf8.count)
    }

    @Test("Clean JSON body is byte-stable through the orchestrator")
    func cleanByteStable() async {
        enableMultimodal()
        defer { disableMultimodal() }

        let b64 = base64Fixture("image-blank")
        let bodyStr = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(b64)"}}
        ]}]}
        """
        let allocator = ByteBufferAllocator()
        var buf = allocator.buffer(capacity: bodyStr.utf8.count)
        buf.writeString(bodyStr)
        let pass = await HTTPRequestInspector.applyMultimodalInspection(
            body: buf,
            contentType: "application/json",
            method: .POST,
            allocator: allocator
        )
        // No findings on a blank image → original ByteBuffer reference
        // returned (zero-copy on the COW-safe path).
        #expect(pass.report.findings.isEmpty)
        let outStr = pass.body.getString(at: pass.body.readerIndex, length: pass.body.readableBytes) ?? ""
        #expect(outStr == bodyStr,
                "Clean payload must be byte-stable through the orchestrator")
    }

    @Test("Pause short-circuits multimodal inspection")
    func pauseShortCircuits() async {
        enableMultimodal()
        defer { disableMultimodal() }
        RedactionPause.pause(for: 60)
        defer { RedactionPause.resume() }

        let b64 = base64Fixture("image-with-iban")
        let bodyStr = """
        {"messages":[{"role":"user","content":[
          {"type":"image_url","image_url":{"url":"data:image/png;base64,\(b64)"}}
        ]}]}
        """
        let allocator = ByteBufferAllocator()
        var buf = allocator.buffer(capacity: bodyStr.utf8.count)
        buf.writeString(bodyStr)
        let pass = await HTTPRequestInspector.applyMultimodalInspection(
            body: buf,
            contentType: "application/json",
            method: .POST,
            allocator: allocator
        )
        // Pause short-circuits FeatureFlags.multimodalInspection, so
        // the scanner never runs and the body stays untouched.
        #expect(pass.report.findings.isEmpty,
                "Pause short-circuit: paused multimodal inspection must not produce findings")
    }
}
