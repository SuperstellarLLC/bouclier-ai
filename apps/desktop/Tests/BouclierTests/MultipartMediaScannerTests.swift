import Foundation
import Testing
@testable import Bouclier

@Suite("MultipartMediaScanner — end-to-end Files-API style uploads")
struct MultipartMediaScannerTests {
    private let boundary = "----BoundaryBouclierTest"

    private func fixture(_ name: String, ext: String) -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures")
            ?? Bundle.module.url(forResource: name, withExtension: ext)
        else {
            Issue.record("Missing fixture \(name).\(ext)")
            return Data()
        }
        return (try? Data(contentsOf: url)) ?? Data()
    }

    /// Build a multipart body that mirrors OpenAI's `/v1/files` upload
    /// shape: a `purpose` text part + a single `file` part with the
    /// given bytes and content-type.
    private func openAIFilesBody(filename: String, contentType: String, bytes: Data, purpose: String = "assistants") -> Data {
        var out = Data()
        out.append(Data("--\(boundary)\r\n".utf8))
        out.append(Data("Content-Disposition: form-data; name=\"purpose\"\r\n\r\n\(purpose)\r\n".utf8))
        out.append(Data("--\(boundary)\r\n".utf8))
        out.append(Data("Content-Disposition: form-data; name=\"file\"; filename=\"\(filename)\"\r\n".utf8))
        out.append(Data("Content-Type: \(contentType)\r\n\r\n".utf8))
        out.append(bytes)
        out.append(Data("\r\n--\(boundary)--\r\n".utf8))
        return out
    }

    private var fullContentType: String { "multipart/form-data; boundary=\(boundary)" }

    @Test("Image upload with PII gets stripped and replaced with text placeholder")
    func imageUploadStripped() async throws {
        let img = fixture("image-with-iban", ext: "png")
        let body = openAIFilesBody(filename: "id-scan.png", contentType: "image/png", bytes: img)
        let result = await MultipartMediaScanner.inspect(body: body, contentType: fullContentType)
        #expect(result != nil)
        #expect(result?.report.imagesScanned == 1)
        #expect(result?.report.findings.isEmpty == false)
        // The rewritten body parses back to a multipart with the same
        // two part names but the file part is now text/plain.
        let rewrittenParts = MultipartParser.parse(body: result!.body, contentType: fullContentType)
        #expect(rewrittenParts?.count == 2)
        let filePart = rewrittenParts?.first { $0.name == "file" }
        #expect(filePart?.contentType.hasPrefix("text/plain") == true)
        let placeholder = String(data: filePart!.bodyData(in: result!.body), encoding: .utf8) ?? ""
        #expect(placeholder.contains("Bouclier blocked"))
    }

    @Test("PDF upload with PII gets stripped")
    func pdfUploadStripped() async throws {
        let pdf = fixture("pdf-text-with-pii", ext: "pdf")
        let body = openAIFilesBody(filename: "invoice.pdf", contentType: "application/pdf", bytes: pdf)
        let result = await MultipartMediaScanner.inspect(body: body, contentType: fullContentType)
        #expect(result?.report.pdfsScanned == 1)
        #expect(result?.report.findings.isEmpty == false)
        let rewrittenParts = MultipartParser.parse(body: result!.body, contentType: fullContentType)
        let filePart = rewrittenParts?.first { $0.name == "file" }
        #expect(filePart?.contentType.hasPrefix("text/plain") == true)
    }

    @Test("Clean image upload passes through byte-identical")
    func cleanImagePassesThrough() async throws {
        let img = fixture("image-blank", ext: "png")
        let body = openAIFilesBody(filename: "blank.png", contentType: "image/png", bytes: img)
        let result = await MultipartMediaScanner.inspect(body: body, contentType: fullContentType)
        #expect(result?.report.findings.isEmpty == true)
        #expect(result?.body == body,
                "Clean multipart payload must be byte-stable so upstream Files API content-hash signatures stay valid")
    }

    @Test("Non-file parts pass through unchanged when file parts have findings")
    func nonFilePartsPreserved() async throws {
        let img = fixture("image-with-iban", ext: "png")
        let body = openAIFilesBody(filename: "id.png", contentType: "image/png", bytes: img, purpose: "fine-tune")
        let result = await MultipartMediaScanner.inspect(body: body, contentType: fullContentType)
        let rewrittenParts = MultipartParser.parse(body: result!.body, contentType: fullContentType)
        let purposePart = rewrittenParts?.first { $0.name == "purpose" }
        let purposeBytes = purposePart?.bodyData(in: result!.body) ?? Data()
        #expect(String(data: purposeBytes, encoding: .utf8) == "fine-tune")
    }

    @Test("Non-multipart Content-Type returns nil so the caller can fall back")
    func nonMultipartReturnsNil() async {
        let result = await MultipartMediaScanner.inspect(
            body: Data("hello".utf8),
            contentType: "application/json"
        )
        #expect(result == nil)
    }

    @Test("application/octet-stream PDF gets sniffed and stripped (P0 fix)")
    func octetStreamSniffsAsPDF() async throws {
        // curl -F file=@invoice.pdf without --mime-type sends
        // Content-Type: application/octet-stream. Before the P0 fix
        // this would silently bypass the inspector.
        let pdf = fixture("pdf-text-with-pii", ext: "pdf")
        let body = openAIFilesBody(filename: "invoice.pdf", contentType: "application/octet-stream", bytes: pdf)
        let result = await MultipartMediaScanner.inspect(body: body, contentType: fullContentType)
        #expect(result?.report.pdfsScanned == 1)
        #expect(result?.report.findings.isEmpty == false)
    }

    @Test("application/octet-stream image gets sniffed and stripped")
    func octetStreamSniffsAsImage() async throws {
        let img = fixture("image-with-iban", ext: "png")
        let body = openAIFilesBody(filename: "scan.png", contentType: "application/octet-stream", bytes: img)
        let result = await MultipartMediaScanner.inspect(body: body, contentType: fullContentType)
        #expect(result?.report.imagesScanned == 1)
        #expect(result?.report.findings.isEmpty == false)
    }

    @Test("Header injection via attacker-controlled name is neutralised (P0 fix)")
    func headerInjectionNeutralised() async throws {
        let img = fixture("image-with-iban", ext: "png")
        // Craft a body whose Content-Disposition name carries CRLF +
        // injected header. Before the P0 fix the rewriter re-emitted
        // this verbatim, smuggling fake headers into the upstream.
        var body = Data()
        body.append(Data("--\(boundary)\r\n".utf8))
        body.append(Data("Content-Disposition: form-data; name=\"file\\\"\r\nX-Injected: bad\"; filename=\"a.png\"\r\n".utf8))
        body.append(Data("Content-Type: image/png\r\n\r\n".utf8))
        body.append(img)
        body.append(Data("\r\n--\(boundary)--\r\n".utf8))
        let result = await MultipartMediaScanner.inspect(body: body, contentType: fullContentType)
        let rewritten = result?.body ?? Data()
        let str = String(data: rewritten, encoding: .utf8) ?? ""
        // The injected header MUST NOT survive into the output.
        #expect(!str.contains("X-Injected"),
                "P0 fix: smuggled header MUST be stripped before re-emission")
    }

    // NOTE: Audio-upload multipart routing isn't exercised here
    // because the production AudioPIIScanner.shared can't be injected
    // and SFSpeechRecognizer's authorisation prompt + temp-file I/O
    // crashes the test runner with SIGABRT in `swift test`. The audio
    // path is unit-tested exhaustively in AudioPIIScannerTests via
    // the injectable transcriber, and the multipart routing into it
    // is structurally identical to the image/PDF routing covered
    // above. End-to-end audio coverage lives in the
    // `test:integration` target run on a developer Mac with Speech
    // authorisation granted.
}
