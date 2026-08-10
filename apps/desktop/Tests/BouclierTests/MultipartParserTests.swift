import Foundation
import Testing
@testable import Bouclier

@Suite("MultipartParser — RFC 7578 minimal parser")
struct MultipartParserTests {
    private func body(boundary: String, parts: [(headers: [(String, String)], body: Data)]) -> Data {
        var out = Data()
        for part in parts {
            out.append(Data("--\(boundary)\r\n".utf8))
            for (n, v) in part.headers {
                out.append(Data("\(n): \(v)\r\n".utf8))
            }
            out.append(Data("\r\n".utf8))
            out.append(part.body)
            out.append(Data("\r\n".utf8))
        }
        out.append(Data("--\(boundary)--\r\n".utf8))
        return out
    }

    @Test("Extracts boundary from a Content-Type header")
    func parsesBoundary() {
        #expect(MultipartParser.boundary(from: "multipart/form-data; boundary=----WebKitFormBoundary") == "----WebKitFormBoundary")
        #expect(MultipartParser.boundary(from: #"multipart/form-data; boundary="abc 123""#) == "abc 123")
        #expect(MultipartParser.boundary(from: "application/json") == nil)
    }

    @Test("Parses a single text part")
    func singleTextPart() {
        let boundary = "----boundary123"
        let bytes = body(boundary: boundary, parts: [
            (headers: [("Content-Disposition", "form-data; name=\"purpose\"")],
             body: Data("assistants".utf8)),
        ])
        let parts = MultipartParser.parse(body: bytes, contentType: "multipart/form-data; boundary=\(boundary)")
        #expect(parts?.count == 1)
        #expect(parts?[0].name == "purpose")
        #expect(parts?[0].bodyData(in: bytes) == Data("assistants".utf8))
    }

    @Test("Parses a file upload with filename + content-type")
    func fileUploadPart() {
        let boundary = "abc"
        let payload = Data((0..<256).map { UInt8($0) })
        let bytes = body(boundary: boundary, parts: [
            (headers: [
                ("Content-Disposition", "form-data; name=\"file\"; filename=\"invoice.pdf\""),
                ("Content-Type", "application/pdf"),
            ], body: payload),
        ])
        let parts = MultipartParser.parse(body: bytes, contentType: "multipart/form-data; boundary=\(boundary)")
        #expect(parts?.count == 1)
        let p = parts![0]
        #expect(p.name == "file")
        #expect(p.filename == "invoice.pdf")
        #expect(p.contentType == "application/pdf")
        #expect(p.bodyData(in: bytes) == payload)
    }

    @Test("Parses multiple mixed parts (file + form fields)")
    func multipleParts() {
        let boundary = "xyz"
        let bytes = body(boundary: boundary, parts: [
            (headers: [("Content-Disposition", "form-data; name=\"purpose\"")],
             body: Data("assistants".utf8)),
            (headers: [
                ("Content-Disposition", "form-data; name=\"file\"; filename=\"a.txt\""),
                ("Content-Type", "text/plain"),
            ], body: Data("hello".utf8)),
            (headers: [("Content-Disposition", "form-data; name=\"label\"")],
             body: Data("training".utf8)),
        ])
        let parts = MultipartParser.parse(body: bytes, contentType: "multipart/form-data; boundary=\(boundary)")
        #expect(parts?.count == 3)
        #expect(parts?[0].name == "purpose")
        #expect(parts?[1].name == "file")
        #expect(parts?[1].filename == "a.txt")
        #expect(parts?[1].bodyData(in: bytes) == Data("hello".utf8))
        #expect(parts?[2].name == "label")
    }

    @Test("Returns nil for non-multipart Content-Type")
    func nonMultipart() {
        let parts = MultipartParser.parse(body: Data(), contentType: "application/json")
        #expect(parts == nil)
    }

    @Test("Returns nil when boundary is missing from a multipart Content-Type")
    func missingBoundary() {
        let parts = MultipartParser.parse(body: Data("nope".utf8), contentType: "multipart/form-data")
        #expect(parts == nil)
    }

    @Test("Boundary bytes embedded in a file payload don't corrupt the parse")
    func boundaryInsideFilePayload() {
        let boundary = "ab"  // intentionally short to maximise collision odds
        // File payload deliberately contains the literal boundary
        // string without a preceding CRLF anchor. The parser must
        // treat those bytes as payload, not as a delimiter.
        var payload = Data("hello world ".utf8)
        payload.append(Data("--ab".utf8))  // boundary bytes inside the file
        payload.append(Data(" more file bytes".utf8))
        var bytes = Data()
        bytes.append(Data("--\(boundary)\r\n".utf8))
        bytes.append(Data("Content-Disposition: form-data; name=\"file\"; filename=\"x.bin\"\r\n".utf8))
        bytes.append(Data("Content-Type: application/octet-stream\r\n\r\n".utf8))
        bytes.append(payload)
        bytes.append(Data("\r\n--\(boundary)--\r\n".utf8))
        let parts = MultipartParser.parse(body: bytes, contentType: "multipart/form-data; boundary=\(boundary)")
        #expect(parts?.count == 1)
        #expect(parts?[0].bodyData(in: bytes) == payload,
                "embedded boundary bytes without a CRLF anchor must not be treated as a delimiter")
    }

    @Test("Tolerates LF-only line endings (some curl invocations)")
    func lfOnlyLineEndings() {
        let boundary = "lfonly"
        var raw = Data()
        raw.append(Data("--\(boundary)\n".utf8))
        raw.append(Data("Content-Disposition: form-data; name=\"file\"; filename=\"x.bin\"\n".utf8))
        raw.append(Data("Content-Type: application/octet-stream\n".utf8))
        raw.append(Data("\n".utf8))
        raw.append(Data([0x01, 0x02, 0x03]))
        raw.append(Data("\n--\(boundary)--\n".utf8))
        let parts = MultipartParser.parse(body: raw, contentType: "multipart/form-data; boundary=\(boundary)")
        #expect(parts?.count == 1)
        #expect(parts?[0].filename == "x.bin")
        #expect(parts?[0].bodyData(in: raw) == Data([0x01, 0x02, 0x03]))
    }
}
