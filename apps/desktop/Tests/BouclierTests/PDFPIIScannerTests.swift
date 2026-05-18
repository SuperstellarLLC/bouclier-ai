import Foundation
import Testing
@testable import Bouclier

@Suite("PDFPIIScanner — text-layer + scanned-page OCR fallback")
struct PDFPIIScannerTests {
    private func fixture(_ name: String, ext: String = "pdf") -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures")
            ?? Bundle.module.url(forResource: name, withExtension: ext)
        else {
            Issue.record("Missing fixture \(name).\(ext) — run scripts/generate-test-fixtures.py")
            return Data()
        }
        return (try? Data(contentsOf: url)) ?? Data()
    }

    @Test("Detects PII via the PDF text layer without OCR")
    func textLayerPath() async throws {
        let data = fixture("pdf-text-with-pii")
        let result = try await PDFPIIScanner.shared.scan(pdfData: data)
        let types = Set(result.piiDetections.map { $0.type })
        #expect(types.contains("EMAIL"))
        #expect(types.contains("IBAN"))
        // The fixture's pages all have a text layer — OCR shouldn't run.
        #expect(result.pagesOCRd == 0)
        #expect(result.pageCount > 0)
    }

    @Test("Detects PII in a scanned PDF via per-page Vision OCR")
    func scannedFallback() async throws {
        let data = fixture("pdf-scanned-with-pii")
        let result = try await PDFPIIScanner.shared.scan(pdfData: data)
        let types = Set(result.piiDetections.map { $0.type })
        // The page has an embedded raster — text layer is empty so
        // OCR is the only way to surface the PII.
        #expect(types.contains("EMAIL") || types.contains("CREDIT_CARD"))
        #expect(result.pagesOCRd > 0)
    }

    @Test("Clean text PDFs surface zero PII")
    func cleanPDFEmpty() async throws {
        let data = fixture("pdf-text-clean")
        let result = try await PDFPIIScanner.shared.scan(pdfData: data)
        #expect(result.piiDetections.isEmpty)
    }

    @Test("Non-PDF bytes return an empty result, not an error")
    func nonPDFIsNoop() async throws {
        let bogus = Data("not a pdf".utf8)
        let result = try await PDFPIIScanner.shared.scan(pdfData: bogus)
        #expect(result.piiDetections.isEmpty)
        #expect(result.pageCount == 0)
    }

    @Test("Empty input returns empty without crashing")
    func emptyIsNoop() async throws {
        let result = try await PDFPIIScanner.shared.scan(pdfData: Data())
        #expect(result.piiDetections.isEmpty)
        #expect(result.unscannable == .malformed)
    }

    @Test("Encrypted PDFs surface as unscannable instead of silently passing through")
    func encryptedPDFIsUnscannable() async throws {
        let data = fixture("pdf-encrypted")
        let result = try await PDFPIIScanner.shared.scan(pdfData: data)
        // No text extracted (we never unlocked) — but the result MUST
        // carry an `unscannable` reason so the rewriter strips the
        // document rather than forwarding it.
        #expect(result.unscannable == .encrypted)
        #expect(result.piiDetections.isEmpty)
        // Page count is still > 0 because PDFKit can parse the metadata
        // even on locked documents.
        #expect(result.pageCount > 0)
    }

    @Test("Non-PDF bytes are unscannable.malformed")
    func nonPDFIsMalformed() async throws {
        let result = try await PDFPIIScanner.shared.scan(pdfData: Data("not a pdf".utf8))
        #expect(result.unscannable == .malformed)
    }
}
