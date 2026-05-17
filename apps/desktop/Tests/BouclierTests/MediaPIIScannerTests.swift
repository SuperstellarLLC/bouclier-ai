import Foundation
import Testing
@testable import Bouclier

@Suite("MediaPIIScanner — Vision OCR + face detection")
struct MediaPIIScannerTests {
    /// Load a bundled test fixture by name. Throws Issue.record-style
    /// reporting if missing so the failure message is actionable.
    private func fixture(_ name: String, ext: String = "png") -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures")
            ?? Bundle.module.url(forResource: name, withExtension: ext)
        else {
            Issue.record("Missing fixture \(name).\(ext) — run scripts/generate-test-fixtures.py")
            return Data()
        }
        return (try? Data(contentsOf: url)) ?? Data()
    }

    @Test("Detects an email rendered into a PNG via on-device OCR")
    func detectsEmailInPNG() async throws {
        let data = fixture("image-with-email")
        let result = try await MediaPIIScanner.shared.scan(imageData: data)
        #expect(result.ocrText.lowercased().contains("jane"))
        #expect(result.piiDetections.contains(where: { $0.type == "EMAIL" }))
        #expect(result.latencyMs > 0)
    }

    @Test("Detects an IBAN rendered into a PNG")
    func detectsIBANInPNG() async throws {
        let data = fixture("image-with-iban")
        let result = try await MediaPIIScanner.shared.scan(imageData: data)
        #expect(result.piiDetections.contains(where: { $0.type == "IBAN" }))
    }

    @Test("Detects a credit card number rendered into a PNG")
    func detectsCardInPNG() async throws {
        let data = fixture("image-with-card")
        let result = try await MediaPIIScanner.shared.scan(imageData: data)
        #expect(result.piiDetections.contains(where: { $0.type == "CREDIT_CARD" }))
    }

    @Test("Decodes JPEG payloads via CGImageSource")
    func decodesJPEG() async throws {
        let data = fixture("image-with-email", ext: "jpg")
        let result = try await MediaPIIScanner.shared.scan(imageData: data)
        #expect(result.piiDetections.contains(where: { $0.type == "EMAIL" }))
    }

    @Test("Empty input returns zero detections without throwing")
    func emptyInputIsNoop() async throws {
        let result = try await MediaPIIScanner.shared.scan(imageData: Data())
        #expect(result.piiDetections.isEmpty)
        #expect(result.faces.isEmpty)
        #expect(result.ocrText.isEmpty)
    }

    @Test("Blank image surfaces no PII and no faces")
    func blankImageNoise() async throws {
        let data = fixture("image-blank")
        let result = try await MediaPIIScanner.shared.scan(imageData: data)
        #expect(result.piiDetections.isEmpty)
        #expect(result.faces.isEmpty)
    }
}
