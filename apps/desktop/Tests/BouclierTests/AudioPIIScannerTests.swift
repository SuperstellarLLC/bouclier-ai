import Foundation
import Testing
@testable import Bouclier

@Suite("AudioPIIScanner — SFSpeechRecognizer wrapper + extractor routing")
struct AudioPIIScannerTests {
    private func fixture(_ name: String, ext: String = "m4a") -> Data {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures")
            ?? Bundle.module.url(forResource: name, withExtension: ext)
        else {
            Issue.record("Missing fixture \(name).\(ext)")
            return Data()
        }
        return (try? Data(contentsOf: url)) ?? Data()
    }

    /// Returns a scanner whose transcriber returns the given canned
    /// string regardless of the input file. Lets the test suite
    /// exercise the full PII-routing pipeline without depending on
    /// the Speech-framework recogniser, which isn't reliably
    /// authorised in headless test environments.
    private func scannerWithCannedTranscript(_ transcript: String) -> AudioPIIScanner {
        AudioPIIScanner(transcribe: { _ in transcript })
    }

    @Test("Routes transcript through PIIScanner and surfaces detections")
    func transcriptDrivesPIIDetection() async throws {
        let scanner = scannerWithCannedTranscript(
            "My email is jane.doe@example.com please use it for invoicing"
        )
        let result = try await scanner.scan(
            audioData: fixture("audio-with-email"),
            mediaType: "audio/mp4"
        )
        let types = Set(result.piiDetections.map { $0.type })
        #expect(types.contains("EMAIL"))
        #expect(result.unscannable == nil)
        #expect(result.durationSeconds > 0)
    }

    @Test("Clean transcript surfaces no findings")
    func cleanTranscript() async throws {
        let scanner = scannerWithCannedTranscript("the weather today is partly cloudy")
        let result = try await scanner.scan(
            audioData: fixture("audio-clean"),
            mediaType: "audio/mp4"
        )
        #expect(result.piiDetections.isEmpty)
        #expect(result.unscannable == nil)
    }

    @Test("Empty audio bytes surface as unscannable.malformed")
    func emptyIsMalformed() async throws {
        let scanner = scannerWithCannedTranscript("")
        let result = try await scanner.scan(audioData: Data(), mediaType: "audio/mp4")
        #expect(result.unscannable == .malformed)
        #expect(result.piiDetections.isEmpty)
    }

    @Test("Transcriber failure maps to recogniserUnavailable, never silent pass")
    func transcriberFailureIsUnscannable() async throws {
        struct Boom: Error {}
        let scanner = AudioPIIScanner(transcribe: { _ in throw Boom() })
        let result = try await scanner.scan(
            audioData: fixture("audio-with-email"),
            mediaType: "audio/mp4"
        )
        #expect(result.unscannable == .recogniserUnavailable)
        #expect(result.piiDetections.isEmpty)
    }

    @Test("notAuthorised TranscriberError maps to notAuthorised unscannable reason")
    func notAuthorisedMapping() async throws {
        let scanner = AudioPIIScanner(transcribe: { _ in
            throw AudioPIIScanner.TranscriberError.notAuthorised
        })
        let result = try await scanner.scan(
            audioData: fixture("audio-with-email"),
            mediaType: "audio/mp4"
        )
        #expect(result.unscannable == .notAuthorised)
    }

    @Test("Unsupported audio format surfaces as unsupportedFormat")
    func unsupportedFormatRejected() async throws {
        // webm gets removed from the explicit allow-list in P0-3 fix.
        // The scanner must short-circuit BEFORE writing a temp file
        // with a misleading extension.
        let scanner = scannerWithCannedTranscript("never reached")
        let result = try await scanner.scan(
            audioData: fixture("audio-with-email"),
            mediaType: "audio/webm"
        )
        #expect(result.unscannable == .unsupportedFormat)
        #expect(result.piiDetections.isEmpty)
    }

    @Test("Empty transcript surfaces no findings, not 'noSpeech'")
    func emptyTranscriptIsClean() async throws {
        // SFSpeechRecognizer can legitimately return an empty
        // transcript for genuinely silent audio. The scanner must
        // treat that as "no PII" not as "unscannable".
        let scanner = scannerWithCannedTranscript("")
        let result = try await scanner.scan(
            audioData: fixture("audio-clean"),
            mediaType: "audio/mp4"
        )
        #expect(result.unscannable == nil)
        #expect(result.piiDetections.isEmpty)
    }

    @Test("timedOut TranscriberError maps to recogniserUnavailable")
    func timedOutMapping() async throws {
        let scanner = AudioPIIScanner(transcribe: { _ in
            throw AudioPIIScanner.TranscriberError.timedOut
        })
        let result = try await scanner.scan(
            audioData: fixture("audio-with-email"),
            mediaType: "audio/mp4"
        )
        // timedOut surfaces as recogniserUnavailable so the rewriter
        // still strips the attachment — never a silent pass-through.
        #expect(result.unscannable == .recogniserUnavailable)
    }
}

@Suite("MultimodalImageExtractor — audio shapes")
struct MultimodalAudioExtractorTests {
    private func base64Fixture(_ name: String, ext: String = "m4a") -> String {
        guard let url = Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures")
            ?? Bundle.module.url(forResource: name, withExtension: ext)
        else {
            Issue.record("Missing fixture \(name).\(ext)")
            return ""
        }
        let data = (try? Data(contentsOf: url)) ?? Data()
        return data.base64EncodedString()
    }

    @Test("Extracts an OpenAI input_audio block")
    func openAIInputAudio() {
        let b64 = base64Fixture("audio-with-email")
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"text","text":"transcribe this"},
          {"type":"input_audio","input_audio":{"data":"\(b64)","format":"m4a"}}
        ]}]}
        """
        let images = MultimodalImageExtractor.extract(from: Data(body.utf8))
        #expect(images.count == 1)
        let attachment = images[0]
        #expect(attachment.provider == .openai)
        #expect(attachment.isAudio)
        #expect(attachment.mediaType.hasPrefix("audio/"))
    }

    @Test("input_audio without the surrounding type:input_audio is NOT picked up (P0-1 fix)")
    func inputAudioGatedOnType() {
        // Without the `type` gate this would be matched as an audio
        // attachment and run through SFSpeechRecognizer for an
        // arbitrary base64 blob in a text block. P0-1 fix: the
        // extractor must require type == "input_audio".
        let b64 = base64Fixture("audio-with-email")
        let body = """
        {"messages":[{"role":"user","content":[
          {"type":"text","text":"hello","input_audio":{"data":"\(b64)","format":"m4a"}}
        ]}]}
        """
        let images = MultimodalImageExtractor.extract(from: Data(body.utf8))
        #expect(images.isEmpty,
                "input_audio without a matching type field must not be extracted")
    }

    @Test("Extracts a Gemini inlineData audio block")
    func geminiInlineAudio() {
        let b64 = base64Fixture("audio-with-email")
        let body = """
        {"contents":[{"parts":[
          {"inlineData":{"mimeType":"audio/mp4","data":"\(b64)"}}
        ]}]}
        """
        let images = MultimodalImageExtractor.extract(from: Data(body.utf8))
        #expect(images.first?.provider == .gemini)
        #expect(images.first?.isAudio == true)
    }
}
