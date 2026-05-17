import Foundation
import NIOCore
import NIOHTTP1
import Testing
@testable import Bouclier

/// Serialized because several tests toggle the global
/// `FeatureFlags.piiRedaction` override — parallel execution otherwise
/// races on the static `testOverrides` dictionary.
@Suite("PII pipeline — Phase 1 end-to-end", .serialized)
struct PIIPipelineTests {
    // MARK: - Scanner

    @Test("PIIScanner detects emails and Luhn cards in a chat-completion body")
    func scannerDetectsCommonEntities() {
        let scanner = PIIScanner()
        let body = """
            user: contact me at alice@example.com or charge 4242 4242 4242 4242 — thanks
            """
        let hits = scanner.scan(body)
        let types = Set(hits.map { $0.type })
        #expect(types.contains("EMAIL"))
        #expect(types.contains("CREDIT_CARD"))
    }

    @Test("PIIScanner picks FR_SIRET over CREDIT_CARD for a Luhn-passing 14-digit number")
    func sirePrecedesCC() {
        let scanner = PIIScanner()
        let hits = scanner.scan("SIRET 732 829 320 00074 immatriculée")
        let types = Set(hits.map { $0.type })
        #expect(types.contains("FR_SIRET"))
        #expect(!types.contains("CREDIT_CARD"))
    }

    @Test("PIIScanner detects UK NHS, NINO, and postcode together")
    func ukEntities() {
        let scanner = PIIScanner()
        let hits = scanner.scan("NHS 943 476 5919, NINO AB123456C, postcode SW1A 1AA")
        let types = Set(hits.map { $0.type })
        #expect(types.contains("UK_NHS"))
        #expect(types.contains("UK_NINO"))
        #expect(types.contains("UK_POSTCODE"))
    }

    @Test("PIIScanner rejects IPv6 shape on date-like log lines (R4 regression)")
    func ipv6RejectsDates() {
        let scanner = PIIScanner()
        let hits = scanner.scan("build started 2024:08:31:12:34:56:78:99 ok")
        #expect(!hits.contains(where: { $0.type == "IPV6" }))
    }

    @Test("PIIScanner CREDIT_CARD context suppression skips Luhn-passing hashes (R3)")
    func ccContextSuppression() {
        let scanner = PIIScanner()
        let hits = scanner.scan("sha256: 4242 4242 4242 4242 then proceed")
        #expect(!hits.contains(where: { $0.type == "CREDIT_CARD" }))
    }

    @Test("PIIScanner returns non-overlapping spans in input order")
    func nonOverlappingOrdered() {
        let scanner = PIIScanner()
        let hits = scanner.scan("email alice@a.io + iban GB82 WEST 1234 5698 7654 32 + email bob@b.io")
        for i in 1..<hits.count {
            #expect(hits[i].start >= hits[i - 1].end)
        }
    }

    // MARK: - Redactor + Session round-trip

    @Test("PIIRedactor + PIISession round-trip restores the original")
    func roundTripOriginal() async {
        let redactor = PIIRedactor()
        let session = PIISession()
        let original = "Hi, my email is jane.doe@example.com and my card is 4242 4242 4242 4242"
        let (redacted, audit) = await redactor.redact(original, with: session)
        #expect(audit.count == 2)
        #expect(redacted != original)
        #expect(redacted.contains(PIISession.tokenPrefix))
        // Reverse using the same session.
        let reversed = await PIIReverser.reverseString(redacted, with: session)
        #expect(reversed == original)
    }

    @Test("PIIReverser leaves user-typed token-shaped strings alone (R6 part 2)")
    func userTypedPlaceholdersPassThrough() async {
        let session = PIISession()
        // Simulate a model response that contains a never-minted token.
        let response = "result: ⟦pii:EMAIL:deadbeef⟧ remains as-is"
        let reversed = await PIIReverser.reverseString(response, with: session)
        #expect(reversed == response)
    }

    @Test("PIIReverser reverses tokens embedded in JSON string leaves")
    func reverseJSONLeaves() async {
        let redactor = PIIRedactor()
        let session = PIISession()
        let payload = ["text": "ping alice@example.com"]
        let bodyData = try! JSONSerialization.data(withJSONObject: payload)
        let bodyString = String(data: bodyData, encoding: .utf8)!
        let (redacted, _) = await redactor.redact(bodyString, with: session)
        // Pretend this is the model response — reverse JSON.
        let responseData = redacted.data(using: .utf8)!
        let reversed = await PIIReverser.reverseJSON(responseData, with: session)
        let parsed = try! JSONSerialization.jsonObject(with: reversed) as! [String: String]
        #expect(parsed["text"] == "ping alice@example.com")
    }

    @Test("Two PIISessions on the same redactor produce different tokens (R6 part 3)")
    func sessionsAreIndependent() async {
        let redactor = PIIRedactor()
        let s1 = PIISession()
        let s2 = PIISession()
        let (r1, _) = await redactor.redact("alice@example.com", with: s1)
        let (r2, _) = await redactor.redact("alice@example.com", with: s2)
        #expect(r1 != r2, "Per-session HMAC keys must make tokens unguessable across sessions.")
        // Reversal across sessions does nothing.
        let crossReversed = await PIIReverser.reverseString(r1, with: s2)
        #expect(crossReversed == r1)
    }

    // MARK: - HTTPRequestInspector.applyPIIRedaction

    @Test("applyPIIRedaction is a no-op when the feature flag is off")
    func applyDisabledByDefault() async {
        FeatureFlags.setTestOverride("piiRedaction", false)
        defer { FeatureFlags.clearTestOverrides() }

        let allocator = ByteBufferAllocator()
        var body = allocator.buffer(capacity: 64)
        body.writeString(#"{"messages":[{"role":"user","content":"alice@example.com"}]}"#)
        let pass = await HTTPRequestInspector.applyPIIRedaction(
            body: body,
            contentType: "application/json",
            method: .POST,
            redactor: PIIRedactor(),
            session: PIISession(),
            allocator: allocator
        )
        #expect(pass.audit.isEmpty)
        // Body is unchanged byte-for-byte.
        #expect(pass.body.readableBytes == body.readableBytes)
    }

    @Test("applyPIIRedaction substitutes tokens and emits audit entries when enabled")
    func applyEnabled() async {
        FeatureFlags.setTestOverride("piiRedaction", true)
        defer { FeatureFlags.clearTestOverrides() }

        let allocator = ByteBufferAllocator()
        var body = allocator.buffer(capacity: 256)
        body.writeString(#"{"prompt":"reach me at bob@b.io about SIRET 732 829 320 00074"}"#)
        let pass = await HTTPRequestInspector.applyPIIRedaction(
            body: body,
            contentType: "application/json",
            method: .POST,
            redactor: PIIRedactor(),
            session: PIISession(),
            allocator: allocator
        )
        #expect(pass.audit.count == 2)
        let types = Set(pass.audit.map(\.type))
        #expect(types.contains("EMAIL"))
        #expect(types.contains("FR_SIRET"))
        let outString = pass.body.getString(at: pass.body.readerIndex, length: pass.body.readableBytes)!
        #expect(outString.contains(PIISession.tokenPrefix))
        #expect(!outString.contains("bob@b.io"))
        #expect(!outString.contains("732 829 320 00074"))
    }

    @Test("applyPIIRedaction skips binary/multipart bodies")
    func skipsBinary() async {
        FeatureFlags.setTestOverride("piiRedaction", true)
        defer { FeatureFlags.clearTestOverrides() }

        let allocator = ByteBufferAllocator()
        var body = allocator.buffer(capacity: 32)
        body.writeString("bytes that look like alice@a.io but aren't json")
        let pass = await HTTPRequestInspector.applyPIIRedaction(
            body: body,
            contentType: "image/png",
            method: .POST,
            redactor: PIIRedactor(),
            session: PIISession(),
            allocator: allocator
        )
        #expect(pass.audit.isEmpty)
    }

    // MARK: - End-to-end round-trip simulating proxy flow

    @Test("End-to-end: outbound redact + inbound reverse restore the prompt across a fake LLM hop")
    func endToEndRoundTrip() async {
        FeatureFlags.setTestOverride("piiRedaction", true)
        defer { FeatureFlags.clearTestOverrides() }

        let allocator = ByteBufferAllocator()
        let redactor = PIIRedactor()
        let session = PIISession()

        let originalPrompt =
            #"{"messages":[{"role":"user","content":"summarise alice@example.com's most recent emails from NHS 943 476 5919"}]}"#
        var body = allocator.buffer(capacity: originalPrompt.utf8.count)
        body.writeString(originalPrompt)

        // Outbound: redactor substitutes tokens.
        let pass = await HTTPRequestInspector.applyPIIRedaction(
            body: body, contentType: "application/json", method: .POST,
            redactor: redactor, session: session, allocator: allocator
        )
        let upstreamBody = pass.body.getString(at: pass.body.readerIndex, length: pass.body.readableBytes)!
        #expect(!upstreamBody.contains("alice@example.com"))
        #expect(!upstreamBody.contains("943 476 5919"))

        // Mock LLM response that echoes the tokens (typical agent behavior).
        let fakeResponseJSON = #"{"choices":[{"message":{"content":"You asked about \#(extractToken(upstreamBody, "EMAIL")) and \#(extractToken(upstreamBody, "UK_NHS"))"}}]}"#
        let responseData = Data(fakeResponseJSON.utf8)

        // Inbound: reverser restores cleartext.
        let reversedData = await PIIReverser.reverseJSON(responseData, with: session)
        let reversed = String(data: reversedData, encoding: .utf8)!
        #expect(reversed.contains("alice@example.com"))
        #expect(reversed.contains("943 476 5919"))
    }

    // MARK: - Helpers

    private func extractToken(_ s: String, _ type: String) -> String {
        let pattern = "⟦pii:\(type):[0-9a-f]{8}⟧"
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return "" }
        let ns = s as NSString
        let match = regex.firstMatch(in: s, range: NSRange(location: 0, length: ns.length))
        return match.map { ns.substring(with: $0.range) } ?? ""
    }
}
