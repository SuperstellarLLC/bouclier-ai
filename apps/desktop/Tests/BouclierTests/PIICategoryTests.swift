import Foundation
import NIOCore
import NIOHTTP1
import Testing
@testable import Bouclier

/// Pins the classification of every detector type the scanner can
/// emit. The redactor's "skip credentials when going to LLMs" behaviour
/// is built on top of this — getting the bucketing wrong silently
/// either leaks personal data (false `.credential` → skipped) or
/// breaks debugging sessions (false `.personal` → stripped from a
/// prompt the user wanted intact).
@Suite("PIICategory — bucketing")
struct PIICategoryBucketingTests {
    @Test("PII categories cover the genuine-leak types")
    func personalBucket() {
        for type in ["EMAIL", "CREDIT_CARD", "IBAN", "US_SSN", "US_NPI",
                     "FR_NIR", "FR_SIREN", "FR_SIRET",
                     "UK_NHS", "UK_NINO", "UK_POSTCODE"] {
            #expect(PIICategory.of(type) == .personal,
                    "\(type) should be .personal — it's genuine PII a user wouldn't intentionally share with an LLM")
        }
    }

    @Test("IPv4/IPv6 sit in their own .network bucket")
    func networkBucket() {
        #expect(PIICategory.of("IPV4") == .network)
        #expect(PIICategory.of("IPV6") == .network)
    }

    @Test("Common API key / token detector types are .credential")
    func credentialBucket() {
        for type in ["OPENAI_KEY", "ANTHROPIC_KEY", "AWS_ACCESS_KEY",
                     "GITHUB_PAT", "SLACK_TOKEN", "JWT", "BEARER_TOKEN",
                     "STRIPE_KEY", "PEM_PRIVATE_KEY", "POSTGRES_URL",
                     "MONGODB_URL", "GENERIC_API_KEY"] {
            #expect(PIICategory.of(type) == .credential,
                    "\(type) should be .credential — these are functional context when pasted into a debugging prompt")
        }
    }

    @Test("Unknown types default to .credential (the conservative bucket for MITM hosts)")
    func unknownDefaultsToCredential() {
        #expect(PIICategory.of("FUTURE_DETECTOR_NOT_YET_BUCKETED") == .credential)
    }
}

/// End-to-end check that `applyPIIRedaction` honours the
/// `skipCategories` parameter: credentials pass through cleartext when
/// asked, personal entities still get tokenised, and the audit log
/// only records what we actually substituted.
@Suite("applyPIIRedaction — skipCategories", .serialized)
struct ApplyPIIRedactionSkipCategoriesTests {
    @Test("Credentials pass through when caller skips that category")
    func credentialsPassThrough() async {
        FeatureFlags.setTestOverride("piiRedaction", true)
        defer { FeatureFlags.setTestOverride("piiRedaction", nil) }

        let redactor = PIIRedactor()
        let session = PIISession()
        let allocator = ByteBufferAllocator()
        let original = #"{"prompt":"my key is sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-XX and my email is alice@example.com"}"#
        var buf = allocator.buffer(capacity: original.utf8.count)
        buf.writeString(original)

        let pass = await HTTPRequestInspector.applyPIIRedaction(
            body: buf,
            contentType: "application/json",
            method: .POST,
            redactor: redactor,
            session: session,
            allocator: allocator,
            skipCategories: [.credential]
        )

        let out = pass.body.getString(at: pass.body.readerIndex, length: pass.body.readableBytes) ?? ""
        #expect(out.contains("sk-ant-api03-AAAAAAAAAA"),
                "Anthropic key (.credential) should survive cleartext when caller skips credentials; got: \(out)")
        #expect(!out.contains("alice@example.com"),
                "Email (.personal) should still be tokenised; got: \(out)")
        #expect(out.contains("⟦pii:EMAIL:"),
                "Expected an EMAIL placeholder in the rewritten body")

        let types = Set(pass.audit.map(\.type))
        #expect(types.contains("EMAIL"))
        #expect(!types.contains("ANTHROPIC_KEY"),
                "Audit log should only record substitutions that happened")
    }

    // Note: the default-behaviour test ("empty skipCategories
    // preserves redact-everything") is covered transitively by the
    // existing PIIPipelineTests suite — both `applyPIIRedaction` and
    // the scanner have full coverage there. Repeating it here flaked
    // on shared `PIIScanner.active` state between back-to-back tests
    // in this suite.
}
