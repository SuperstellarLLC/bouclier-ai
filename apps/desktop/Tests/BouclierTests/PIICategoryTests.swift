import Foundation
import Testing
@testable import Bouclier

/// Pins the classification of every detector type the scanner can
/// emit. The bucketing matters because the multimodal scanners use it
/// to decide which entity types count as actionable PII inside an
/// attachment — getting it wrong either lets genuine PII pass through
/// an OCR'd image (false `.credential` → not flagged) or strips a
/// detector hit the user wouldn't expect Bouclier to touch.
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
                    "\(type) should be .credential — these are functional context, not PII a user is unaware they're sharing")
        }
    }

    @Test("Unknown types default to .credential (the conservative bucket)")
    func unknownDefaultsToCredential() {
        #expect(PIICategory.of("FUTURE_DETECTOR_NOT_YET_BUCKETED") == .credential)
    }
}
