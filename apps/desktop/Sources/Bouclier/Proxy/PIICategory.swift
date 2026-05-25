import Foundation

/// Coarse classification of PII entity types. Used by the redactor to
/// decide *whether* to substitute, given the destination — the same
/// detection set is right for every host, but the *action* varies.
///
/// **Why this exists.** A user pasting `OPENAI_API_KEY=sk-…` into a
/// Claude prompt asking "why doesn't this work?" wants the model to
/// see the key — that's functional context, not a leak. Redacting it
/// to `[REDACTED-OPENAI_KEY-abc12345]` breaks the debugging session
/// and trips the LLM's abuse detection (we got the user soft-banned
/// from api.anthropic.com on 2026-05-25 doing exactly this).
///
/// **The split.**
/// - `.personal` — what the user means by "PII": emails, addresses,
///    government IDs, financial numbers. These genuinely leak when
///    sent to a third-party LLM; always redact.
/// - `.credential` — API keys, tokens, OAuth secrets, DB URLs, private
///    keys. Sensitive in absolute terms but usually functional context
///    when a user is asking the LLM for help. Default-skip for hosts
///    we already trust enough to MITM (i.e. AI provider APIs). Users
///    paranoid about supply-chain leaks can flip the "strict" mode in
///    Settings → Privacy.
/// - `.network` — IP addresses. Ambiguous; today still treated as PII
///    but exposed as its own category so we can flip it independently.
enum PIICategory: String, Sendable, Hashable, CaseIterable {
    case personal
    case credential
    case network

    /// Classify an entity type produced by `PIIScanner`. Unknown types
    /// default to `.credential` so a new detector added in the future
    /// can't accidentally start leaking by being treated as "personal
    /// and therefore always redactable, which is fine" — credential is
    /// the conservative bucket for the proxy's MITM hosts (skipped),
    /// and any genuinely-personal new type should be added explicitly.
    static func of(_ entityType: String) -> PIICategory {
        switch entityType {
        case "EMAIL", "CREDIT_CARD", "IBAN",
             "US_SSN", "US_NPI",
             "FR_NIR", "FR_SIREN", "FR_SIRET",
             "UK_NHS", "UK_NINO", "UK_POSTCODE":
            return .personal
        case "IPV4", "IPV6":
            return .network
        default:
            return .credential
        }
    }
}
