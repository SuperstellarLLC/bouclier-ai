import Foundation

/// Coarse classification of PII entity types. Used by the multimodal
/// scanners to bucket the entities they detect inside attachments, and
/// surfaced in the audit log so the operator can see what kinds of
/// content the file-inspection pass found.
///
/// **The split.**
/// - `.personal` — what the user means by "PII": emails, addresses,
///    government IDs, financial numbers. The reason a user enables
///    file inspection in the first place.
/// - `.credential` — API keys, tokens, OAuth secrets, DB URLs, private
///    keys. These show up inside screenshots of dotfiles, leaked
///    config snippets in PDFs, etc.
/// - `.network` — IP addresses. Ambiguous; exposed as its own category
///    so we can choose to flag or ignore them independently from
///    other PII.
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
