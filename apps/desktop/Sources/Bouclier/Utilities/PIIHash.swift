import CryptoKit
import Foundation

/// Stateless helper for the audit-log fingerprint of a PII cleartext
/// value. The hash is one-way and intentionally short (4 bytes / 8
/// hex) — enough to recognise the same value reused in a session,
/// useless to anyone scraping the SQLite file. Lives outside
/// `ProxyManager` so it isn't bound to `@MainActor` actor isolation,
/// which lets the multimodal pipeline call it from any task context
/// without an actor hop.
enum PIIHash {
    /// First 4 bytes of SHA-256 of `value`, rendered as lowercase hex.
    /// Matches the byte format the legacy `SHA256Tiny` helper used so
    /// audit rows look identical to a reader regardless of which
    /// branch of code wrote them.
    static func prefix(of value: String) -> String {
        let digest = SHA256.hash(data: Data(value.utf8))
        return digest.prefix(4).map { String(format: "%02x", $0) }.joined()
    }
}
