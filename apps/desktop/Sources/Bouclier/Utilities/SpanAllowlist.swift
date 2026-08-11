import CryptoKit
import Foundation

/// A persistent allowlist of untrusted-span fingerprints that must not be
/// blocked, even when the detector would refuse them.
///
/// ## Why this exists
///
/// No classifier is perfect, and a block on a long-lived agent session is
/// uniquely painful: the whole conversation is resent on every turn, so a
/// single false positive on one tool result 403s the session *and every
/// resume of it* — the failure mode that motivated this feature. When the
/// operator judges a specific flagged span benign, they can release it
/// once and get their session back, without turning enforcement off
/// wholesale.
///
/// ## What is stored
///
/// Only a salted SHA-256 **fingerprint** of the offending span — never the
/// span text. The salt is a per-install random value, so a fingerprint is
/// meaningless off this machine and the list can't be used to recover what
/// content a user allowlisted. This mirrors the PII audit log's
/// hash-prefix-only discipline: the app records that *a* span was released,
/// not *what* it said.
///
/// Fingerprints are the same value the detector computes for the scanned
/// span (`InjectionInspectionPass.spanFingerprint`), so a release taken
/// from a block notification matches the exact span that blocked.
///
/// Backed by `UserDefaults` (small, string-set) rather than SQLite: it is
/// consulted on the hot request path and must be readable without the
/// audit DB — which, as of v0.9.4, can legitimately be unavailable.
enum SpanAllowlist {
    private static let listKey = "injectionSpanAllowlist"
    private static let saltKey = "injectionSpanAllowlistSalt"

    /// Per-install salt, minted once and persisted. Base64 of 32 random
    /// bytes. Not a secret (an allowlist is not sensitive), but salting
    /// keeps fingerprints machine-local so the list never doubles as a
    /// content oracle.
    static func salt(_ defaults: UserDefaults = .standard) -> Data {
        if let b64 = defaults.string(forKey: saltKey), let data = Data(base64Encoded: b64) {
            return data
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        let data = Data(bytes)
        defaults.set(data.base64EncodedString(), forKey: saltKey)
        return data
    }

    /// True when this span fingerprint has been released by the operator.
    static func contains(_ fingerprint: String, _ defaults: UserDefaults = .standard) -> Bool {
        guard let list = defaults.array(forKey: listKey) as? [String] else { return false }
        return list.contains(fingerprint)
    }

    /// All released fingerprints (for Settings display / management).
    static func all(_ defaults: UserDefaults = .standard) -> [String] {
        defaults.array(forKey: listKey) as? [String] ?? []
    }

    /// Release a span: subsequent requests carrying it are forwarded even
    /// if the detector would block. Idempotent.
    static func add(_ fingerprint: String, _ defaults: UserDefaults = .standard) {
        guard !fingerprint.isEmpty else { return }
        var list = defaults.array(forKey: listKey) as? [String] ?? []
        guard !list.contains(fingerprint) else { return }
        list.append(fingerprint)
        defaults.set(list, forKey: listKey)
    }

    /// Re-arm a previously released span.
    static func remove(_ fingerprint: String, _ defaults: UserDefaults = .standard) {
        var list = defaults.array(forKey: listKey) as? [String] ?? []
        list.removeAll { $0 == fingerprint }
        defaults.set(list, forKey: listKey)
    }

    /// Clear the whole allowlist (Settings "re-arm everything").
    static func clear(_ defaults: UserDefaults = .standard) {
        defaults.removeObject(forKey: listKey)
    }

    /// The current allowlisted set, resolved for a scan. Handed to
    /// `InjectionInspectionPass.inspect` so the pure inspection layer never
    /// touches `UserDefaults` itself.
    static func snapshot(_ defaults: UserDefaults = .standard) -> Set<String> {
        Set(all(defaults))
    }
}
