import CryptoKit
import Foundation

/// Client side of the `/api/report` proof-of-work gate.
///
/// The reporter must include a nonce such that `SHA-256(material‖nonce)` has at
/// least `difficultyBits` leading zero bits, where
/// `material = "<timestamp-ms>:<fingerprint>"`. This costs the caller real CPU
/// per report — an abuse deterrent that needs no IP, identity, or shipped
/// secret (PoW security does not depend on the algorithm being secret, so it is
/// safe in an open-source client).
///
/// This must stay byte-identical to the server's verifier
/// (`apps/site/src/lib/pow.ts`): same input bytes, same leading-zero-bit count.
/// The cross-language parity vector in the tests pins that agreement.
enum ReportProofOfWork {
    /// Difficulty the client mines to — matches the server's `DEFAULT_POW_BITS`.
    /// The server's `REPORT_POW_BITS` env override is a break-glass lever;
    /// raising it above this makes older clients fail to report until updated.
    static let difficultyBits = 20

    /// The value the nonce is mined against — a fresh timestamp bound to the report.
    static func material(timestamp: Int64, fingerprint: String) -> String {
        "\(timestamp):\(fingerprint)"
    }

    /// Leading zero bits of a SHA-256 digest — the same count the server computes.
    static func leadingZeroBits(_ digest: SHA256.Digest) -> Int {
        var count = 0
        for byte in digest {
            if byte == 0 {
                count += 8
                continue
            }
            count += byte.leadingZeroBitCount
            break
        }
        return count
    }

    /// True iff `SHA-256(material‖nonce)` has ≥ `bits` leading zero bits.
    static func satisfies(material: String, nonce: String, bits: Int) -> Bool {
        if bits <= 0 { return true }
        let digest = SHA256.hash(data: Data((material + nonce).utf8))
        return leadingZeroBits(digest) >= bits
    }

    /// Mine the first nonce (counting from 0) that satisfies `bits`.
    static func solve(material: String, bits: Int) -> String {
        var n = 0
        while true {
            let nonce = String(n)
            if satisfies(material: material, nonce: nonce, bits: bits) { return nonce }
            n += 1
        }
    }

    /// Current epoch milliseconds — the PoW timestamp the server freshness-checks.
    static func nowMillis() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }
}
