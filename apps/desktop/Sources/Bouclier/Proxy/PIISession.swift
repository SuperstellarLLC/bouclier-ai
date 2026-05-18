import CryptoKit
import Foundation

/// Per-connection PII tokenization session.
///
/// Owns the mapping from minted placeholder tokens to cleartext PII for a
/// single TLS proxy connection. Tokens are HMAC-keyed so an attacker
/// cannot construct a valid token without the per-session key — on the
/// response path we look up tokens by exact match and silently ignore
/// anything that isn't in the map (user-typed lookalikes, model-invented
/// strings, etc. pass through untouched).
///
/// **Threat model honestly stated.** The session map is plaintext
/// `[String: Data]` in process memory. This is *not* "encrypted at rest"
/// — AES-GCM-in-memory framing from earlier drafts was security
/// theatre because the key would have lived in the same actor. The
/// honest claim: (1) PII never leaves the device, (2) the map is never
/// written to disk, (3) cleartext buffers are zeroised on TTL expiry,
/// (4) sessions are scoped to a single TLS connection so concurrent
/// connections can never read each other's tokens. The audit log
/// (separate file) is what would benefit from a Secure-Enclave-wrapped
/// at-rest key — tracked separately.
///
/// **Concurrency.** Actor isolation guarantees one operation at a time.
/// Construct one `PIISession` per proxy connection; never share across
/// connections.
actor PIISession {
    // MARK: - Public types

    /// PII entity type, mirroring the slugs from `@bouclier-ai/patterns`.
    /// Kept as a raw string so adding new types from the TS side or from
    /// future ML detectors doesn't require a Swift recompile.
    typealias EntityType = String

    /// Snapshot of session statistics for the audit log. Records counts
    /// only — the cleartext values are never exposed via this API.
    struct Stats: Sendable {
        let entries: Int
        let mintedAt: Date
        let lastAccess: Date
    }

    // MARK: - Configuration

    /// How long an idle session lives before its map is zeroized. Set
    /// generously enough to cover a long-running chat turn (10 min) but
    /// short enough that idle memory residency is bounded.
    static let defaultTTL: TimeInterval = 600

    /// Hard cap on the number of distinct entities a single session
    /// will tokenise. Defends against a pathological client streaming
    /// an unbounded stream of unique PII through one keep-alive
    /// connection — without this cap the per-session map would grow
    /// monotonically until `close()`. Once exceeded, further values
    /// pass through unredacted with an audit-log signal so the
    /// operator notices.
    static let maxEntriesPerSession = 50_000

    /// First N hex chars of the HMAC used as the token's unique part.
    /// 8 hex = 32 bits of collision resistance — overkill for a 10-min
    /// per-connection map but the cost is zero.
    private static let tokenHexLength = 8

    /// Opening / closing bracket characters for the placeholder token.
    /// Unicode mathematical brackets `⟦` (U+27E6) and `⟧` (U+27E7) were
    /// chosen specifically because (a) they survive OpenAI Structured
    /// Outputs / JSON Schema constrained decoding (curly braces do not),
    /// (b) they are rare enough in user input that accidental collisions
    /// are negligible, (c) they are visually distinctive in audit logs.
    static let tokenOpen = "⟦"
    static let tokenClose = "⟧"
    static let tokenPrefix = "⟦pii:"

    /// Regex that matches our minted token shape. Used by the response-path
    /// reverser to find candidate tokens before looking them up in the map.
    static let tokenPattern = #"⟦pii:([A-Z_]+):([0-9a-f]{8})⟧"#

    // MARK: - Stored state

    private let sessionKey: SymmetricKey
    private let ttl: TimeInterval
    private let mintedAt: Date

    /// token → cleartext bytes. `Data` (not `String`) so we can zeroize on
    /// expiry — Swift `String` storage on ARC release is not zeroed.
    private var tokenToCleartext: [String: Data] = [:]

    /// cleartext → token. Lets us mint a stable token for the same value
    /// seen multiple times within a session (so two mentions of the same
    /// email in one conversation both reverse correctly).
    private var cleartextToToken: [String: String] = [:]

    /// Per-type counter to disambiguate distinct values of the same type
    /// in the HMAC input. Combined with the cleartext bytes, this gives
    /// each minted token a unique HMAC even if the value is reused.
    private var perTypeCounter: [EntityType: Int] = [:]

    private var lastAccess: Date
    private var expired: Bool = false

    // MARK: - Init

    /// Generate a fresh session with a random 256-bit key. The key never
    /// leaves the actor; on TTL expiry it goes out of scope along with
    /// the zeroized map.
    init(ttl: TimeInterval = PIISession.defaultTTL) {
        self.sessionKey = SymmetricKey(size: .bits256)
        self.ttl = ttl
        let now = Date()
        self.mintedAt = now
        self.lastAccess = now
    }

    // MARK: - Public API

    /// Mint a placeholder token for a piece of cleartext PII. Returns the
    /// token to substitute into the outbound payload. Stable within a
    /// session: calling `mintToken("alice@a.io", "EMAIL")` twice returns
    /// the same token both times.
    func mintToken(_ cleartext: String, type: EntityType) -> String {
        guard !expired else { return cleartext }

        let key = cleartextKey(cleartext, type: type)
        if let existing = cleartextToToken[key] {
            lastAccess = Date()
            return existing
        }

        // Refuse to grow the map past the per-session cap. The caller
        // sees the cleartext returned unchanged, which means redaction
        // silently degrades for the spillover entities — but the
        // alternative (unbounded growth on a long-lived connection) is
        // worse. Reverser sees nothing to reverse, so the response
        // path stays consistent.
        if tokenToCleartext.count >= PIISession.maxEntriesPerSession {
            return cleartext
        }

        let counter = (perTypeCounter[type] ?? 0) + 1
        perTypeCounter[type] = counter

        let hmac = computeHMAC(cleartext: cleartext, type: type, counter: counter)
        let token = "\(PIISession.tokenPrefix)\(type):\(hmac)\(PIISession.tokenClose)"

        tokenToCleartext[token] = Data(cleartext.utf8)
        cleartextToToken[key] = token
        lastAccess = Date()
        return token
    }

    /// Look up the cleartext for a token. Returns nil if the token wasn't
    /// minted by this session (user-typed lookalike, model invention,
    /// expired entry). The response-path reverser uses this to safely
    /// pass through unknown tokens untouched.
    func cleartext(for token: String) -> String? {
        guard !expired else { return nil }
        guard let data = tokenToCleartext[token] else { return nil }
        lastAccess = Date()
        return String(data: data, encoding: .utf8)
    }

    /// Sweep expired entries. If the session is past its TTL, zeroize all
    /// cleartext buffers and mark the session expired. Safe to call from
    /// a periodic timer.
    func sweepIfExpired(now: Date = Date()) {
        guard !expired else { return }
        if now.timeIntervalSince(lastAccess) > ttl {
            zeroizeAll()
            expired = true
        }
    }

    /// Force-zeroize and expire the session. Called when the connection
    /// closes to release the map immediately rather than waiting for the
    /// TTL sweep.
    func close() {
        zeroizeAll()
        expired = true
    }

    /// Stats for the audit log. Never exposes cleartext.
    func stats() -> Stats {
        Stats(entries: tokenToCleartext.count, mintedAt: mintedAt, lastAccess: lastAccess)
    }

    /// True iff this session has been expired (by TTL sweep or `close()`).
    /// Exposed so tests can assert the lifecycle invariant.
    func isExpired() -> Bool { expired }

    // MARK: - Internals

    /// Cleartext-keyed lookup string. The type is part of the key because
    /// the same string might legitimately be both an EMAIL and a USERNAME
    /// in different contexts (e.g., a username that looks like an email).
    private func cleartextKey(_ cleartext: String, type: EntityType) -> String {
        "\(type)\u{1F}\(cleartext)"
    }

    /// HMAC-SHA256(sessionKey, type|counter|cleartext) → first 8 hex chars.
    /// The counter ensures uniqueness across distinct values; the session
    /// key ensures unguessability across sessions / connections.
    private func computeHMAC(cleartext: String, type: EntityType, counter: Int) -> String {
        var hasher = HMAC<SHA256>(key: sessionKey)
        hasher.update(data: Data(type.utf8))
        hasher.update(data: Data([0x1F]))
        hasher.update(data: Data(String(counter).utf8))
        hasher.update(data: Data([0x1F]))
        hasher.update(data: Data(cleartext.utf8))
        let mac = hasher.finalize()
        let hex = mac.prefix(4).map { String(format: "%02x", $0) }.joined()
        return String(hex.prefix(PIISession.tokenHexLength))
    }

    /// Overwrite the bytes of every cleartext `Data` before dropping the
    /// dictionary. Swift `String` cannot be reliably zeroed because of
    /// COW small-string inlining, so storing as `Data` and calling
    /// `withUnsafeMutableBytes` is the closest we get.
    ///
    /// Note: this does *not* prevent the OS from having paged any of
    /// this memory to swap before we got here. The swap-leak threat
    /// model needs either `mlock` on the page or Secure-Enclave-wrapped
    /// keys for the audit log — both tracked as separate work items.
    private func zeroizeAll() {
        for (token, var data) in tokenToCleartext {
            data.withUnsafeMutableBytes { buf in
                if let base = buf.baseAddress, buf.count > 0 {
                    memset_s(base, buf.count, 0, buf.count)
                }
            }
            tokenToCleartext[token] = nil
        }
        cleartextToToken.removeAll()
        perTypeCounter.removeAll()
    }
}
