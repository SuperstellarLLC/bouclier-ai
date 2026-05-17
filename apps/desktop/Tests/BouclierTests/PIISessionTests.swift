import Foundation
import Testing
@testable import Bouclier

@Suite("PIISession")
struct PIISessionTests {
    // MARK: - Token format

    @Test("Minted tokens have the documented Unicode-bracket shape")
    func tokenFormat() async {
        let session = PIISession()
        let token = await session.mintToken("alice@example.com", type: "EMAIL")
        #expect(token.hasPrefix(PIISession.tokenPrefix))
        #expect(token.hasSuffix(PIISession.tokenClose))
        #expect(token.contains("EMAIL"))
        // 8 hex chars between the type and the closing bracket.
        let re = try! NSRegularExpression(pattern: PIISession.tokenPattern)
        let range = NSRange(token.startIndex..., in: token)
        #expect(re.firstMatch(in: token, range: range) != nil)
    }

    // MARK: - Determinism

    @Test("Same value and type within a session always mints the same token")
    func stableWithinSession() async {
        let session = PIISession()
        let t1 = await session.mintToken("alice@example.com", type: "EMAIL")
        let t2 = await session.mintToken("alice@example.com", type: "EMAIL")
        #expect(t1 == t2)
    }

    @Test("Different values of the same type mint distinct tokens")
    func distinctValuesDistinctTokens() async {
        let session = PIISession()
        let a = await session.mintToken("alice@example.com", type: "EMAIL")
        let b = await session.mintToken("bob@example.com", type: "EMAIL")
        #expect(a != b)
    }

    @Test("Same string with different types mints distinct tokens")
    func sameValueDifferentTypeDistinctTokens() async {
        let session = PIISession()
        let asEmail = await session.mintToken("abc@def.gh", type: "EMAIL")
        let asUsername = await session.mintToken("abc@def.gh", type: "USERNAME")
        #expect(asEmail != asUsername)
    }

    // MARK: - Per-session isolation (R6 part 3)

    @Test("Two sessions mint different tokens for the same cleartext")
    func crossSessionUnguessability() async {
        let s1 = PIISession()
        let s2 = PIISession()
        let t1 = await s1.mintToken("alice@example.com", type: "EMAIL")
        let t2 = await s2.mintToken("alice@example.com", type: "EMAIL")
        #expect(t1 != t2, "Sessions must have independent HMAC keys so a token from session A cannot be forged on session B.")
    }

    // MARK: - Reversal

    @Test("Round-trips: cleartext(for: mintToken(x)) == x")
    func roundTrip() async {
        let session = PIISession()
        for value in ["alice@example.com", "+33 6 12 34 56 78", "GB82 WEST 1234 5698 7654 32"] {
            let token = await session.mintToken(value, type: "EMAIL")
            let recovered = await session.cleartext(for: token)
            #expect(recovered == value)
        }
    }

    @Test("Returns nil for tokens not minted by this session (R6 part 2)")
    func unknownTokenReturnsNil() async {
        let session = PIISession()
        // A user-typed lookalike — same shape, but the HMAC was not minted
        // by our session key so it cannot be in the map.
        let lookalike = "\(PIISession.tokenPrefix)EMAIL:deadbeef\(PIISession.tokenClose)"
        #expect(await session.cleartext(for: lookalike) == nil)
        // Even a real-looking token from a *different* session must not
        // resolve here.
        let other = PIISession()
        let foreignToken = await other.mintToken("alice@example.com", type: "EMAIL")
        #expect(await session.cleartext(for: foreignToken) == nil)
    }

    // MARK: - TTL and zeroization

    @Test("Sweep expires the session and zeroizes the map after TTL")
    func ttlSweep() async {
        let session = PIISession(ttl: 0.01)
        _ = await session.mintToken("alice@example.com", type: "EMAIL")
        #expect(await session.stats().entries == 1)
        // Wait past TTL and sweep.
        try? await Task.sleep(nanoseconds: 50_000_000) // 50ms
        await session.sweepIfExpired()
        #expect(await session.isExpired())
        #expect(await session.stats().entries == 0)
    }

    @Test("close() force-expires and zeroizes immediately")
    func closeExpiresImmediately() async {
        let session = PIISession()
        let token = await session.mintToken("alice@example.com", type: "EMAIL")
        await session.close()
        #expect(await session.isExpired())
        #expect(await session.cleartext(for: token) == nil)
    }

    @Test("Mint after expiry is a no-op that returns the cleartext untouched")
    func mintAfterExpiry() async {
        let session = PIISession()
        await session.close()
        let result = await session.mintToken("alice@example.com", type: "EMAIL")
        #expect(result == "alice@example.com", "After expiry mintToken must be a no-op returning input untouched, never partially populating state.")
    }

    // MARK: - Audit log surface

    @Test("Stats expose counts only, never cleartext")
    func statsCountsOnly() async {
        let session = PIISession()
        _ = await session.mintToken("alice@example.com", type: "EMAIL")
        _ = await session.mintToken("bob@example.com", type: "EMAIL")
        _ = await session.mintToken("4242 4242 4242 4242", type: "CREDIT_CARD")
        let stats = await session.stats()
        #expect(stats.entries == 3)
    }
}
