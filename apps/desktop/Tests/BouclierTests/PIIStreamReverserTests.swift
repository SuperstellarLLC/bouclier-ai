import Foundation
import Testing
@testable import Bouclier

@Suite("PIIStreamReverser — Phase 3 scaffolding")
struct PIIStreamReverserTests {
    @Test("Emits nothing until the buffer exceeds the holdback")
    func holdsBackUntilBuffered() async {
        let session = PIISession()
        let r = PIIStreamReverser(session: session)
        let small = String(repeating: "x", count: PIIStreamReverser.holdback - 1)
        let out = await r.ingest(small)
        #expect(out.isEmpty)
    }

    @Test("Reverses a placeholder that crosses chunk boundaries")
    func reversesAcrossChunkBoundary() async {
        let session = PIISession()
        let token = await session.mintToken("alice@example.com", type: "EMAIL")
        let r = PIIStreamReverser(session: session)
        // Split the token into 3 chunks; the reverser must still emit
        // the cleartext (eventually) on flush.
        let third = token.count / 3
        let i1 = token.index(token.startIndex, offsetBy: third)
        let i2 = token.index(token.startIndex, offsetBy: 2 * third)
        let chunks = [
            "prefix " + String(repeating: "y", count: PIIStreamReverser.holdback) + String(token[..<i1]),
            String(token[i1..<i2]),
            String(token[i2...]) + " suffix",
        ]
        var collected = ""
        for c in chunks {
            collected += await r.ingest(c)
        }
        collected += await r.finish()
        #expect(collected.contains("alice@example.com"))
        #expect(!collected.contains(token), "reversed output must not still contain the placeholder")
    }

    @Test("Leaves unknown placeholder shapes alone (R6 invariant in streaming)")
    func unknownTokensPassThrough() async {
        let session = PIISession()
        let r = PIIStreamReverser(session: session)
        let chunk1 = "result: ⟦pii:EMAIL:dead"
        let chunk2 = "beef⟧ trailing content " + String(repeating: " ", count: PIIStreamReverser.holdback)
        var collected = await r.ingest(chunk1)
        collected += await r.ingest(chunk2)
        collected += await r.finish()
        #expect(collected.contains("⟦pii:EMAIL:deadbeef⟧"))
    }

    @Test("finish() emits the remaining tail and closes")
    func finishFlushes() async {
        let session = PIISession()
        let token = await session.mintToken("bob@b.io", type: "EMAIL")
        let r = PIIStreamReverser(session: session)
        // Whole token fits in one chunk but stays in the holdback.
        let chunk = "hello " + token + "."
        let live = await r.ingest(chunk)
        let final = await r.finish()
        let combined = live + final
        #expect(combined.contains("bob@b.io"))
        #expect(await r.ingest("noop") == "")
    }
}
