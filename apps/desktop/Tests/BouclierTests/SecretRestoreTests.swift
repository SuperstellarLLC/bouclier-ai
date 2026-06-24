import Foundation
import Testing
@testable import Bouclier

@Suite("SecretRestore — streaming de-anonymize")
struct SecretRestoreTests {
    private let ph = SecretRule.placeholder(for: "stripe")
    private let value = "sk_live_RESTORED_VALUE_123456"

    private func bytes(_ s: String) -> [UInt8] { Array(s.utf8) }
    private func str(_ b: [UInt8]) -> String { String(decoding: b, as: UTF8.self) }

    private func makeRestore() -> SecretRestore {
        SecretRestore(map: [(ph, value)])
    }

    @Test("Placeholder fully inside one chunk is restored")
    func singleChunk() {
        var r = makeRestore()
        var out = r.ingest(bytes("before \(ph) after"))
        out += r.finish()
        #expect(str(out) == "before \(value) after")
    }

    @Test("Placeholder split across chunk boundary is reassembled (straddle-safe)")
    func straddle() {
        var r = makeRestore()
        // Split the placeholder down the middle across two ingests.
        let mid = ph.index(ph.startIndex, offsetBy: ph.count / 2)
        let first = "head " + String(ph[..<mid])
        let second = String(ph[mid...]) + " tail"
        var out = r.ingest(bytes(first))
        out += r.ingest(bytes(second))
        out += r.finish()
        #expect(str(out) == "head \(value) tail")
    }

    @Test("Byte-at-a-time streaming still restores")
    func byteAtATime() {
        var r = makeRestore()
        let input = "x\(ph)y"
        var out: [UInt8] = []
        for b in bytes(input) { out += r.ingest([b]) }
        out += r.finish()
        #expect(str(out) == "x\(value)y")
    }

    @Test("Multi-byte UTF-8 split across chunks is not corrupted")
    func multibyteSafe() {
        var r = makeRestore()
        let emoji = "🔒" // 4 UTF-8 bytes
        let full = bytes("a\(emoji)b \(ph) c")
        // Split at every byte offset to stress boundary handling.
        var out: [UInt8] = []
        var i = 0
        while i < full.count {
            let end = min(i + 3, full.count)
            out += r.ingest(Array(full[i..<end]))
            i = end
        }
        out += r.finish()
        #expect(str(out) == "a\(emoji)b \(value) c")
    }

    @Test("No placeholder ⇒ output bytes identical to input")
    func identity() {
        var r = makeRestore()
        let input = bytes("nothing to restore here, just text 🔒 and json {}")
        var out: [UInt8] = []
        out += r.ingest(input)
        out += r.finish()
        #expect(out == input)
    }

    @Test("Exact-match only: a near-miss placeholder is NOT restored")
    func exactMatchOnly() {
        var r = makeRestore()
        // One char off — must NOT splice the live secret in.
        let nearMiss = "__BOUCLIER_SECRET_strip__" // 'stripe' → 'strip'
        var out = r.ingest(bytes("x \(nearMiss) y"))
        out += r.finish()
        #expect(!str(out).contains(value), "near-miss must not restore a live secret: \(str(out))")
        #expect(str(out).contains(nearMiss))
    }

    @Test("Cross-rule: a restored value containing another rule's placeholder is NOT re-restored")
    func crossRuleNoDoubleRestore() {
        let phA = SecretRule.placeholder(for: "a")
        let phB = SecretRule.placeholder(for: "b")
        // Rule a's real value literally embeds rule b's placeholder.
        let valA = "VAL_\(phB)_END"
        var r = SecretRestore(map: [(phA, valA), (phB, "BBBBBBBB")])
        var out = r.ingest(bytes("x \(phA) y"))
        out += r.finish()
        // a is restored; b's placeholder INSIDE a's value must survive —
        // the model never emitted b. The old sequential-pass impl would
        // splice b's live secret here (the bug this guards).
        #expect(str(out) == "x VAL_\(phB)_END y", "cross-rule double-restore: \(str(out))")
        #expect(!str(out).contains("BBBBBBBB"), "b's value was wrongly spliced in")
    }

    @Test("Adjacent placeholders both restore")
    func adjacent() {
        var r = makeRestore()
        var out = r.ingest(bytes("\(ph)\(ph)"))
        out += r.finish()
        #expect(str(out) == "\(value)\(value)")
    }

    @Test("Longest placeholder first: prefix-colliding names both restore")
    func longestFirst() {
        let a = SecretRule.placeholder(for: "a")    // __BOUCLIER_SECRET_a__
        let a_ = SecretRule.placeholder(for: "a_")  // __BOUCLIER_SECRET_a___ (superstring of a__)
        var r = SecretRestore(map: [(a, "VAL_A"), (a_, "VAL_A_UNDERSCORE")])
        var out = r.ingest(bytes("\(a) | \(a_)"))
        out += r.finish()
        #expect(str(out) == "VAL_A | VAL_A_UNDERSCORE", "got: \(str(out))")
    }
}
