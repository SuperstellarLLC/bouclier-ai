import Foundation
import Testing
@testable import Bouclier

@Suite("Report proof of work")
struct ReportProofOfWorkTests {
    @Test("a mined nonce satisfies the difficulty it was mined for")
    func mineRoundTrip() {
        for bits in [4, 8, 12] {
            let material = ReportProofOfWork.material(timestamp: 1000, fingerprint: "fp")
            let nonce = ReportProofOfWork.solve(material: material, bits: bits)
            #expect(ReportProofOfWork.satisfies(material: material, nonce: nonce, bits: bits))
        }
    }

    @Test("a nonce mined for low difficulty fails a much higher one")
    func lowFailsHigh() {
        let material = ReportProofOfWork.material(timestamp: 1000, fingerprint: "fp")
        let nonce = ReportProofOfWork.solve(material: material, bits: 4)
        // 1/2^24 false-positive probability — effectively deterministic.
        #expect(!ReportProofOfWork.satisfies(material: material, nonce: nonce, bits: 24))
    }

    @Test("bits <= 0 disables the check")
    func disabled() {
        #expect(ReportProofOfWork.satisfies(material: "anything", nonce: "x", bits: 0))
    }

    @Test("material binds the timestamp to the fingerprint")
    func materialBinding() {
        #expect(
            ReportProofOfWork.material(timestamp: 1000, fingerprint: "fp-A")
                != ReportProofOfWork.material(timestamp: 1000, fingerprint: "fp-B"))
        #expect(
            ReportProofOfWork.material(timestamp: 1000, fingerprint: "fp")
                != ReportProofOfWork.material(timestamp: 2000, fingerprint: "fp"))
    }

    @Test("matches the cross-language parity vector the TS server verifies")
    func parityVector() {
        // SHA-256("parity:anchor" ‖ "884") has EXACTLY 12 leading zero bits.
        // apps/site/src/__tests__/pow.test.ts asserts the identical vector, so
        // the client provably mines what the server verifies — no drift.
        #expect(ReportProofOfWork.satisfies(material: "parity:anchor", nonce: "884", bits: 12))
        #expect(!ReportProofOfWork.satisfies(material: "parity:anchor", nonce: "884", bits: 13))
    }
}
