import Testing
@testable import Bouclier

@Suite("PII parity regressions")
struct PIIParityTests {
    @Test("Checksum validators reject repeated-digit placeholders")
    func repeatedDigitPlaceholders() {
        #expect(!PIIValidators.luhn("0000 0000 0000 0000"))
        #expect(!PIIValidators.luhn("1111 1111 1111 1111"))
        #expect(!PIIValidators.isPlausibleSIREN("000 000 000"))
        #expect(!PIIValidators.isPlausibleSIRET("00000000000000"))
        #expect(!PIIValidators.isPlausibleNHS("000 000 0000"))
        #expect(!PIIValidators.isPlausibleNPI("0000000000"))
    }

    @Test("IPv6 detector catches leading compression")
    func leadingCompressedIPv6() {
        let hits = PIIScanner().scan("peer ::abcd:1 connected")
        #expect(hits.contains { $0.type == "IPV6" && $0.value == "::abcd:1" })
    }

    @Test("Detector priority wins when a broad overlap starts earlier")
    func priorityBeatsEarlierStart() {
        let specific = PIIScanner.Raw(
            d: .init(type: "JWT", start: 4, end: 10, value: "secret"),
            rank: 0
        )
        let broad = PIIScanner.Raw(
            d: .init(type: "GENERIC_API_KEY", start: 2, end: 16, value: "a-secret-value"),
            rank: 1
        )
        let result = PIIScanner.resolveOverlaps([broad, specific])
        #expect(result == [specific.d])
    }
}
