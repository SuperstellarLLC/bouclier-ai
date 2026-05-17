import Foundation
import Testing
@testable import Bouclier

@Suite("PIINativeDetector — NSDataDetector wrapper")
struct PIINativeDetectorTests {
    let detector = PIINativeDetector.shared

    @Test("Detects an international phone number")
    func detectsInternationalPhone() {
        // NSDataDetector handles E.164 + most national formats out of the box.
        let hits = detector.scan("Call me on +33 6 12 34 56 78 tomorrow")
        #expect(hits.contains(where: { $0.type == "PHONE" }))
    }

    @Test("Detects a US-formatted phone number")
    func detectsUSPhone() {
        let hits = detector.scan("Reach Alice at (415) 555-2671 anytime")
        #expect(hits.contains(where: { $0.type == "PHONE" }))
    }

    @Test("Detects a multi-line postal address")
    func detectsAddress() {
        // NSDataDetector's address recogniser. Newlines inside the address
        // are OK; we don't trim them — the redactor handles the substring
        // verbatim.
        let hits = detector.scan("Ship it to 1 Infinite Loop, Cupertino, CA 95014 please")
        #expect(hits.contains(where: { $0.type == "ADDRESS" }))
    }

    @Test("No PHONE/ADDRESS in plain prose")
    func noFalsePositivesInProse() {
        let hits = detector.scan(
            "Yesterday the team shipped v0.3.3 and updated the documentation pages."
        )
        #expect(hits.allSatisfy { $0.type != "PHONE" && $0.type != "ADDRESS" })
    }

    @Test("Returns empty for empty input")
    func handlesEmptyInput() {
        #expect(detector.scan("").isEmpty)
    }

    @Test("Reports correct UTF-16 offsets that round-trip to the original substring")
    func offsetsRoundTrip() {
        let text = "Email Bob at +44 20 7946 0958 by Friday"
        let hits = detector.scan(text)
        guard let phone = hits.first(where: { $0.type == "PHONE" }) else {
            Issue.record("expected a PHONE hit")
            return
        }
        let ns = text as NSString
        let span = ns.substring(with: NSRange(location: phone.start, length: phone.end - phone.start))
        #expect(span == phone.value)
    }
}
