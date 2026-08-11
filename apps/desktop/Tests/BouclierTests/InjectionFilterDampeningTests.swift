import Foundation
import Testing
@testable import Bouclier

/// Guards the fix for the v0.9.4-era false positives where the ML tier
/// blocked on security content it was only *reading about*.
///
/// The regex tier dampens each match by its proximity to a benign-context
/// marker, but the ML score has no offset, so before this fix it bypassed
/// dampening entirely — a quoted advisory or this project's own pattern
/// files scored ~1.0 and 403'd a live agent session on every resume.
/// `mlBenignMultiplier` is the whole-span analogue of that dampening; it
/// is pure and offset-driven, so it is tested here directly without
/// standing up a CoreML classifier.
@Suite("InjectionFilter — ML benign-context dampening")
struct InjectionFilterDampeningTests {

    @Test("No benign markers → ML is trusted fully (multiplier 1.0)")
    func noDampenersMeansNoDampening() {
        #expect(InjectionFilter.mlBenignMultiplier(dampenerRanges: [], contentLength: 4000) == 1.0)
    }

    @Test("Empty content is a no-op, never a divide-by-zero")
    func emptyContentIsSafe() {
        let ranges = [DampenerRange(start: 0, end: 10, dampen: 0.4)]
        #expect(InjectionFilter.mlBenignMultiplier(dampenerRanges: ranges, contentLength: 0) == 1.0)
    }

    @Test("A span saturated with benign markers pulls ML down toward the strongest dampener")
    func saturatedBenignContextDampensHard() {
        // Markers spread densely across a short span: with the ±200
        // proximity expansion their windows cover the whole span, so the
        // multiplier collapses to (near) the strongest dampener present.
        let len = 1000
        let ranges = [
            DampenerRange(start: 100, end: 110, dampen: 0.4),  // owasp-style
            DampenerRange(start: 500, end: 510, dampen: 0.4),
            DampenerRange(start: 900, end: 910, dampen: 0.4),
        ]
        let m = InjectionFilter.mlBenignMultiplier(dampenerRanges: ranges, contentLength: len)
        #expect(m <= 0.45, "Saturated benign context should dampen close to the 0.4 floor, got \(m)")

        // A raw ML score that used to force a block (0.99) must now fall
        // below the ML-alone bar (0.85) once dampened by this context.
        #expect(0.99 * m < 0.85, "Dampened ML on quoted security content must not clear the ML-alone bar")
    }

    @Test("One incidental marker in a long span barely dampens — genuine attacks survive")
    func sparseMarkerBarelyDampens() {
        // A single benign marker in a large span: its ±200 window covers a
        // small fraction, so ML is left nearly intact and a real injection
        // elsewhere in the span still blocks.
        let len = 64_000
        let ranges = [DampenerRange(start: 32_000, end: 32_010, dampen: 0.4)]
        let m = InjectionFilter.mlBenignMultiplier(dampenerRanges: ranges, contentLength: len)
        #expect(m > 0.99, "One incidental marker in a 64KB span should barely move ML, got \(m)")
        #expect(0.95 * m >= 0.85, "A genuine ML-alone attack must still clear the bar despite one stray marker")
    }

    @Test("Overlapping marker windows aren't double-counted past full coverage")
    func overlappingWindowsClampToOne() {
        // Two markers whose proximity windows overlap and exceed the span:
        // coverage must clamp at 1.0, never over-dampen below the floor.
        let ranges = [
            DampenerRange(start: 0, end: 5, dampen: 0.2),
            DampenerRange(start: 50, end: 55, dampen: 0.2),
        ]
        let m = InjectionFilter.mlBenignMultiplier(dampenerRanges: ranges, contentLength: 100)
        #expect(abs(m - 0.2) < 0.001, "Full coverage should reach the strongest dampener (0.2), got \(m)")
    }
}
