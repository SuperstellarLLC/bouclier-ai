import Foundation
import Testing
@testable import Bouclier

@Suite("Notification coalescer")
struct NotificationCoalescerTests {
    @Test("first blocks show individually; a burst coalesces, then resets after the window clears")
    func burstThenReset() {
        var c = NotificationCoalescer() // window 60, threshold 3, throttle 60
        #expect(c.onBlock(at: 0) == .individual)
        #expect(c.onBlock(at: 1) == .individual)
        #expect(c.onBlock(at: 2) == .individual)
        #expect(c.onBlock(at: 3) == .summary(count: 4)) // 4th in the window → summarize
        #expect(c.onBlock(at: 4) == .suppress) // within the summary throttle
        #expect(c.onBlock(at: 5) == .suppress)
        // Long after the window has cleared, back to individual banners.
        #expect(c.onBlock(at: 200) == .individual)
    }

    @Test("slow, isolated blocks never coalesce (only a real burst does)")
    func slowBlocksStayIndividual() {
        var c = NotificationCoalescer()
        // One block every 30s: at most ~2 ever sit inside the 60s window.
        for i in 0 ..< 6 {
            #expect(c.onBlock(at: TimeInterval(i) * 30) == .individual)
        }
    }

    @Test("a sustained burst emits exactly one summary per throttle interval")
    func sustainedBurstThrottled() {
        var c = NotificationCoalescer()
        var individuals = 0, summaries = 0, suppressed = 0
        // A dense burst: one block per second for 64s.
        for t in 0 ... 63 {
            switch c.onBlock(at: TimeInterval(t)) {
            case .individual: individuals += 1
            case .summary: summaries += 1
            case .suppress: suppressed += 1
            }
        }
        // First 3 individual; a summary at the 4th (t=3); suppressed until the
        // 60s throttle elapses at t=63 → a second summary. Never a banner storm.
        #expect(individuals == 3)
        #expect(summaries == 2)
        #expect(suppressed == 64 - 3 - 2)
    }

    @Test("the summary count reflects blocks currently in the window")
    func summaryCountIsWindowed() {
        var c = NotificationCoalescer()
        for t in 0 ... 2 { _ = c.onBlock(at: TimeInterval(t)) } // 3 individual
        #expect(c.onBlock(at: 3) == .summary(count: 4)) // 4 within the 60s window
    }
}
