import Foundation

/// Coalesces a burst of block notifications so a false-positive storm — many
/// tool_results blocked in one agent session — doesn't fire a banner per block.
///
/// The first `burstThreshold` blocks in a rolling `window` each show their own
/// banner (the common case: a stray block or two, where the pattern + locator
/// matter). Past that, individual banners are suppressed and one coalesced
/// summary is shown per `summaryThrottle` interval. Once the window clears, it
/// resets to individual banners.
///
/// Pure and deterministic — `now` is injected — so the decision logic is
/// unit-testable without a wall clock or `UNUserNotificationCenter`.
struct NotificationCoalescer {
    /// Rolling window (seconds) over which blocks are counted.
    var window: TimeInterval = 60
    /// How many blocks in the window still show individual banners.
    var burstThreshold: Int = 3
    /// Minimum spacing (seconds) between coalesced summary banners.
    var summaryThrottle: TimeInterval = 60

    enum Decision: Equatable {
        /// Show the normal per-block banner.
        case individual
        /// Show a coalesced summary banner standing for `count` blocks in the window.
        case summary(count: Int)
        /// Inside a burst, already summarized within the throttle — stay quiet.
        case suppress
    }

    private var recent: [TimeInterval] = []
    private var lastSummary: TimeInterval?

    /// Record a block at `now` and decide how (or whether) to notify.
    mutating func onBlock(at now: TimeInterval) -> Decision {
        recent = recent.filter { now - $0 < window }
        recent.append(now)

        if recent.count <= burstThreshold {
            return .individual
        }
        if let last = lastSummary, now - last < summaryThrottle {
            return .suppress
        }
        lastSummary = now
        return .summary(count: recent.count)
    }
}
