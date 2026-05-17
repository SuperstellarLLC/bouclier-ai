import Foundation

/// Operator panic switch: pause PII redaction for a short window.
///
/// **Why this exists.** A redaction can break an agent loop mid-demo
/// (false positive on a SIRET that's a part number, model refusing to
/// use a placeholder, etc.). The operator needs a single one-click
/// "get out of my way" button without having to dig through Settings.
///
/// **Behavior.** When `pause(for:)` is called, `pausedUntil` is set to
/// `Date() + duration`. Until that moment, `isPaused()` returns true
/// and `FeatureFlags.piiRedaction` treats the feature as off. The TTL
/// is stored in UserDefaults so the pause survives a menu-bar reopen
/// but a fresh app launch always starts unpaused (we don't want a
/// pause to leak across days).
enum RedactionPause {
    /// AppStorage / UserDefaults key for the resume time. Stored as
    /// Date.timeIntervalSinceReferenceDate so SwiftUI's @AppStorage
    /// can read/write the same value with a Double bridge.
    static let pausedUntilKey = "piiRedactionPausedUntil"

    /// Common pause durations exposed in the menu UI.
    static let presets: [(label: String, seconds: TimeInterval)] = [
        ("1 minute", 60),
        ("5 minutes", 300),
        ("15 minutes", 900),
        ("1 hour", 3600),
    ]

    /// Start a pause of the given duration. The TTL also caps at
    /// session boundaries — a fresh `BouclierApp` launch clears the
    /// key in its init so a pause doesn't outlive a restart.
    static func pause(for duration: TimeInterval, now: Date = Date()) {
        let until = now.addingTimeInterval(duration)
        UserDefaults.standard.set(until.timeIntervalSinceReferenceDate, forKey: pausedUntilKey)
    }

    /// Clear any pending pause.
    static func resume() {
        UserDefaults.standard.removeObject(forKey: pausedUntilKey)
    }

    /// Date the pause ends, or `nil` if not paused.
    static func pausedUntil(now: Date = Date()) -> Date? {
        guard UserDefaults.standard.object(forKey: pausedUntilKey) != nil else { return nil }
        let raw = UserDefaults.standard.double(forKey: pausedUntilKey)
        let until = Date(timeIntervalSinceReferenceDate: raw)
        if until <= now {
            // Stale pause expired between writes; clean it up
            // opportunistically so the menu doesn't keep showing
            // a paused state.
            UserDefaults.standard.removeObject(forKey: pausedUntilKey)
            return nil
        }
        return until
    }

    /// True iff redaction is currently paused.
    static func isPaused(now: Date = Date()) -> Bool {
        pausedUntil(now: now) != nil
    }

    /// Seconds remaining on the pause, or 0 when not paused. Surfaced
    /// in the menu bar as a live countdown.
    static func secondsRemaining(now: Date = Date()) -> Int {
        guard let until = pausedUntil(now: now) else { return 0 }
        return max(0, Int(until.timeIntervalSince(now).rounded()))
    }
}
