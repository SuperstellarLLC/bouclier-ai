import Foundation

/// One-shot cleanup of UserDefaults keys that belonged to the
/// pre-v0.6 text-PII redactor / pause / preview / per-host policy
/// surface. None of those features exist anymore — the keys are pure
/// cruft on upgrade, and a future code reader greps for them and
/// wonders why they're set.
///
/// Keyed on a sentinel default so the work runs exactly once per
/// user, regardless of how many times the app launches. Not a SQLite
/// migration because there's no DB involved — these are all plain
/// `UserDefaults` keys.
enum LegacyDefaultsCleanup {
    /// Sentinel that records the scrub already ran. Once set, the
    /// scrubber is a no-op even if more keys are added to the list
    /// below (we'd just bump the sentinel name to re-run).
    static let sentinelKey = "bouclier.legacyScopeCutScrubDone.v1"

    /// Every UserDefaults key that v0.6 no longer reads. Listed
    /// explicitly so the audit trail is clear and so a future grep
    /// for any one of these keys lands in this file.
    static let removedKeys: [String] = [
        // Text-redaction feature toggle + sub-toggles
        "piiRedactionEnabled",
        "piiRedactionEnabledOverridden",      // .overridden sentinels
        "piiPreviewBeforeSend",
        "strictCredentialRedactionEnabled",
        // Operator pause + preview suppression
        "piiRedactionPausedUntil",
        "piiPreviewSuppressedHosts",
        // Per-host allow/deny lists for text redaction
        "piiAllowDomains",
        "piiAllowDomains.overridden",
        "piiDenyDomains",
        "piiDenyDomains.overridden",
    ]

    /// Run the scrub if it hasn't run yet on this device. Safe to call
    /// from `BouclierApp.init` — the operations are pure UserDefaults
    /// writes and complete in microseconds.
    static func runIfNeeded(defaults: UserDefaults = .standard) {
        guard !defaults.bool(forKey: sentinelKey) else { return }
        for key in removedKeys {
            defaults.removeObject(forKey: key)
        }
        defaults.set(true, forKey: sentinelKey)
    }
}
