import Foundation

/// Per-host suppression of the PII preview modal.
///
/// **Why per-host, not per-day.** The consultant flagged that "Don't
/// ask again today" was the wrong axis: a user is happy to keep seeing
/// the preview for some hosts (a brand-new endpoint they don't trust
/// yet) while wanting it gone for others (their everyday Claude
/// Desktop traffic). Per-host preserves user judgement at the
/// granularity where it actually matters.
///
/// Storage: a single JSON-encoded `[String: Date]` in UserDefaults
/// where the key is a lowercased suffix-matched host and the value is
/// the time at which suppression expires (`Date.distantFuture` for
/// permanent suppression — same semantics as macOS notification
/// "Don't ask again", which is permanent until reset).
enum PreviewSuppression {
    static let storageKey = "piiPreviewSuppressedHosts"

    /// Suppress the preview for the given host. Suffix-matched at read
    /// time, so suppressing `openai.com` also suppresses
    /// `api.openai.com`.
    static func suppress(host: String) {
        guard !host.isEmpty else { return }
        var map = readMap()
        map[host.lowercased()] = Date.distantFuture
        writeMap(map)
    }

    /// Should the preview be shown for this host? Returns true iff no
    /// suppression rule covers the host.
    static func shouldShowPreview(forHost host: String) -> Bool {
        let normalized = host.lowercased()
        let map = readMap()
        let now = Date()
        for (rule, until) in map {
            if normalized.hasSuffix(rule), until > now { return false }
        }
        return true
    }

    /// Clear all suppression rules. Surfaced in Settings as "Reset
    /// preview suppressions" so users who once said "don't ask again"
    /// can reverse the decision.
    static func clearAll() {
        UserDefaults.standard.removeObject(forKey: storageKey)
    }

    // MARK: - Storage

    private static func readMap() -> [String: Date] {
        guard let raw = UserDefaults.standard.string(forKey: storageKey),
              let data = raw.data(using: .utf8),
              let decoded = try? JSONDecoder().decode([String: Date].self, from: data)
        else { return [:] }
        return decoded
    }

    private static func writeMap(_ map: [String: Date]) {
        guard let data = try? JSONEncoder().encode(map),
              let str = String(data: data, encoding: .utf8)
        else { return }
        UserDefaults.standard.set(str, forKey: storageKey)
    }
}
