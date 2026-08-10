import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// A read-only snapshot of Bouclier's state, published by the app to
/// `status.json` and read by the CLI so an agent can orient itself ("is
/// protection on? which mode? how much has it inspected?") before doing
/// anything. Counts only — never request content.
public struct BouclierStatus: Codable, Sendable, Equatable {
    public struct Activity: Codable, Sendable, Equatable {
        public let requestsScanned: Int
        public let injectionsBlocked: Int
        public init(requestsScanned: Int, injectionsBlocked: Int) {
            self.requestsScanned = requestsScanned
            self.injectionsBlocked = injectionsBlocked
        }
    }

    /// Bumped to 2 when the secret-keeper fields were removed. Older readers
    /// that expected schema 1 will treat a v2 snapshot as decodable (the
    /// removed fields were non-optional there, so a v1 reader against v2 data
    /// simply fails to decode and reports not-running — acceptable across an
    /// app+CLI upgrade that ship together).
    public let schemaVersion: Int
    public let writtenAt: Double   // epoch seconds — readers compute staleness
    public let pid: Int32
    public let appVersion: String
    public let running: Bool
    /// Always "standard" now — extreme mode (CA-based interception) was
    /// removed. Kept as a field (rather than dropped) for status-schema
    /// stability; see `ProxyMode`.
    public let mode: String
    /// Always false now — extreme mode was the only feature that ever
    /// installed a CA. Kept for status-schema stability.
    public let caInstalled: Bool
    public let protectionEnabled: Bool
    public let activity: Activity

    public init(schemaVersion: Int = 2, writtenAt: Double, pid: Int32, appVersion: String,
                running: Bool, mode: String, caInstalled: Bool, protectionEnabled: Bool,
                activity: Activity) {
        self.schemaVersion = schemaVersion; self.writtenAt = writtenAt; self.pid = pid
        self.appVersion = appVersion; self.running = running; self.mode = mode
        self.caInstalled = caInstalled; self.protectionEnabled = protectionEnabled
        self.activity = activity
    }
}

/// Reads `status.json` and reports an honest state: a present-but-stale or
/// orphaned snapshot is reported as not-running, never trusted as live.
/// Liveness is proven by the pid carried in the snapshot itself
/// (`kill(pid, 0)`), so there is no separate pid file to keep in sync.
public enum StatusReader {
    public static let staleThresholdSeconds: Double = 20  // 4× the 5s publish interval

    public enum State: Sendable, Equatable {
        case running(BouclierStatus)
        case notRunning(reason: String)
    }

    public static func read(
        statusFile: URL = BouclierPaths.statusFile,
        now: Date = Date()
    ) -> State {
        guard let data = try? Data(contentsOf: statusFile),
              let s = try? JSONDecoder().decode(BouclierStatus.self, from: data)
        else {
            return .notRunning(reason: "Bouclier is not running")
        }
        if now.timeIntervalSince1970 - s.writtenAt > staleThresholdSeconds {
            return .notRunning(reason: "Bouclier status is stale — the app may have crashed")
        }
        guard isProcessAlive(s.pid) else {
            return .notRunning(reason: "Bouclier is not running")
        }
        return .running(s)
    }

    /// Probe with `kill(pid, 0)` (sends no signal). EPERM still means "exists".
    static func isProcessAlive(_ pid: Int32) -> Bool {
        guard pid > 0 else { return false }
        let r = kill(pid, 0)
        return r == 0 || (r == -1 && errno == EPERM)
    }
}
