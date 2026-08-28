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
        /// Request-level monitor findings allowed for forwarding.
        public let injectionFindingsFlagged: Int
        /// Requests for which body inspection did not run (including
        /// passthrough, unavailable engine, size, or encoding limits).
        public let requestsSkippedInspection: Int
        /// Coverage-policy refusals with no detector verdict.
        public let requestsBlockedByInspectionLimit: Int

        public init(
            requestsScanned: Int,
            injectionsBlocked: Int,
            injectionFindingsFlagged: Int = 0,
            requestsSkippedInspection: Int = 0,
            requestsBlockedByInspectionLimit: Int = 0
        ) {
            self.requestsScanned = requestsScanned
            self.injectionsBlocked = injectionsBlocked
            self.injectionFindingsFlagged = injectionFindingsFlagged
            self.requestsSkippedInspection = requestsSkippedInspection
            self.requestsBlockedByInspectionLimit = requestsBlockedByInspectionLimit
        }

        private enum CodingKeys: String, CodingKey {
            case requestsScanned, injectionsBlocked, injectionFindingsFlagged
            case requestsSkippedInspection, requestsBlockedByInspectionLimit
        }

        public init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            requestsScanned = try container.decode(Int.self, forKey: .requestsScanned)
            injectionsBlocked = try container.decode(Int.self, forKey: .injectionsBlocked)
            injectionFindingsFlagged = try container.decodeIfPresent(
                Int.self, forKey: .injectionFindingsFlagged
            ) ?? 0
            requestsSkippedInspection = try container.decodeIfPresent(
                Int.self, forKey: .requestsSkippedInspection
            ) ?? 0
            requestsBlockedByInspectionLimit = try container.decodeIfPresent(
                Int.self, forKey: .requestsBlockedByInspectionLimit
            ) ?? 0
        }
    }

    /// Schema 3 added `blockingEnabled`; schema 4 added honest monitor/skip/
    /// coverage-refusal activity counts; schema 5 exposes the active detector
    /// tiers; schema 6 distinguishes enabled protection from a detector that
    /// policy has disabled. All additions decode with safe defaults so rolling
    /// app/CLI upgrades remain compatible.
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
    /// True only when the gateway listener is running, protection is enabled,
    /// and the request detector is actually allowed to inspect traffic. A
    /// false value with requested protection is not monitor mode.
    public let detectorEnabled: Bool
    /// True when suspicious untrusted content can be refused. False means
    /// either the live detector is monitor-only or it is disabled; callers
    /// must consult `detectorEnabled` to distinguish those states.
    public let blockingEnabled: Bool
    /// Enabled signed/runtime pattern count (zero means unknown on old schema).
    public let patternCount: Int
    /// One of `active`, `loading`, `unavailable`, or `unknown`.
    public let mlClassifierState: String
    public let activity: Activity

    public init(schemaVersion: Int = 6, writtenAt: Double, pid: Int32, appVersion: String,
                running: Bool, mode: String, caInstalled: Bool, protectionEnabled: Bool,
                detectorEnabled: Bool = true, blockingEnabled: Bool = false, patternCount: Int = 0,
                mlClassifierState: String = "unknown", activity: Activity) {
        self.schemaVersion = schemaVersion; self.writtenAt = writtenAt; self.pid = pid
        self.appVersion = appVersion; self.running = running; self.mode = mode
        self.caInstalled = caInstalled; self.protectionEnabled = protectionEnabled
        // Callers compiled against the pre-v6 initializer naturally inherit
        // the old assumption that enabled protection has a working detector.
        // New publishers pass the effective value explicitly.
        self.detectorEnabled = running && protectionEnabled && detectorEnabled
        self.blockingEnabled = self.detectorEnabled && blockingEnabled
        self.patternCount = patternCount
        self.mlClassifierState = mlClassifierState
        self.activity = activity
    }

    private enum CodingKeys: String, CodingKey {
        case schemaVersion, writtenAt, pid, appVersion, running, mode
        case caInstalled, protectionEnabled, detectorEnabled, blockingEnabled, patternCount
        case mlClassifierState, activity
    }

    /// Schema 2 snapshots remain readable during a rolling app/CLI upgrade.
    /// They predate the monitoring-vs-blocking field, and the historically
    /// accurate interpretation is monitor-only rather than silently claiming
    /// enforcement.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decode(Int.self, forKey: .schemaVersion)
        writtenAt = try container.decode(Double.self, forKey: .writtenAt)
        pid = try container.decode(Int32.self, forKey: .pid)
        appVersion = try container.decode(String.self, forKey: .appVersion)
        running = try container.decode(Bool.self, forKey: .running)
        mode = try container.decode(String.self, forKey: .mode)
        caInstalled = try container.decode(Bool.self, forKey: .caInstalled)
        protectionEnabled = try container.decode(Bool.self, forKey: .protectionEnabled)
        // Pre-v6 snapshots cannot express the managed detector kill switch.
        // Preserve their historical meaning: protection on implied detection
        // on for a live listener, while passthrough/stopped implied no
        // effective detector. Schema 6+ omissions fail closed.
        let decodedDetector = try container.decodeIfPresent(
            Bool.self, forKey: .detectorEnabled
        ) ?? (schemaVersion < 6)
        detectorEnabled = running && protectionEnabled && decodedDetector
        let decodedBlocking = try container.decodeIfPresent(
            Bool.self, forKey: .blockingEnabled
        ) ?? false
        blockingEnabled = detectorEnabled && decodedBlocking
        patternCount = try container.decodeIfPresent(Int.self, forKey: .patternCount) ?? 0
        mlClassifierState = try container.decodeIfPresent(
            String.self, forKey: .mlClassifierState
        ) ?? "unknown"
        activity = try container.decode(Activity.self, forKey: .activity)
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
