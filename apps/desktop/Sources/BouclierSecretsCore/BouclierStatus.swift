import Foundation

/// A read-only snapshot of Bouclier's state, published by the app to
/// `status.json` and read by the MCP server / CLI so an agent can orient
/// itself ("is protection on? which mode? is the secret keeper healthy?")
/// before doing anything. Counts only — NEVER a secret value.
public struct BouclierStatus: Codable, Sendable, Equatable {
    public struct SecretKeeper: Codable, Sendable, Equatable {
        public let enabled: Bool
        public let healthy: Bool
        public let circuitBreakerTripped: Bool
        public init(enabled: Bool, healthy: Bool, circuitBreakerTripped: Bool) {
            self.enabled = enabled; self.healthy = healthy; self.circuitBreakerTripped = circuitBreakerTripped
        }
    }
    public struct Secrets: Codable, Sendable, Equatable {
        public let total: Int
        public let agentAccessible: Int
        public let active: Int
        public init(total: Int, agentAccessible: Int, active: Int) {
            self.total = total; self.agentAccessible = agentAccessible; self.active = active
        }
    }
    public struct Activity: Codable, Sendable, Equatable {
        public let requestsScanned: Int
        public let injectionsBlocked: Int
        public let secretsScrubbed: Int
        public let secretsInjected: Int
        public let secretsBlocked: Int
        public init(requestsScanned: Int, injectionsBlocked: Int, secretsScrubbed: Int, secretsInjected: Int, secretsBlocked: Int) {
            self.requestsScanned = requestsScanned; self.injectionsBlocked = injectionsBlocked
            self.secretsScrubbed = secretsScrubbed; self.secretsInjected = secretsInjected; self.secretsBlocked = secretsBlocked
        }
    }

    public let schemaVersion: Int
    public let writtenAt: Double   // epoch seconds — readers compute staleness
    public let pid: Int32
    public let appVersion: String
    public let running: Bool
    public let mode: String        // "standard" | "extreme"
    public let caInstalled: Bool
    public let protectionEnabled: Bool
    public let secretKeeper: SecretKeeper
    public let secrets: Secrets
    public let activity: Activity

    public init(schemaVersion: Int = 1, writtenAt: Double, pid: Int32, appVersion: String,
                running: Bool, mode: String, caInstalled: Bool, protectionEnabled: Bool,
                secretKeeper: SecretKeeper, secrets: Secrets, activity: Activity) {
        self.schemaVersion = schemaVersion; self.writtenAt = writtenAt; self.pid = pid
        self.appVersion = appVersion; self.running = running; self.mode = mode
        self.caInstalled = caInstalled; self.protectionEnabled = protectionEnabled
        self.secretKeeper = secretKeeper; self.secrets = secrets; self.activity = activity
    }
}

/// Reads `status.json` and reports an honest state: a present-but-stale or
/// orphaned snapshot is reported as not-running, never trusted as live.
public enum StatusReader {
    public static let staleThresholdSeconds: Double = 20  // 4× the 5s publish interval

    public enum State: Sendable, Equatable {
        case running(BouclierStatus)
        case notRunning(reason: String)
    }

    public static func read(
        statusFile: URL = SecretEnvPaths.statusFile,
        pidFile: URL = SecretEnvPaths.responderPidFile,
        now: Date = Date()
    ) -> State {
        guard let data = try? Data(contentsOf: statusFile),
              let s = try? JSONDecoder().decode(BouclierStatus.self, from: data)
        else {
            return SecretRequestClient.isResponderAlive(pidFile: pidFile)
                ? .notRunning(reason: "Bouclier is starting up")
                : .notRunning(reason: "Bouclier is not running")
        }
        if now.timeIntervalSince1970 - s.writtenAt > staleThresholdSeconds {
            return .notRunning(reason: "Bouclier status is stale — the app may have crashed")
        }
        guard SecretRequestClient.isResponderAlive(pidFile: pidFile) else {
            return .notRunning(reason: "Bouclier is not running")
        }
        return .running(s)
    }
}
