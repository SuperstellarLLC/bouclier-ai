import Foundation

/// A state-changing action an agent *proposes* and the user *approves*
/// out-of-band in Bouclier's own dialog — the same IPC handshake as a
/// secret request, generalized. Used for YELLOW operations like
/// `enable_protection`. The invariant holds: the agent never mutates app
/// state directly, and no secret value ever crosses this envelope (params
/// and result are plain strings: a mode, a name, a status).
public struct ActionRequestIPC: Codable, Sendable, Equatable {
    public let id: String
    public let schemaVersion: Int
    public let action: String          // discriminator, e.g. "enable_protection"
    public let params: [String: String]
    public let reason: String          // agent's untrusted explanation, shown to the human
    public let createdAt: Double

    public init(id: String, schemaVersion: Int = 1, action: String, params: [String: String], reason: String, createdAt: Double) {
        self.id = id; self.schemaVersion = schemaVersion; self.action = action
        self.params = params; self.reason = reason; self.createdAt = createdAt
    }
}

public struct ActionResponseIPC: Codable, Sendable, Equatable {
    public enum Status: String, Codable, Sendable {
        case approved      // user approved; the app performed the action
        case declined      // user declined
        case timeout       // no response in time
        case invalid       // malformed / stale / bad params
        case unsupported   // unknown action
    }
    public let id: String
    public let action: String
    public let status: Status
    public let result: [String: String]   // action-specific, NEVER a value
    public let message: String            // human-readable, safe for the model

    public init(id: String, action: String, status: Status, result: [String: String] = [:], message: String) {
        self.id = id; self.action = action; self.status = status; self.result = result; self.message = message
    }
}

/// Peek at a request file to tell an action envelope from a secret request
/// (both live in `requests/`). An `action` key ⇒ action envelope.
public struct IPCEnvelopePeek: Codable {
    public let action: String?
}

/// Agent/MCP/CLI side: propose an action, block until the user approves or
/// declines (or we time out / can't reach the app).
public enum ActionClient {
    public enum Failure: Error, Equatable { case responderNotRunning, ioError }

    public static func request(
        action: String,
        params: [String: String] = [:],
        reason: String,
        timeout: TimeInterval = 120,
        pollIntervalMicros: useconds_t = 120_000,
        requestsDir: URL = SecretEnvPaths.ipcRequestsDir,
        responsesDir: URL = SecretEnvPaths.ipcResponsesDir,
        pidFile: URL = SecretEnvPaths.responderPidFile,
        now: () -> Date = { Date() }
    ) throws -> ActionResponseIPC {
        guard SecretRequestClient.isResponderAlive(pidFile: pidFile) else { throw Failure.responderNotRunning }

        let id = UUID().uuidString
        let reqURL = requestsDir.appendingPathComponent("\(id).json")
        let respURL = responsesDir.appendingPathComponent("\(id).json")
        let payload = ActionRequestIPC(id: id, action: action, params: params, reason: reason, createdAt: now().timeIntervalSince1970)
        guard let data = try? JSONEncoder().encode(payload) else { throw Failure.ioError }
        do { try AtomicFile.write(data, to: reqURL) } catch { throw Failure.ioError }

        let deadline = now().addingTimeInterval(timeout)
        var ticks = 0
        while now() < deadline {
            if let rdata = try? Data(contentsOf: respURL),
               let resp = try? JSONDecoder().decode(ActionResponseIPC.self, from: rdata) {
                try? FileManager.default.removeItem(at: respURL)
                try? FileManager.default.removeItem(at: reqURL)
                return resp
            }
            ticks += 1
            if ticks % 16 == 0, !SecretRequestClient.isResponderAlive(pidFile: pidFile) {
                try? FileManager.default.removeItem(at: reqURL)
                throw Failure.responderNotRunning
            }
            usleep(pollIntervalMicros)
        }
        try? FileManager.default.removeItem(at: reqURL)
        return ActionResponseIPC(id: id, action: action, status: .timeout, message: "No response from the user.")
    }
}
