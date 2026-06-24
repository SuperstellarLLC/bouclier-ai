import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Just-in-time secret request: the agent (via the MCP server) asks the
/// user — through Bouclier's own dialog — to supply secret values, so the
/// agent can USE them without ever SEEing them.
///
/// CARDINAL RULE: neither this request nor its response ever carries a
/// secret VALUE. The request carries the requested env-var names + the
/// agent's (untrusted) reason; the response carries only which names were
/// provided/skipped and a status. The real values go from the user's
/// keystrokes → the app → the Keychain, never through these files, the MCP
/// channel, or the model's context.
public struct SecretRequestIPC: Codable, Sendable, Equatable {
    public let id: String
    public let envVars: [String]
    public let reason: String
    public let createdAt: Double   // epoch seconds
    /// The agent is asking Bouclier to CREATE these secrets (random
    /// values), not paste existing ones — the dialog pre-fills generated
    /// values the user reviews/approves. Still never seen by the agent.
    public let generate: Bool

    public init(id: String, envVars: [String], reason: String, createdAt: Double, generate: Bool = false) {
        self.id = id
        self.envVars = envVars
        self.reason = reason
        self.createdAt = createdAt
        self.generate = generate
    }

    enum CodingKeys: String, CodingKey { case id, envVars, reason, createdAt, generate }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        envVars = try c.decode([String].self, forKey: .envVars)
        reason = (try c.decodeIfPresent(String.self, forKey: .reason)) ?? ""
        createdAt = (try c.decodeIfPresent(Double.self, forKey: .createdAt)) ?? 0
        generate = (try c.decodeIfPresent(Bool.self, forKey: .generate)) ?? false
    }
}

public struct SecretResponseIPC: Codable, Sendable, Equatable {
    public enum Status: String, Codable, Sendable {
        case provided   // at least one value entered
        case cancelled  // user dismissed / declined
        case timeout    // no one answered in time
        case invalid    // app rejected the request (stale / bad names) — no dialog shown
    }
    public let id: String
    public let status: Status
    public let provided: [String]  // env-var names that received a value
    public let skipped: [String]   // requested but left blank

    public init(id: String, status: Status, provided: [String], skipped: [String]) {
        self.id = id
        self.status = status
        self.provided = provided
        self.skipped = skipped
    }
}

/// Atomic file write: temp file in the SAME directory, 0600 from birth,
/// fsync, then rename(2) — so a watcher never observes a partial file and
/// the file is never briefly world-readable. (`Data.write(.atomic)` also
/// renames, but this guarantees same-dir temp + 0600-at-creation, which we
/// want for a security product.)
public enum AtomicFile {
    public static func write(_ data: Data, to dst: URL) throws {
        let dir = dst.deletingLastPathComponent()
        let tmp = dir.appendingPathComponent(".tmp-\(UUID().uuidString)")
        let fd = open(tmp.path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var closed = false
        func closeFd() { if !closed { close(fd); closed = true } }
        defer { closeFd() }
        try data.withUnsafeBytes { raw in
            guard var p = raw.baseAddress else { return }
            var left = raw.count
            while left > 0 {
                let n = Darwin.write(fd, p, left)
                if n < 0 {
                    let e = errno
                    unlink(tmp.path)
                    throw POSIXError(POSIXErrorCode(rawValue: e) ?? .EIO)
                }
                p = p.advanced(by: n); left -= n
            }
        }
        fsync(fd)
        closeFd()
        if rename(tmp.path, dst.path) != 0 {
            let e = errno
            unlink(tmp.path)
            throw POSIXError(POSIXErrorCode(rawValue: e) ?? .EIO)
        }
    }
}

/// MCP-server side of the handshake: drop a request, block until the app
/// answers (or we time out / can't reach it).
public enum SecretRequestClient {
    public enum Failure: Error, Equatable { case responderNotRunning, ioError }

    /// Is the Bouclier app alive? Read the pid file and probe with
    /// `kill(pid, 0)` (sends no signal). EPERM still means "exists".
    public static func isResponderAlive(pidFile: URL = SecretEnvPaths.responderPidFile) -> Bool {
        guard let s = try? String(contentsOf: pidFile, encoding: .utf8),
              let pid = pid_t(s.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 0
        else { return false }
        let r = kill(pid, 0)
        return r == 0 || (r == -1 && errno == EPERM)
    }

    /// Write a request and poll for the response. Returns the response
    /// (which may be `.timeout`); throws `responderNotRunning` if the app
    /// isn't there, so the agent gets an immediate, honest failure.
    public static func request(
        envVars: [String],
        reason: String,
        generate: Bool = false,
        timeout: TimeInterval = 120,
        pollIntervalMicros: useconds_t = 120_000,
        requestsDir: URL = SecretEnvPaths.ipcRequestsDir,
        responsesDir: URL = SecretEnvPaths.ipcResponsesDir,
        pidFile: URL = SecretEnvPaths.responderPidFile,
        now: () -> Date = { Date() }
    ) throws -> SecretResponseIPC {
        guard isResponderAlive(pidFile: pidFile) else { throw Failure.responderNotRunning }

        let id = UUID().uuidString
        let reqURL = requestsDir.appendingPathComponent("\(id).json")
        let respURL = responsesDir.appendingPathComponent("\(id).json")
        let payload = SecretRequestIPC(id: id, envVars: envVars, reason: reason, createdAt: now().timeIntervalSince1970, generate: generate)
        guard let data = try? JSONEncoder().encode(payload) else { throw Failure.ioError }
        do { try AtomicFile.write(data, to: reqURL) } catch { throw Failure.ioError }

        let deadline = now().addingTimeInterval(timeout)
        var ticks = 0
        while now() < deadline {
            if let rdata = try? Data(contentsOf: respURL),
               let resp = try? JSONDecoder().decode(SecretResponseIPC.self, from: rdata) {
                try? FileManager.default.removeItem(at: respURL)
                try? FileManager.default.removeItem(at: reqURL)
                return resp
            }
            // Re-check liveness ~every 2s so we bail early if the app dies.
            ticks += 1
            if ticks % 16 == 0, !isResponderAlive(pidFile: pidFile) {
                try? FileManager.default.removeItem(at: reqURL)
                throw Failure.responderNotRunning
            }
            usleep(pollIntervalMicros)
        }
        try? FileManager.default.removeItem(at: reqURL)
        return SecretResponseIPC(id: id, status: .timeout, provided: [], skipped: envVars)
    }
}

/// App side: validate an incoming request file before showing a dialog.
/// Pure + testable — the file is untrusted input from any local process.
public enum SecretRequestValidator {
    public static let maxFileBytes = 16 * 1024
    public static let maxEnvVars = 50
    public static let maxReasonChars = 2000
    public static let staleAfterSeconds: Double = 150  // older than this ⇒ requester gave up

    public enum Rejection: Error, Equatable { case tooLarge, malformed, stale, noValidEnvVars }

    /// Validate raw request bytes. Returns a sanitized request (deduped,
    /// valid env-var names only, clamped reason) or a rejection reason.
    public static func validate(data: Data, now: Date = Date()) -> Result<SecretRequestIPC, Rejection> {
        guard data.count <= maxFileBytes else { return .failure(.tooLarge) }
        guard let req = try? JSONDecoder().decode(SecretRequestIPC.self, from: data), !req.id.isEmpty else {
            return .failure(.malformed)
        }
        if now.timeIntervalSince1970 - req.createdAt > staleAfterSeconds { return .failure(.stale) }
        // Keep only well-formed env-var names (defense at the executor: these
        // become shell `export` targets). Dedupe, cap count.
        var seen = Set<String>()
        let names = req.envVars
            .filter { SecretEnvResolver.isValidEnvName($0) && seen.insert($0).inserted }
            .prefix(maxEnvVars)
        guard !names.isEmpty else { return .failure(.noValidEnvVars) }
        let reason = String(req.reason.prefix(maxReasonChars))
        return .success(SecretRequestIPC(id: req.id, envVars: Array(names), reason: reason, createdAt: req.createdAt, generate: req.generate))
    }
}
