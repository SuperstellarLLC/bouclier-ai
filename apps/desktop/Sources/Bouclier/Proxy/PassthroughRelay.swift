import BouclierCore
import Darwin
import Dispatch
import Foundation

/// Keeps a running agent session alive across an app quit — cleanly.
///
/// A launched Claude Code process holds `ANTHROPIC_BASE_URL=127.0.0.1:<port>`
/// for its whole lifetime. If the app simply exits, that port dies and the
/// agent's next request is refused. So on quit the app re-spawns *itself*
/// in a headless `--relay` mode that holds the port as a pure passthrough
/// (no inspection, no CA) until either:
///
///   - the app relaunches and **reclaims** it (`reclaim()` at launch), or
///   - it sits **idle** past `idleTimeoutSeconds` and exits on its own.
///
/// The design point is cleanliness: there is **no LaunchAgent, no daemon,
/// no always-on helper, no persistent state**. The relay is a transient
/// bridge that exists only in the gap between quit and relaunch, and the
/// app tidies it up on next launch regardless — so a fresh checkout of the
/// repo installs nothing that outlives the app. This is the open-source
/// "leave no residue" version of keeping the port alive.
///
/// Not covered by design: a hard `SIGKILL` / power loss leaves no chance to
/// hand off. That is the accepted cost of not running a persistent relay;
/// the shell dotfile's fail-open probe still rescues newly-spawned shells,
/// and `reclaim()` cleans up any stale pidfile on the next launch.
enum RelaySupport {
    /// A relay with no traffic for this long exits itself, so a quit-and-
    /// never-relaunch can't leave a process lingering.
    static let idleTimeoutSeconds: Double = 15 * 60

    static var pidfileURL: URL {
        BouclierPaths.appSupportDir.appendingPathComponent("relay.pid")
    }

    // MARK: Activity tracking (for idle self-exit)

    private static let lock = NSLock()
    private nonisolated(unsafe) static var lastActivity = Date()

    static func bumpActivity() {
        lock.lock(); lastActivity = Date(); lock.unlock()
    }

    static func idleSeconds() -> Double {
        lock.lock(); defer { lock.unlock() }
        return Date().timeIntervalSince(lastActivity)
    }

    // MARK: Pidfile

    struct RelayInfo: Equatable {
        let pid: Int32
        let port: Int
        let token: String?

        init(pid: Int32, port: Int, token: String? = nil) {
            self.pid = pid
            self.port = port
            self.token = token
        }
    }

    static func writePidfile(pid: Int32, port: Int, token: String) {
        try? FileManager.default.createDirectory(
            at: BouclierPaths.appSupportDir, withIntermediateDirectories: true
        )
        try? "\(pid)\n\(port)\n\(token)\n".write(
            to: pidfileURL, atomically: true, encoding: .utf8
        )
    }

    static func removePidfile() {
        try? FileManager.default.removeItem(at: pidfileURL)
    }

    static func removePidfile(ifOwnedBy expected: RelayInfo) {
        guard readPidfile() == expected else { return }
        removePidfile()
    }

    /// Parse a `pid\nport\ntoken` pidfile. The two-line legacy form remains
    /// readable so the first token-aware release can reclaim a relay spawned
    /// by the immediately previous app version.
    static func parsePidfile(_ contents: String) -> RelayInfo? {
        let parts = contents.split(whereSeparator: \.isNewline)
        guard parts.count == 2 || parts.count == 3,
              let pid = Int32(parts[0].trimmingCharacters(in: .whitespaces)),
              pid > 1,
              let port = Int(parts[1].trimmingCharacters(in: .whitespaces)),
              (1...65535).contains(port)
        else { return nil }
        let token = parts.count == 3
            ? String(parts[2]).trimmingCharacters(in: .whitespaces)
            : nil
        if let token, UUID(uuidString: token) == nil { return nil }
        return RelayInfo(pid: pid, port: port, token: token?.isEmpty == false ? token : nil)
    }

    static func readPidfile() -> RelayInfo? {
        guard let s = try? String(contentsOf: pidfileURL, encoding: .utf8) else { return nil }
        return parsePidfile(s)
    }

    static func isAlive(_ pid: Int32) -> Bool { pid > 1 && kill(pid, 0) == 0 }

    /// A stale pidfile must never authorize SIGTERM by PID alone: macOS can
    /// reuse that number for an unrelated process. Verify that the live
    /// command is this exact app executable in relay mode, on this port, and
    /// (for new pidfiles) carries the handoff token.
    static func commandLineIdentifiesRelay(
        _ commandLine: String,
        info: RelayInfo,
        expectedExecutablePath: String
    ) -> Bool {
        let executable = URL(fileURLWithPath: expectedExecutablePath)
            .resolvingSymlinksInPath().path
        let suffix: String
        if let token = info.token {
            suffix = " --relay \(info.port) --relay-token \(token)"
        } else {
            suffix = " --relay \(info.port)"
        }
        return commandLine == executable + suffix
    }

    private static func verifiedRelayIsAlive(_ info: RelayInfo) -> Bool {
        guard isAlive(info.pid),
              let expectedExecutable = Bundle.main.executableURL?.resolvingSymlinksInPath().path,
              let observedExecutable = executablePath(of: info.pid),
              observedExecutable == expectedExecutable
        else { return false }

        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/ps")
        process.arguments = ["-ww", "-p", "\(info.pid)", "-o", "command="]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return false }
            let command = String(
                data: output.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8
            )?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return commandLineIdentifiesRelay(
                command, info: info, expectedExecutablePath: expectedExecutable
            )
        } catch {
            return false
        }
    }

    private static func executablePath(of pid: Int32) -> String? {
        guard pid > 1 else { return nil }
        var buffer = [CChar](repeating: 0, count: 4_096)
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }
        let pathBytes = buffer.prefix(Int(length))
            .prefix { $0 != 0 }
            .map { UInt8(bitPattern: $0) }
        guard !pathBytes.isEmpty else { return nil }
        return URL(fileURLWithPath: String(decoding: pathBytes, as: UTF8.self))
            .resolvingSymlinksInPath().path
    }

    // MARK: Lifecycle

    /// Kill any leftover relay and free the port, then drop the pidfile.
    /// Runs at app launch *before* the gateway binds — this is the
    /// "undo the relay work on relaunch" that keeps the system clean
    /// whether the relay self-exited, was force-killed, or is still up.
    static func reclaim() {
        guard let info = readPidfile() else {
            // A malformed/stale file authorizes no process action, but it
            // should not become permanent residue either.
            removePidfile()
            return
        }
        // Verify twice so a process exit/reuse between inspection and signal
        // has the smallest practical race window on macOS (which has no
        // pidfd). Failure is safe: leave the process alone and let the later
        // bind report the occupied port.
        if verifiedRelayIsAlive(info), verifiedRelayIsAlive(info),
           kill(info.pid, SIGTERM) == 0 {
            // Give it up to ~1.5s to release the port before we bind.
            for _ in 0..<15 {
                if !isAlive(info.pid) { break }
                usleep(100_000)
            }
        }
        removePidfile(ifOwnedBy: info)
    }

    /// Spawn a detached passthrough relay to hold `port` after the app
    /// exits. Best-effort; called from `applicationWillTerminate`, which
    /// runs in normal process context (unlike a signal handler), so a
    /// plain `Process` launch is safe. The child is reparented to launchd
    /// when we exit and keeps running.
    static func handOff(port: Int) {
        guard let exe = Bundle.main.executableURL else { return }
        let token = UUID().uuidString.lowercased()
        let p = Process()
        p.executableURL = exe
        p.arguments = ["--relay", "\(port)", "--relay-token", token]
        try? p.run() // do not wait — it must outlive us
    }
}

/// The `--relay <port> <token>` entry point: a headless, inspection-free gateway.
enum RelayMode {
    /// Runs the passthrough relay and blocks forever (until reclaimed or
    /// idle). Never returns.
    static func run(port: Int, token: String) -> Never {
        let identity = RelaySupport.RelayInfo(pid: getpid(), port: port, token: token)
        RelaySupport.writePidfile(pid: identity.pid, port: identity.port, token: token)
        RelaySupport.bumpActivity()

        // Clean shutdown on SIGTERM (the app reclaiming us): drop the
        // pidfile so no stale entry survives. DispatchSource lets us do
        // real work in the handler, unlike a C signal function.
        signal(SIGTERM, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        term.setEventHandler {
            RelaySupport.removePidfile(ifOwnedBy: identity)
            exit(0)
        }
        term.resume()

        // Pure passthrough: inspection permanently off, traffic just
        // relayed. Reuses the exact same gateway the app runs — the only
        // difference is nobody inspects.
        let gateway = GatewayServer(
            port: port,
            inspectionEnabled: { false },
            onRequest: { _ in RelaySupport.bumpActivity() }
        )

        // The app is releasing the port as we start; retry the bind for a
        // few seconds rather than losing the race.
        Task {
            for attempt in 0..<25 {
                do {
                    _ = try await gateway.start()
                    return
                } catch {
                    if attempt == 24 {
                        RelaySupport.removePidfile(ifOwnedBy: identity)
                        exit(1)
                    }
                    try? await Task.sleep(nanoseconds: 200_000_000)
                }
            }
        }

        // Idle self-exit: if no traffic for the timeout, tidy up and go.
        let idle = DispatchSource.makeTimerSource(queue: .main)
        idle.schedule(deadline: .now() + 60, repeating: 60)
        idle.setEventHandler {
            if RelaySupport.idleSeconds() > RelaySupport.idleTimeoutSeconds {
                RelaySupport.removePidfile(ifOwnedBy: identity)
                exit(0)
            }
        }
        idle.resume()

        dispatchMain()
    }
}
