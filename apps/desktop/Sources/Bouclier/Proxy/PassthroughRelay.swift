import BouclierCore
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
    }

    static func writePidfile(pid: Int32, port: Int) {
        try? FileManager.default.createDirectory(
            at: BouclierPaths.appSupportDir, withIntermediateDirectories: true
        )
        try? "\(pid)\n\(port)\n".write(to: pidfileURL, atomically: true, encoding: .utf8)
    }

    static func removePidfile() {
        try? FileManager.default.removeItem(at: pidfileURL)
    }

    /// Parse a `pid\nport` pidfile. Pure and total — exposed for tests.
    static func parsePidfile(_ contents: String) -> RelayInfo? {
        let parts = contents.split(whereSeparator: \.isNewline)
        guard parts.count >= 2,
              let pid = Int32(parts[0].trimmingCharacters(in: .whitespaces)),
              let port = Int(parts[1].trimmingCharacters(in: .whitespaces))
        else { return nil }
        return RelayInfo(pid: pid, port: port)
    }

    static func readPidfile() -> RelayInfo? {
        guard let s = try? String(contentsOf: pidfileURL, encoding: .utf8) else { return nil }
        return parsePidfile(s)
    }

    static func isAlive(_ pid: Int32) -> Bool { kill(pid, 0) == 0 }

    // MARK: Lifecycle

    /// Kill any leftover relay and free the port, then drop the pidfile.
    /// Runs at app launch *before* the gateway binds — this is the
    /// "undo the relay work on relaunch" that keeps the system clean
    /// whether the relay self-exited, was force-killed, or is still up.
    static func reclaim() {
        guard let info = readPidfile() else { return }
        if isAlive(info.pid) {
            kill(info.pid, SIGTERM)
            // Give it up to ~1.5s to release the port before we bind.
            for _ in 0..<15 {
                if !isAlive(info.pid) { break }
                usleep(100_000)
            }
        }
        removePidfile()
    }

    /// Spawn a detached passthrough relay to hold `port` after the app
    /// exits. Best-effort; called from `applicationWillTerminate`, which
    /// runs in normal process context (unlike a signal handler), so a
    /// plain `Process` launch is safe. The child is reparented to launchd
    /// when we exit and keeps running.
    static func handOff(port: Int) {
        guard let exe = Bundle.main.executableURL else { return }
        let p = Process()
        p.executableURL = exe
        p.arguments = ["--relay", "\(port)"]
        try? p.run() // do not wait — it must outlive us
    }
}

/// The `--relay <port>` entry point: a headless, inspection-free gateway.
enum RelayMode {
    /// Runs the passthrough relay and blocks forever (until reclaimed or
    /// idle). Never returns.
    static func run(port: Int) -> Never {
        RelaySupport.writePidfile(pid: getpid(), port: port)
        RelaySupport.bumpActivity()

        // Clean shutdown on SIGTERM (the app reclaiming us): drop the
        // pidfile so no stale entry survives. DispatchSource lets us do
        // real work in the handler, unlike a C signal function.
        signal(SIGTERM, SIG_IGN)
        let term = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        term.setEventHandler {
            RelaySupport.removePidfile()
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
                        RelaySupport.removePidfile()
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
                RelaySupport.removePidfile()
                exit(0)
            }
        }
        idle.resume()

        dispatchMain()
    }
}
