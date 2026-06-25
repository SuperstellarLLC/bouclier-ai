import BouclierSecretsCore
import Foundation

/// Publishes a read-only `status.json` snapshot the MCP server / CLI read so
/// an agent can answer "is Bouclier running/healthy?" without the app being
/// interactively involved. Written on a 5s heartbeat (so `writtenAt` stays
/// fresh and readers can detect a crash) and removed on clean shutdown.
/// Counts only — never a secret value.
@MainActor
final class StatusPublisher {
    private var timer: Timer?
    private let snapshot: () -> BouclierStatus

    init(snapshot: @escaping () -> BouclierStatus) { self.snapshot = snapshot }

    func start() {
        write()
        let t = Timer(timeInterval: 5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.write() }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    func stop() {
        timer?.invalidate()
        timer = nil
        try? FileManager.default.removeItem(at: SecretEnvPaths.statusFile)
    }

    /// Force an immediate refresh (call on a state change for low latency).
    func refresh() { write() }

    private func write() {
        guard let data = try? JSONEncoder().encode(snapshot()) else { return }
        try? AtomicFile.write(data, to: SecretEnvPaths.statusFile)
    }
}
