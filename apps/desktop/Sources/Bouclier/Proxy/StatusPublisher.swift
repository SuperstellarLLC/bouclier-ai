import BouclierCore
import Foundation

/// Publishes a read-only `status.json` snapshot the CLI reads so
/// an agent can answer "is Bouclier running/healthy?" without the app being
/// interactively involved. Written immediately on meaningful state changes
/// and on a 5s heartbeat (so `writtenAt` stays fresh and readers can detect a
/// crash), then removed on clean shutdown.
///
@MainActor
final class StatusPublisher {
    private var timer: Timer?
    private let snapshot: () -> BouclierStatus
    private let statusFile: URL

    init(
        statusFile: URL = BouclierPaths.statusFile,
        snapshot: @escaping () -> BouclierStatus
    ) {
        self.statusFile = statusFile
        self.snapshot = snapshot
    }

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
        try? FileManager.default.removeItem(at: statusFile)
    }

    /// Force an immediate refresh (call on a state change for low latency).
    func refresh() { write() }

    private func write() {
        guard let data = try? JSONEncoder().encode(snapshot()) else { return }
        try? AtomicFile.write(data, to: statusFile)
    }
}
