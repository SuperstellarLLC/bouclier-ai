import Foundation
import Testing
@testable import BouclierCore

/// `StatusReader` is the agent's orientation read. It must NEVER report a
/// stale or orphaned snapshot as live — that would tell an agent the
/// firewall is up when it isn't. Liveness is proven by the pid carried in
/// the snapshot itself, so there is no separate pid file.
@Suite("StatusReader — honest liveness")
struct StatusReaderTests {
    private func tempDir() -> URL {
        let d = FileManager.default.temporaryDirectory.appendingPathComponent("bstatus-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d
    }

    private func sampleStatus(writtenAt: Double, pid: Int32) -> BouclierStatus {
        BouclierStatus(
            writtenAt: writtenAt, pid: pid, appVersion: "9.9.9",
            running: true, mode: "standard", caInstalled: false, protectionEnabled: true,
            activity: .init(requestsScanned: 10, injectionsBlocked: 2)
        )
    }

    private func writeStatus(_ s: BouclierStatus, to url: URL) {
        try! JSONEncoder().encode(s).write(to: url)
    }

    @Test("fresh snapshot + live pid → running")
    func freshRunning() {
        let dir = tempDir()
        let statusFile = dir.appendingPathComponent("status.json")
        let now = Date()
        writeStatus(sampleStatus(writtenAt: now.timeIntervalSince1970, pid: getpid()), to: statusFile)

        if case .running(let s) = StatusReader.read(statusFile: statusFile, now: now) {
            #expect(s.mode == "standard")
            #expect(s.activity.injectionsBlocked == 2)
        } else {
            Issue.record("expected running")
        }
    }

    @Test("stale snapshot → notRunning even if pid is alive")
    func staleIsNotRunning() {
        let dir = tempDir()
        let statusFile = dir.appendingPathComponent("status.json")
        let now = Date()
        // Written well beyond the stale threshold, but with our own live pid.
        writeStatus(sampleStatus(writtenAt: now.timeIntervalSince1970 - (StatusReader.staleThresholdSeconds + 30), pid: getpid()), to: statusFile)

        guard case .notRunning = StatusReader.read(statusFile: statusFile, now: now) else {
            Issue.record("a stale snapshot must be reported not-running"); return
        }
    }

    @Test("missing snapshot → notRunning")
    func missingIsNotRunning() {
        let dir = tempDir()
        let statusFile = dir.appendingPathComponent("nope.json")
        guard case .notRunning = StatusReader.read(statusFile: statusFile, now: Date()) else {
            Issue.record("missing file must be not-running"); return
        }
    }

    @Test("fresh snapshot but dead pid → notRunning")
    func deadPidIsNotRunning() {
        let dir = tempDir()
        let statusFile = dir.appendingPathComponent("status.json")
        let now = Date()
        // A pid that's (almost certainly) not running.
        writeStatus(sampleStatus(writtenAt: now.timeIntervalSince1970, pid: 999_999), to: statusFile)
        guard case .notRunning = StatusReader.read(statusFile: statusFile, now: now) else {
            Issue.record("a dead pid must be not-running"); return
        }
    }

    @Test("status snapshot round-trips and carries no request content")
    func codecRoundTrip() throws {
        let s = sampleStatus(writtenAt: 123, pid: 7)
        let back = try JSONDecoder().decode(BouclierStatus.self, from: JSONEncoder().encode(s))
        #expect(back == s)
        #expect(back.schemaVersion == 2)
    }
}
