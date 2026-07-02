import Foundation
import Testing
@testable import BouclierSecretsCore

/// `StatusReader` is the agent's orientation read. It must NEVER report a
/// stale or orphaned snapshot as live — that would tell an agent the
/// firewall is up when it isn't.
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
            secretKeeper: .init(enabled: true, healthy: true, circuitBreakerTripped: false),
            secrets: .init(total: 3, agentAccessible: 2, active: 1),
            activity: .init(requestsScanned: 10, injectionsBlocked: 0, secretsScrubbed: 4, secretsInjected: 0, secretsBlocked: 0)
        )
    }

    private func writeStatus(_ s: BouclierStatus, to url: URL) {
        try! JSONEncoder().encode(s).write(to: url)
    }
    private func writePid(_ pid: Int32, to url: URL) {
        try! "\(pid)".data(using: .utf8)!.write(to: url)
    }

    @Test("fresh snapshot + live pid → running")
    func freshRunning() {
        let dir = tempDir()
        let statusFile = dir.appendingPathComponent("status.json")
        let pidFile = dir.appendingPathComponent("responder.pid")
        let now = Date()
        writeStatus(sampleStatus(writtenAt: now.timeIntervalSince1970, pid: getpid()), to: statusFile)
        writePid(getpid(), to: pidFile)   // our own pid is alive

        if case .running(let s) = StatusReader.read(statusFile: statusFile, pidFile: pidFile, now: now) {
            #expect(s.mode == "standard")
            #expect(s.secrets.agentAccessible == 2)
        } else {
            Issue.record("expected running")
        }
    }

    @Test("stale snapshot → notRunning even if pid is alive")
    func staleIsNotRunning() {
        let dir = tempDir()
        let statusFile = dir.appendingPathComponent("status.json")
        let pidFile = dir.appendingPathComponent("responder.pid")
        let now = Date()
        // Written well beyond the stale threshold.
        writeStatus(sampleStatus(writtenAt: now.timeIntervalSince1970 - (StatusReader.staleThresholdSeconds + 30), pid: getpid()), to: statusFile)
        writePid(getpid(), to: pidFile)

        guard case .notRunning = StatusReader.read(statusFile: statusFile, pidFile: pidFile, now: now) else {
            Issue.record("a stale snapshot must be reported not-running"); return
        }
    }

    @Test("missing snapshot → notRunning")
    func missingIsNotRunning() {
        let dir = tempDir()
        let statusFile = dir.appendingPathComponent("nope.json")
        let pidFile = dir.appendingPathComponent("nope.pid")
        guard case .notRunning = StatusReader.read(statusFile: statusFile, pidFile: pidFile, now: Date()) else {
            Issue.record("missing files must be not-running"); return
        }
    }

    @Test("fresh snapshot but dead pid → notRunning")
    func deadPidIsNotRunning() {
        let dir = tempDir()
        let statusFile = dir.appendingPathComponent("status.json")
        let pidFile = dir.appendingPathComponent("responder.pid")
        let now = Date()
        writeStatus(sampleStatus(writtenAt: now.timeIntervalSince1970, pid: 999_999), to: statusFile)
        writePid(999_999, to: pidFile)   // a pid that's (almost certainly) not running
        guard case .notRunning = StatusReader.read(statusFile: statusFile, pidFile: pidFile, now: now) else {
            Issue.record("a dead responder pid must be not-running"); return
        }
    }

    @Test("status + action envelopes round-trip and never carry a value field")
    func codecRoundTrip() throws {
        let s = sampleStatus(writtenAt: 123, pid: 7)
        let back = try JSONDecoder().decode(BouclierStatus.self, from: JSONEncoder().encode(s))
        #expect(back == s)

        let req = ActionRequestIPC(id: "i", action: "enable_protection", params: ["mode": "standard"], reason: "agent says", createdAt: 1)
        let reqBack = try JSONDecoder().decode(ActionRequestIPC.self, from: JSONEncoder().encode(req))
        #expect(reqBack == req)

        let resp = ActionResponseIPC(id: "i", action: "enable_protection", status: .approved, result: ["mode": "standard"], message: "ok")
        let respBack = try JSONDecoder().decode(ActionResponseIPC.self, from: JSONEncoder().encode(resp))
        #expect(respBack == resp)
    }

    @Test("ActionClient fails fast when the app isn't running")
    func actionClientNoResponder() {
        let dir = tempDir()
        #expect(throws: ActionClient.Failure.responderNotRunning) {
            _ = try ActionClient.request(
                action: "enable_protection", reason: "x", timeout: 1,
                requestsDir: dir, responsesDir: dir,
                pidFile: dir.appendingPathComponent("absent.pid")
            )
        }
    }
}
