import BouclierSecretsCore
import Foundation

/// App-side responder for the just-in-time secret-request IPC. Watches the
/// `requests/` dir for files dropped by the MCP server, validates them
/// (untrusted input), presents the approval dialog, and writes a
/// names-only response. Advertises liveness via a pid file so the MCP
/// client can fail fast when the app isn't running.
///
/// Watcher pattern (per research): `DispatchSource` vnode on `requests/`
/// (separate dir from `responses/` so our own writes don't wake it) on a
/// SERIAL queue, plus a low-frequency Timer fallback and a sweeper for
/// orphaned files. The dialog (values) is handled entirely by the
/// `@MainActor` coordinator — this type never touches a secret value.
final class SecretRequestResponder: @unchecked Sendable {
    private let queue = DispatchQueue(label: "ai.bouclier.secret-responder")
    private var source: DispatchSourceFileSystemObject?
    private var fd: CInt = -1
    private var timer: DispatchSourceTimer?
    private var sweepTimer: DispatchSourceTimer?
    private var seen = Set<String>()

    private let requestsDir: URL
    private let responsesDir: URL
    private let pidFile: URL

    init(requestsDir: URL = SecretEnvPaths.ipcRequestsDir,
         responsesDir: URL = SecretEnvPaths.ipcResponsesDir,
         pidFile: URL = SecretEnvPaths.responderPidFile) {
        self.requestsDir = requestsDir
        self.responsesDir = responsesDir
        self.pidFile = pidFile
    }

    func start() {
        // Advertise liveness for the MCP client's fail-fast check.
        try? "\(getpid())".write(to: pidFile, atomically: true, encoding: .utf8)
        queue.async { [weak self] in
            guard let self else { return }
            self.armSource()
            self.armTimer()
            self.armSweeper()
            self.sweep()
            self.scan()
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.timer?.cancel(); self.timer = nil
            self.sweepTimer?.cancel(); self.sweepTimer = nil
            self.source?.cancel()
        }
        try? FileManager.default.removeItem(at: pidFile)
    }

    // MARK: Watcher

    private func armSource() {
        guard source == nil else { return }
        fd = open(requestsDir.path, O_EVTONLY)
        guard fd >= 0 else { return }   // dir missing → Timer fallback still runs
        let src = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: fd, eventMask: [.write, .delete, .rename], queue: queue)
        src.setEventHandler { [weak self] in
            guard let self, let src = self.source else { return }
            if src.data.contains(.delete) || src.data.contains(.rename) {
                self.source?.cancel()   // dir inode replaced → re-arm on a fresh fd
                self.armSource()
            }
            self.scan()
        }
        src.setCancelHandler { [weak self] in
            guard let self else { return }
            if self.fd >= 0 { close(self.fd); self.fd = -1 }
            self.source = nil
        }
        source = src
        src.resume()
    }

    private func armTimer() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 3, repeating: 3.0, leeway: .seconds(1))
        t.setEventHandler { [weak self] in
            guard let self else { return }
            if self.source == nil { self.armSource() }   // self-heal if the fd was lost
            self.scan()
        }
        timer = t
        t.resume()
    }

    private func armSweeper() {
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 60, repeating: 60.0, leeway: .seconds(10))
        t.setEventHandler { [weak self] in self?.sweep() }
        sweepTimer = t
        t.resume()
    }

    private func scan() {
        let fm = FileManager.default
        guard let entries = try? fm.contentsOfDirectory(
            at: requestsDir, includingPropertiesForKeys: nil, options: [.skipsHiddenFiles]) else { return }
        let ready = entries.filter { $0.pathExtension == "json" }
        var fresh: [URL] = []
        for url in ready where !seen.contains(url.lastPathComponent) {
            seen.insert(url.lastPathComponent)
            fresh.append(url)
        }
        seen.formIntersection(Set(ready.map { $0.lastPathComponent }))   // bound the set
        for url in fresh { handle(url) }
    }

    private func handle(_ url: URL) {
        // Size-cap untrusted input before reading.
        if let size = try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int,
           size > SecretRequestValidator.maxFileBytes {
            try? FileManager.default.removeItem(at: url); return
        }
        guard let data = try? Data(contentsOf: url) else { return }
        switch SecretRequestValidator.validate(data: data) {
        case .failure:
            try? FileManager.default.removeItem(at: url)   // malformed/stale → drop, no dialog
        case .success(let req):
            Task { @MainActor [weak self] in
                let resp = await SecretApprovalCoordinator.shared.present(req)
                self?.writeResponse(resp, requestURL: url)
            }
        }
    }

    private func writeResponse(_ resp: SecretResponseIPC, requestURL: URL) {
        queue.async { [weak self] in
            guard let self else { return }
            if let data = try? JSONEncoder().encode(resp) {
                try? AtomicFile.write(data, to: self.responsesDir.appendingPathComponent("\(resp.id).json"))
            }
            try? FileManager.default.removeItem(at: requestURL)
        }
    }

    private func sweep() {
        let now = Date()
        func reap(_ dir: URL, ttl: TimeInterval) {
            guard let items = try? FileManager.default.contentsOfDirectory(
                at: dir, includingPropertiesForKeys: [.contentModificationDateKey]) else { return }
            for u in items {
                let m = (try? u.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? .distantFuture
                if now.timeIntervalSince(m) > ttl { try? FileManager.default.removeItem(at: u) }
            }
        }
        reap(requestsDir, ttl: 300)    // abandoned requests
        reap(responsesDir, ttl: 60)    // responses nobody picked up
    }
}
