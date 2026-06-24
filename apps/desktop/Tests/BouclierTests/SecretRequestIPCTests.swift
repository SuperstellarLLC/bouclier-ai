import Foundation
import Testing
@testable import BouclierSecretsCore

@Suite("SecretRequest IPC", .serialized)
struct SecretRequestIPCTests {
    private func tempIPC() throws -> (base: URL, req: URL, resp: URL, pid: URL) {
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("bouclier-ipc-\(UUID())")
        let req = base.appendingPathComponent("requests")
        let resp = base.appendingPathComponent("responses")
        try FileManager.default.createDirectory(at: req, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: resp, withIntermediateDirectories: true)
        return (base, req, resp, base.appendingPathComponent("responder.pid"))
    }

    @Test("AtomicFile writes 0600 and reads back")
    func atomicWrite() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("bouclier-atomic-\(UUID())")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("x.json")
        try AtomicFile.write(Data("hello".utf8), to: url)
        #expect(try Data(contentsOf: url) == Data("hello".utf8))
        let perms = (try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? NSNumber)?.intValue
        #expect(perms == 0o600)
    }

    @Test("request() fails fast when responder isn't running")
    func responderNotRunning() throws {
        let t = try tempIPC()
        defer { try? FileManager.default.removeItem(at: t.base) }
        try "999999".write(to: t.pid, atomically: true, encoding: .utf8)  // almost certainly dead pid
        #expect(throws: SecretRequestClient.Failure.responderNotRunning) {
            _ = try SecretRequestClient.request(envVars: ["X"], reason: "r", timeout: 1,
                                                requestsDir: t.req, responsesDir: t.resp, pidFile: t.pid)
        }
    }

    @Test("request() returns .timeout when nobody answers")
    func timeoutPath() throws {
        let t = try tempIPC()
        defer { try? FileManager.default.removeItem(at: t.base) }
        try "\(getpid())".write(to: t.pid, atomically: true, encoding: .utf8)  // we're alive
        let resp = try SecretRequestClient.request(envVars: ["X"], reason: "r", timeout: 0.5,
                                                   requestsDir: t.req, responsesDir: t.resp, pidFile: t.pid)
        #expect(resp.status == .timeout)
        #expect(resp.skipped == ["X"])
        // The request file must be cleaned up after timeout.
        #expect((try? FileManager.default.contentsOfDirectory(atPath: t.req.path))?.isEmpty == true)
    }

    @Test("Full round-trip: a background responder provides values")
    func roundTrip() throws {
        let t = try tempIPC()
        defer { try? FileManager.default.removeItem(at: t.base) }
        try "\(getpid())".write(to: t.pid, atomically: true, encoding: .utf8)

        // Background "app": watch requests/, answer with .provided.
        DispatchQueue.global().async {
            for _ in 0..<300 {
                if let f = (try? FileManager.default.contentsOfDirectory(at: t.req, includingPropertiesForKeys: nil))?
                    .first(where: { $0.pathExtension == "json" }),
                    let data = try? Data(contentsOf: f),
                    let req = try? JSONDecoder().decode(SecretRequestIPC.self, from: data) {
                    let resp = SecretResponseIPC(id: req.id, status: .provided, provided: req.envVars, skipped: [])
                    try? AtomicFile.write(try! JSONEncoder().encode(resp), to: t.resp.appendingPathComponent("\(req.id).json"))
                    return
                }
                usleep(20_000)
            }
        }

        let resp = try SecretRequestClient.request(envVars: ["STRIPE_KEY", "OPENAI_API_KEY"], reason: "setup", timeout: 8,
                                                   requestsDir: t.req, responsesDir: t.resp, pidFile: t.pid)
        #expect(resp.status == .provided)
        #expect(resp.provided == ["STRIPE_KEY", "OPENAI_API_KEY"])
        // Both files cleaned up by the client after reading the response.
        #expect((try? FileManager.default.contentsOfDirectory(atPath: t.req.path))?.isEmpty == true)
        #expect((try? FileManager.default.contentsOfDirectory(atPath: t.resp.path))?.isEmpty == true)
    }
}

@Suite("SecretRequestValidator")
struct SecretRequestValidatorTests {
    private func encode(_ r: SecretRequestIPC) -> Data { try! JSONEncoder().encode(r) }
    private func now() -> Double { Date().timeIntervalSince1970 }

    @Test("Valid request is sanitized: invalid names dropped, deduped, reason clamped")
    func valid() {
        let req = SecretRequestIPC(id: "1", envVars: ["STRIPE_KEY", "STRIPE_KEY", "1bad", "ok_2"], reason: String(repeating: "x", count: 5000), createdAt: now())
        let r = SecretRequestValidator.validate(data: encode(req))
        guard case .success(let s) = r else { Issue.record("expected success"); return }
        #expect(s.envVars == ["STRIPE_KEY", "ok_2"])   // "1bad" dropped, dupe removed
        #expect(s.reason.count == SecretRequestValidator.maxReasonChars)
    }

    @Test("Oversized file rejected")
    func tooLarge() {
        let big = Data(count: SecretRequestValidator.maxFileBytes + 1)
        #expect(SecretRequestValidator.validate(data: big) == .failure(.tooLarge))
    }

    @Test("Malformed JSON rejected")
    func malformed() {
        #expect(SecretRequestValidator.validate(data: Data("{not json".utf8)) == .failure(.malformed))
    }

    @Test("Stale request rejected")
    func stale() {
        let old = SecretRequestIPC(id: "1", envVars: ["X"], reason: "r", createdAt: now() - 999)
        #expect(SecretRequestValidator.validate(data: encode(old)) == .failure(.stale))
    }

    @Test("Request with no valid env-var names rejected")
    func noValid() {
        let req = SecretRequestIPC(id: "1", envVars: ["1bad", "also bad", ""], reason: "r", createdAt: now())
        #expect(SecretRequestValidator.validate(data: encode(req)) == .failure(.noValidEnvVars))
    }

    @Test("generate flag survives validation")
    func generatePreserved() {
        let req = SecretRequestIPC(id: "1", envVars: ["TOKEN"], reason: "new key", createdAt: now(), generate: true)
        guard case .success(let s) = SecretRequestValidator.validate(data: encode(req)) else { Issue.record("expected success"); return }
        #expect(s.generate == true)
    }

    @Test("Legacy request JSON (no generate) decodes generate=false")
    func legacyGenerateDefault() throws {
        let json = #"{"id":"1","envVars":["X"],"reason":"r","createdAt":0}"#
        let req = try JSONDecoder().decode(SecretRequestIPC.self, from: Data(json.utf8))
        #expect(req.generate == false)
    }
}

@Suite("SecretGenerator")
struct SecretGeneratorTests {
    @Test("Runs the command and returns trimmed stdout")
    func deterministic() {
        #expect(SecretGenerator.generate(command: "printf 'abc123XYZ'") == "abc123XYZ")
        // Trailing newline trimmed.
        #expect(SecretGenerator.generate(command: "echo hello") == "hello")
    }

    @Test("Failure / empty output ⇒ nil")
    func failures() {
        #expect(SecretGenerator.generate(command: "false") == nil)
        #expect(SecretGenerator.generate(command: "printf ''") == nil)
    }

    @Test("Multi-line output is rejected (not a single-line secret)")
    func multilineRejected() {
        #expect(SecretGenerator.generate(command: "printf 'a\\nb'") == nil)
    }

    @Test("Default openssl command produces a storable value")
    func defaultProducesValue() {
        let v = SecretGenerator.generate(command: SecretGenerator.defaultCommand)
        #expect(v != nil)
        #expect((v?.count ?? 0) >= 16)   // strong enough to clear the scrub floor
    }
}
