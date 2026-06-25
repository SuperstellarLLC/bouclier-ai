import Testing
@testable import BouclierSecretsCore

/// Large secret sets must complete across multiple approval transfers
/// without ever silently dropping a var. These pin that aggregation +
/// the precise provided/skipped/pending accounting an agent relies on.
@Suite("SecretBatchRequest — no silent drops")
struct SecretBatchRequestTests {
    private func provideAll(_ batch: [String], _ r: String, _ g: Bool) -> SecretResponseIPC? {
        SecretResponseIPC(id: "x", status: .provided, provided: batch, skipped: [])
    }

    @Test("splits a large set into batches and aggregates every var")
    func aggregatesAcrossBatches() {
        let vars = (1...5).map { "V\($0)" }
        var seenBatches = 0
        let out = SecretBatchRequest.requestAll(envVars: vars, reason: "setup", generate: false, batchSize: 2) { batch, r, g in
            seenBatches += 1
            #expect(batch.count <= 2)
            return SecretResponseIPC(id: "x", status: .provided, provided: batch, skipped: [])
        }
        #expect(seenBatches == 3)               // 2 + 2 + 1
        #expect(out.batches == 3)
        #expect(out.provided == vars)           // nothing dropped
        #expect(out.pending.isEmpty)
        #expect(out.reachable)
    }

    @Test("interruption mid-way → earlier provided kept, rest reported pending")
    func interruptionReportsPending() {
        let vars = (1...6).map { "V\($0)" }      // 3 batches of 2
        var call = 0
        let out = SecretBatchRequest.requestAll(envVars: vars, reason: "", generate: false, batchSize: 2) { batch, _, _ in
            call += 1
            if call == 1 { return SecretResponseIPC(id: "x", status: .provided, provided: batch, skipped: []) }
            return SecretResponseIPC(id: "x", status: .cancelled, provided: [], skipped: [])   // user cancels batch 2
        }
        #expect(out.provided == ["V1", "V2"])
        #expect(out.pending == ["V3", "V4", "V5", "V6"])   // batch 2 + 3, nothing lost
        #expect(out.interruptedBy == .cancelled)
    }

    @Test("app goes away mid-way → reachable false, remaining pending")
    func unreachableMidway() {
        let vars = (1...4).map { "V\($0)" }
        var call = 0
        let out = SecretBatchRequest.requestAll(envVars: vars, reason: "", generate: false, batchSize: 2) { batch, _, _ in
            call += 1
            return call == 1 ? SecretResponseIPC(id: "x", status: .provided, provided: batch, skipped: []) : nil
        }
        #expect(out.reachable == false)
        #expect(out.provided == ["V1", "V2"])
        #expect(out.pending == ["V3", "V4"])
    }

    @Test("partial fill within a batch: skipped tracked separately from pending")
    func skippedVsPending() {
        let out = SecretBatchRequest.requestAll(envVars: ["A", "B"], reason: "", generate: false, batchSize: 50) { _, _, _ in
            SecretResponseIPC(id: "x", status: .provided, provided: ["A"], skipped: ["B"])
        }
        #expect(out.provided == ["A"])
        #expect(out.skipped == ["B"])
        #expect(out.pending.isEmpty)            // B was a choice (blank), not lost
    }

    @Test("duplicate names are collapsed, order preserved")
    func dedup() {
        let out = SecretBatchRequest.requestAll(envVars: ["A", "B", "A"], reason: "", generate: false, request: provideAll)
        #expect(out.provided == ["A", "B"])
    }
}
