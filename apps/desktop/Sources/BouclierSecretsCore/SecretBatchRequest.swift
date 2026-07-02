import Foundation

/// Requests an arbitrary number of secrets without ever silently dropping
/// any. A single approval transfer is capped (dialog sanity +
/// untrusted-input bound), so large sets are split into as many transfers
/// as needed and the results are aggregated. The agent's logical
/// "request these N secrets" always completes — or reports precisely which
/// ones are still `pending` so it can re-request them. Used by both the MCP
/// server and the `bouclier` CLI so they behave identically.
public enum SecretBatchRequest {
    /// One transfer's worth — kept in sync with the validator's cap.
    public static var batchSize: Int { SecretRequestValidator.maxEnvVars }

    public struct Outcome: Equatable, Sendable {
        /// False if Bouclier became unreachable partway (or at the start).
        public let reachable: Bool
        public let provided: [String]   // user supplied a value
        public let skipped: [String]    // user left the field blank
        public let pending: [String]    // never resolved (declined / timed out / app gone) — re-request these
        public let batches: Int         // how many approval dialogs this took
        public let interruptedBy: SecretResponseIPC.Status?

        public init(reachable: Bool, provided: [String], skipped: [String], pending: [String], batches: Int, interruptedBy: SecretResponseIPC.Status?) {
            self.reachable = reachable; self.provided = provided; self.skipped = skipped
            self.pending = pending; self.batches = batches; self.interruptedBy = interruptedBy
        }
    }

    /// `request` performs ONE transfer (one dialog). Returning nil means the
    /// app is unreachable.
    public static func requestAll(
        envVars: [String],
        reason: String,
        generate: Bool,
        batchSize: Int? = nil,
        request: (_ batch: [String], _ reason: String, _ generate: Bool) -> SecretResponseIPC?
    ) -> Outcome {
        let size = max(1, batchSize ?? Self.batchSize)
        // De-dupe, preserve order.
        var seen = Set<String>()
        let all = envVars.filter { seen.insert($0).inserted }
        guard !all.isEmpty else {
            return Outcome(reachable: true, provided: [], skipped: [], pending: [], batches: 0, interruptedBy: nil)
        }
        let batches = stride(from: 0, to: all.count, by: size).map { Array(all[$0 ..< min($0 + size, all.count)]) }

        var provided: [String] = []
        var skipped: [String] = []
        func remaining() -> [String] {
            let done = Set(provided + skipped)
            return all.filter { !done.contains($0) }
        }

        for (i, batch) in batches.enumerated() {
            let r = reasonFor(reason, index: i, total: batches.count)
            guard let resp = request(batch, r, generate) else {
                return Outcome(reachable: false, provided: provided, skipped: skipped, pending: remaining(), batches: i, interruptedBy: nil)
            }
            switch resp.status {
            case .provided:
                provided += resp.provided
                skipped += resp.skipped
            case .cancelled, .timeout, .invalid:
                // Stop: this batch and every later one is still pending.
                return Outcome(reachable: true, provided: provided, skipped: skipped, pending: remaining(), batches: i + 1, interruptedBy: resp.status)
            }
        }
        return Outcome(reachable: true, provided: provided, skipped: skipped, pending: [], batches: batches.count, interruptedBy: nil)
    }

    static func reasonFor(_ reason: String, index: Int, total: Int) -> String {
        guard total > 1 else { return reason }
        let tag = "batch \(index + 1) of \(total)"
        return reason.isEmpty ? tag.prefix(1).uppercased() + tag.dropFirst() : "\(reason) (\(tag))"
    }
}
