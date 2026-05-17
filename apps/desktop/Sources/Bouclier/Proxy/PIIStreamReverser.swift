import Foundation

/// **Phase 3 scaffolding — not wired into the proxy yet.**
///
/// Sliding-window reverser for SSE streaming responses. The design is
/// modeled on NVIDIA NeMo Guardrails' streaming-output pattern (~50
/// token holdback) — see:
/// https://developer.nvidia.com/blog/stream-smarter-and-safer-learn-how-nvidia-nemo-guardrails-enhance-llm-output-streaming/
///
/// **Why we hold back tokens.** A minted placeholder like
/// `⟦pii:EMAIL:a3f2c1d4⟧` is 21 bytes. In OpenAI's BPE-token stream
/// each SSE event carries a few characters; a placeholder will split
/// across 3–5 events. If we emit each event the instant it arrives,
/// the client renders a half-token mid-stream and the user sees
/// `⟦pii:EMAI` for a frame before the reversed cleartext catches up.
/// Worse, if the model emits a *partial* placeholder shape that never
/// completes (token boundary lands inside `⟦pii:` and the model
/// continues with different content), we'd never know to either
/// reverse or pass through.
///
/// **The protocol.** Each `ingest(_:)` call appends to a rolling
/// buffer. The reverser emits any *prefix* of the buffer that ends
/// at least `holdback` characters away from a potential placeholder
/// boundary. When the upstream marks end-of-stream, `finish()` flushes
/// the entire remainder through the reverser.
///
/// **What this scaffolding gives Phase 3.** A pure-Swift, unit-testable
/// state machine that the SSE inspector and tool-call argument-stream
/// reader can plug into without re-deriving the holdback algebra.
/// The TLS pipeline integration (extending `SSEStreamInspector` to
/// call this and to handle Anthropic `input_json_delta` deltas) lands
/// in v0.2.15.
final class PIIStreamReverser {
    /// How many characters at the buffer tail to hold back. Must be
    /// larger than the maximum possible placeholder length so a
    /// placeholder can never be entirely inside the un-flushed tail
    /// across an event boundary.
    ///
    /// Token shape: `⟦pii:<TYPE>:<8 hex>⟧`. Longest `TYPE` slug is
    /// `AWS_ACCESS_KEY` (14 chars) → max placeholder length is
    /// `⟦pii:` (5) + 14 + `:` (1) + 8 + `⟧` (1) = 29 chars. Add some
    /// slack for safety.
    static let holdback = 40

    private let session: PIISession
    private var buffer: String = ""
    private var closed = false

    init(session: PIISession) {
        self.session = session
    }

    /// Append upstream-delivered text to the buffer and return whatever
    /// can be safely emitted to the client right now (i.e., everything
    /// except the last `holdback` characters). Callers should write the
    /// returned string to the client channel verbatim.
    func ingest(_ chunk: String) async -> String {
        guard !closed else { return "" }
        buffer += chunk
        return await emitWindow(keepingTail: PIIStreamReverser.holdback)
    }

    /// Flush the remaining buffer through the reverser, return the
    /// final bytes to forward. After this the reverser is closed and
    /// further `ingest` calls return empty.
    func finish() async -> String {
        guard !closed else { return "" }
        closed = true
        return await emitWindow(keepingTail: 0)
    }

    /// Run the reverser over `buffer[..< buffer.count - keep]`. Pop the
    /// emitted prefix from the buffer and return its reversed form. The
    /// reverser is map-based so unknown tokens pass through unchanged
    /// (R6 part 2 invariant).
    private func emitWindow(keepingTail keep: Int) async -> String {
        let length = buffer.count
        guard length > keep else { return "" }
        let endIndex = buffer.index(buffer.startIndex, offsetBy: length - keep)
        let toEmit = String(buffer[..<endIndex])
        buffer = String(buffer[endIndex...])
        return await PIIReverser.reverseString(toEmit, with: session)
    }
}
