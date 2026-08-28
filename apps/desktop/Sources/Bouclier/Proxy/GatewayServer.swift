import Foundation
// NIO's handler types are event-loop-confined and predate Swift's full
// Sendable model. Pipeline installation below uses synchronous operations on
// that loop; these imports keep the remaining legacy annotations contained.
@preconcurrency import NIO
@preconcurrency import NIOCore
import NIOHTTP1
import NIOPosix
@preconcurrency import NIOSSL
import NIOTLS

/// Non-CA "base-URL redirection" gateway — the whole of Bouclier's proxy.
///
/// This never terminates the client's TLS and installs no certificate
/// authority. The agent points `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`
/// at `http://127.0.0.1:<port>` and speaks **plaintext HTTP to loopback**;
/// the gateway re-issues each request to the real provider over TLS and
/// streams the response back. No CA install, no system-trust changes —
/// the friction that blocked adoption simply isn't here.
///
/// Pipeline (plaintext front, TLS only to upstream):
/// ```
/// Agent ──[HTTP/loopback]──► HTTPRequestDecoder
///                                │ (HTTPServerRequestPart)
///                          GatewayHandler  ←── route, (Phase 2: scrub)
///                                │ (raw HTTP/1.1 bytes)
///                          NIOSSLClientHandler ──[TLS]──► api.anthropic.com
///                                │
///                          GatewayRelayHandler ──► back to agent (raw bytes)
/// ```
///
/// The gateway preserves model-visible request-body bytes: it forwards them
/// unchanged or refuses the request outright. End-to-end header fidelity is
/// equally important: `anthropic-beta`, `anthropic-version`, the model id,
/// and auth are forwarded verbatim (Claude Code's own 1M-context /
/// prompt-cache accounting rides on them). Proxy-only routing/framing headers
/// are normalized, and the upstream leg is pinned to HTTP/1.1 so surviving
/// header name casing/order is retained (HTTP/2 lowercases names).
final class GatewayServer: Sendable {
    private let group: EventLoopGroup
    private let port: Int
    private let overrides: UpstreamOverrides
    private let admissionController: GatewayAdmissionController
    private let responseTimeouts: GatewayResponseTimeouts
    private let onRequest: @Sendable (RequestLog) -> Void
    /// Consulted once per request before any inspection work. When it
    /// returns false the gateway is a pure allow-all relay: no trigger
    /// gate, no scan, no block — so "protection off" degrades to
    /// passthrough instead of a dead port under active agent sessions.
    /// A closure (not a captured Bool) so the owner can flip it on a
    /// *running* gateway; the production value reads `UserDefaults`.
    private let inspectionEnabled: @Sendable () -> Bool
    /// Reports injected-action findings observed on the response leg. Never
    /// affects forwarding (the response relay is byte-faithful); this is a
    /// monitoring signal only.
    private let onResponseAction: @Sendable ([ResponseActionInspector.Finding]) -> Void
    /// Override system trust roots for upstream TLS verification. Set only
    /// by the e2e test (in-process HTTPS upstream signed by a throwaway
    /// CA). `nil` in production keeps `.fullVerification` against the
    /// system store.
    let upstreamTrustRootsPEM: [String]?

    init(
        port: Int,
        overrides: UpstreamOverrides = .default,
        upstreamTrustRootsPEM: [String]? = nil,
        admissionController: GatewayAdmissionController = .shared,
        responseTimeouts: GatewayResponseTimeouts = .production,
        inspectionEnabled: @Sendable @escaping () -> Bool = { true },
        onResponseAction: @Sendable @escaping ([ResponseActionInspector.Finding]) -> Void = { _ in },
        onRequest: @Sendable @escaping (RequestLog) -> Void
    ) {
        // Start the shared bounded inspection pool during gateway setup, not
        // lazily on the first channel event loop that receives a request.
        _ = GatewayInspectionExecutor.pool
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        self.port = port
        self.overrides = overrides
        self.admissionController = admissionController
        self.responseTimeouts = responseTimeouts
        self.upstreamTrustRootsPEM = upstreamTrustRootsPEM
        self.inspectionEnabled = inspectionEnabled
        self.onResponseAction = onResponseAction
        self.onRequest = onRequest
    }

    func start() async throws -> Channel {
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [overrides, upstreamTrustRootsPEM, admissionController, responseTimeouts, inspectionEnabled, onResponseAction, onRequest] channel in
                // Front pipeline is decoder-only: we parse inbound requests
                // for routing, but relay responses as raw bytes (no
                // response encoder), so upstream bytes reach the agent
                // byte-for-byte. `.forwardBytes` preserves any trailing
                // body bytes the decoder doesn't consume.
                return channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandlers(
                        ByteToMessageHandler(
                            HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes)
                        ),
                        GatewayHandler(
                            overrides: overrides,
                            upstreamTrustRootsPEM: upstreamTrustRootsPEM,
                            admissionController: admissionController,
                            responseTimeouts: responseTimeouts,
                            inspectionEnabled: inspectionEnabled,
                            onResponseAction: onResponseAction,
                            onRequest: onRequest,
                            eventLoop: channel.eventLoop
                        )
                    )
                }
            }
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)
            // Bound the response bytes that can queue behind a slow or
            // non-reading local client. `GatewayHandler` mirrors these
            // writability transitions to upstream `autoRead` after TLS is
            // established, providing end-to-end backpressure.
            .childChannelOption(
                ChannelOptions.writeBufferWaterMark,
                value: .init(low: 256 * 1024, high: 512 * 1024)
            )

        // Bind loopback only. The gateway forwards credentials upstream,
        // so it must never be reachable off-box.
        return try await bootstrap.bind(host: "127.0.0.1", port: port).get()
    }

    func shutdown() {
        group.shutdownGracefully { _ in }
    }
}

// MARK: - Upstream resolution

/// Where each provider's traffic is really sent. Production always uses the
/// two public provider origins below. The injectable value exists only so the
/// end-to-end suite can route to an in-process TLS server; inherited process
/// environment must never silently repoint credential-bearing traffic.
struct UpstreamOverrides: Sendable, Equatable {
    var anthropicHost: String
    var anthropicPort: Int
    var openaiHost: String
    var openaiPort: Int

    static let `default` = UpstreamOverrides(
        anthropicHost: "api.anthropic.com", anthropicPort: 443,
        openaiHost: "api.openai.com", openaiPort: 443
    )

}

/// Pure, channel-free routing decision — unit-testable without a socket.
enum GatewayRoute: Equatable {
    case proxy(host: String, port: Int)
    case ops(OpsKind)
    /// No provider could be established without guessing where credentials
    /// belong. The handler fails closed instead of forwarding a bearer token
    /// to the wrong vendor.
    case rejectUnknownProvider

    enum OpsKind: Equatable { case livez, readyz, health }

    /// Resolve a request to its upstream (or a local ops response).
    ///
    /// Exact path segments decide the provider for canonical routes. Unknown
    /// routes require explicit Anthropic-specific evidence; a generic bearer
    /// token is deliberately not treated as provider identity. Provider-
    /// specific credentials that contradict the path fail closed rather than
    /// being disclosed to the other vendor.
    static func resolve(method: HTTPMethod, uri: String, headers: HTTPHeaders, overrides: UpstreamOverrides) -> GatewayRoute {
        let path = String(uri.split(separator: "?", maxSplits: 1).first ?? "")
        let evidence = providerEvidence(in: headers)

        switch path {
        case "/livez": return .ops(.livez)
        case "/readyz": return .ops(.readyz)
        case "/health": return .ops(.health)
        default: break
        }

        if matches(path, segment: "/v1/messages") || matches(path, segment: "/v1/complete") {
            guard evidence != .openAI, evidence != .conflicting else {
                return .rejectUnknownProvider
            }
            return .proxy(host: overrides.anthropicHost, port: overrides.anthropicPort)
        }
        if matches(path, segment: "/v1/models") {
            // `/v1/models` is offered by both. Provider-specific evidence
            // disambiguates it; contradictory evidence is never forwarded.
            switch evidence {
            case .anthropic:
                return .proxy(host: overrides.anthropicHost, port: overrides.anthropicPort)
            case .none, .openAI:
                return .proxy(host: overrides.openaiHost, port: overrides.openaiPort)
            case .conflicting:
                return .rejectUnknownProvider
            }
        }
        if matches(path, segment: "/v1/chat")
            || matches(path, segment: "/v1/responses")
            || matches(path, segment: "/v1/completions")
            || matches(path, segment: "/v1/embeddings")
            || matches(path, segment: "/v1/moderations") {
            guard evidence != .anthropic, evidence != .conflicting else {
                return .rejectUnknownProvider
            }
            return .proxy(host: overrides.openaiHost, port: overrides.openaiPort)
        }

        // Unknown path: sniff the auth header.
        if evidence == .anthropic {
            return .proxy(host: overrides.anthropicHost, port: overrides.anthropicPort)
        }
        // A generic Bearer token is not provider evidence: OAuth and future
        // credential formats are shared across vendors. Unknown paths fail
        // closed rather than sending that credential to a guessed origin.
        return .rejectUnknownProvider
    }

    private enum ProviderEvidence: Equatable {
        case none, anthropic, openAI, conflicting
    }

    /// Match a route base exactly or as a slash-delimited descendant. A raw
    /// prefix match would mistake `/v1/messages-evil` for `/v1/messages`.
    private static func matches(_ path: String, segment: String) -> Bool {
        path == segment || path.hasPrefix(segment + "/")
    }

    private static func providerEvidence(in headers: HTTPHeaders) -> ProviderEvidence {
        let apiKeyValues = headers["x-api-key"]
        var anthropic = !apiKeyValues.isEmpty || !headers["anthropic-version"].isEmpty
        var openAI = false

        // `x-api-key` is Anthropic's canonical credential header, but the
        // value can still accidentally contain an OpenAI key. Treat that as
        // contradictory evidence instead of forwarding one vendor's secret
        // to the other. Inspect every duplicate field; HTTPHeaders lookup is
        // case-insensitive.
        for rawValue in apiKeyValues {
            for candidate in credentialCandidates(in: rawValue) {
                if candidate.hasPrefix("sk-ant-") {
                    anthropic = true
                } else if candidate.hasPrefix("sk-") {
                    openAI = true
                }
            }
        }

        // Inspect every Authorization field. Looking only at the first would
        // let a duplicate contradictory credential evade the boundary check.
        for rawValue in headers["authorization"] {
            let fields = rawValue.split(maxSplits: 1, whereSeparator: { $0.isWhitespace })
            guard fields.count == 2, fields[0].caseInsensitiveCompare("bearer") == .orderedSame else {
                continue
            }
            // A combined/malformed field can contain more than one bearer
            // credential. Scan each delimiter-separated candidate so a
            // second provider key cannot hide behind the first.
            for candidate in credentialCandidates(in: String(fields[1])) {
                if candidate.hasPrefix("sk-ant-") {
                    anthropic = true
                } else if candidate.hasPrefix("sk-") {
                    // OpenAI project/admin/service-account and legacy API
                    // keys retain the `sk-` prefix. Opaque OAuth/session
                    // bearer values remain deliberately unclassified because
                    // both vendors may use them now or in the future.
                    openAI = true
                }
            }
        }

        switch (anthropic, openAI) {
        case (false, false): return .none
        case (true, false): return .anthropic
        case (false, true): return .openAI
        case (true, true): return .conflicting
        }
    }

    private static func credentialCandidates(in rawValue: String) -> [String] {
        rawValue.split(whereSeparator: { character in
            character.isWhitespace || character == "," || character == ";"
        }).map { $0.lowercased() }
    }

}

// MARK: - Process-wide resource admission

/// Production response deadlines. The idle timer is reset by every upstream
/// response read, so ordinary SSE/token streams can run for a long time. The
/// absolute lifetime is deliberately generous but finite: a wedged provider
/// or permanently non-reading local client cannot retain a channel forever.
struct GatewayResponseTimeouts: Sendable, Equatable {
    let idle: TimeAmount
    let maximumLifetime: TimeAmount

    static let production = GatewayResponseTimeouts(
        idle: .minutes(5),
        maximumLifetime: .hours(2)
    )
}

/// Process-wide admission controller for client connections and retained
/// request bodies. A per-channel 64 MiB ceiling is insufficient on its own:
/// many loopback clients could otherwise buffer or queue those bodies at the
/// same time while the two inspection workers remain bounded.
///
/// The production body budget admits two maximum-sized requests (128 MiB of
/// raw bodies). Inspection temporarily materialises one additional copy, so
/// this also bounds the dominant body-related heap cost to roughly 256 MiB,
/// plus small framing/detector overhead. Thirty-two connection slots leave
/// ample room for concurrent local agents while bounding descriptors and
/// header-only/incomplete requests.
final class GatewayAdmissionController: @unchecked Sendable {
    struct Snapshot: Sendable, Equatable {
        let activeConnections: Int
        let retainedBodyBytes: Int
    }

    static let shared = GatewayAdmissionController(
        maximumConnections: 32,
        maximumRetainedBodyBytes: 2 * HTTPRequestInspector.maxBodyBytes
    )

    private struct Entry {
        var connectionActive = true
        var retainedBodyBytes = 0
    }

    private struct State {
        var nextIdentifier: UInt64 = 0
        var activeConnections = 0
        var retainedBodyBytes = 0
        var entries: [UInt64: Entry] = [:]
    }

    private let maximumConnections: Int
    private let maximumRetainedBodyBytes: Int
    private let lock = NSLock()
    private var state = State()

    init(maximumConnections: Int, maximumRetainedBodyBytes: Int) {
        precondition(maximumConnections > 0)
        precondition(maximumRetainedBodyBytes >= 0)
        self.maximumConnections = maximumConnections
        self.maximumRetainedBodyBytes = maximumRetainedBodyBytes
    }

    func tryAcquireConnection() -> GatewayAdmissionLease? {
        lock.lock()
        defer { lock.unlock() }
        guard state.activeConnections < maximumConnections else { return nil }

        repeat { state.nextIdentifier &+= 1 } while state.entries[state.nextIdentifier] != nil
        let identifier = state.nextIdentifier
        state.entries[identifier] = Entry()
        state.activeConnections += 1
        return GatewayAdmissionLease(controller: self, identifier: identifier)
    }

    fileprivate func tryReserveBodyBytes(_ count: Int, for identifier: UInt64) -> Bool {
        guard count >= 0 else { return false }
        guard count > 0 else { return true }
        lock.lock()
        defer { lock.unlock() }
        guard var entry = state.entries[identifier] else { return false }
        guard count <= maximumRetainedBodyBytes - state.retainedBodyBytes else { return false }
        entry.retainedBodyBytes += count
        state.retainedBodyBytes += count
        state.entries[identifier] = entry
        return true
    }

    fileprivate func releaseRetainedBodyBytes(for identifier: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        guard var entry = state.entries[identifier] else { return }
        state.retainedBodyBytes -= entry.retainedBodyBytes
        entry.retainedBodyBytes = 0
        if entry.connectionActive {
            state.entries[identifier] = entry
        } else {
            state.entries.removeValue(forKey: identifier)
        }
    }

    fileprivate func releaseConnection(for identifier: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        guard var entry = state.entries[identifier], entry.connectionActive else { return }
        entry.connectionActive = false
        state.activeConnections -= 1
        if entry.retainedBodyBytes == 0 {
            state.entries.removeValue(forKey: identifier)
        } else {
            state.entries[identifier] = entry
        }
    }

    func snapshot() -> Snapshot {
        lock.lock()
        defer { lock.unlock() }
        return Snapshot(
            activeConnections: state.activeConnections,
            retainedBodyBytes: state.retainedBodyBytes
        )
    }
}

/// One channel's admission lease. Connection and body release are separate:
/// when a client disconnects during inspection, its descriptor slot can be
/// reclaimed immediately while its body remains charged until the worker (or
/// pending upstream write) has actually dropped the retained bytes.
final class GatewayAdmissionLease: @unchecked Sendable {
    private let controller: GatewayAdmissionController
    private let identifier: UInt64

    fileprivate init(controller: GatewayAdmissionController, identifier: UInt64) {
        self.controller = controller
        self.identifier = identifier
    }

    func tryReserveBodyBytes(_ count: Int) -> Bool {
        controller.tryReserveBodyBytes(count, for: identifier)
    }

    func releaseRetainedBodyBytes() {
        controller.releaseRetainedBodyBytes(for: identifier)
    }

    func releaseConnection() {
        controller.releaseConnection(for: identifier)
    }

    deinit {
        releaseRetainedBodyBytes()
        releaseConnection()
    }
}

/// Strictly parse one canonical Content-Length for conservative up-front
/// body reservation. Invalid/ambiguous framing remains NIO's responsibility;
/// those requests are still charged incrementally before every body append.
enum GatewayAdmissionSizing {
    static func declaredBodyBytes(in headers: HTTPHeaders) -> Int? {
        let values = headers["content-length"]
        guard values.count == 1 else { return nil }
        let value = values[0].trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty,
              value.utf8.allSatisfy({ (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) }),
              let parsed = Int(value),
              parsed >= 0
        else { return nil }
        return parsed
    }
}

/// Transfers or discards a request buffer without retaining its prior
/// capacity in the channel handler. `ByteBuffer.clear()` intentionally keeps
/// storage for reuse and, when a snapshot shares that storage, may allocate a
/// second buffer of the same capacity. Either behavior would leave as much as
/// 64 MiB per live response outside the process-wide admission budget.
enum GatewayBodyBufferOwnership {
    static func handOff(_ buffer: inout ByteBuffer) -> ByteBuffer {
        let owned = buffer
        buffer = ByteBuffer()
        return owned
    }

    static func discard(_ buffer: inout ByteBuffer) {
        buffer = ByteBuffer()
    }
}

// MARK: - Bounded inspection execution

/// Process-lifetime worker pool for CPU- and allocation-heavy request
/// inspection. Keeping it shared avoids creating a thread pool for every
/// short-lived agent connection, while the fixed width prevents a burst of
/// loopback clients from spawning an unbounded number of scanner threads.
private enum GatewayInspectionExecutor {
    static let pool: NIOThreadPool = {
        // Two workers cap worst-case simultaneous 64 MiB JSON/object/window
        // allocations while still allowing one slow historical session not
        // to head-of-line block every other agent request.
        let pool = NIOThreadPool(numberOfThreads: max(1, min(2, System.coreCount)))
        pool.start()
        return pool
    }()
}

private struct GatewayRequestPolicy: Sendable {
    let blockEnabled: Bool
    let responseFilter: InjectionFilter?
}

private struct GatewayInspectionJob: Sendable {
    /// Immutable value snapshot of the channel buffer. `ByteBuffer` is
    /// copy-on-write and Sendable; the channel replaces/clears its own value
    /// before this reaches the worker, so materialising up to 64 MiB as Data
    /// does not stall the NIO event loop.
    let bodyBuffer: ByteBuffer
    let protectionRequested: Bool
    let unsupportedContentEncoding: String?
    let filter: InjectionFilter?
    let strict: Bool
    let allowlisted: Set<String>
    let salt: Data
    let trustAuthoredReads: Bool
    let blockEnabled: Bool
    let captureBlockSamples: Bool
    let targetHost: String
}

private struct GatewayInspectionResult: Sendable {
    let body: Data
    let injection: InjectionInspectionPass.Outcome
    let inspectionPerformed: Bool
    let scanSkippedReason: InjectionScanSkipReason?
    let unsupportedContentEncoding: String?
    let scanDurationSeconds: TimeInterval
    let hitCategories: [String]
    let hitSeverities: [String]

    static func run(_ job: GatewayInspectionJob) -> GatewayInspectionResult {
        let body = Data(job.bodyBuffer.readableBytesView)
        let scanStart = Date()
        var injection: InjectionInspectionPass.Outcome = .clean
        var inspectionPerformed = false
        var scanSkippedReason: InjectionScanSkipReason?
        var oversizedHasUntrustedMarker = false

        if !job.protectionRequested {
            scanSkippedReason = .protectionDisabled
        } else if job.unsupportedContentEncoding != nil {
            // NIO preserves Content-Encoding and does not inflate the body.
            // Never scan compressed bytes as though they were JSON.
            scanSkippedReason = .unsupportedContentEncoding
        } else if body.count > InjectionInspectionPass.maxScanBytes {
            scanSkippedReason = .oversized
            oversizedHasUntrustedMarker = body.withUnsafeBytes {
                InjectionInspectionPass.hasPlausibleUntrustedMarker(bytes: $0)
            }
            // A long, valid conversation with historical tool results must
            // not become permanently unusable merely because the envelope
            // crossed the ordinary fast-path ceiling. Once the bounded raw
            // gate establishes a supported shape, parse it on this worker
            // pool and evenly sample at most 24 untrusted detector windows.
            if oversizedHasUntrustedMarker, let filter = job.filter {
                injection = InjectionInspectionPass.inspectOversized(
                    body: body,
                    filter: filter,
                    strict: job.strict,
                    allowlisted: job.allowlisted,
                    salt: job.salt,
                    trustAuthoredReads: job.trustAuthoredReads
                )
                // A sampled positive is an actionable detector verdict. A
                // clean sample is not full coverage, so it remains an honest
                // oversized skip and is forwarded in either mode.
                if job.blockEnabled, injection.decision == .block {
                    inspectionPerformed = true
                    scanSkippedReason = nil
                }
            }
        } else if let filter = job.filter {
            inspectionPerformed = true
            let triggered = !body.isEmpty && body.withUnsafeBytes {
                InjectionInspectionPass.hasTrigger(bytes: $0)
            }
            if triggered {
                injection = InjectionInspectionPass.inspect(
                    body: body,
                    filter: filter,
                    strict: job.strict,
                    allowlisted: job.allowlisted,
                    salt: job.salt,
                    trustAuthoredReads: job.trustAuthoredReads
                )
            }
        } else {
            scanSkippedReason = .engineUnavailable
        }

        // Block explanations re-extract spans and may run attribution scans
        // plus a filesystem append. Keep that explicitly opt-in work on this
        // pool too, never on an NIO event loop.
        if job.captureBlockSamples,
           job.blockEnabled,
           injection.decision == .block,
           let filter = job.filter {
            let iso = ISO8601DateFormatter().string(from: Date())
            if let sample = InjectionInspectionPass.explain(
                body: body,
                filter: filter,
                outcome: injection,
                salt: job.salt,
                targetHost: job.targetHost,
                timestamp: iso
            ) {
                BlockSampleStore.append(sample)
            }
        }

        let scanDurationSeconds = inspectionPerformed
            ? max(0, Date().timeIntervalSince(scanStart))
            : 0
        return GatewayInspectionResult(
            body: body,
            injection: injection,
            inspectionPerformed: inspectionPerformed,
            scanSkippedReason: scanSkippedReason,
            unsupportedContentEncoding: job.unsupportedContentEncoding,
            scanDurationSeconds: scanDurationSeconds,
            hitCategories: Array(Set(injection.findings.flatMap(\.categories))).sorted(),
            hitSeverities: Array(Set(injection.findings.flatMap(\.severities))).sorted()
        )
    }
}

/// Owns the retained request-body budget while a serialized upstream write
/// is queued. Dropping an unstarted write releases it immediately; once the
/// write starts, its completion promise holds the budget until NIO has
/// accepted or failed the full outbound buffer.
private final class GatewayPendingUpstreamWrite: @unchecked Sendable {
    private let buffer: ByteBuffer
    private let admissionLease: GatewayAdmissionLease
    private var started = false

    init(buffer: ByteBuffer, admissionLease: GatewayAdmissionLease) {
        self.buffer = buffer
        self.admissionLease = admissionLease
    }

    func perform(on channel: Channel) {
        guard !started else { return }
        started = true
        let promise = channel.eventLoop.makePromise(of: Void.self)
        promise.futureResult.whenComplete { [admissionLease] _ in
            admissionLease.releaseRetainedBodyBytes()
        }
        channel.writeAndFlush(buffer, promise: promise)
    }

    deinit {
        if !started {
            admissionLease.releaseRetainedBodyBytes()
        }
    }
}

// MARK: - Gateway Handler (client-facing)

/// Buffers one inbound request, resolves its upstream, and forwards it
/// over TLS. Connects upstream *lazily* (on `.end`), because the route —
/// and therefore the upstream host — isn't known until the request is
/// parsed.
///
/// Every method runs on this channel's event loop, so `@unchecked
/// Sendable` documents that captures are loop-confined.
private final class GatewayHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = ByteBuffer

    private let overrides: UpstreamOverrides
    private let upstreamTrustRootsPEM: [String]?
    private let admissionController: GatewayAdmissionController
    private let responseTimeouts: GatewayResponseTimeouts
    private let inspectionEnabled: @Sendable () -> Bool
    private let onResponseAction: @Sendable ([ResponseActionInspector.Finding]) -> Void
    private let onRequest: @Sendable (RequestLog) -> Void
    private let eventLoop: EventLoop

    private var admissionLease: GatewayAdmissionLease?
    private var reservedBodyBytes = 0
    /// False while this handler owns the buffered bytes. Once inspection is
    /// queued, the worker closure/pending write owns their reservation even
    /// if the downstream channel disappears.
    private var bodyReservationHandedOff = false
    private var requestHead: HTTPRequestHead?
    private var bodyBuffer = ByteBuffer()
    /// A downstream connection carries exactly one request. This is a
    /// deliberate resource boundary, not merely a response-monitoring
    /// restriction: one accepted body (at most 64 MiB) is the maximum amount
    /// of request data this handler can retain or enqueue toward a slow
    /// upstream. The upstream request also carries `Connection: close`.
    private var downstreamRequestGate = DownstreamRequestGate()
    /// Mutable holder shared with the upstream relay installed during the
    /// async connect. It keeps request provenance stable across that lifetime
    /// without the relay capturing an optional inspector by value.
    private let responseInspectionSession = ResponseInspectionSession()
    /// Defence in depth around the request-scoped response inspector. The
    /// downstream gate already enforces one exchange; this separately makes
    /// it impossible to re-prime provenance if that transport policy changes.
    private var responseMonitoringGate = ResponseMonitoringGate()

    private var upstreamChannel: Channel?
    private let relayReadController = GatewayRelayReadController()
    /// Pins the full authority and ensures only the accepted request starts a
    /// connection. The queue remains independently bounded as defence in
    /// depth against a future change to the downstream policy.
    private var upstreamConnectGate = UpstreamConnectGate()
    private var pendingWrites: [GatewayPendingUpstreamWrite] = []
    // One request may wait for the upstream connect. A second request is
    // pipelining and is rejected instead of retaining another body (each can
    // be tens of MiB) and turning the count bound into a ~512 MiB queue.
    private static let maxPendingWrites = 1

    init(
        overrides: UpstreamOverrides,
        upstreamTrustRootsPEM: [String]?,
        admissionController: GatewayAdmissionController,
        responseTimeouts: GatewayResponseTimeouts,
        inspectionEnabled: @Sendable @escaping () -> Bool,
        onResponseAction: @Sendable @escaping ([ResponseActionInspector.Finding]) -> Void,
        onRequest: @Sendable @escaping (RequestLog) -> Void,
        eventLoop: EventLoop
    ) {
        self.overrides = overrides
        self.upstreamTrustRootsPEM = upstreamTrustRootsPEM
        self.admissionController = admissionController
        self.responseTimeouts = responseTimeouts
        self.inspectionEnabled = inspectionEnabled
        self.onResponseAction = onResponseAction
        self.onRequest = onRequest
        self.eventLoop = eventLoop
    }

    func channelActive(context: ChannelHandlerContext) {
        guard let lease = admissionController.tryAcquireConnection() else {
            // Saturation is a temporary local capacity condition. Return a
            // complete HTTP response rather than accepting a body that the
            // process cannot safely retain.
            respondLocally(
                channel: context.channel,
                status: "503 Service Unavailable",
                body: "Bouclier gateway capacity is temporarily exhausted",
                contentType: "text/plain"
            )
            return
        }
        admissionLease = lease
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            // Reject DNS-rebinding/non-loopback authorities before accepting
            // or buffering a single body byte. Deferring this check until
            // `.end` let many hostile connections each retain the full
            // 64 MiB transport allowance before receiving their 421.
            switch GatewayWire.inboundHostDisposition(in: head.headers) {
            case .accepted:
                break
            case .misdirected:
                respondLocally(context: context, status: "421 Misdirected Request")
                return
            case .malformed:
                respondLocally(context: context, status: "400 Bad Request")
                return
            }
            if GatewayWire.declaredContentLengthExceedsLimit(
                in: head.headers,
                limit: HTTPRequestInspector.maxBodyBytes
            ) {
                respondLocally(context: context, status: "413 Payload Too Large")
                return
            }
            guard downstreamRequestGate.beginRequest() else {
                // A second decoded head can only be HTTP/1.1 pipelining. It
                // violates this connection's advertised close semantics and
                // would otherwise let a fast loopback sender accumulate
                // whole requests behind a slow provider. Cancel the exchange
                // with one deterministic terminal response.
                respondLocally(
                    context: context,
                    status: "429 Too Many Requests",
                    body: "One request is allowed per Bouclier gateway connection",
                    contentType: "text/plain"
                )
                return
            }
            if let declaredBodyBytes = GatewayAdmissionSizing.declaredBodyBytes(in: head.headers) {
                guard reserveBodyBytes(upTo: declaredBodyBytes) else {
                    respondLocally(
                        context: context,
                        status: "503 Service Unavailable",
                        body: "Bouclier gateway body capacity is temporarily exhausted",
                        contentType: "text/plain"
                    )
                    return
                }
            }
            var acceptedHead = head
            switch GatewayWire.expectation(in: head.headers) {
            case .none:
                break
            case .continue:
                // A conforming client may wait for this interim response
                // before sending the body. Validate the loopback boundary
                // first so a rebinding request never receives encouragement.
                var interim = context.channel.allocator.buffer(capacity: 25)
                interim.writeString("HTTP/1.1 100 Continue\r\n\r\n")
                context.channel.writeAndFlush(interim, promise: nil)
                // Bouclier, not the origin, satisfied this hop's expectation.
                // Forwarding it would invite a second upstream 100 response
                // after the client has already started streaming the body.
                GatewayWire.removeLocallyHandledExpectation(from: &acceptedHead.headers)
            case .unsupported:
                respondLocally(context: context, status: "417 Expectation Failed")
                return
            }
            requestHead = acceptedHead
            GatewayBodyBufferOwnership.discard(&bodyBuffer)

        case .body(var body):
            guard requestHead != nil else { return }
            let accumulatedBytes = bodyBuffer.readableBytes + body.readableBytes
            if accumulatedBytes > HTTPRequestInspector.maxBodyBytes {
                respondLocally(context: context, status: "413 Payload Too Large")
                return
            }
            // Reserve aggregate process capacity before retaining this chunk.
            // This covers chunked/undeclared bodies and any decoder-tolerated
            // mismatch beyond the up-front Content-Length reservation.
            guard reserveBodyBytes(upTo: accumulatedBytes) else {
                respondLocally(
                    context: context,
                    status: "503 Service Unavailable",
                    body: "Bouclier gateway body capacity is temporarily exhausted",
                    contentType: "text/plain"
                )
                return
            }
            bodyBuffer.writeBuffer(&body)

        case .end:
            guard requestHead != nil else { return }
            // Stop socket reads before inspection/connect work begins. Bytes
            // for a pipelined request that arrive in a later packet remain in
            // the bounded kernel receive buffer until this connection closes;
            // a second head already decoded from the current packet is caught
            // by `downstreamRequestGate` above.
            let clientChannel = context.channel
            clientChannel.setOption(ChannelOptions.autoRead, value: false).whenFailure { _ in
                clientChannel.close(promise: nil)
            }
            handleRequest(context: context)
        }
    }

    private func reserveBodyBytes(upTo requestedBytes: Int) -> Bool {
        guard requestedBytes >= reservedBodyBytes else { return true }
        let additionalBytes = requestedBytes - reservedBodyBytes
        guard admissionLease?.tryReserveBodyBytes(additionalBytes) == true else { return false }
        reservedBodyBytes = requestedBytes
        return true
    }

    private func handleRequest(context: ChannelHandlerContext) {
        guard let head = requestHead else { return }

        // DNS-rebinding defence: a malicious web page can resolve a
        // hostname to 127.0.0.1 and POST to us, but the `Host` header it
        // sends won't be loopback. We only serve loopback Hosts.
        guard GatewayWire.inboundHostDisposition(in: head.headers) == .accepted else {
            respondLocally(context: context, status: "421 Misdirected Request")
            return
        }

        let route = GatewayRoute.resolve(method: head.method, uri: head.uri, headers: head.headers, overrides: overrides)

        switch route {
        case .ops(let kind):
            respondOps(context: context, kind: kind)
        case .proxy(let host, let port):
            forwardUpstream(context: context, head: head, host: host, port: port)
        case .rejectUnknownProvider:
            respondLocally(
                context: context,
                status: "400 Bad Request",
                body: "Unable to determine the upstream provider for this path",
                contentType: "text/plain"
            )
        }
    }

    // MARK: Upstream forwarding

    private func forwardUpstream(context: ChannelHandlerContext, head: HTTPRequestHead, host: String, port: Int) {
        guard let workLease = admissionLease else {
            respondLocally(context: context, status: "503 Service Unavailable")
            return
        }
        // Snapshot all mutable policy inputs once per request. The expensive
        // trigger scan, JSON parse, regex/ML work, and full-body oversized
        // marker scan then run on a bounded worker pool instead of the NIO
        // event loop. No upstream bytes are emitted until the result returns,
        // preserving request order and the block-before-forward invariant.
        let bodyBufferSnapshot = GatewayBodyBufferOwnership.handOff(&bodyBuffer)
        let gatewayInspectionEnabled = inspectionEnabled()
        let activeFilter = InjectionFilter.active.current()
        let protectionRequested = gatewayInspectionEnabled && FeatureFlags.injectionDetection
        let unsupportedContentEncoding = GatewayWire.unsupportedContentEncoding(in: head.headers)
        let detectorEligible = protectionRequested
            && unsupportedContentEncoding == nil
            && activeFilter != nil
        let allowlisted = detectorEligible ? SpanAllowlist.snapshot() : []
        let fingerprintSalt = detectorEligible ? SpanAllowlist.salt() : Data()
        let policy = GatewayRequestPolicy(
            blockEnabled: FeatureFlags.injectionBlock,
            responseFilter: gatewayInspectionEnabled && FeatureFlags.responseActionMonitoring
                ? activeFilter
                : nil
        )
        let job = GatewayInspectionJob(
            bodyBuffer: bodyBufferSnapshot,
            protectionRequested: protectionRequested,
            unsupportedContentEncoding: unsupportedContentEncoding,
            filter: activeFilter,
            strict: FeatureFlags.injectionStrict,
            allowlisted: allowlisted,
            salt: fingerprintSalt,
            trustAuthoredReads: FeatureFlags.injectionTrustAuthoredReads,
            blockEnabled: policy.blockEnabled,
            captureBlockSamples: UserDefaults.standard.bool(forKey: "captureBlockSamplesEnabled"),
            targetHost: host
        )

        // The immutable ByteBuffer value snapshot owns the body while the
        // worker runs; release the channel-local request state immediately.
        let clientChannel = context.channel
        requestHead = nil
        bodyReservationHandedOff = true

        GatewayInspectionExecutor.pool.runIfActive(eventLoop: eventLoop) {
            GatewayInspectionResult.run(job)
        }.whenComplete { [weak self, workLease] result in
            guard let self, clientChannel.isActive else {
                workLease.releaseRetainedBodyBytes()
                return
            }
            switch result {
            case .success(let inspection):
                self.finishForwardUpstream(
                    channel: clientChannel,
                    head: head,
                    host: host,
                    port: port,
                    body: inspection.body,
                    policy: policy,
                    inspection: inspection,
                    admissionLease: workLease
                )
            case .failure:
                // The process-lifetime worker pool should only be inactive
                // during teardown. Never silently label an uninspected body
                // clean if that invariant is violated.
                workLease.releaseRetainedBodyBytes()
                self.respondLocally(channel: clientChannel, status: "503 Service Unavailable")
            }
        }
    }

    private func finishForwardUpstream(
        channel: Channel,
        head: HTTPRequestHead,
        host: String,
        port: Int,
        body: Data,
        policy: GatewayRequestPolicy,
        inspection: GatewayInspectionResult,
        admissionLease: GatewayAdmissionLease
    ) {
        var bodyReservationTransferred = false
        defer {
            if !bodyReservationTransferred {
                admissionLease.releaseRetainedBodyBytes()
            }
        }
        let allocator = channel.allocator
        var headers = head.headers
        let requestURI = head.uri
        let injection = inspection.injection
        let inspectionPerformed = inspection.inspectionPerformed
        let scanSkippedReason = inspection.scanSkippedReason
        let scanDurationSeconds = inspection.scanDurationSeconds
        let hitCategories = inspection.hitCategories
        let hitSeverities = inspection.hitSeverities
        let unsupportedContentEncoding = inspection.unsupportedContentEncoding

        if scanSkippedReason == .unsupportedContentEncoding,
           let unsupportedContentEncoding,
           policy.blockEnabled {
            onRequest(RequestLog(
                timestamp: Date(),
                targetHost: host,
                detected: true,
                matchCount: 0,
                patternNames: [],
                bodySize: body.count,
                mlScore: nil,
                entropyAnomaly: 0,
                fusedScore: 0,
                mlAvailable: false,
                scanDurationSeconds: 0,
                inspectionPerformed: false,
                scanSkippedReason: .unsupportedContentEncoding
            ))
            respondLocally(
                channel: channel,
                status: "422 Unprocessable Entity",
                body: InjectionInspectionPass.unsupportedEncodingRefusalJSON(
                    encoding: unsupportedContentEncoding
                ),
                contentType: "application/json"
            )
            return
        }

        // Enforcement is OPT-IN (monitor mode by default): a would-block
        // detection is logged but forwarded unless `injectionBlock` is on.
        // Untrusted spans that trip a critical pattern are very often benign
        // — source, diffs, email templates, LLM-prompt strings all contain
        // "system prompt" / "ignore previous instructions" — and a pattern
        // engine can't tell a quoted payload from a live one. Hard-blocking
        // by default breaks normal agent work; prevention is a deliberate
        // opt-in.
        if injection.decision == .block, policy.blockEnabled {
            let blocker = injection.blockedFinding
            onRequest(RequestLog(
                timestamp: Date(),
                targetHost: host,
                detected: true,
                matchCount: blocker?.matchCount ?? 0,
                patternNames: blocker?.patternNames ?? [],
                bodySize: body.count,
                mlScore: injection.blockedFinding?.mlScore,
                entropyAnomaly: injection.blockedFinding?.entropyAnomaly ?? 0,
                // Record the fused score of the span that actually drove
                // the block, not `topScore` (the max across all spans).
                // With several untrusted spans those differ, and pairing a
                // max fused score with the blocking span's ml/entropy made
                // the audit row incoherent — three columns describing
                // different spans. Fall back to topScore only if there is
                // somehow no blocked finding.
                fusedScore: injection.blockedFinding?.fusedScore ?? injection.topScore,
                mlAvailable: injection.mlAvailable,
                multimodal: nil,
                // Lets the activity feed / notification offer "release this
                // span" so the operator can recover a session a false
                // positive would otherwise wedge on every resume.
                spanFingerprint: injection.blockedFingerprint,
                // JSON path of the blocking span — structural metadata for
                // the notification, never the span's content.
                locator: injection.blockedFinding?.locator,
                categories: blocker?.categories ?? [],
                severities: blocker?.severities ?? [],
                scanDurationSeconds: scanDurationSeconds,
                inspectionPerformed: inspectionPerformed,
                scanSkippedReason: scanSkippedReason
            ))
            // Optional block-sample explanation was also produced and
            // persisted on the inspection pool; no filesystem or secondary
            // detector work is performed on the event loop here.
            respondWithRefusal(channel: channel, outcome: injection)
            return
        }

        // Rewrite Host to the upstream (the client sent "127.0.0.1:<port>")
        // and strip hop-by-hop headers that must not cross a proxy. Drop
        // Content-Length too: the raw path re-derives it, the parts path
        // lets the encoder set it. Every other header — anthropic-beta,
        // anthropic-version, the auth credential, content-type, user-agent
        // — is forwarded verbatim: Claude Code's 1M-context and prompt-cache
        // behaviour depend on it.
        headers.replaceOrAdd(name: "Host", value: GatewayWire.upstreamHostHeader(host: host, port: port))
        // `Connection` can nominate additional per-hop fields (for example,
        // `Connection: X-Local-Auth`). Resolve that list before removing the
        // Connection header itself so those values never leak to the origin.
        for h in GatewayWire.hopByHopHeaderNames(in: headers) { headers.remove(name: h) }
        headers.remove(name: "Content-Length")
        // A single exchange per downstream connection is the gateway's hard
        // memory/provenance boundary. Ask the provider to terminate its side
        // after the corresponding response as well.
        headers.replaceOrAdd(name: "Connection", value: "close")

        // Wire-safety: a CR/LF/NUL in the request line or a header would
        // smuggle a second request. `requestURI` is checked (not head.uri)
        // because scrub may have rewritten it.
        guard HTTPRequestInspector.containsControlBytes(requestURI) == false,
              GatewayWire.isWireSafe(headers: headers) else {
            respondLocally(channel: channel, status: "400 Bad Request")
            return
        }

        if let responseFilter = policy.responseFilter {
            guard responseMonitoringGate.beginMonitoredRequest() else {
                // ResponseActionInspector is request-scoped. Re-priming it
                // for a pipelined request would attribute response N to
                // request N+1, so fail this unusual transport shape closed
                // and discard monitoring state rather than emit a false
                // trifecta finding.
                responseInspectionSession.disable()
                respondLocally(
                    channel: channel,
                    status: "409 Conflict",
                    body: "HTTP pipelining is unsupported while response monitoring is active",
                    contentType: "text/plain"
                )
                return
            }
            responseInspectionSession.begin(
                filter: responseFilter,
                requestHadUntrusted: injection.untrustedSpanCount > 0
            )
        } else {
            // Monitoring may have been turned off after this connection was
            // created. Clear any old request state before relaying again.
            responseInspectionSession.disable()
        }

        let bodySize = body.count
        // Raw path: byte-faithful hand-serialized request.
        let writeRequest: GatewayPendingUpstreamWrite
        do {
            var outHeaders = headers
            outHeaders.replaceOrAdd(name: "Content-Length", value: "\(bodySize)")
            var raw = allocator.buffer(capacity: 1024 + bodySize)
            raw.writeString("\(head.method) \(requestURI) HTTP/1.1\r\n")
            for (name, value) in outHeaders { raw.writeString("\(name): \(value)\r\n") }
            raw.writeString("\r\n")
            raw.writeBytes(body)
            writeRequest = GatewayPendingUpstreamWrite(
                buffer: raw,
                admissionLease: admissionLease
            )
        }

        // `detected` drives the red shield in the activity log and is
        // reserved for requests we actually refused. A `.flag` outcome
        // (something matched, but on the operator's own text) is recorded
        // with its score and pattern names and forwarded unchanged — the
        // v0.6.1 lesson about not showing a block indicator for something
        // that wasn't blocked.
        let topFinding = injection.findings.max { lhs, rhs in
            lhs.fusedScore < rhs.fusedScore
        }
        onRequest(RequestLog(
            timestamp: Date(),
            targetHost: host,
            detected: false,
            matchCount: injection.findings.reduce(0) { $0 + $1.matchCount },
            patternNames: Array(Set(injection.findings.flatMap(\.patternNames))),
            bodySize: bodySize,
            mlScore: topFinding?.mlScore,
            entropyAnomaly: topFinding?.entropyAnomaly ?? 0,
            fusedScore: topFinding?.fusedScore ?? 0,
            mlAvailable: injection.mlAvailable,
            multimodal: nil,
            categories: hitCategories,
            severities: hitSeverities,
            scanDurationSeconds: scanDurationSeconds,
            injectionFlagged: !injection.findings.isEmpty,
            inspectionPerformed: inspectionPerformed,
            scanSkippedReason: scanSkippedReason
        ))

        if sendUpstream(channel: channel, write: writeRequest, host: host, port: port) {
            bodyReservationTransferred = true
        } else {
            responseInspectionSession.disable()
        }
    }

    @discardableResult
    private func sendUpstream(
        channel: Channel,
        write: GatewayPendingUpstreamWrite,
        host: String,
        port: Int
    ) -> Bool {
        let requestedAuthority = UpstreamAuthority(host: host, port: port)

        switch upstreamConnectGate.route(
            requestedAuthority,
            hasUpstreamChannel: upstreamChannel != nil,
            queuedWriteCount: pendingWrites.count,
            queueLimit: Self.maxPendingWrites
        ) {
        case .rejectAuthority:
            respondLocally(channel: channel, status: "421 Misdirected Request")
            return false
        case .rejectBusy:
            // Closing this downstream connection deterministically rejects
            // every pipelined request rather than retaining unbounded bodies.
            // A late successful connect observes the closed client and closes
            // without replaying the discarded writes.
            pendingWrites.removeAll(keepingCapacity: false)
            upstreamConnectGate.didFail()
            respondLocally(channel: channel, status: "503 Service Unavailable")
            return false
        case .writeNow:
            guard let upstream = upstreamChannel else {
                assertionFailure("connect gate selected writeNow without an upstream channel")
                return false
            }
            write.perform(on: upstream)
            return true
        case .queue:
            pendingWrites.append(write)
            return true
        case .queueAndConnect:
            pendingWrites.append(write)
            connectToUpstream(clientChannel: channel, host: host, port: port)
            return true
        }
    }

    private func connectToUpstream(clientChannel: Channel, host: String, port: Int) {
        // The relay captures a stable session holder rather than the current
        // optional inspector, so runtime setting changes cannot freeze nil or
        // retain stale request provenance for the life of the connection.
        let inspectionSession = responseInspectionSession
        let readController = relayReadController
        let responseTimeouts = responseTimeouts
        let onAction = onResponseAction
        do {
            var tlsConfig = TLSConfiguration.makeClientConfiguration()
            tlsConfig.certificateVerification = .fullVerification
            // No ALPN: pin upstream to HTTP/1.1. HTTP/2 lowercases all
            // header names (RFC 9113), which would mangle byte-faithful
            // pass-through of `anthropic-beta` and friends.
            tlsConfig.applicationProtocols = ["http/1.1"]
            if let pems = upstreamTrustRootsPEM {
                var roots: [NIOSSLCertificate] = []
                for pem in pems { roots.append(contentsOf: try NIOSSLCertificate.fromPEMBytes(Array(pem.utf8))) }
                tlsConfig.trustRoots = .certificates(roots)
            }
            let sslContext = try NIOSSLContext(configuration: tlsConfig)

            // Raw response relay. The request asks the provider to close after
            // one response; model-visible request body bytes are forwarded
            // unchanged or the request is refused.
            let bootstrap = ClientBootstrap(group: eventLoop)
                .connectTimeout(.seconds(10))
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        try channel.pipeline.syncOperations.addHandlers(
                            NIOSSLClientHandler(context: sslContext, serverHostname: host),
                            GatewayRelayHandler(
                                clientChannel: clientChannel,
                                inspectionSession: inspectionSession,
                                readController: readController,
                                idleTimeout: responseTimeouts.idle,
                                maximumLifetime: responseTimeouts.maximumLifetime,
                                onFinding: onAction
                            )
                        )
                    }
                }

            bootstrap.connect(host: host, port: port).whenComplete { [weak self] result in
                guard let self else {
                    // The downstream handler can disappear while DNS/TCP/TLS
                    // is still in flight. A successful late channel still
                    // needs an explicit close; otherwise its relay retains
                    // the dead client until the remote idle timeout.
                    if case .success(let channel) = result {
                        channel.close(promise: nil)
                    }
                    return
                }
                switch result {
                case .success(let channel):
                    guard clientChannel.isActive else {
                        self.pendingWrites.removeAll(keepingCapacity: false)
                        self.upstreamConnectGate.didFail()
                        channel.close(promise: nil)
                        return
                    }
                    self.upstreamChannel = channel
                    self.upstreamConnectGate.didConnect()
                    let writes = self.pendingWrites
                    self.pendingWrites.removeAll(keepingCapacity: true)
                    for write in writes { write.perform(on: channel) }
                case .failure:
                    // Fail toward the client with an honest 502 rather than
                    // hanging it.
                    self.pendingWrites.removeAll(keepingCapacity: false)
                    self.upstreamConnectGate.didFail()
                    self.respondLocally(channel: clientChannel, status: "502 Bad Gateway")
                }
            }
        } catch {
            pendingWrites.removeAll(keepingCapacity: false)
            upstreamConnectGate.didFail()
            respondLocally(channel: clientChannel, status: "502 Bad Gateway")
        }
    }

    // MARK: Local (non-proxied) responses

    private func respondOps(context: ChannelHandlerContext, kind: GatewayRoute.OpsKind) {
        let channel = context.channel
        switch kind {
        case .livez:
            respondLocally(channel: channel, status: "200 OK", body: "ok")
        case .readyz:
            respondLocally(channel: channel, status: "200 OK", body: "ready")
        case .health:
            // Config is only ever exposed to loopback callers, which by
            // bind + Host-header guard is everyone who reaches here.
            let json = "{\"status\":\"ok\",\"mode\":\"standard\",\"anthropic\":\"\(overrides.anthropicHost)\",\"openai\":\"\(overrides.openaiHost)\"}"
            respondLocally(channel: channel, status: "200 OK", body: json, contentType: "application/json")
        }
        requestHead = nil
        GatewayBodyBufferOwnership.discard(&bodyBuffer)
    }

    private func respondLocally(
        context: ChannelHandlerContext,
        status: String,
        body: String = "",
        contentType: String = "text/plain"
    ) {
        respondLocally(
            channel: context.channel,
            status: status,
            body: body,
            contentType: contentType
        )
        requestHead = nil
        GatewayBodyBufferOwnership.discard(&bodyBuffer)
    }

    /// Refuse a request whose untrusted content carried instructions.
    ///
    /// 422 (Unprocessable Entity) with a provider-shaped JSON error body:
    /// the agent SDK raises a readable API error naming the offending
    /// location instead of dying on a closed socket, so the operator can
    /// see *what* was blocked and *where* without opening the menu bar.
    ///
    /// Deliberately **not** 401/403: Claude Code (and the Anthropic SDK's
    /// auth handling) maps both to a credential failure and tells the user
    /// to run `/login`, mislabelling a policy block as an auth problem.
    /// Deliberately **not** a retryable code (408/409/429/5xx): the block is
    /// deterministic, so the SDK's auto-retry would loop it forever. 422 is
    /// non-auth and non-retryable, so the refusal message surfaces cleanly.
    private func respondWithRefusal(channel: Channel, outcome: InjectionInspectionPass.Outcome) {
        respondLocally(
            channel: channel,
            status: "422 Unprocessable Entity",
            body: InjectionInspectionPass.refusalJSON(for: outcome),
            contentType: "application/json"
        )
    }

    private func respondLocally(channel: Channel, status: String, body: String = "", contentType: String = "text/plain") {
        let payload = Array(body.utf8)
        var resp = "HTTP/1.1 \(status)\r\nConnection: close\r\nContent-Type: \(contentType)\r\nContent-Length: \(payload.count)\r\n\r\n"
        resp += body
        var buf = channel.allocator.buffer(capacity: resp.utf8.count)
        buf.writeString(resp)
        channel.writeAndFlush(buf, promise: nil)
        channel.close(promise: nil)
        upstreamChannel?.close(promise: nil)
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        relayReadController.downstreamWritabilityChanged(context.channel.isWritable)
        context.fireChannelWritabilityChanged()
    }

    func channelInactive(context: ChannelHandlerContext) {
        releaseAdmissionForChannelClose()
        pendingWrites.removeAll(keepingCapacity: false)
        upstreamChannel?.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        releaseAdmissionForChannelClose()
        pendingWrites.removeAll(keepingCapacity: false)
        upstreamChannel?.close(promise: nil)
        context.close(promise: nil)
    }

    private func releaseAdmissionForChannelClose() {
        guard let lease = admissionLease else { return }
        lease.releaseConnection()
        if !bodyReservationHandedOff {
            lease.releaseRetainedBodyBytes()
        }
        admissionLease = nil
    }

    deinit {
        releaseAdmissionForChannelClose()
    }

}

// MARK: - Wire helpers (pure, unit-testable)

/// Outbound wire-format guards shared by the gateway handler and its
/// tests. Channel-free so they can be exercised without a socket.
enum GatewayWire {
    enum Expectation: Equatable { case none, `continue`, unsupported }
    enum InboundHostDisposition: Equatable { case accepted, misdirected, malformed }
    /// Hop-by-hop headers (RFC 7230 §6.1) — must not be forwarded across a
    /// proxy. The gateway supplies fresh framing and explicitly closes the
    /// one-exchange upstream leg.
    static let hopByHopHeaders = [
        "connection", "keep-alive", "proxy-connection",
        "transfer-encoding", "te", "upgrade", "trailer",
        // Credentials for an inbound proxy hop are never origin headers.
        "proxy-authorization", "proxy-authenticate",
    ]

    static func hopByHopHeaderNames(in headers: HTTPHeaders) -> Set<String> {
        var names = Set(hopByHopHeaders)
        for token in headers[canonicalForm: "connection"] {
            let name = String(token).lowercased()
            if HTTPRequestInspector.isValidHeaderName(name) {
                names.insert(name)
            }
        }
        return names
    }

    /// RFC 9110 requires the authority's non-default port in Host. Omitting
    /// it broke virtual-host routing for HTTPS upstream overrides on 8443.
    static func upstreamHostHeader(host: String, port: Int) -> String {
        let renderedHost = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        return port == 443 ? renderedHost : "\(renderedHost):\(port)"
    }

    static func isWireSafe(headers: HTTPHeaders) -> Bool {
        for (name, value) in headers {
            if !HTTPRequestInspector.isValidHeaderName(name) { return false }
            if HTTPRequestInspector.containsControlBytes(value) { return false }
        }
        return true
    }

    /// Return the unsupported coding(s), or nil when the body is directly
    /// inspectable. `identity` is the only supported Content-Encoding;
    /// transfer framing (chunked) is decoded separately by NIO.
    static func unsupportedContentEncoding(in headers: HTTPHeaders) -> String? {
        let codings = headers[canonicalForm: "content-encoding"]
            .flatMap { value in
                value.split(separator: ",", omittingEmptySubsequences: false)
                    .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            }
        guard !codings.isEmpty else { return nil }
        let unsupported = codings.filter {
            !$0.isEmpty && $0.caseInsensitiveCompare("identity") != .orderedSame
        }
        // An explicitly empty/malformed header is not evidence of encoded
        // bytes; treat it like absence rather than breaking availability.
        return unsupported.isEmpty ? nil : unsupported.joined(separator: ", ")
    }

    static func expectation(in headers: HTTPHeaders) -> Expectation {
        let values = headers[canonicalForm: "expect"]
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
        guard !values.isEmpty else { return .none }
        return values.count == 1
            && values[0].caseInsensitiveCompare("100-continue") == .orderedSame
            ? .continue
            : .unsupported
    }

    /// Remove an expectation that this gateway has already satisfied on the
    /// client-facing hop. `Expect` is end-to-end in HTTP semantics, so it is
    /// not part of the generic hop-by-hop list; this explicit consumption is
    /// required after locally emitting `100 Continue`.
    static func removeLocallyHandledExpectation(from headers: inout HTTPHeaders) {
        headers.remove(name: "Expect")
    }

    /// Classify the client-facing Host header without accepting ambiguity.
    /// HTTP/1.1 requires exactly one authority; duplicates/missing/malformed
    /// syntax are a 400, while one well-formed non-loopback authority is a
    /// DNS-rebinding attempt and receives 421.
    static func inboundHostDisposition(in headers: HTTPHeaders) -> InboundHostDisposition {
        let values = headers["host"]
        guard values.count == 1 else { return .malformed }
        let value = values[0].trimmingCharacters(in: .whitespacesAndNewlines)
        guard value == values[0], !value.isEmpty else { return .malformed }
        if isLoopbackHostHeader(value) { return .accepted }
        return isSyntacticallyValidAuthority(value) ? .misdirected : .malformed
    }

    /// Cheap early body-limit guard. It acts only on one unambiguous decimal
    /// Content-Length. Duplicate, combined, signed, or otherwise invalid
    /// framing is left to NIO's decoder, and the streaming byte counter remains
    /// authoritative for chunked/undeclared bodies.
    static func declaredContentLengthExceedsLimit(in headers: HTTPHeaders, limit: Int) -> Bool {
        guard limit >= 0 else { return false }
        let values = headers["content-length"]
        guard values.count == 1 else { return false }
        let value = values[0].trimmingCharacters(in: .whitespacesAndNewlines)
        guard !value.isEmpty,
              value.utf8.allSatisfy({ (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0) })
        else { return false }
        // Decimal overflow is still unambiguously larger than the 64 MiB
        // limit; it need not survive an integer conversion to reject early.
        guard let declared = UInt64(value) else { return true }
        return declared > UInt64(limit)
    }

    /// The `Host` a loopback caller legitimately sends. Anything else is a
    /// rebinding attempt against a credential-forwarding service.
    static func isLoopbackHostHeader(_ raw: String) -> Bool {
        let value = raw.lowercased()
        if value.hasPrefix("[") {
            guard let close = value.firstIndex(of: "]"),
                  value[value.index(after: value.startIndex)..<close] == "::1",
                  validPortSuffix(value[value.index(after: close)...])
            else { return false }
            return true
        }

        let colon = value.firstIndex(of: ":")
        let host = colon.map { value[..<$0] } ?? value[...]
        let suffix = colon.map { value[$0...] } ?? value[value.endIndex...]
        guard validPortSuffix(suffix),
              host == "127.0.0.1" || host == "localhost"
        else { return false }
        return true
    }

    private static func isSyntacticallyValidAuthority(_ value: String) -> Bool {
        if value.hasPrefix("[") {
            guard let close = value.firstIndex(of: "]"),
                  close > value.index(after: value.startIndex),
                  validPortSuffix(value[value.index(after: close)...])
            else { return false }
            let literal = value[value.index(after: value.startIndex)..<close]
            // A bracketed authority is an IPv6 literal. This lexical check is
            // intentionally strict enough to reject smuggling syntax; the
            // value is never used for routing because all non-loopback Hosts
            // are rejected regardless.
            guard literal.contains(":"), literal.allSatisfy({ character in
                character == ":" || character == "." || character.isHexDigit
            }) else { return false }
            return true
        }

        let parts = value.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        guard let host = parts.first, !host.isEmpty,
              ManagedConfigValidator.validatedHostname(String(host)) != nil
        else { return false }
        if parts.count == 2 {
            guard let colon = value.firstIndex(of: ":") else { return false }
            return validPortSuffix(value[colon...])
        }
        return true
    }

    private static func validPortSuffix(_ suffix: Substring) -> Bool {
        guard !suffix.isEmpty else { return true }
        guard suffix.first == ":",
              let port = Int(suffix.dropFirst()),
              (1...65535).contains(port)
        else { return false }
        return true
    }
}

/// Full upstream authority identity. Host alone is insufficient: two provider
/// overrides may deliberately share a gateway hostname while using separate
/// TLS ports. Kept explicit even with one exchange per downstream connection.
struct UpstreamAuthority: Sendable, Equatable {
    let host: String
    let port: Int
}

/// Hard one-exchange boundary for each client-facing channel. Claiming at
/// request-head time prevents a pipelined body from replacing the current
/// buffer while its predecessor is being inspected or connected upstream.
struct DownstreamRequestGate: Sendable {
    private(set) var hasClaimedConnection = false

    mutating func beginRequest() -> Bool {
        guard !hasClaimedConnection else { return false }
        hasClaimedConnection = true
        return true
    }
}

/// Pure connection-state gate for `GatewayHandler`. It pins authority as
/// soon as connection starts and distinguishes the one request allowed to
/// start I/O from later requests that must only queue. Kept channel-free so
/// pipelining and failure transitions have deterministic regression tests.
struct UpstreamConnectGate: Sendable {
    enum Action: Sendable, Equatable {
        case writeNow
        case queueAndConnect
        case queue
        case rejectAuthority
        case rejectBusy
    }

    private(set) var authority: UpstreamAuthority?
    private(set) var isConnecting = false

    mutating func route(
        _ requestedAuthority: UpstreamAuthority,
        hasUpstreamChannel: Bool,
        queuedWriteCount: Int,
        queueLimit: Int
    ) -> Action {
        if let authority, authority != requestedAuthority { return .rejectAuthority }
        if hasUpstreamChannel {
            authority = requestedAuthority
            return .writeNow
        }
        guard queuedWriteCount < queueLimit else { return .rejectBusy }
        authority = requestedAuthority
        if isConnecting { return .queue }
        isConnecting = true
        return .queueAndConnect
    }

    mutating func didConnect() {
        isConnecting = false
    }

    mutating func didFail() {
        authority = nil
        isConnecting = false
    }
}

/// One monitored response per downstream connection. The corresponding
/// request asks the upstream to close after its response, so a second claim
/// can only be pipelining that would make request/response provenance
/// ambiguous for the streaming inspector.
struct ResponseMonitoringGate: Sendable {
    private(set) var hasClaimedConnection = false

    mutating func beginMonitoredRequest() -> Bool {
        guard !hasClaimedConnection else { return false }
        hasClaimedConnection = true
        return true
    }
}

/// Event-loop-confined reference shared by the request handler and raw
/// response relay. The holder is stable across asynchronous upstream setup
/// and the full streaming response lifetime.
final class ResponseInspectionSession: @unchecked Sendable {
    private var inspector: ResponseActionInspector?

    func begin(filter: InjectionFilter, requestHadUntrusted: Bool) {
        inspector = ResponseActionInspector(
            filter: filter,
            requestHadUntrusted: requestHadUntrusted
        )
    }

    func disable() {
        inspector = nil
    }

    func ingest(_ text: String) -> [ResponseActionInspector.Finding] {
        guard let inspector else { return [] }
        inspector.ingest(text)
        return inspector.takeNewFindings()
    }

    func finish() -> [ResponseActionInspector.Finding] {
        guard let inspector else { return [] }
        inspector.finish()
        let findings = inspector.takeNewFindings()
        self.inspector = nil
        return findings
    }
}

/// Event-loop-confined state machine for cross-channel response
/// backpressure. Upstream reads are left enabled through TCP/TLS setup; only
/// after the handshake does downstream writability control `autoRead`.
struct GatewayRelayBackpressureState: Sendable, Equatable {
    private(set) var downstreamWritable = true
    private(set) var upstreamReady = false

    mutating func downstreamWritabilityChanged(_ writable: Bool) -> Bool? {
        guard downstreamWritable != writable else { return nil }
        downstreamWritable = writable
        return upstreamReady ? writable : nil
    }

    mutating func upstreamBecameReady() -> Bool {
        upstreamReady = true
        return downstreamWritable
    }

    mutating func upstreamClosed() {
        upstreamReady = false
    }
}

/// Bridges the client channel's write-buffer watermark to the upstream
/// channel's read loop. Both channels intentionally share `GatewayHandler`'s
/// event loop, so state transitions and option changes remain ordered without
/// cross-thread synchronization.
final class GatewayRelayReadController: @unchecked Sendable {
    private var state = GatewayRelayBackpressureState()
    private weak var upstreamChannel: Channel?

    func downstreamWritabilityChanged(_ writable: Bool) {
        guard let autoRead = state.downstreamWritabilityChanged(writable),
              let upstreamChannel
        else { return }
        apply(autoRead: autoRead, to: upstreamChannel)
    }

    func upstreamHandshakeCompleted(_ channel: Channel) {
        upstreamChannel = channel
        apply(autoRead: state.upstreamBecameReady(), to: channel)
    }

    func upstreamClosed(_ channel: Channel) {
        if upstreamChannel === channel {
            upstreamChannel = nil
            state.upstreamClosed()
        }
    }

    private func apply(autoRead: Bool, to channel: Channel) {
        channel.setOption(ChannelOptions.autoRead, value: autoRead).whenFailure { _ in
            channel.close(promise: nil)
        }
    }
}

// MARK: - Upstream Relay (response side)

/// Shovels response bytes from the provider back to the agent, raw and
/// unmodified — the relay is byte-faithful and never rewrites the response.
///
/// It may *observe*: when a `ResponseActionInspector` is attached, each
/// chunk is forwarded first (unchanged) and then a non-consuming copy is
/// fed to the inspector to watch for an injected outbound action. The
/// observation cannot affect forwarding — the bytes are already on their
/// way — and any parse failure is swallowed. With no inspector this is the
/// exact pure passthrough it always was.
final class GatewayRelayHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let clientChannel: Channel
    private let inspectionSession: ResponseInspectionSession
    private let readController: GatewayRelayReadController
    private let idleTimeout: TimeAmount
    private let maximumLifetime: TimeAmount
    private let onFinding: @Sendable ([ResponseActionInspector.Finding]) -> Void
    private var idleTask: Scheduled<Void>?
    private var lifetimeTask: Scheduled<Void>?

    init(
        clientChannel: Channel,
        inspectionSession: ResponseInspectionSession,
        readController: GatewayRelayReadController,
        idleTimeout: TimeAmount,
        maximumLifetime: TimeAmount,
        onFinding: @escaping @Sendable ([ResponseActionInspector.Finding]) -> Void = { _ in }
    ) {
        self.clientChannel = clientChannel
        self.inspectionSession = inspectionSession
        self.readController = readController
        self.idleTimeout = idleTimeout
        self.maximumLifetime = maximumLifetime
        self.onFinding = onFinding
    }

    func handlerAdded(context: ChannelHandlerContext) {
        if context.channel.isActive {
            scheduleIdleTimeout(context: context)
            scheduleMaximumLifetime(context: context)
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        scheduleIdleTimeout(context: context)
        scheduleMaximumLifetime(context: context)
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buffer = unwrapInboundIn(data)
        if buffer.readableBytes > 0 {
            // Only actual decrypted response bytes demonstrate progress; an
            // empty pipeline event must not keep a wedged exchange alive.
            scheduleIdleTimeout(context: context)
        }
        // Forward first, byte-for-byte. Observation happens after and can
        // never delay or alter what the agent receives.
        let upstreamChannel = context.channel
        clientChannel.writeAndFlush(buffer).whenFailure { _ in
            upstreamChannel.close(promise: nil)
        }

        guard buffer.readableBytes > 0,
              let text = buffer.getString(at: buffer.readerIndex, length: buffer.readableBytes)
        else { return }
        let found = inspectionSession.ingest(text)
        if !found.isEmpty { onFinding(found) }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case .handshakeCompleted = event as? TLSUserEvent {
            // Delaying this attachment until TLS completes avoids pausing the
            // reads required by the handshake when the downstream happens to
            // be non-writable during connection setup.
            readController.upstreamHandshakeCompleted(context.channel)
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelInactive(context: ChannelHandlerContext) {
        cancelIdleTimeout()
        cancelMaximumLifetime()
        readController.upstreamClosed(context.channel)
        let found = inspectionSession.finish()
        if !found.isEmpty { onFinding(found) }
        clientChannel.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        closeBoth(context: context)
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        cancelIdleTimeout()
        cancelMaximumLifetime()
        readController.upstreamClosed(context.channel)
    }

    private func scheduleMaximumLifetime(context: ChannelHandlerContext) {
        guard lifetimeTask == nil else { return }
        let upstreamChannel = context.channel
        let clientChannel = clientChannel
        lifetimeTask = context.eventLoop.scheduleTask(in: maximumLifetime) {
            clientChannel.close(promise: nil)
            upstreamChannel.close(promise: nil)
        }
    }

    private func scheduleIdleTimeout(context: ChannelHandlerContext) {
        idleTask?.cancel()
        let upstreamChannel = context.channel
        let clientChannel = clientChannel
        idleTask = context.eventLoop.scheduleTask(in: idleTimeout) {
            clientChannel.close(promise: nil)
            upstreamChannel.close(promise: nil)
        }
    }

    private func cancelIdleTimeout() {
        idleTask?.cancel()
        idleTask = nil
    }

    private func cancelMaximumLifetime() {
        lifetimeTask?.cancel()
        lifetimeTask = nil
    }

    private func closeBoth(context: ChannelHandlerContext) {
        clientChannel.close(promise: nil)
        context.close(promise: nil)
    }
}
