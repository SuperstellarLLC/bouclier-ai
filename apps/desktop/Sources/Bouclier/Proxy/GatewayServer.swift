import Foundation
// The handler types we touch are event-loop-confined in practice;
// `@preconcurrency` quiets the "conformance to Sendable unavailable"
// warnings without changing behaviour. Drop the modifier once NIO ships
// full Sendable annotations.
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
/// Phase 1 is a **byte-faithful transparent relay** — no secret
/// scrub/restore yet. Header fidelity is the whole game: `anthropic-beta`,
/// `anthropic-version`, the model id, and auth are forwarded verbatim
/// (Claude Code's own 1M-context / prompt-cache accounting rides on them),
/// and the upstream leg is pinned to HTTP/1.1 so header name casing/order
/// survive (HTTP/2 lowercases names).
final class GatewayServer: Sendable {
    /// Above this body size the secret scrub/restore is skipped and the
    /// body forwarded untouched. Placeholders and key-shaped secrets live
    /// in small tool-call/chat JSON; large bodies are vision images / file
    /// uploads, which must not be slowed. Mirrors
    /// `HTTPInspectionHandler.maxSecretScanBytes`.
    static let maxSecretScanBytes = 1 * 1024 * 1024

    private let group: EventLoopGroup
    private let port: Int
    private let overrides: UpstreamOverrides
    private let onRequest: @Sendable (RequestLog) -> Void
    /// Override system trust roots for upstream TLS verification. Set only
    /// by the e2e test (in-process HTTPS upstream signed by a throwaway
    /// CA). `nil` in production keeps `.fullVerification` against the
    /// system store.
    let upstreamTrustRootsPEM: [String]?

    init(
        port: Int,
        overrides: UpstreamOverrides = .fromEnvironment(),
        upstreamTrustRootsPEM: [String]? = nil,
        onRequest: @Sendable @escaping (RequestLog) -> Void
    ) {
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        self.port = port
        self.overrides = overrides
        self.upstreamTrustRootsPEM = upstreamTrustRootsPEM
        self.onRequest = onRequest
    }

    func start() async throws -> Channel {
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [overrides, upstreamTrustRootsPEM, onRequest] channel in
                // Front pipeline is decoder-only: we parse inbound requests
                // for routing, but relay responses as raw bytes (no
                // response encoder), so upstream bytes reach the agent
                // byte-for-byte. `.forwardBytes` preserves any trailing
                // body bytes the decoder doesn't consume.
                let decoder = ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes))
                return channel.pipeline.addHandler(decoder).flatMap {
                    channel.pipeline.addHandler(
                        GatewayHandler(
                            overrides: overrides,
                            upstreamTrustRootsPEM: upstreamTrustRootsPEM,
                            onRequest: onRequest,
                            eventLoop: channel.eventLoop
                        )
                    )
                }
            }
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)

        // Bind loopback only. The gateway forwards credentials upstream,
        // so it must never be reachable off-box.
        return try await bootstrap.bind(host: "127.0.0.1", port: port).get()
    }

    func shutdown() {
        group.shutdownGracefully { _ in }
    }
}

// MARK: - Upstream resolution

/// Where each provider's traffic is really sent. Defaults to the public
/// APIs; `*_TARGET_API_URL` env vars repoint them (gateways, Bedrock-style
/// endpoints), mirroring Headroom's split between the client-facing
/// `*_BASE_URL` (points at us) and the upstream `*_TARGET_API_URL`.
struct UpstreamOverrides: Sendable, Equatable {
    var anthropicHost: String
    var anthropicPort: Int
    var openaiHost: String
    var openaiPort: Int

    static let `default` = UpstreamOverrides(
        anthropicHost: "api.anthropic.com", anthropicPort: 443,
        openaiHost: "api.openai.com", openaiPort: 443
    )

    static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) -> UpstreamOverrides {
        var o = UpstreamOverrides.default
        if let (h, p) = Self.parseTarget(env["ANTHROPIC_TARGET_API_URL"]) { o.anthropicHost = h; o.anthropicPort = p }
        if let (h, p) = Self.parseTarget(env["OPENAI_TARGET_API_URL"]) { o.openaiHost = h; o.openaiPort = p }
        return o
    }

    /// Parse a target override into a validated (host, port). Only http/https
    /// with a sane RFC-1123 host and unprivileged port are accepted; a
    /// loopback or cloud-metadata target is rejected so the override can't
    /// be turned into an SSRF or self-loop primitive (same posture as the
    /// secret-keeper host validation).
    static func parseTarget(_ raw: String?) -> (String, Int)? {
        guard let url = ManagedConfigValidator.validatedProxyURL(raw),
              let host = url.host,
              !CorporateProxy.isLoopbackHost(host),
              !NetworkGuards.isCloudMetadataHost(host)
        else { return nil }
        let port = url.port ?? (url.scheme == "http" ? 80 : 443)
        return (host, port)
    }
}

/// Pure, channel-free routing decision — unit-testable without a socket.
enum GatewayRoute: Equatable {
    case proxy(host: String, port: Int)
    case ops(OpsKind)

    enum OpsKind: Equatable { case livez, readyz, health }

    /// Resolve a request to its upstream (or a local ops response).
    ///
    /// Path prefix decides the provider for the canonical routes; anything
    /// else falls back to auth-header sniffing and then defaults to
    /// Anthropic (this is primarily a Claude tool). We deliberately route
    /// *everything* somewhere — a catch-all passthrough — rather than 404,
    /// so new provider routes work without a code change.
    static func resolve(method: HTTPMethod, uri: String, headers: HTTPHeaders, overrides: UpstreamOverrides) -> GatewayRoute {
        let path = String(uri.split(separator: "?", maxSplits: 1).first ?? "")

        switch path {
        case "/livez": return .ops(.livez)
        case "/readyz": return .ops(.readyz)
        case "/health": return .ops(.health)
        default: break
        }

        if path.hasPrefix("/v1/messages") || path.hasPrefix("/v1/complete") {
            return .proxy(host: overrides.anthropicHost, port: overrides.anthropicPort)
        }
        if path.hasPrefix("/v1/chat/")
            || path.hasPrefix("/v1/responses")
            || path.hasPrefix("/v1/completions")
            || path.hasPrefix("/v1/embeddings")
            || path.hasPrefix("/v1/moderations")
            || path.hasPrefix("/v1/models") {
            // `/v1/models` is offered by both; if an Anthropic key is
            // present, prefer Anthropic, else treat as OpenAI-shaped.
            if path.hasPrefix("/v1/models"), detectsAnthropic(headers) {
                return .proxy(host: overrides.anthropicHost, port: overrides.anthropicPort)
            }
            return .proxy(host: overrides.openaiHost, port: overrides.openaiPort)
        }

        // Unknown path: sniff the auth header.
        if detectsAnthropic(headers) {
            return .proxy(host: overrides.anthropicHost, port: overrides.anthropicPort)
        }
        if let auth = headers.first(name: "authorization")?.lowercased(), auth.contains("bearer sk-") {
            return .proxy(host: overrides.openaiHost, port: overrides.openaiPort)
        }
        // Default: Anthropic.
        return .proxy(host: overrides.anthropicHost, port: overrides.anthropicPort)
    }

    private static func detectsAnthropic(_ headers: HTTPHeaders) -> Bool {
        if headers.first(name: "x-api-key") != nil { return true }
        if headers.first(name: "anthropic-version") != nil { return true }
        if let auth = headers.first(name: "authorization")?.lowercased(), auth.contains("bearer sk-ant") { return true }
        return false
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
    private let onRequest: @Sendable (RequestLog) -> Void
    private let eventLoop: EventLoop

    private var requestHead: HTTPRequestHead?
    private var bodyBuffer = ByteBuffer()

    private var upstreamChannel: Channel?
    /// The host the upstream connection was opened to. A single client
    /// keep-alive connection talks to exactly one provider (its base URL
    /// is fixed), so we connect once and reuse. A later request resolving
    /// to a *different* host on the same connection is a misuse we refuse
    /// rather than silently cross credentials between providers.
    private var upstreamHost: String?
    /// Buffered request write, replayed once the upstream connects. A
    /// closure so it can be either a raw byte write (clean traffic, the
    /// byte-faithful keep-alive path) or an HTTP-parts write (restore path,
    /// where the encoder re-frames after the body length changes).
    private var pendingWrite: ((Channel) -> Void)?
    /// True for this connection when secrets are configured: the upstream
    /// is a full HTTP client (encoder + decoder) and the response is
    /// restored placeholder→value. False keeps the raw byte-faithful relay.
    private var restoreActive = false
    /// Secret rules pinned at the FIRST request on this connection. The
    /// response restore pipeline is fixed once (at first connect), so the
    /// request scrub must use the same rule set for every request on the
    /// connection — otherwise a mid-connection config change could scrub a
    /// request whose response won't be restored (placeholder leaks to the
    /// agent) or vice-versa. New connections pick up config changes.
    private var connectionRules: [SecretRule]?

    init(
        overrides: UpstreamOverrides,
        upstreamTrustRootsPEM: [String]?,
        onRequest: @Sendable @escaping (RequestLog) -> Void,
        eventLoop: EventLoop
    ) {
        self.overrides = overrides
        self.upstreamTrustRootsPEM = upstreamTrustRootsPEM
        self.onRequest = onRequest
        self.eventLoop = eventLoop
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            requestHead = head
            bodyBuffer.clear()

        case .body(var body):
            if bodyBuffer.readableBytes + body.readableBytes > HTTPRequestInspector.maxBodyBytes {
                respondLocally(context: context, status: "413 Payload Too Large")
                return
            }
            bodyBuffer.writeBuffer(&body)

        case .end:
            handleRequest(context: context)
        }
    }

    private func handleRequest(context: ChannelHandlerContext) {
        guard let head = requestHead else { return }

        // DNS-rebinding defence: a malicious web page can resolve a
        // hostname to 127.0.0.1 and POST to us, but the `Host` header it
        // sends won't be loopback. We only serve loopback Hosts.
        if let host = head.headers.first(name: "host"), !GatewayWire.isLoopbackHostHeader(host) {
            respondLocally(context: context, status: "421 Misdirected Request")
            return
        }

        let route = GatewayRoute.resolve(method: head.method, uri: head.uri, headers: head.headers, overrides: overrides)

        switch route {
        case .ops(let kind):
            respondOps(context: context, kind: kind)
        case .proxy(let host, let port):
            forwardUpstream(context: context, head: head, host: host, port: port)
        }
    }

    // MARK: Upstream forwarding

    private func forwardUpstream(context: ChannelHandlerContext, head: HTTPRequestHead, host: String, port: Int) {
        let allocator = context.channel.allocator

        var headers = head.headers
        var requestURI = head.uri
        var mutableBody = bodyBuffer
        var scrubbedNames: [String] = []

        // ─── Prompt-injection inspection (primary protection) ───
        // Runs BEFORE the secret scrub for two reasons: a refused request
        // must never have had its secrets substituted (nothing leaves the
        // box, so there is nothing to scrub), and scoring the untouched
        // body means placeholders can't perturb detection.
        //
        // Cheap `hasTrigger` gate first — a request with no tool output in
        // it is forwarded byte-for-byte, exactly as before. Fail-open if
        // the engine hasn't loaded: Bouclier being unready must not break
        // the user's agent.
        var injection: InjectionInspectionPass.Outcome = .clean
        if FeatureFlags.injectionDetection,
           mutableBody.readableBytes > 0,
           mutableBody.readableBytes <= InjectionInspectionPass.maxScanBytes,
           let filter = InjectionFilter.active.current()
        {
            // Gate on the buffer in place; only materialise a `Data` once
            // we know we're going to parse it.
            let triggered = mutableBody.withUnsafeReadableBytes {
                InjectionInspectionPass.hasTrigger(bytes: $0)
            }
            if triggered {
                injection = InjectionInspectionPass.inspect(
                    body: Data(mutableBody.readableBytesView),
                    filter: filter,
                    strict: FeatureFlags.injectionStrict
                )
            }
        }

        // Enforcement is OPT-IN (monitor mode by default): a would-block
        // detection is logged but forwarded unless `injectionBlock` is on.
        // Untrusted spans that trip a critical pattern are very often benign
        // — source, diffs, email templates, LLM-prompt strings all contain
        // "system prompt" / "ignore previous instructions" — and a pattern
        // engine can't tell a quoted payload from a live one. Hard-blocking
        // by default breaks normal agent work; prevention is a deliberate
        // opt-in.
        if injection.decision == .block, FeatureFlags.injectionBlock {
            onRequest(RequestLog(
                timestamp: Date(),
                targetHost: host,
                detected: true,
                matchCount: injection.findings.reduce(0) { $0 + $1.matchCount },
                patternNames: Array(Set(injection.findings.flatMap(\.patternNames))),
                bodySize: mutableBody.readableBytes,
                mlScore: injection.blockedFinding?.mlScore,
                entropyAnomaly: injection.blockedFinding?.entropyAnomaly ?? 0,
                fusedScore: injection.topScore,
                mlAvailable: injection.mlAvailable,
                multimodal: nil
            ))
            respondWithRefusal(context: context, outcome: injection)
            requestHead = nil
            bodyBuffer.clear()
            return
        }

        // Secrets configured ⇒ standard-mode sandwich is live for this
        // connection: scrub the request and restore the response. Pin the
        // rule set on the FIRST request so scrub and the (per-connection)
        // restore pipeline always agree. If the live secret-config state
        // changes mid keep-alive connection, the fixed response pipeline no
        // longer matches — refuse with a retryable 503 so the client
        // reopens a fresh connection that picks up the new config (else a
        // stale connection could skip scrubbing a now-managed secret).
        let secretsOn = FeatureFlags.secretInjection && !SecretKeeperMonitor.isTripped
        let liveRules = secretsOn ? SecretStore.shared.rules() : []
        if let pinned = connectionRules {
            if liveRules.isEmpty != pinned.isEmpty {
                respondLocally(context: context, status: "503 Service Unavailable")
                return
            }
        } else {
            connectionRules = liveRules
        }
        let rules = connectionRules ?? []
        restoreActive = !rules.isEmpty

        // Standard-mode secret SCRUB: replace managed real secret values
        // with their placeholders BEFORE the request reaches the model
        // provider, so the secret never leaves the machine for the vendor.
        // The matching restore (`GatewayRestoreHandler`) reverses it in the
        // response so the agent's local tool calls still see the real value.
        // Same integrity gate (`hasTrigger`) as injection, so clean LLM
        // traffic is provably untouched.
        if restoreActive {
            // The response is restored on a plaintext byte stream, so ask
            // the upstream not to compress it (SSE is already plaintext;
            // this covers non-streaming JSON). Only when secrets exist.
            headers.remove(name: "Accept-Encoding")

            let scannable = mutableBody.readableBytes <= GatewayServer.maxSecretScanBytes
            let scanBody = scannable ? Data(mutableBody.readableBytesView) : Data()
            let inHeaders = headers.map { SecretInjectionPass.Header($0.name, $0.value) }
            let resolve: (String) -> String? = { SecretStore.shared.resolve($0) }
            if SecretRedactionPass.hasTrigger(uri: requestURI, headers: inHeaders, body: scanBody, rules: rules, resolve: resolve) {
                let outcome = SecretRedactionPass.apply(uri: requestURI, headers: inHeaders, body: scanBody, rules: rules, resolve: resolve)
                if outcome.changed {
                    requestURI = outcome.uri
                    var rebuilt = HTTPHeaders()
                    for h in outcome.headers { rebuilt.add(name: h.name, value: h.value) }
                    headers = rebuilt
                    if scannable {
                        var nb = allocator.buffer(capacity: outcome.body.count)
                        nb.writeBytes(outcome.body)
                        mutableBody = nb
                    }
                    scrubbedNames = outcome.scrubbed
                }
            }
        }

        // Rewrite Host to the upstream (the client sent "127.0.0.1:<port>")
        // and strip hop-by-hop headers that must not cross a proxy. Drop
        // Content-Length too: the raw path re-derives it, the parts path
        // lets the encoder set it. Every other header — anthropic-beta,
        // anthropic-version, the auth credential, content-type, user-agent
        // — is forwarded verbatim: Claude Code's 1M-context and prompt-cache
        // behaviour depend on it.
        headers.replaceOrAdd(name: "Host", value: host)
        for h in GatewayWire.hopByHopHeaders { headers.remove(name: h) }
        headers.remove(name: "Content-Length")

        // Wire-safety: a CR/LF/NUL in the request line or a header would
        // smuggle a second request. `requestURI` is checked (not head.uri)
        // because scrub may have rewritten it.
        guard HTTPRequestInspector.containsControlBytes(requestURI) == false,
              GatewayWire.isWireSafe(headers: headers) else {
            respondLocally(context: context, status: "400 Bad Request")
            return
        }

        let bodySize = mutableBody.readableBytes
        let writeRequest: (Channel) -> Void
        if restoreActive {
            // Parts path: a proper HTTP client (encoder) re-frames the
            // request, computing Content-Length from the post-scrub body.
            var outHead = HTTPRequestHead(version: .http1_1, method: head.method, uri: requestURI)
            outHead.headers = headers
            let body = mutableBody
            writeRequest = { ch in
                ch.write(NIOAny(HTTPClientRequestPart.head(outHead)), promise: nil)
                if body.readableBytes > 0 {
                    ch.write(NIOAny(HTTPClientRequestPart.body(.byteBuffer(body))), promise: nil)
                }
                ch.writeAndFlush(NIOAny(HTTPClientRequestPart.end(nil)), promise: nil)
            }
        } else {
            // Raw path: byte-faithful hand-serialized request (keep-alive).
            var outHeaders = headers
            outHeaders.replaceOrAdd(name: "Content-Length", value: "\(bodySize)")
            var raw = allocator.buffer(capacity: 1024 + bodySize)
            raw.writeString("\(head.method) \(requestURI) HTTP/1.1\r\n")
            for (name, value) in outHeaders { raw.writeString("\(name): \(value)\r\n") }
            raw.writeString("\r\n")
            raw.writeBuffer(&mutableBody)
            writeRequest = { ch in ch.writeAndFlush(NIOAny(raw), promise: nil) }
        }

        // `detected` drives the red shield in the activity log and is
        // reserved for requests we actually refused. A `.flag` outcome
        // (something matched, but on the operator's own text) is recorded
        // with its score and pattern names and forwarded unchanged — the
        // v0.6.1 lesson about not showing a block indicator for something
        // that wasn't blocked.
        onRequest(RequestLog(
            timestamp: Date(),
            targetHost: host,
            detected: false,
            matchCount: injection.findings.reduce(0) { $0 + $1.matchCount },
            patternNames: Array(Set(injection.findings.flatMap(\.patternNames))),
            bodySize: bodySize,
            mlScore: injection.findings.first?.mlScore,
            entropyAnomaly: injection.findings.first?.entropyAnomaly ?? 0,
            fusedScore: injection.topScore,
            mlAvailable: injection.mlAvailable,
            multimodal: nil
        ))
        if !scrubbedNames.isEmpty {
            onRequest(RequestLog(secretEvent: SecretEvent(host: host, kind: .scrubbed(names: scrubbedNames))))
        }

        sendUpstream(context: context, write: writeRequest, host: host, port: port)

        requestHead = nil
        bodyBuffer.clear()
    }

    private func sendUpstream(context: ChannelHandlerContext, write: @escaping (Channel) -> Void, host: String, port: Int) {
        if let upstream = upstreamChannel {
            // Reusing an existing connection: it must be the same host, or
            // we'd leak one provider's credential to another.
            guard upstreamHost == host else {
                respondLocally(context: context, status: "421 Misdirected Request")
                return
            }
            write(upstream)
            return
        }
        upstreamHost = host
        pendingWrite = write
        connectToUpstream(context: context, host: host, port: port)
    }

    private func connectToUpstream(context: ChannelHandlerContext, host: String, port: Int) {
        let clientChannel = context.channel
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

            // Response path was decided in forwardUpstream (`restoreActive`).
            // Restore path: a full HTTP client (encoder + decoder) so NIO
            // handles request/response framing (incl. de-chunking) — we
            // restore the decoded body and re-emit with connection-close.
            // Clean path: byte-faithful raw relay, keep-alive preserved.
            let useRestore = restoreActive
            let restore: SecretRestore = {
                guard useRestore else { return SecretRestore(map: []) }
                // Same pinned rule set the scrub used (see connectionRules).
                let map = (self.connectionRules ?? []).compactMap { r -> (placeholder: String, value: String)? in
                    guard let v = SecretStore.shared.resolve(r.name), SecretInjectionPass.isTripwireEligible(v) else { return nil }
                    return (r.placeholder, v)
                }
                return SecretRestore(map: map)
            }()

            let bootstrap = ClientBootstrap(group: eventLoop)
                .channelInitializer { channel in
                    do {
                        let sslHandler = try NIOSSLClientHandler(context: sslContext, serverHostname: host)
                        if useRestore {
                            return channel.pipeline.addHandler(sslHandler).flatMap {
                                channel.pipeline.addHTTPClientHandlers()
                            }.flatMap {
                                channel.pipeline.addHandler(GatewayRestoreHandler(clientChannel: clientChannel, restore: restore))
                            }
                        }
                        return channel.pipeline.addHandlers([
                            sslHandler,
                            GatewayRelayHandler(clientChannel: clientChannel),
                        ])
                    } catch {
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                }

            bootstrap.connect(host: host, port: port).whenComplete { [weak self] result in
                guard let self else { return }
                switch result {
                case .success(let channel):
                    self.upstreamChannel = channel
                    self.pendingWrite?(channel)
                    self.pendingWrite = nil
                case .failure:
                    // Fail toward the client with an honest 502 rather than
                    // hanging it.
                    self.respondLocally(channel: clientChannel, status: "502 Bad Gateway")
                }
            }
        } catch {
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
        bodyBuffer.clear()
    }

    private func respondLocally(context: ChannelHandlerContext, status: String) {
        respondLocally(channel: context.channel, status: status)
        requestHead = nil
        bodyBuffer.clear()
    }

    /// Refuse a request whose untrusted content carried instructions.
    ///
    /// 403 with a provider-shaped JSON error body: the agent SDK raises a
    /// readable API error naming the offending location instead of dying
    /// on a closed socket, so the operator can see *what* was blocked and
    /// *where* without opening the menu bar.
    private func respondWithRefusal(context: ChannelHandlerContext, outcome: InjectionInspectionPass.Outcome) {
        respondLocally(
            channel: context.channel,
            status: "403 Forbidden",
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

    func channelInactive(context: ChannelHandlerContext) {
        upstreamChannel?.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        upstreamChannel?.close(promise: nil)
        context.close(promise: nil)
    }

}

// MARK: - Wire helpers (pure, unit-testable)

/// Outbound wire-format guards shared by the gateway handler and its
/// tests. Channel-free so they can be exercised without a socket.
enum GatewayWire {
    /// Hop-by-hop headers (RFC 7230 §6.1) — must not be forwarded across a
    /// proxy. We let the upstream TLS leg manage its own framing/keep-alive.
    static let hopByHopHeaders = [
        "connection", "keep-alive", "proxy-connection",
        "transfer-encoding", "te", "upgrade", "trailer",
    ]

    static func isWireSafe(headers: HTTPHeaders) -> Bool {
        for (name, value) in headers {
            if !HTTPRequestInspector.isValidHeaderName(name) { return false }
            if HTTPRequestInspector.containsControlBytes(value) { return false }
        }
        return true
    }

    /// The `Host` a loopback caller legitimately sends. Anything else is a
    /// rebinding attempt against a credential-forwarding service.
    static func isLoopbackHostHeader(_ raw: String) -> Bool {
        // IPv6 literals are bracketed (`[::1]:port`); split on the last
        // colon only when it isn't inside brackets.
        var host = raw
        if host.hasPrefix("[") {
            if let close = host.firstIndex(of: "]") {
                host = String(host[host.index(after: host.startIndex)..<close])
            }
        } else if let colon = host.firstIndex(of: ":") {
            host = String(host[host.startIndex..<colon])
        }
        host = host.lowercased()
        return host == "127.0.0.1" || host == "localhost" || host == "::1"
    }
}

// MARK: - Upstream Relay (response side)

/// Shovels response bytes from the provider back to the agent, raw and
/// unmodified. Phase 1 is a pure passthrough — request-side handling is
/// the only mutation path. Phase 2 will interpose the placeholder→real
/// restore here (straddle-safe over SSE frames), reusing
/// `SSEStreamInspector`'s buffering.
private final class GatewayRelayHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let clientChannel: Channel

    init(clientChannel: Channel) {
        self.clientChannel = clientChannel
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        clientChannel.writeAndFlush(unwrapInboundIn(data), promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        clientChannel.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        clientChannel.close(promise: nil)
        context.close(promise: nil)
    }
}

// MARK: - Upstream Relay with secret restore (standard-mode sandwich)

/// Response path when secrets are configured: parse the upstream response,
/// restore placeholders→real values in the body (straddle-safe), and
/// re-emit to the agent with **connection-close framing**. Restore changes
/// the body length, so we drop Content-Length/Transfer-Encoding and let
/// the connection close delimit the body — valid HTTP/1.1, supported by
/// every client, and it avoids re-chunking / Content-Length recompute. The
/// trade-off is no client-side keep-alive for secret-protected
/// connections; acceptable since restore only runs when secrets exist.
private final class GatewayRestoreHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPClientResponsePart

    private let clientChannel: Channel
    private var restore: SecretRestore
    private var finished = false

    init(clientChannel: Channel, restore: SecretRestore) {
        self.clientChannel = clientChannel
        self.restore = restore
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            writeResponseHead(head)
        case .body(let buf):
            let emit = restore.ingest(Array(buf.readableBytesView))
            if !emit.isEmpty { writeBytes(emit) }
        case .end:
            flushAndClose()
        }
    }

    private func writeResponseHead(_ head: HTTPResponseHead) {
        var s = "HTTP/1.1 \(head.status.code) \(head.status.reasonPhrase)\r\n"
        for (name, value) in head.headers {
            let lower = name.lowercased()
            // Drop framing headers (restore changes the length) and any
            // stale Connection header; forward everything else verbatim.
            if lower == "content-length" || lower == "transfer-encoding" || lower == "connection" { continue }
            s += "\(name): \(value)\r\n"
        }
        s += "Connection: close\r\n\r\n"
        writeString(s)
    }

    private func flushAndClose() {
        guard !finished else { return }
        finished = true
        let tail = restore.finish()
        if !tail.isEmpty { writeBytes(tail) }
        clientChannel.close(promise: nil)
    }

    private func writeBytes(_ bytes: [UInt8]) {
        var buf = clientChannel.allocator.buffer(capacity: bytes.count)
        buf.writeBytes(bytes)
        clientChannel.writeAndFlush(buf, promise: nil)
    }

    private func writeString(_ s: String) {
        var buf = clientChannel.allocator.buffer(capacity: s.utf8.count)
        buf.writeString(s)
        clientChannel.writeAndFlush(buf, promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        // Upstream closed without a clean .end (or after it): flush any
        // retained tail so the last bytes aren't dropped.
        flushAndClose()
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        clientChannel.close(promise: nil)
        context.close(promise: nil)
    }
}
