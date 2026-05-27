import Foundation
// Several NIO 2.x types our pipeline touches (NIOSSLHandler,
// ByteToMessageHandler, ChannelHandlerContext) are not yet marked
// Sendable in upstream NIO, but every site we capture them in is
// event-loop-confined in practice. The `@preconcurrency` imports
// suppress the noisy "conformance to Sendable unavailable" warnings
// without changing runtime behaviour. Drop the modifier once NIO ships
// full Sendable annotations.
@preconcurrency import NIO
@preconcurrency import NIOCore
import NIOHTTP1
import NIOPosix
@preconcurrency import NIOSSL
import NIOTLS

/// NIO-based TLS-intercepting proxy with HTTP-aware inspection.
///
/// Intercepted pipeline (after TLS handshake):
/// ```
/// Client ──[TLS]──► NIOSSLServerHandler
///                       │ (plaintext bytes)
///                 HTTPRequestDecoder
///                       │ (HTTPServerRequestPart)
///                 HTTPInspectionHandler  ←── scans body, adjusts Content-Length
///                       │ (raw bytes, rewritten)
///                 NIOSSLClientHandler ──[TLS]──► Upstream
///                       │
///                 UpstreamRelayHandler ──► back to client
/// ```
final class TLSProxy: Sendable {
    private let group: EventLoopGroup
    private let ca: CertificateAuthority
    private let filter: InjectionFilter
    private let port: Int
    private let onRequest: @Sendable (RequestLog) -> Void
    /// Override system trust roots for upstream TLS verification. Set
    /// only by the e2e test, which talks to an in-process HTTPS upstream
    /// signed by a throwaway CA — system roots have no reason to trust
    /// it, but we still want full verification rather than a blanket
    /// "trust anything" switch. `nil` (the production default) preserves
    /// `.fullVerification` against the system trust store.
    let upstreamTrustRootsPEM: [String]?

    init(
        port: Int,
        ca: CertificateAuthority,
        filter: InjectionFilter,
        upstreamTrustRootsPEM: [String]? = nil,
        onRequest: @Sendable @escaping (RequestLog) -> Void
    ) {
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        self.ca = ca
        self.filter = filter
        self.port = port
        self.upstreamTrustRootsPEM = upstreamTrustRootsPEM
        self.onRequest = onRequest
    }

    func start() async throws -> Channel {
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [ca, filter, upstreamTrustRootsPEM, onRequest] channel in
                channel.pipeline.addHandler(
                    ConnectHandler(
                        ca: ca,
                        filter: filter,
                        upstreamTrustRootsPEM: upstreamTrustRootsPEM,
                        onRequest: onRequest
                    )
                )
            }
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)

        return try await bootstrap.bind(host: "127.0.0.1", port: port).get()
    }

    func shutdown() {
        group.shutdownGracefully { _ in }
    }

    /// Hosts that point at cloud-instance metadata services — never
    /// tunnelled, even though we otherwise act as a general CONNECT
    /// proxy for non-AI hosts. Lifted out of the handler so a test
    /// can pin the allowlist without spinning up a live proxy.
    static func isCloudMetadataHost(_ host: String) -> Bool {
        let h = host.lowercased()
        return h == "169.254.169.254"
            || h == "metadata.google.internal"
            || h == "metadata.azure.com"
            || h == "[fd00:ec2::254]"
    }
}

// MARK: - CONNECT Handler

// NIO invokes every ChannelHandler instance from a single event loop,
// so capturing `self` and `context` into `@Sendable` closures bound to
// that loop (`whenSuccess`, `whenFailure`, `whenComplete`) is safe in
// practice. The `@unchecked Sendable` conformance documents the
// invariant for the Swift 6 region-isolation checker.
private final class ConnectHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let ca: CertificateAuthority
    private let filter: InjectionFilter
    private let upstreamTrustRootsPEM: [String]?
    private let onRequest: @Sendable (RequestLog) -> Void
    private var buffer = ""

    init(
        ca: CertificateAuthority,
        filter: InjectionFilter,
        upstreamTrustRootsPEM: [String]?,
        onRequest: @Sendable @escaping (RequestLog) -> Void
    ) {
        self.ca = ca
        self.filter = filter
        self.upstreamTrustRootsPEM = upstreamTrustRootsPEM
        self.onRequest = onRequest
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        guard let str = buf.readString(length: buf.readableBytes) else {
            context.close(promise: nil)
            return
        }

        // Check size BEFORE appending to avoid allocating an oversized string.
        if buffer.utf8.count + str.utf8.count > HTTPRequestInspector.maxConnectHeaderBytes {
            let resp = "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n"
            var errBuf = context.channel.allocator.buffer(capacity: resp.utf8.count)
            errBuf.writeString(resp)
            context.writeAndFlush(wrapOutboundOut(errBuf), promise: nil)
            context.close(promise: nil)
            return
        }

        buffer += str

        guard buffer.contains("\r\n") else { return }

        let firstLine = buffer.components(separatedBy: "\r\n").first ?? ""
        let parts = firstLine.split(separator: " ", maxSplits: 2)

        guard parts.count >= 2, parts[0] == "CONNECT" else {
            let body = "{\"service\":\"Bouclier\",\"status\":\"running\"}"
            let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
            var outBuf = context.channel.allocator.buffer(capacity: resp.utf8.count)
            outBuf.writeString(resp)
            context.writeAndFlush(wrapOutboundOut(outBuf), promise: nil)
            context.close(promise: nil)
            return
        }

        guard let (host, port) = HTTPRequestInspector.parseConnectTarget(String(parts[1])) else {
            let resp = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
            var errBuf = context.channel.allocator.buffer(capacity: resp.utf8.count)
            errBuf.writeString(resp)
            context.writeAndFlush(wrapOutboundOut(errBuf), promise: nil)
            context.close(promise: nil)
            return
        }

        // AI-API hosts get MITM'd so we can inspect & redact. Every
        // other host gets a plain CONNECT tunnel — required now that
        // `ShellEnvInjector` plants `HTTPS_PROXY=…` in every shell, so
        // git / npm / brew / curl-to-non-AI-hosts all flow through
        // this listener. The previous design 403'd them, which broke
        // every CLI tool the moment the user enabled the feature.
        //
        // Cloud-metadata IPs are blocked outright — there's no
        // legitimate reason a user CLI tool needs to be tunnelled to
        // 169.254.169.254 (AWS/Azure) or metadata.google.internal,
        // and these are the classic SSRF jackpot.
        if TLSProxy.isCloudMetadataHost(host) {
            let resp = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
            var errBuf = context.channel.allocator.buffer(capacity: resp.utf8.count)
            errBuf.writeString(resp)
            context.writeAndFlush(wrapOutboundOut(errBuf), promise: nil)
            context.close(promise: nil)
            return
        }

        if SystemProxy.interceptedDomains.contains(host) {
            let established = "HTTP/1.1 200 Connection Established\r\n\r\n"
            var respBuf = context.channel.allocator.buffer(capacity: established.utf8.count)
            respBuf.writeString(established)

            let ctxBound = NIOLoopBound(context, eventLoop: context.eventLoop)
            context.writeAndFlush(wrapOutboundOut(respBuf)).whenSuccess { [self] in
                let context = ctxBound.value
                context.pipeline.removeHandler(self, promise: nil)
                self.setupTLS(context: context, host: host, port: port)
            }
        } else {
            setupPassthrough(context: context, host: host, port: port)
        }
    }

    /// Forward bytes between client and upstream without TLS
    /// termination — the proxy never sees plaintext. Used for hosts
    /// outside the AI-API allowlist so they keep working when the user
    /// has Bouclier in their `HTTPS_PROXY` env.
    ///
    /// Ordering is load-bearing: we answer `200 Connection Established`
    /// FIRST so the client unblocks and starts the TLS handshake, then
    /// install the glue handler. The handshake bytes are buffered by
    /// the pipeline until our glue is in place — pipeline reads stay
    /// strictly ordered on the event loop, so no race.
    private func setupPassthrough(context: ChannelHandlerContext, host: String, port: Int) {
        let clientChannel = context.channel
        let clientBound = NIOLoopBound(clientChannel, eventLoop: context.eventLoop)

        let bootstrap = ClientBootstrap(group: context.eventLoop)
            .channelInitializer { upstream in
                // Glue the upstream side: every inbound byte gets
                // shovelled to the client. Closure on either side tears
                // the other down via the glue handler's channelInactive.
                upstream.pipeline.addHandler(
                    PassthroughGlueHandler(partner: clientBound.value)
                )
            }

        bootstrap.connect(host: host, port: port).whenComplete { [self] result in
            switch result {
            case .success(let upstreamChannel):
                // Write 200 to the client through the channel (not the
                // about-to-be-removed handler's context). Then swap
                // ConnectHandler out for the client-side glue.
                let established = "HTTP/1.1 200 Connection Established\r\n\r\n"
                var respBuf = clientChannel.allocator.buffer(capacity: established.utf8.count)
                respBuf.writeString(established)
                clientChannel.writeAndFlush(respBuf, promise: nil)

                clientChannel.pipeline.removeHandler(self).flatMap {
                    clientChannel.pipeline.addHandler(
                        PassthroughGlueHandler(partner: upstreamChannel),
                        position: .first
                    )
                }.whenFailure { _ in
                    upstreamChannel.close(promise: nil)
                    clientChannel.close(promise: nil)
                }
            case .failure:
                let resp = "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
                var errBuf = clientChannel.allocator.buffer(capacity: resp.utf8.count)
                errBuf.writeString(resp)
                clientChannel.writeAndFlush(errBuf, promise: nil)
                clientChannel.close(promise: nil)
            }
        }
    }

    private func setupTLS(context: ChannelHandlerContext, host: String, port: Int) {
        guard let (certPEM, keyPEM) = ca.leafCertAndKey(forHost: host) else {
            context.close(promise: nil)
            return
        }

        do {
            let cert = try NIOSSLCertificate(bytes: Array(certPEM.utf8), format: .pem)
            let key = try NIOSSLPrivateKey(bytes: Array(keyPEM.utf8), format: .pem)

            var tlsConfig = TLSConfiguration.makeServerConfiguration(
                certificateChain: [.certificate(cert)],
                privateKey: .privateKey(key)
            )
            tlsConfig.minimumTLSVersion = .tlsv12

            let sslContext = try NIOSSLContext(configuration: tlsConfig)
            let sslHandler = NIOSSLServerHandler(context: sslContext)
            // NIOLoopBound lets the @Sendable callback re-acquire the
            // non-Sendable context value safely on the same event loop.
            let ctxBound = NIOLoopBound(context, eventLoop: context.eventLoop)
            let sslBound = NIOLoopBound(sslHandler, eventLoop: context.eventLoop)

            context.pipeline.addHandler(sslBound.value, position: .first).whenSuccess { [self] in
                let context = ctxBound.value
                context.pipeline.addHandler(
                    HandshakeWaiter(
                        host: host,
                        port: port,
                        filter: self.filter,
                        upstreamTrustRootsPEM: self.upstreamTrustRootsPEM,
                        onRequest: self.onRequest
                    )
                ).whenFailure { _ in context.close(promise: nil) }
            }
        } catch {
            context.close(promise: nil)
        }
    }
}

// MARK: - Passthrough Glue

/// One-way byte shovel between a NIO channel and its peer. Two
/// instances form a bidirectional bridge — used for CONNECT tunnels
/// to non-AI hosts where Bouclier acts as a plain HTTP CONNECT proxy
/// and never terminates TLS.
///
/// Holds a strong reference to its partner channel. NIO closes both
/// channels when either side goes inactive, so the cycle is broken
/// at connection teardown.
private final class PassthroughGlueHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let partner: Channel

    init(partner: Channel) {
        self.partner = partner
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        partner.writeAndFlush(data, promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        partner.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        partner.close(promise: nil)
        context.close(promise: nil)
    }
}

// MARK: - Handshake Waiter

// Same NIO single-event-loop invariant as ConnectHandler.
private final class HandshakeWaiter: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let host: String
    private let port: Int
    private let filter: InjectionFilter
    private let upstreamTrustRootsPEM: [String]?
    private let onRequest: @Sendable (RequestLog) -> Void

    init(
        host: String,
        port: Int,
        filter: InjectionFilter,
        upstreamTrustRootsPEM: [String]?,
        onRequest: @Sendable @escaping (RequestLog) -> Void
    ) {
        self.host = host
        self.port = port
        self.filter = filter
        self.upstreamTrustRootsPEM = upstreamTrustRootsPEM
        self.onRequest = onRequest
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is TLSUserEvent {
            context.pipeline.removeHandler(self, promise: nil)

            // Add HTTP decoder → inspection handler
            // The inspection handler accumulates the full HTTP request,
            // scans the body, rebuilds the request with adjusted Content-Length,
            // and forwards raw bytes to upstream via a direct channel bridge.
            let ctxBound = NIOLoopBound(context, eventLoop: context.eventLoop)
            let decoder = ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes))
            let decoderBound = NIOLoopBound(decoder, eventLoop: context.eventLoop)

            context.pipeline.addHandler(decoderBound.value).flatMap { [self] in
                let context = ctxBound.value
                return context.pipeline.addHandler(
                    HTTPInspectionHandler(
                        host: self.host,
                        port: self.port,
                        filter: self.filter,
                        upstreamTrustRootsPEM: self.upstreamTrustRootsPEM,
                        onRequest: self.onRequest,
                        eventLoop: context.eventLoop
                    )
                )
            }.whenFailure { _ in ctxBound.value.close(promise: nil) }
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(data)
    }
}

// MARK: - HTTP-Aware Inspection Handler

/// Parses HTTP requests, accumulates the body, scans for injections,
/// adjusts Content-Length, and forwards the complete request to upstream.
// NIO ensures every ChannelHandler instance is invoked from a single
// event loop, so capturing `self` into Task/EL closures is safe in
// practice even though the type isn't structurally Sendable. The
// `@unchecked Sendable` conformance documents that invariant for the
// Swift 6 region-isolation checker.
private final class HTTPInspectionHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = ByteBuffer

    private let host: String
    private let port: Int
    private let filter: InjectionFilter
    private let upstreamTrustRootsPEM: [String]?
    private let onRequest: @Sendable (RequestLog) -> Void
    private let eventLoop: EventLoop

    private var upstreamChannel: Channel?
    private var requestHead: HTTPRequestHead?
    private var bodyBuffer = ByteBuffer()
    private var pendingRawWrites: [ByteBuffer] = []

    init(
        host: String,
        port: Int,
        filter: InjectionFilter,
        upstreamTrustRootsPEM: [String]?,
        onRequest: @Sendable @escaping (RequestLog) -> Void,
        eventLoop: EventLoop
    ) {
        self.host = host
        self.port = port
        self.filter = filter
        self.upstreamTrustRootsPEM = upstreamTrustRootsPEM
        self.onRequest = onRequest
        self.eventLoop = eventLoop
    }

    func handlerAdded(context: ChannelHandlerContext) {
        connectToUpstream(context: context)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let part = unwrapInboundIn(data)

        switch part {
        case .head(let head):
            requestHead = head
            bodyBuffer.clear()

        case .body(var body):
            // Hard cap on buffered body size. Reject the request rather
            // than accumulating unbounded bytes on the event loop.
            if bodyBuffer.readableBytes + body.readableBytes > HTTPRequestInspector.maxBodyBytes {
                sendRejection(context: context, status: "413 Payload Too Large")
                return
            }
            bodyBuffer.writeBuffer(&body)

        case .end:
            processRequest(context: context)
        }
    }

    /// Scan the accumulated body, rebuild the HTTP request, forward to upstream.
    private func processRequest(context: ChannelHandlerContext) {
        guard let head = requestHead else { return }

        let bodySize = bodyBuffer.readableBytes
        let scanStart = Date()
        let inspection = HTTPRequestInspector.inspect(
            head: head,
            body: bodyBuffer,
            filter: filter,
            allocator: context.channel.allocator
        )
        let scanDuration = Date().timeIntervalSince(scanStart)

        if inspection.rejectedOversize {
            Task { [host] in
                await Metrics.shared.recordRequest(
                    host: host,
                    bodySize: bodySize,
                    scanDurationSeconds: scanDuration,
                    detected: false,
                    rewritten: false,
                    oversized: true,
                    categories: [],
                    severities: []
                )
            }
            sendRejection(context: context, status: "413 Payload Too Large")
            return
        }

        Task { [host, inspection] in
            await Metrics.shared.recordRequest(
                host: host,
                bodySize: bodySize,
                scanDurationSeconds: scanDuration,
                detected: inspection.detected,
                rewritten: inspection.bodyRewritten,
                oversized: false,
                categories: inspection.categories,
                severities: inspection.severities
            )
        }

        let finalBody = inspection.sanitizedBody

        // Multimodal (file) PII inspection — the only PII rewrite path
        // Bouclier runs. Text prompts are forwarded unchanged: redacting
        // them was incompatible with provider abuse-detection heuristics
        // and risked touching `user`/`metadata`/auth fields the operator
        // didn't want us inside of. Files are unambiguous user content,
        // and the rewriter swaps the attachment for a descriptive
        // placeholder rather than minting a token — nothing for the
        // model's prompt to react to.
        //
        // Two non-obvious gates:
        //
        //   1. `bodyScanSkipped` is true for any body the injection
        //      scanner doesn't recognise, including multipart/form-data
        //      (the Files API shape). Without the explicit override,
        //      every file upload would skip the multimodal pass.
        //
        //   2. We gate on `bodyRewritten`, not `detected`. URI-only
        //      injection matches don't touch body bytes, so attachments
        //      are still present and still need scanning. A URI like
        //      `?q=ignore+previous+instructions` must not bypass image
        //      and PDF inspection in the body.
        let mmContentType = (head.headers.first(name: "Content-Type") ?? "").lowercased()
        let isMultipart = mmContentType.hasPrefix("multipart/")
        let mmEligible = FeatureFlags.multimodalInspection
            && !inspection.bodyRewritten
            && (!inspection.bodyScanSkipped || isMultipart)

        if mmEligible {
            let contentType = head.headers.first(name: "Content-Type") ?? ""
            let method = head.method
            let allocator = context.channel.allocator
            let eventLoop = context.eventLoop
            let headRef = head
            let baseBody = finalBody
            let inspectionRef = inspection
            let hostRef = host
            let sizeRef = bodySize
            Task {
                let mmPass = await HTTPRequestInspector.applyMultimodalInspection(
                    body: baseBody,
                    contentType: contentType,
                    method: method,
                    allocator: allocator
                )

                eventLoop.execute { [weak self] in
                    guard let self else { return }
                    self.emitRequestLog(
                        host: hostRef,
                        bodySize: sizeRef,
                        inspection: inspectionRef,
                        multimodal: mmPass.report
                    )
                    self.forwardUpstream(head: headRef, body: mmPass.body, allocator: allocator)
                }
            }
        } else {
            emitRequestLog(host: host, bodySize: bodySize, inspection: inspection, multimodal: nil)
            forwardUpstream(head: head, body: finalBody, allocator: context.channel.allocator)
        }
    }

    /// Combine the injection inspection + the (optional) multimodal
    /// report into one RequestLog and emit it. The menu bar's counters
    /// and the audit-log table consume the unified shape.
    private func emitRequestLog(
        host: String,
        bodySize: Int,
        inspection: HTTPRequestInspector.InspectionResult,
        multimodal: MultimodalPIIInspector.Report?
    ) {
        onRequest(RequestLog(
            timestamp: Date(),
            targetHost: host,
            detected: inspection.detected,
            matchCount: inspection.matchCount,
            patternNames: inspection.patternNames,
            bodySize: bodySize,
            mlScore: inspection.mlScore,
            entropyAnomaly: inspection.entropyAnomaly,
            fusedScore: inspection.fusedScore,
            mlAvailable: inspection.mlAvailable,
            multimodal: multimodal
        ))
    }

    /// Build the raw HTTP request bytes (head + headers + body) and queue
    /// them upstream. Factored out so the sync (no PII) and async (PII)
    /// paths share the same wire-format step.
    private func forwardUpstream(head: HTTPRequestHead, body: ByteBuffer, allocator: ByteBufferAllocator) {
        var mutableBody = body
        var headers = head.headers
        // Always re-derive Content-Length from the final body, not the
        // header. Redaction (injection or PII) may have changed the size,
        // and the upstream rejects mismatches with a 400.
        headers.replaceOrAdd(name: "Content-Length", value: "\(mutableBody.readableBytes)")

        // Defence in depth: NIO's HTTPRequestDecoder normally rejects
        // malformed headers, but we synthesise the outbound wire format
        // manually so a single CR/LF/NUL byte in a header value or in
        // the request line would smuggle a second request to the
        // upstream. Reject the entire request rather than forward
        // something that could be reinterpreted as two requests.
        guard isWireSafe(head: head, headers: headers) else {
            sendRejectionToClient(status: "400 Bad Request", allocator: allocator)
            return
        }

        var raw = allocator.buffer(capacity: 1024 + mutableBody.readableBytes)
        raw.writeString("\(head.method) \(head.uri) HTTP/1.1\r\n")
        for (name, value) in headers {
            raw.writeString("\(name): \(value)\r\n")
        }
        raw.writeString("\r\n")
        raw.writeBuffer(&mutableBody)

        sendToUpstream(raw)

        // Reset for next request (HTTP keep-alive)
        requestHead = nil
        bodyBuffer.clear()
    }

    /// Reject any request whose URI or headers carry control bytes
    /// (CR / LF / NUL) — these are the classic HTTP-request-smuggling
    /// primitives. Header names also have to be token characters per
    /// RFC 7230 §3.2.6. Static helpers live on `HTTPRequestInspector`
    /// so they're unit-testable without a channel.
    private func isWireSafe(head: HTTPRequestHead, headers: HTTPHeaders) -> Bool {
        if HTTPRequestInspector.containsControlBytes(head.uri) { return false }
        for (name, value) in headers {
            if !HTTPRequestInspector.isValidHeaderName(name) { return false }
            if HTTPRequestInspector.containsControlBytes(value) { return false }
        }
        return true
    }

    /// Push a synthetic error response to the client and tear down the
    /// connection. Used by `forwardUpstream` when its own pre-flight
    /// safety check refuses to forward a request the decoder produced.
    private func sendRejectionToClient(status: String, allocator: ByteBufferAllocator) {
        let resp = "HTTP/1.1 \(status)\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        var buf = allocator.buffer(capacity: resp.utf8.count)
        buf.writeString(resp)
        if let client = upstreamChannel {
            client.writeAndFlush(buf, promise: nil)
            client.close(promise: nil)
        }
        requestHead = nil
        bodyBuffer.clear()
    }

    private func sendToUpstream(_ buf: ByteBuffer) {
        if let upstream = upstreamChannel {
            upstream.writeAndFlush(buf, promise: nil)
        } else {
            pendingRawWrites.append(buf)
        }
    }

    private func sendRejection(context: ChannelHandlerContext, status: String) {
        let resp = "HTTP/1.1 \(status)\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
        var buf = context.channel.allocator.buffer(capacity: resp.utf8.count)
        buf.writeString(resp)
        context.writeAndFlush(wrapOutboundOut(buf), promise: nil)
        context.close(promise: nil)
        requestHead = nil
        bodyBuffer.clear()
    }

    private func connectToUpstream(context: ChannelHandlerContext) {
        do {
            var tlsConfig = TLSConfiguration.makeClientConfiguration()
            tlsConfig.certificateVerification = .fullVerification
            // Test injects an in-process upstream signed by a throwaway
            // CA that system roots have no reason to trust. Production
            // callers leave this nil and we keep `.fullVerification`
            // against the system store unchanged.
            if let pems = upstreamTrustRootsPEM {
                var roots: [NIOSSLCertificate] = []
                for pem in pems {
                    roots.append(contentsOf: try NIOSSLCertificate.fromPEMBytes(Array(pem.utf8)))
                }
                tlsConfig.trustRoots = .certificates(roots)
            }
            let sslContext = try NIOSSLContext(configuration: tlsConfig)

            // Check for upstream corporate proxy
            let bootstrap = ClientBootstrap(group: eventLoop)
                .channelInitializer { channel in
                    do {
                        let sslHandler = try NIOSSLClientHandler(context: sslContext, serverHostname: self.host)
                        return channel.pipeline.addHandlers([
                            sslHandler,
                            UpstreamRelayHandler(
                                clientChannel: context.channel,
                                filter: self.filter
                            ),
                        ])
                    } catch {
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                }

            // Use corporate proxy if configured
            let connectHost: String
            let connectPort: Int
            if let proxyConfig = CorporateProxy.detect() {
                connectHost = proxyConfig.host
                connectPort = proxyConfig.port
                // TODO: Send CONNECT through corporate proxy to reach AI endpoint
            } else {
                connectHost = host
                connectPort = port
            }

            bootstrap.connect(host: connectHost, port: connectPort).whenComplete { result in
                switch result {
                case .success(let channel):
                    self.upstreamChannel = channel
                    for buf in self.pendingRawWrites {
                        channel.writeAndFlush(buf, promise: nil)
                    }
                    self.pendingRawWrites.removeAll()
                case .failure:
                    context.close(promise: nil)
                }
            }
        } catch {
            context.close(promise: nil)
        }
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

// MARK: - Upstream Relay

/// Forwards bytes from the upstream (AI provider) channel back to the
/// client. For text/event-stream responses an SSEStreamInspector is
/// interposed so streaming completions are scanned frame-by-frame and
/// detected injections terminate the stream with a redaction event.
///
/// Non-SSE responses (plain JSON, binary) are forwarded verbatim —
/// request-side scanning already covers those.
private final class UpstreamRelayHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private let clientChannel: Channel
    private let sseInspector: SSEStreamInspector
    private var headersParsed = false
    private var isEventStream = false
    private var headerBuffer = ""

    init(clientChannel: Channel, filter: InjectionFilter) {
        self.clientChannel = clientChannel
        self.sseInspector = SSEStreamInspector(filter: filter)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buf = unwrapInboundIn(data)

        // Fast path: once headers are forwarded and the body isn't an
        // SSE stream, relay raw bytes with zero conversion. Response
        // bodies are never rewritten by Bouclier — request-side scanning
        // is the only mutation path.
        if headersParsed && !isEventStream {
            clientChannel.writeAndFlush(buf, promise: nil)
            return
        }

        var mutableBuf = buf
        let bytes = mutableBuf.readableBytes
        guard let chunk = mutableBuf.readString(length: bytes) else {
            clientChannel.writeAndFlush(buf, promise: nil)
            return
        }

        // Parse the status line + headers incrementally to learn whether
        // the upstream is sending text/event-stream (so the SSE inspector
        // gets framed bytes) or something we can pass through.
        if !headersParsed {
            headerBuffer += chunk
            if let headerEnd = headerBuffer.range(of: "\r\n\r\n") {
                let headerBlock = String(headerBuffer[..<headerEnd.lowerBound])
                let bodyStart = String(headerBuffer[headerEnd.upperBound...])
                headersParsed = true
                isEventStream = headerBlock.lowercased().contains("content-type: text/event-stream")

                var headBuf = context.channel.allocator.buffer(capacity: headerBlock.utf8.count + 4)
                headBuf.writeString(headerBlock)
                headBuf.writeString("\r\n\r\n")
                clientChannel.writeAndFlush(headBuf, promise: nil)
                headerBuffer = ""
                if !bodyStart.isEmpty {
                    forwardBody(bodyStart, context: context)
                }
            }
            return
        }

        forwardBody(chunk, context: context)
    }

    private func forwardBody(_ chunk: String, context: ChannelHandlerContext) {
        if isEventStream && FeatureFlags.sseInspection {
            let safe = sseInspector.ingest(chunk)
            if !safe.isEmpty {
                var buf = context.channel.allocator.buffer(capacity: safe.utf8.count)
                buf.writeString(safe)
                clientChannel.writeAndFlush(buf, promise: nil)
            }
            let blocked = sseInspector.closed
            Task { await Metrics.shared.recordSSEFrame(blocked: blocked) }
            if blocked {
                clientChannel.close(promise: nil)
                context.close(promise: nil)
            }
        } else {
            var buf = context.channel.allocator.buffer(capacity: chunk.utf8.count)
            buf.writeString(chunk)
            clientChannel.writeAndFlush(buf, promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if isEventStream && !sseInspector.closed {
            let tail = sseInspector.finish()
            if !tail.isEmpty {
                var buf = context.channel.allocator.buffer(capacity: tail.utf8.count)
                buf.writeString(tail)
                clientChannel.writeAndFlush(buf, promise: nil)
            }
        }
        clientChannel.close(promise: nil)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        clientChannel.close(promise: nil)
        context.close(promise: nil)
    }
}

// MARK: - Corporate Proxy Detection

enum CorporateProxy {
    struct Config {
        let host: String
        let port: Int
    }

    /// Detect upstream corporate proxy from environment variables.
    /// Only URLs that pass `ManagedConfigValidator.validatedProxyURL`
    /// are accepted — scheme must be http/https, host must be a valid
    /// RFC 1123 hostname, port must be in the unprivileged range.
    ///
    /// Loopback hosts are deliberately ignored. With v0.5.0's
    /// `ShellEnvInjector`, the Bouclier process itself inherits
    /// `HTTPS_PROXY=http://127.0.0.1:8484` from the launchctl session,
    /// and naively trusting that env would make the proxy try to relay
    /// every upstream request *through itself* — an instant TLS-handshake
    /// loop that times out every API call. A real corporate proxy is by
    /// definition not on the loopback, so dropping these candidates
    /// costs nothing legitimate.
    static func detect() -> Config? {
        let env = ProcessInfo.processInfo.environment
        let candidates = [
            env["HTTPS_PROXY"], env["https_proxy"],
            env["HTTP_PROXY"], env["http_proxy"],
        ]
        for raw in candidates {
            guard let url = ManagedConfigValidator.validatedProxyURL(raw),
                  let host = url.host,
                  !isLoopbackHost(host)
            else { continue }
            return Config(host: host, port: url.port ?? 8080)
        }
        return nil
    }

    static func isLoopbackHost(_ host: String) -> Bool {
        let h = host.lowercased()
        return h == "localhost"
            || h == "127.0.0.1"
            || h.hasPrefix("127.")
            || h == "::1"
            || h == "[::1]"
    }
}

// MARK: - Request Log

struct RequestLog: Sendable {
    let timestamp: Date
    let targetHost: String
    let detected: Bool
    let matchCount: Int
    let patternNames: [String]
    let bodySize: Int
    // Fused scoring telemetry — populated by InjectionFilter.scan().
    // mlScore is nil when the classifier wasn't consulted; mlAvailable
    // distinguishes "ML cleared this" from "ML never ran".
    let mlScore: Float?
    let entropyAnomaly: Double
    let fusedScore: Double
    let mlAvailable: Bool
    /// Multimodal scan report. Nil when multimodal inspection didn't
    /// run for this request (feature off, etc.); empty findings when
    /// it ran and the attachments were clean.
    let multimodal: MultimodalPIIInspector.Report?

    init(
        timestamp: Date,
        targetHost: String,
        detected: Bool,
        matchCount: Int,
        patternNames: [String],
        bodySize: Int,
        mlScore: Float?,
        entropyAnomaly: Double,
        fusedScore: Double,
        mlAvailable: Bool,
        multimodal: MultimodalPIIInspector.Report? = nil
    ) {
        self.timestamp = timestamp
        self.targetHost = targetHost
        self.detected = detected
        self.matchCount = matchCount
        self.patternNames = patternNames
        self.bodySize = bodySize
        self.mlScore = mlScore
        self.entropyAnomaly = entropyAnomaly
        self.fusedScore = fusedScore
        self.mlAvailable = mlAvailable
        self.multimodal = multimodal
    }
}
