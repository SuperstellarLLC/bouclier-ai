import Foundation
import NIO
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
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

    init(port: Int, ca: CertificateAuthority, filter: InjectionFilter, onRequest: @Sendable @escaping (RequestLog) -> Void) {
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: System.coreCount)
        self.ca = ca
        self.filter = filter
        self.port = port
        self.onRequest = onRequest
    }

    func start() async throws -> Channel {
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 256)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { [ca, filter, onRequest] channel in
                channel.pipeline.addHandler(
                    ConnectHandler(ca: ca, filter: filter, onRequest: onRequest)
                )
            }
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)

        return try await bootstrap.bind(host: "127.0.0.1", port: port).get()
    }

    func shutdown() {
        group.shutdownGracefully { _ in }
    }
}

// MARK: - CONNECT Handler

private final class ConnectHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer

    private let ca: CertificateAuthority
    private let filter: InjectionFilter
    private let onRequest: @Sendable (RequestLog) -> Void
    private var buffer = ""

    init(ca: CertificateAuthority, filter: InjectionFilter, onRequest: @Sendable @escaping (RequestLog) -> Void) {
        self.ca = ca
        self.filter = filter
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
            context.writeAndFlush(wrapInboundOut(errBuf), promise: nil)
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
            context.writeAndFlush(wrapInboundOut(outBuf), promise: nil)
            context.close(promise: nil)
            return
        }

        guard let (host, port) = HTTPRequestInspector.parseConnectTarget(String(parts[1])) else {
            let resp = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
            var errBuf = context.channel.allocator.buffer(capacity: resp.utf8.count)
            errBuf.writeString(resp)
            context.writeAndFlush(wrapInboundOut(errBuf), promise: nil)
            context.close(promise: nil)
            return
        }

        // Only allow intercepted domains (SSRF protection)
        guard SystemProxy.interceptedDomains.contains(host) else {
            let resp = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
            var errBuf = context.channel.allocator.buffer(capacity: resp.utf8.count)
            errBuf.writeString(resp)
            context.writeAndFlush(wrapInboundOut(errBuf), promise: nil)
            context.close(promise: nil)
            return
        }

        let established = "HTTP/1.1 200 Connection Established\r\n\r\n"
        var respBuf = context.channel.allocator.buffer(capacity: established.utf8.count)
        respBuf.writeString(established)

        context.writeAndFlush(wrapInboundOut(respBuf)).whenSuccess { [self] in
            context.pipeline.removeHandler(self, promise: nil)
            setupTLS(context: context, host: host, port: port)
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

            context.pipeline.addHandler(sslHandler, position: .first).whenSuccess {
                context.pipeline.addHandler(
                    HandshakeWaiter(host: host, port: port, filter: self.filter, onRequest: self.onRequest)
                ).whenFailure { _ in context.close(promise: nil) }
            }
        } catch {
            context.close(promise: nil)
        }
    }
}

// MARK: - Handshake Waiter

private final class HandshakeWaiter: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer

    private let host: String
    private let port: Int
    private let filter: InjectionFilter
    private let onRequest: @Sendable (RequestLog) -> Void

    init(host: String, port: Int, filter: InjectionFilter, onRequest: @Sendable @escaping (RequestLog) -> Void) {
        self.host = host
        self.port = port
        self.filter = filter
        self.onRequest = onRequest
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is TLSUserEvent {
            context.pipeline.removeHandler(self, promise: nil)

            // Add HTTP decoder → inspection handler
            // The inspection handler accumulates the full HTTP request,
            // scans the body, rebuilds the request with adjusted Content-Length,
            // and forwards raw bytes to upstream via a direct channel bridge.
            context.pipeline.addHandler(ByteToMessageHandler(HTTPRequestDecoder(leftOverBytesStrategy: .forwardBytes))).flatMap {
                context.pipeline.addHandler(
                    HTTPInspectionHandler(
                        host: self.host,
                        port: self.port,
                        filter: self.filter,
                        onRequest: self.onRequest,
                        eventLoop: context.eventLoop
                    )
                )
            }.whenFailure { _ in context.close(promise: nil) }
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
private final class HTTPInspectionHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = HTTPServerRequestPart

    private let host: String
    private let port: Int
    private let filter: InjectionFilter
    private let onRequest: @Sendable (RequestLog) -> Void
    private let eventLoop: EventLoop

    private var upstreamChannel: Channel?
    private var requestHead: HTTPRequestHead?
    private var bodyBuffer = ByteBuffer()
    private var pendingRawWrites: [ByteBuffer] = []

    init(host: String, port: Int, filter: InjectionFilter, onRequest: @Sendable @escaping (RequestLog) -> Void, eventLoop: EventLoop) {
        self.host = host
        self.port = port
        self.filter = filter
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
                rewritten: inspection.detected && !inspection.bodyScanSkipped,
                oversized: false,
                categories: inspection.categories,
                severities: inspection.severities
            )
        }

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
            mlAvailable: inspection.mlAvailable
        ))

        var finalBody = inspection.sanitizedBody
        var headers = head.headers

        if inspection.detected && !inspection.bodyScanSkipped {
            // Update Content-Length to match the (possibly rewritten) body.
            headers.replaceOrAdd(name: "Content-Length", value: "\(finalBody.readableBytes)")
        }

        // Serialize the HTTP request as raw bytes for upstream
        var raw = context.channel.allocator.buffer(capacity: 1024 + finalBody.readableBytes)
        raw.writeString("\(head.method) \(head.uri) HTTP/1.1\r\n")
        for (name, value) in headers {
            raw.writeString("\(name): \(value)\r\n")
        }
        raw.writeString("\r\n")
        raw.writeBuffer(&finalBody)

        sendToUpstream(raw)

        // Reset for next request (HTTP keep-alive)
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
        context.writeAndFlush(NIOAny(buf), promise: nil)
        context.close(promise: nil)
        requestHead = nil
        bodyBuffer.clear()
    }

    private func connectToUpstream(context: ChannelHandlerContext) {
        do {
            var tlsConfig = TLSConfiguration.makeClientConfiguration()
            tlsConfig.certificateVerification = .fullVerification
            let sslContext = try NIOSSLContext(configuration: tlsConfig)

            // Check for upstream corporate proxy
            let bootstrap = ClientBootstrap(group: eventLoop)
                .channelInitializer { channel in
                    do {
                        let sslHandler = try NIOSSLClientHandler(context: sslContext, serverHostname: self.host)
                        return channel.pipeline.addHandlers([
                            sslHandler,
                            UpstreamRelayHandler(clientChannel: context.channel, filter: self.filter),
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
private final class UpstreamRelayHandler: ChannelInboundHandler {
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

        // Fast path: once we've decided the response isn't SSE, relay raw
        // bytes with zero String conversion overhead.
        if headersParsed && !isEventStream {
            clientChannel.writeAndFlush(NIOAny(buf), promise: nil)
            return
        }

        var mutableBuf = buf
        let bytes = mutableBuf.readableBytes
        guard let chunk = mutableBuf.readString(length: bytes) else {
            clientChannel.writeAndFlush(NIOAny(buf), promise: nil)
            return
        }

        // Parse the status line + headers incrementally to learn whether
        // the upstream is sending text/event-stream. This is a minimal
        // HTTP/1.1 response parser sufficient for proxied responses.
        if !headersParsed {
            headerBuffer += chunk
            if let headerEnd = headerBuffer.range(of: "\r\n\r\n") {
                let headerBlock = String(headerBuffer[..<headerEnd.lowerBound])
                let bodyStart = String(headerBuffer[headerEnd.upperBound...])
                headersParsed = true
                isEventStream = headerBlock
                    .lowercased()
                    .contains("content-type: text/event-stream")

                // Forward headers as-is.
                var headBuf = context.channel.allocator.buffer(capacity: headerBlock.utf8.count + 4)
                headBuf.writeString(headerBlock)
                headBuf.writeString("\r\n\r\n")
                clientChannel.writeAndFlush(NIOAny(headBuf), promise: nil)
                headerBuffer = ""

                // If any body bytes came along in the same TCP frame,
                // route them through the appropriate path.
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
                clientChannel.writeAndFlush(NIOAny(buf), promise: nil)
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
            clientChannel.writeAndFlush(NIOAny(buf), promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        if isEventStream && !sseInspector.closed {
            let tail = sseInspector.finish()
            if !tail.isEmpty {
                var buf = context.channel.allocator.buffer(capacity: tail.utf8.count)
                buf.writeString(tail)
                clientChannel.writeAndFlush(NIOAny(buf), promise: nil)
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
    static func detect() -> Config? {
        let env = ProcessInfo.processInfo.environment
        let candidates = [
            env["HTTPS_PROXY"], env["https_proxy"],
            env["HTTP_PROXY"], env["http_proxy"],
        ]
        for raw in candidates {
            guard let url = ManagedConfigValidator.validatedProxyURL(raw),
                  let host = url.host
            else { continue }
            return Config(host: host, port: url.port ?? 8080)
        }
        return nil
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
}
