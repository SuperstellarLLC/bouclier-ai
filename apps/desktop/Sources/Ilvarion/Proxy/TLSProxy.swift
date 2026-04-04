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

        buffer += str
        guard buffer.contains("\r\n") else { return }

        let firstLine = buffer.components(separatedBy: "\r\n").first ?? ""
        let parts = firstLine.split(separator: " ", maxSplits: 2)

        guard parts.count >= 2, parts[0] == "CONNECT" else {
            let body = "{\"service\":\"Ilvarion\",\"status\":\"running\"}"
            let resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
            var outBuf = context.channel.allocator.buffer(capacity: resp.utf8.count)
            outBuf.writeString(resp)
            context.writeAndFlush(wrapInboundOut(outBuf), promise: nil)
            context.close(promise: nil)
            return
        }

        let target = String(parts[1])
        let hostPort = target.split(separator: ":")
        let host = String(hostPort.first ?? "")
        let port = hostPort.count > 1 ? Int(hostPort[1]) ?? 443 : 443

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
            bodyBuffer.writeBuffer(&body)

        case .end:
            processRequest(context: context)
        }
    }

    /// Scan the accumulated body, rebuild the HTTP request, forward to upstream.
    private func processRequest(context: ChannelHandlerContext) {
        guard let head = requestHead else { return }

        let bodySize = bodyBuffer.readableBytes
        let bodyString = bodyBuffer.getString(at: bodyBuffer.readerIndex, length: bodySize) ?? ""

        let scanResult = filter.scan(bodyString)

        onRequest(RequestLog(
            timestamp: Date(),
            targetHost: host,
            detected: scanResult.detected,
            matchCount: scanResult.matchCount,
            patternNames: scanResult.patternNames,
            bodySize: bodySize
        ))

        // Rebuild the full HTTP request as raw bytes
        var finalBody = bodyBuffer
        var headers = head.headers

        if scanResult.detected {
            // Replace body with sanitized content
            let sanitized = scanResult.sanitized
            finalBody = context.channel.allocator.buffer(capacity: sanitized.utf8.count)
            finalBody.writeString(sanitized)

            // Update Content-Length to match new body size
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
                            UpstreamRelayHandler(clientChannel: context.channel),
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

private final class UpstreamRelayHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private let clientChannel: Channel

    init(clientChannel: Channel) {
        self.clientChannel = clientChannel
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buf = unwrapInboundIn(data)
        clientChannel.writeAndFlush(buf, promise: nil)
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

// MARK: - Corporate Proxy Detection

enum CorporateProxy {
    struct Config {
        let host: String
        let port: Int
    }

    /// Detect upstream corporate proxy from environment or system settings.
    static func detect() -> Config? {
        // Check HTTPS_PROXY env var (standard for corporate environments)
        if let proxyURL = ProcessInfo.processInfo.environment["HTTPS_PROXY"] ?? ProcessInfo.processInfo.environment["https_proxy"],
           let url = URL(string: proxyURL),
           let host = url.host
        {
            let port = url.port ?? 8080
            return Config(host: host, port: port)
        }

        // Check HTTP_PROXY as fallback
        if let proxyURL = ProcessInfo.processInfo.environment["HTTP_PROXY"] ?? ProcessInfo.processInfo.environment["http_proxy"],
           let url = URL(string: proxyURL),
           let host = url.host
        {
            let port = url.port ?? 8080
            return Config(host: host, port: port)
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
}
