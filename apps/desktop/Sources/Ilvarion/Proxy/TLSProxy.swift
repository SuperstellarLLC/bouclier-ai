import Foundation
import NIO
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOTLS

/// NIO-based TLS-intercepting proxy with proper HTTP framing.
///
/// Pipeline for intercepted connections:
/// ```
/// Client ──[TLS]──► NIOSSLServerHandler
///                         │
///                   HTTPRequestDecoder ──► InspectionHandler ──► HTTPRequestEncoder
///                         │                                           │
///                   NIOSSLClientHandler ◄── HTTPResponseEncoder ◄── HTTPResponseDecoder
///                         │
///                  ──[TLS]──► Upstream
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
            .childChannelOption(.maxMessagesPerRead, value: 16)

        let channel = try await bootstrap.bind(host: "127.0.0.1", port: port).get()
        return channel
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
            let body = "{\"service\":\"Ilvarion TLS Proxy\",\"status\":\"running\"}"
            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
            var outBuf = context.channel.allocator.buffer(capacity: response.utf8.count)
            outBuf.writeString(response)
            context.writeAndFlush(wrapInboundOut(outBuf), promise: nil)
            context.close(promise: nil)
            return
        }

        let target = String(parts[1])
        let hostPort = target.split(separator: ":")
        let host = String(hostPort.first ?? "")
        let port = hostPort.count > 1 ? Int(hostPort[1]) ?? 443 : 443

        let shouldIntercept = SystemProxy.interceptedDomains.contains(host)

        // SSRF: reject CONNECT to non-intercepted hosts entirely
        guard shouldIntercept else {
            let errorResp = "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n"
            var errBuf = context.channel.allocator.buffer(capacity: errorResp.utf8.count)
            errBuf.writeString(errorResp)
            context.writeAndFlush(wrapInboundOut(errBuf), promise: nil)
            context.close(promise: nil)
            return
        }

        // Send 200 then set up interception
        let established = "HTTP/1.1 200 Connection Established\r\n\r\n"
        var responseBuf = context.channel.allocator.buffer(capacity: established.utf8.count)
        responseBuf.writeString(established)

        context.writeAndFlush(wrapInboundOut(responseBuf)).whenSuccess { [self] in
            context.pipeline.removeHandler(self, promise: nil)
            setupInterception(context: context, host: host, port: port)
        }
    }

    private func setupInterception(context: ChannelHandlerContext, host: String, port: Int) {
        guard let (certPEM, keyPEM) = ca.leafCertAndKey(forHost: host) else {
            context.close(promise: nil)
            return
        }

        do {
            let cert = try NIOSSLCertificate(bytes: Array(certPEM.utf8), format: .pem)
            let key = try NIOSSLPrivateKey(bytes: Array(keyPEM.utf8), format: .pem)

            var serverTLSConfig = TLSConfiguration.makeServerConfiguration(
                certificateChain: [.certificate(cert)],
                privateKey: .privateKey(key)
            )
            serverTLSConfig.minimumTLSVersion = .tlsv12

            let sslServerContext = try NIOSSLContext(configuration: serverTLSConfig)
            let sslServerHandler = NIOSSLServerHandler(context: sslServerContext)

            // Add TLS handler, then wait for handshake completion
            context.pipeline.addHandler(sslServerHandler, position: .first).whenSuccess {
                context.pipeline.addHandler(
                    TLSHandshakeWaiter(host: host, port: port, filter: self.filter, onRequest: self.onRequest)
                ).whenFailure { error in
                    context.close(promise: nil)
                }
            }
        } catch {
            context.close(promise: nil)
        }
    }
}

// MARK: - TLS Handshake Waiter

/// Waits for TLS handshake to complete before adding the inspection bridge.
private final class TLSHandshakeWaiter: ChannelInboundHandler, RemovableChannelHandler {
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
            // TLS handshake completed — now add the inspection bridge
            context.pipeline.removeHandler(self, promise: nil)

            context.pipeline.addHandler(
                InspectionBridgeHandler(
                    host: host,
                    port: port,
                    filter: filter,
                    onRequest: onRequest,
                    eventLoop: context.eventLoop
                )
            ).whenFailure { _ in
                context.close(promise: nil)
            }
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        // Buffer data until handshake completes — shouldn't normally happen
        context.fireChannelRead(data)
    }
}

// MARK: - Inspection Bridge

/// Bridges client and upstream, scanning plaintext HTTP for injections.
/// Operates on raw bytes (post-TLS) — scans content and forwards.
private final class InspectionBridgeHandler: ChannelInboundHandler, RemovableChannelHandler {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer

    private let host: String
    private let port: Int
    private let filter: InjectionFilter
    private let onRequest: @Sendable (RequestLog) -> Void
    private let eventLoop: EventLoop
    private var upstreamChannel: Channel?
    private var pendingWrites: [ByteBuffer] = []

    init(host: String, port: Int, filter: InjectionFilter, onRequest: @Sendable @escaping (RequestLog) -> Void, eventLoop: EventLoop) {
        self.host = host
        self.port = port
        self.filter = filter
        self.onRequest = onRequest
        self.eventLoop = eventLoop
    }

    func handlerAdded(context: ChannelHandlerContext) {
        do {
            var clientTLSConfig = TLSConfiguration.makeClientConfiguration()
            clientTLSConfig.certificateVerification = .fullVerification
            let sslClientContext = try NIOSSLContext(configuration: clientTLSConfig)

            ClientBootstrap(group: eventLoop)
                .channelInitializer { channel in
                    do {
                        let sslHandler = try NIOSSLClientHandler(context: sslClientContext, serverHostname: self.host)
                        return channel.pipeline.addHandlers([
                            sslHandler,
                            UpstreamRelayHandler(clientChannel: context.channel),
                        ])
                    } catch {
                        return channel.eventLoop.makeFailedFuture(error)
                    }
                }
                .connect(host: host, port: port)
                .whenComplete { result in
                    switch result {
                    case .success(let channel):
                        self.upstreamChannel = channel
                        for buf in self.pendingWrites {
                            channel.writeAndFlush(buf, promise: nil)
                        }
                        self.pendingWrites.removeAll()
                    case .failure:
                        context.close(promise: nil)
                    }
                }
        } catch {
            context.close(promise: nil)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        let size = buf.readableBytes

        // Scan plaintext for injections
        if let str = buf.getString(at: buf.readerIndex, length: buf.readableBytes) {
            let result = filter.scan(str)

            onRequest(RequestLog(
                timestamp: Date(),
                targetHost: host,
                detected: result.detected,
                matchCount: result.matchCount,
                patternNames: result.patternNames,
                bodySize: size
            ))

            if result.detected {
                var sanitizedBuf = context.channel.allocator.buffer(capacity: result.sanitized.utf8.count)
                sanitizedBuf.writeString(result.sanitized)
                forwardToUpstream(sanitizedBuf)
                return
            }
        }

        forwardToUpstream(buf)
    }

    private func forwardToUpstream(_ buf: ByteBuffer) {
        if let upstream = upstreamChannel {
            upstream.writeAndFlush(buf, promise: nil)
        } else {
            pendingWrites.append(buf)
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

// MARK: - Request Log

struct RequestLog: Sendable {
    let timestamp: Date
    let targetHost: String
    let detected: Bool
    let matchCount: Int
    let patternNames: [String]
    let bodySize: Int
}
