import Foundation
import NIO
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL

/// NIO-based TLS-intercepting proxy.
///
/// Architecture:
/// ```
/// Client ──[TLS w/ our cert]──► NIOSSLServerHandler
///                                      │
///                                [plaintext HTTP]
///                                      │
///                                InspectionHandler (scans for injections)
///                                      │
///                                [plaintext HTTP — possibly sanitized]
///                                      │
///                                NIOSSLClientHandler ──[TLS w/ real cert]──► Upstream
/// ```
///
/// The proxy listens on a local port. For each CONNECT request:
/// 1. Parse the target host from the CONNECT line
/// 2. Send "200 Connection Established" back to client
/// 3. Generate a leaf cert for the target host (signed by our CA)
/// 4. Perform TLS handshake with client using our leaf cert
/// 5. Connect to real upstream over TLS
/// 6. Bridge the two, scanning HTTP bodies in between
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
        print("[ilvarion-tls] Proxy listening on 127.0.0.1:\(port)")
        return channel
    }

    func shutdown() {
        try? group.syncShutdownGracefully()
    }
}

// MARK: - CONNECT Handler

/// Handles the initial HTTP CONNECT request, then upgrades the connection
/// to TLS interception or passthrough based on the target domain.
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

        // Wait for complete request line
        guard buffer.contains("\r\n") else { return }

        let firstLine = buffer.components(separatedBy: "\r\n").first ?? ""
        let parts = firstLine.split(separator: " ", maxSplits: 2)

        guard parts.count >= 2, parts[0] == "CONNECT" else {
            // Not a CONNECT — return a status page
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

        // Send 200 Connection Established
        let established = "HTTP/1.1 200 Connection Established\r\n\r\n"
        var responseBuf = context.channel.allocator.buffer(capacity: established.utf8.count)
        responseBuf.writeString(established)

        context.writeAndFlush(wrapInboundOut(responseBuf)).whenSuccess { [self] in
            // Remove this handler — we're done parsing CONNECT
            context.pipeline.removeHandler(self, promise: nil)

            if shouldIntercept {
                self.setupInterception(context: context, host: host, port: port)
            } else {
                self.setupPassthrough(context: context, host: host, port: port)
            }
        }
    }

    // MARK: - TLS Interception

    private func setupInterception(context: ChannelHandlerContext, host: String, port: Int) {
        // Get TLS certificate and key for this host from our CA
        guard let (certPEM, keyPEM) = ca.leafCertAndKey(forHost: host) else {
            print("[ilvarion-tls] Cannot generate cert for \(host), falling back to passthrough")
            setupPassthrough(context: context, host: host, port: port)
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

            // Add TLS server handler — this performs the handshake with the client
            context.pipeline.addHandler(sslServerHandler, position: .first).whenSuccess {
                // After TLS handshake, add the inspection + upstream bridge
                context.pipeline.addHandler(
                    InterceptionBridgeHandler(
                        host: host,
                        port: port,
                        filter: self.filter,
                        onRequest: self.onRequest,
                        eventLoop: context.eventLoop
                    )
                ).whenFailure { error in
                    print("[ilvarion-tls] Failed to add bridge handler: \(error)")
                    context.close(promise: nil)
                }
            }
        } catch {
            print("[ilvarion-tls] TLS setup error for \(host): \(error)")
            setupPassthrough(context: context, host: host, port: port)
        }
    }

    // MARK: - Passthrough (non-intercepted domains)

    private func setupPassthrough(context: ChannelHandlerContext, host: String, port: Int) {
        // Connect to upstream and relay bytes bidirectionally
        ClientBootstrap(group: context.eventLoop)
            .channelInitializer { channel in
                channel.pipeline.addHandler(RelayHandler(partner: context.channel))
            }
            .connect(host: host, port: port)
            .whenSuccess { upstreamChannel in
                context.pipeline.addHandler(RelayHandler(partner: upstreamChannel)).whenFailure { _ in
                    context.close(promise: nil)
                    upstreamChannel.close(promise: nil)
                }
            }
    }
}

// MARK: - Interception Bridge

/// Sits between the client-side TLS and the upstream connection.
/// Reads plaintext HTTP from the client, scans for injections,
/// forwards to the upstream, and relays the response back.
private final class InterceptionBridgeHandler: ChannelInboundHandler, RemovableChannelHandler {
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
        // Connect to real upstream with TLS
        var clientTLSConfig = TLSConfiguration.makeClientConfiguration()
        clientTLSConfig.certificateVerification = .fullVerification

        do {
            let sslClientContext = try NIOSSLContext(configuration: clientTLSConfig)

            ClientBootstrap(group: eventLoop)
                .channelInitializer { channel in
                    let sslClientHandler = try! NIOSSLClientHandler(context: sslClientContext, serverHostname: self.host)
                    return channel.pipeline.addHandlers([
                        sslClientHandler,
                        UpstreamRelayHandler(clientChannel: context.channel),
                    ])
                }
                .connect(host: host, port: port)
                .whenComplete { result in
                    switch result {
                    case .success(let channel):
                        self.upstreamChannel = channel
                        // Flush any pending writes
                        for buf in self.pendingWrites {
                            channel.writeAndFlush(buf, promise: nil)
                        }
                        self.pendingWrites.removeAll()
                    case .failure(let error):
                        print("[ilvarion-tls] Upstream connection failed for \(self.host): \(error)")
                        context.close(promise: nil)
                    }
                }
        } catch {
            print("[ilvarion-tls] SSL context error: \(error)")
            context.close(promise: nil)
        }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        let size = buf.readableBytes

        // Read plaintext data from client (after our TLS decryption)
        if let str = buf.getString(at: buf.readerIndex, length: buf.readableBytes) {
            let result = filter.scan(str)

            onRequest(RequestLog(
                timestamp: Date(),
                method: "POST",
                path: "/",
                targetHost: host,
                detected: result.detected,
                matchCount: result.matchCount,
                patternNames: result.patternNames,
                bodySize: size
            ))

            if result.detected {
                // Replace with sanitized content
                var sanitizedBuf = context.channel.allocator.buffer(capacity: result.sanitized.utf8.count)
                sanitizedBuf.writeString(result.sanitized)

                if let upstream = upstreamChannel {
                    upstream.writeAndFlush(sanitizedBuf, promise: nil)
                } else {
                    pendingWrites.append(sanitizedBuf)
                }
                return
            }
        }

        // Forward original data to upstream
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

// MARK: - Upstream Relay Handler

/// Relays data from the upstream back to the client channel.
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

// MARK: - Bidirectional Relay

/// Simple bidirectional byte relay for passthrough (non-intercepted) connections.
private final class RelayHandler: ChannelInboundHandler {
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

// MARK: - Request Log

struct RequestLog: Sendable {
    let timestamp: Date
    let method: String
    let path: String
    let targetHost: String
    let detected: Bool
    let matchCount: Int
    let patternNames: [String]
    let bodySize: Int
}
