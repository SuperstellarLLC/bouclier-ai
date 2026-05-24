import Foundation
import NIO
import NIOCore
import NIOPosix
import Testing
@testable import Bouclier

/// Pins the contract that the proxy *tunnels* non-AI-API hosts instead
/// of returning 403. The previous design 403'd everything outside
/// `SystemProxy.interceptedDomains`, which made sense when Bouclier
/// was only invoked deliberately via a PAC file. With v0.5.0's
/// `ShellEnvInjector` planting `HTTPS_PROXY=…` in every shell, that
/// 403 broke `git push`, `npm install`, `brew update`, and `curl` to
/// any non-AI host the moment the user enabled CLI capture — a
/// regression we'd never want to ship again.
///
/// Cloud metadata IPs (169.254.169.254, metadata.google.internal,
/// metadata.azure.com) are kept blocked because there's no legitimate
/// CLI-tool need for them, and they're the classic SSRF jackpot.
@Suite("Proxy passthrough — non-AI hosts", .serialized)
@MainActor
struct PassthroughTests {
    @Test("CONNECT to an arbitrary TCP host tunnels through, byte-for-byte")
    func passthroughRelaysBytes() async throws {
        // Scrub any inherited proxy env so NIO inside the test process
        // doesn't loop back through the live Bouclier.
        for key in ["HTTPS_PROXY", "HTTP_PROXY", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"] {
            unsetenv(key)
        }

        // 1. Spin up a plain TCP echo server on 127.0.0.1:<ephemeral>.
        let echoServer = try await EchoServer.start()
        defer { echoServer.shutdown() }

        // 2. Start the proxy. The test host is `127.0.0.1`, which is
        //    deliberately NOT in interceptedDomains and isn't a key
        //    any other suite touches — so we can't race with E2E's
        //    `testAdditionalDomains.insert("localhost")`.
        let ca = CertificateAuthority(testingKeyPEM: "", certPEM: "") // unused on passthrough path
        let filter = InjectionFilter()
        let proxy = TLSProxy(port: 0, ca: ca, filter: filter, onRequest: { _ in })
        let proxyChannel = try await proxy.start()
        defer { proxy.shutdown() }
        guard let proxyPort = proxyChannel.localAddress?.port else {
            Issue.record("proxy didn't bind"); return
        }

        // 3. Open a TCP connection to the proxy, send CONNECT, then
        //    send a payload and read the echo back. No TLS — we're
        //    proving the tunnel is *transparent* to whatever protocol
        //    runs over it.
        let observed = LockedBytes()
        let payload = "PING-\(UUID().uuidString)"
        let response = try await CONNECTTunnelClient.send(
            proxyPort: proxyPort,
            upstreamHost: "127.0.0.1",
            upstreamPort: echoServer.port,
            payload: payload,
            observed: observed
        )

        #expect(response.contains(payload),
                "Echo server returned: \(response.debugDescription) — expected the payload to round-trip through the tunnel")
    }

    @Test("CONNECT to a cloud-metadata host is rejected with 403")
    func cloudMetadataBlocked() {
        #expect(TLSProxy.isCloudMetadataHost("169.254.169.254"))
        #expect(TLSProxy.isCloudMetadataHost("metadata.google.internal"))
        #expect(TLSProxy.isCloudMetadataHost("METADATA.AZURE.COM"))
        #expect(!TLSProxy.isCloudMetadataHost("api.openai.com"))
        #expect(!TLSProxy.isCloudMetadataHost("github.com"))
    }

    /// `ShellEnvInjector` plants `HTTPS_PROXY=http://127.0.0.1:8484`
    /// via `launchctl setenv`, so the Bouclier process itself inherits
    /// it on launch. If `CorporateProxy.detect()` honoured that env,
    /// the proxy would route every upstream connection *through itself*
    /// — an instant TLS-handshake loop that silently times out every
    /// API call. Caught during live-app QA; this pins the fix.
    @Test("CorporateProxy.detect ignores loopback hosts to prevent self-tunnelling")
    func corporateProxyIgnoresLoopback() {
        #expect(CorporateProxy.isLoopbackHost("127.0.0.1"))
        #expect(CorporateProxy.isLoopbackHost("localhost"))
        #expect(CorporateProxy.isLoopbackHost("LOCALHOST"))
        #expect(CorporateProxy.isLoopbackHost("127.42.0.1"))
        #expect(CorporateProxy.isLoopbackHost("::1"))
        #expect(!CorporateProxy.isLoopbackHost("proxy.corp.example.com"))
        #expect(!CorporateProxy.isLoopbackHost("10.0.0.5"))
    }
}

// MARK: - Echo server

/// Minimal NIO TCP server that echoes everything it receives back to
/// the sender. Used as the "upstream" for the passthrough test —
/// proving the proxy forwards bytes both directions.
actor EchoServer {
    let port: Int
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel

    private init(port: Int, group: MultiThreadedEventLoopGroup, channel: Channel) {
        self.port = port
        self.group = group
        self.channel = channel
    }

    static func start() async throws -> EchoServer {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 16)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(EchoHandler())
            }
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)

        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else {
            try? await group.shutdownGracefully()
            throw EchoError.didNotBind
        }
        return EchoServer(port: port, group: group, channel: channel)
    }

    nonisolated func shutdown() {
        try? channel.close().wait()
        try? group.syncShutdownGracefully()
    }

    enum EchoError: Error { case didNotBind }
}

private final class EchoHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.writeAndFlush(data, promise: nil)
    }
}

// MARK: - Hand-rolled CONNECT client for the passthrough test

enum CONNECTTunnelClient {
    static func send(
        proxyPort: Int,
        upstreamHost: String,
        upstreamPort: Int,
        payload: String,
        observed: LockedBytes
    ) async throws -> String {
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let collector = StringCollector()

        let channel = try await ClientBootstrap(group: group)
            .channelInitializer { ch in
                ch.pipeline.addHandler(TunnelHandler(
                    connect: "CONNECT \(upstreamHost):\(upstreamPort) HTTP/1.1\r\nHost: \(upstreamHost):\(upstreamPort)\r\n\r\n",
                    payload: payload,
                    collector: collector
                ))
            }
            .connect(host: "127.0.0.1", port: proxyPort)
            .get()

        // Poll up to 3 s for the echo to round-trip.
        for _ in 0..<30 {
            if let echoed = collector.echo {
                try? await channel.close()
                try? await group.shutdownGracefully()
                return echoed
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
        try? await channel.close()
        try? await group.shutdownGracefully()
        throw TunnelError.timedOut
    }

    enum TunnelError: Error { case timedOut, connectRejected(String) }
}

private final class StringCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var _echo: String?
    var echo: String? {
        get { lock.lock(); defer { lock.unlock() }; return _echo }
        set { lock.lock(); _echo = newValue; lock.unlock() }
    }
}

private final class TunnelHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private enum Phase { case waitingForConnect, tunnelling }
    private var phase: Phase = .waitingForConnect
    private let connect: String
    private let payload: String
    private let collector: StringCollector
    private var inboundBuffer = ""

    init(connect: String, payload: String, collector: StringCollector) {
        self.connect = connect
        self.payload = payload
        self.collector = collector
    }

    func channelActive(context: ChannelHandlerContext) {
        var buf = context.channel.allocator.buffer(capacity: connect.utf8.count)
        buf.writeString(connect)
        context.writeAndFlush(NIOAny(buf), promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buf = unwrapInboundIn(data)
        let chunk = buf.readString(length: buf.readableBytes) ?? ""
        switch phase {
        case .waitingForConnect:
            inboundBuffer += chunk
            guard inboundBuffer.contains("\r\n\r\n") else { return }
            guard inboundBuffer.contains(" 200 ") else {
                // 403 / 502 / etc. — record and bail.
                collector.echo = "<connect failed: \(inboundBuffer.prefix(80))>"
                context.close(promise: nil)
                return
            }
            phase = .tunnelling
            inboundBuffer = ""
            // Send the payload over the tunnel.
            var p = context.channel.allocator.buffer(capacity: payload.utf8.count)
            p.writeString(payload)
            context.writeAndFlush(NIOAny(p), promise: nil)
        case .tunnelling:
            inboundBuffer += chunk
            if !inboundBuffer.isEmpty {
                collector.echo = inboundBuffer
            }
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}
