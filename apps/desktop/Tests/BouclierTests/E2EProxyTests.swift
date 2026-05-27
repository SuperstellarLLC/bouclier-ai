import Foundation
import NIO
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import Testing
@testable import Bouclier

/// End-to-end test for the live TLS interception path.
///
/// **What this proves.** A real HTTPS POST (hand-rolled NIO CONNECT +
/// TLS) → real `TLSProxy` over TCP → real TLS handshake (proxy mints a
/// leaf signed by a throwaway CA) → real upstream HTTPS server
/// in-process. The assertion is against the bytes the *upstream*
/// observes: the text body must arrive **unmodified**. Bouclier never
/// rewrites text prompts — only file attachments (handled by the
/// separate multimodal pass) — and any drift back into prompt
/// rewriting is the failure mode that put us on Anthropic's abuse
/// list in v0.5.x.
///
/// **Why NIO and not URLSession.** `URLSessionConfiguration
/// .connectionProxyDictionary` silently bypasses HTTPS proxying in
/// several macOS configurations. A client that flakily routes around
/// the proxy would falsely pass this exact test, so we drive CONNECT
/// + TLS ourselves where there's no ambiguity.
///
/// **Why serialized.** Seeds `SystemProxy.testAdditionalDomains`.
/// Parallel execution would race the global.
@Suite("E2E — proxy → upstream over real TLS", .serialized)
@MainActor
struct E2EProxyTests {
    @Test("Text request bodies pass through to upstream unmodified")
    func textBodyPassesThroughUnmodified() async throws {
        // 0. Scrub proxy env vars that may have been planted by a
        //    running Bouclier on this machine (`launchctl setenv
        //    HTTPS_PROXY=…` propagates to every child of the user
        //    session, including `swift test`). If we left them in
        //    place, OCSP/CRL fetches issued by NIOSSL during the
        //    upstream handshake would try to route back through the
        //    live proxy and deadlock — masquerading as "test broken"
        //    when the actual symptom is "test environment poisoned by
        //    the very feature we're verifying."
        for key in ["HTTPS_PROXY", "HTTP_PROXY", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"] {
            unsetenv(key)
        }

        // 1. Generate a throwaway CA and a leaf cert for the upstream.
        //    The same CA signs both the upstream's serving cert AND is
        //    handed to TLSProxy as the in-memory root — so the proxy
        //    trusts the upstream end of the hop, and the proxy also
        //    uses this CA to mint MITM leaves URLSession will trust.
        let pki = try TestPKI.generate(upstreamHost: "localhost")

        // 2. Stand up the upstream HTTPS server that records bytes.
        let upstream = try await UpstreamRecorder.start(
            certificatePEM: pki.upstreamCertPEM,
            keyPEM: pki.upstreamKeyPEM
        )
        defer { upstream.shutdown() }

        // 3. Configure the SSRF allowlist so the proxy will accept the
        //    in-process upstream as a MITM target. No PII feature flag
        //    is needed — text bodies are never rewritten regardless.
        SystemProxy.testAdditionalDomains.insert("localhost")
        defer {
            SystemProxy.testAdditionalDomains.remove("localhost")
        }

        // 4. Start the proxy.
        let ca = CertificateAuthority(testingKeyPEM: pki.caKeyPEM, certPEM: pki.caCertPEM)
        let filter = InjectionFilter()
        let observedRequests = ObservedRequests()
        let proxy = TLSProxy(
            port: 0, // bind ephemeral
            ca: ca,
            filter: filter,
            upstreamTrustRootsPEM: [pki.caCertPEM],
            onRequest: { log in observedRequests.append(log) }
        )
        let proxyChannel = try await proxy.start()
        defer { proxy.shutdown() }
        guard let proxyPort = proxyChannel.localAddress?.port else {
            Issue.record("Proxy didn't bind a port")
            return
        }

        // 5. Send the actual HTTPS request *through* the proxy. We
        //    drive this via NIO rather than URLSession because
        //    `URLSessionConfiguration.connectionProxyDictionary` has
        //    long-standing flakiness for HTTPS on macOS — it silently
        //    falls back to direct egress, which would make this test
        //    falsely pass for the bug we're trying to catch. Hand-rolled
        //    CONNECT + TLS over a plain TCP socket leaves no ambiguity:
        //    if the bytes don't go through the proxy, the test fails.
        let cleartextEmail = "alice@example.com"
        let bodyString = #"{"prompt":"please email me at \#(cleartextEmail) about the order"}"#
        let statusCode = try await ProxyDrivenClient.sendThroughProxy(
            proxyHost: "127.0.0.1",
            proxyPort: proxyPort,
            upstreamHost: "localhost",
            upstreamPort: upstream.port,
            method: "POST",
            path: "/v1/messages",
            contentType: "application/json",
            body: bodyString,
            trustRootPEM: pki.caCertPEM
        )
        #expect(statusCode == 200, "Upstream should accept the proxied request")

        // 7. The whole point: what did the *upstream* receive?
        let observedBody = await upstream.observedRequestBody()
        let observedString = String(data: observedBody, encoding: .utf8) ?? ""

        let logs = observedRequests.snapshot()
        #expect(!logs.isEmpty,
                "TLSProxy never saw the request — the client isn't routing through the proxy")

        // The load-bearing invariant for the post-0.5.x scope-down:
        // text bodies traverse the proxy unmodified. If a future change
        // ever reintroduces prompt-side redaction, this test catches it
        // before it ships and re-trips the upstream abuse detectors
        // we got de-listed from.
        #expect(observedString.contains(cleartextEmail),
                "Email cleartext disappeared in transit — Bouclier rewrote a text body, which is the regression this guards against; got: \(observedString)")
        #expect(!observedString.contains("⟦pii:"),
                "Found a PII placeholder in upstream bytes — text redaction has been re-enabled; got: \(observedString)")
        #expect(observedString.contains(bodyString),
                "Body wasn't byte-stable through the proxy; got: \(observedString)")
    }

    /// The other half of the customer-facing promise: client-supplied
    /// request headers — `Authorization`, `x-api-key`, custom trace IDs,
    /// a non-default `User-Agent` — reach the upstream unmodified.
    /// These are the fields LLM providers use for auth, abuse
    /// monitoring, and analytics, and Bouclier must not touch them.
    ///
    /// If this test fails the failure mode is direct revenue impact:
    /// either auth breaks ("we changed your Bearer token"), abuse
    /// detection flags the request ("the client looks anonymised"), or
    /// observability breaks ("we dropped your trace ID"). All of those
    /// were the abuse-list incidents the v0.6 scope cut was designed
    /// to make impossible by construction; this test pins it.
    @Test("Request headers (auth, api-key, trace IDs, user-agent) pass through to upstream unmodified")
    func headersPassThroughUnmodified() async throws {
        for key in ["HTTPS_PROXY", "HTTP_PROXY", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"] {
            unsetenv(key)
        }

        let pki = try TestPKI.generate(upstreamHost: "localhost")
        let upstream = try await UpstreamRecorder.start(
            certificatePEM: pki.upstreamCertPEM,
            keyPEM: pki.upstreamKeyPEM
        )
        defer { upstream.shutdown() }

        SystemProxy.testAdditionalDomains.insert("localhost")
        defer { SystemProxy.testAdditionalDomains.remove("localhost") }

        let ca = CertificateAuthority(testingKeyPEM: pki.caKeyPEM, certPEM: pki.caCertPEM)
        let filter = InjectionFilter()
        let observedRequests = ObservedRequests()
        let proxy = TLSProxy(
            port: 0,
            ca: ca,
            filter: filter,
            upstreamTrustRootsPEM: [pki.caCertPEM],
            onRequest: { log in observedRequests.append(log) }
        )
        let proxyChannel = try await proxy.start()
        defer { proxy.shutdown() }
        guard let proxyPort = proxyChannel.localAddress?.port else {
            Issue.record("Proxy didn't bind a port")
            return
        }

        // A representative spread of headers that real LLM clients send.
        // Mixed case names + values with `=` and `-` cover the wire-safe
        // characters most likely to trip a naïve rewriter.
        let extras: [(String, String)] = [
            ("Authorization", "Bearer sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-XX"),
            ("x-api-key", "sk-ant-api03-ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ-YY"),
            ("X-Trace-Id", "b1a3c2d4-e5f6-7890-abcd-ef0123456789"),
            ("X-Request-ID", "req_2026_05_27_xyz=="),
            ("User-Agent", "AnthropicSDK/Python 1.10.0"),
            ("Anthropic-Version", "2023-06-01"),
            ("Anthropic-Beta", "pdfs-2024-09-25,prompt-caching-2024-07-31"),
        ]

        let bodyString = #"{"prompt":"hello"}"#
        let statusCode = try await ProxyDrivenClient.sendThroughProxy(
            proxyHost: "127.0.0.1",
            proxyPort: proxyPort,
            upstreamHost: "localhost",
            upstreamPort: upstream.port,
            method: "POST",
            path: "/v1/messages",
            contentType: "application/json",
            body: bodyString,
            trustRootPEM: pki.caCertPEM,
            extraHeaders: extras
        )
        #expect(statusCode == 200, "Upstream should accept the proxied request")

        // Headers are matched case-insensitively on the name and
        // byte-identical on the value. NIO's HTTPParser lowercases the
        // name on receive so we compare normalized.
        let observedHeaders = await upstream.observedRequestHeaders()
        let observedByLowerName: [String: String] = Dictionary(
            observedHeaders.map { ($0.0.lowercased(), $0.1) },
            uniquingKeysWith: { _, latest in latest }
        )

        for (name, value) in extras {
            let lower = name.lowercased()
            let received = observedByLowerName[lower]
            #expect(received != nil,
                    "Header \(name) was dropped between client and upstream — Bouclier is mutating the header set")
            #expect(received == value,
                    "Header \(name) was rewritten in transit: client sent \"\(value)\", upstream received \"\(received ?? "<missing>")\"")
        }
    }
}

/// Thread-safe accumulator for `RequestLog` callbacks fired from NIO.
/// We don't assert directly inside the callback (TLSProxy invokes it
/// from an event-loop thread that's not the test's @MainActor), so
/// callers snapshot after the response round-trips.
final class ObservedRequests: @unchecked Sendable {
    private let lock = NSLock()
    private var logs: [RequestLog] = []
    func append(_ log: RequestLog) { lock.lock(); logs.append(log); lock.unlock() }
    func snapshot() -> [RequestLog] { lock.lock(); defer { lock.unlock() }; return logs }
}

// MARK: - Throwaway PKI

/// Generates a CA + a leaf cert for a single hostname using the system
/// `openssl`. The keys never leave the test's tmp directory; nothing
/// touches the user's Keychain or Application Support.
struct TestPKI {
    let caKeyPEM: String
    let caCertPEM: String
    let upstreamKeyPEM: String
    let upstreamCertPEM: String

    static func generate(upstreamHost: String) throws -> TestPKI {
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("bouclier-e2e-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let caKey = tmp.appendingPathComponent("ca.key")
        let caCert = tmp.appendingPathComponent("ca.pem")
        try runOpenSSL([
            "req", "-x509", "-new", "-newkey", "rsa:2048",
            "-keyout", caKey.path, "-out", caCert.path,
            "-days", "1", "-nodes",
            "-subj", "/CN=Bouclier Test CA",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ])

        let leafKey = tmp.appendingPathComponent("leaf.key")
        let leafCsr = tmp.appendingPathComponent("leaf.csr")
        let leafCert = tmp.appendingPathComponent("leaf.pem")
        let ext = tmp.appendingPathComponent("ext.cnf")

        try runOpenSSL([
            "req", "-new", "-newkey", "rsa:2048", "-nodes",
            "-keyout", leafKey.path, "-out", leafCsr.path,
            "-subj", "/CN=\(upstreamHost)",
        ])
        try """
        authorityKeyIdentifier=keyid,issuer
        basicConstraints=CA:FALSE
        keyUsage=digitalSignature,keyEncipherment
        extendedKeyUsage=serverAuth
        subjectAltName=DNS:\(upstreamHost)
        """.write(to: ext, atomically: true, encoding: .utf8)
        try runOpenSSL([
            "x509", "-req", "-in", leafCsr.path,
            "-CA", caCert.path, "-CAkey", caKey.path,
            "-CAcreateserial", "-out", leafCert.path,
            "-days", "1", "-sha256",
            "-extfile", ext.path,
        ])

        return TestPKI(
            caKeyPEM: try String(contentsOf: caKey, encoding: .utf8),
            caCertPEM: try String(contentsOf: caCert, encoding: .utf8),
            upstreamKeyPEM: try String(contentsOf: leafKey, encoding: .utf8),
            upstreamCertPEM: try String(contentsOf: leafCert, encoding: .utf8)
        )
    }

    private static func runOpenSSL(_ args: [String]) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/openssl")
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        try p.run()
        p.waitUntilExit()
        if p.terminationStatus != 0 {
            throw TestPKIError.opensslFailed(args.first ?? "?", p.terminationStatus)
        }
    }

    enum TestPKIError: Error { case opensslFailed(String, Int32) }
}

// MARK: - In-process HTTPS upstream that records the request body

/// Thread-safe holder for the bytes the upstream observed. The
/// recorder handler writes from a NIO event loop thread; the test
/// awaits the response and then reads from the main actor — we need
/// the synchronization edge or TSan would flag it.
final class LockedBytes: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    private var headers: [(String, String)] = []
    func store(_ d: Data) { lock.lock(); data = d; lock.unlock() }
    func read() -> Data { lock.lock(); defer { lock.unlock() }; return data }
    func storeHeaders(_ h: [(String, String)]) { lock.lock(); headers = h; lock.unlock() }
    func readHeaders() -> [(String, String)] { lock.lock(); defer { lock.unlock() }; return headers }
}

/// Minimal NIO HTTPS server that accepts a single POST, records the
/// body bytes, and answers `200 OK`. Bound to 127.0.0.1 on an ephemeral
/// port so a flaky CI runner can't collide with another listener.
actor UpstreamRecorder {
    let port: Int
    private let group: MultiThreadedEventLoopGroup
    private let channel: Channel
    private var recordedBody: Data = Data()

    private init(port: Int, group: MultiThreadedEventLoopGroup, channel: Channel) {
        self.port = port
        self.group = group
        self.channel = channel
    }

    static func start(certificatePEM: String, keyPEM: String) async throws -> UpstreamRecorder {
        let cert = try NIOSSLCertificate.fromPEMBytes(Array(certificatePEM.utf8))
        let key = try NIOSSLPrivateKey(bytes: Array(keyPEM.utf8), format: .pem)
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: cert.map { .certificate($0) },
            privateKey: .privateKey(key)
        )
        config.minimumTLSVersion = .tlsv12
        let sslContext = try NIOSSLContext(configuration: config)

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let recorder = LockedBytes()

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(.backlog, value: 16)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                let sslHandler = NIOSSLServerHandler(context: sslContext)
                return channel.pipeline.addHandler(sslHandler).flatMap {
                    channel.pipeline.configureHTTPServerPipeline().flatMap {
                        channel.pipeline.addHandler(RecorderHandler(recorder: recorder))
                    }
                }
            }
            .childChannelOption(.socketOption(.so_reuseaddr), value: 1)

        let channel = try await bootstrap.bind(host: "127.0.0.1", port: 0).get()
        guard let port = channel.localAddress?.port else {
            try? await group.shutdownGracefully()
            throw UpstreamError.didNotBind
        }

        let server = UpstreamRecorder(port: port, group: group, channel: channel)
        await server.attachRecorder(recorder)
        return server
    }

    private var recorderBox: LockedBytes?

    private func attachRecorder(_ box: LockedBytes) {
        recorderBox = box
    }

    /// The bytes the upstream actually saw. Read after the response
    /// round-trips so we know the handler had a chance to populate it.
    func observedRequestBody() -> Data {
        recorderBox?.read() ?? Data()
    }

    /// The headers the upstream actually saw. Order-preserving so a
    /// test can assert against the wire ordering if it ever matters.
    func observedRequestHeaders() -> [(String, String)] {
        recorderBox?.readHeaders() ?? []
    }

    nonisolated func shutdown() {
        try? channel.close().wait()
        try? group.syncShutdownGracefully()
    }

    enum UpstreamError: Error { case didNotBind }
}

/// Captures the request body into the shared `NIOLockedValueBox` and
/// answers a fixed `200 OK`. Lives only as long as the connection.
private final class RecorderHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let recorder: LockedBytes
    private var accumulator = Data()

    init(recorder: LockedBytes) {
        self.recorder = recorder
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head):
            accumulator.removeAll(keepingCapacity: true)
            recorder.storeHeaders(head.headers.map { ($0.name, $0.value) })
        case .body(let buffer):
            if let bytes = buffer.getBytes(at: buffer.readerIndex, length: buffer.readableBytes) {
                accumulator.append(contentsOf: bytes)
            }
        case .end:
            recorder.store(accumulator)

            var headers = HTTPHeaders()
            headers.add(name: "Content-Type", value: "application/json")
            headers.add(name: "Content-Length", value: "2")
            let head = HTTPResponseHead(version: .init(major: 1, minor: 1), status: .ok, headers: headers)
            context.write(wrapOutboundOut(.head(head)), promise: nil)
            var buf = context.channel.allocator.buffer(capacity: 2)
            buf.writeString("{}")
            context.write(wrapOutboundOut(.body(.byteBuffer(buf))), promise: nil)
            context.writeAndFlush(wrapOutboundOut(.end(nil)), promise: nil)
        }
    }
}

// MARK: - NIO-driven proxy client (CONNECT + TLS by hand)

/// Hand-rolled HTTPS-through-proxy client. Opens a plain TCP socket to
/// the proxy, writes a `CONNECT host:port` line, waits for `200
/// Connection Established`, then bolts a NIOSSL handler on top of the
/// same socket and sends the actual HTTP request. Returns the status
/// code of the upstream response.
///
/// We use NIO rather than `URLSession` because URLSession's
/// `connectionProxyDictionary` silently bypasses HTTPS proxies on macOS
/// in too many configurations — a flaky test client would mask the
/// exact failure mode we're trying to catch (PII slipping past the
/// proxy because the proxy was never invoked).
enum ProxyDrivenClient {
    static func sendThroughProxy(
        proxyHost: String,
        proxyPort: Int,
        upstreamHost: String,
        upstreamPort: Int,
        method: String,
        path: String,
        contentType: String,
        body: String,
        trustRootPEM: String,
        extraHeaders: [(String, String)] = []
    ) async throws -> Int {
        // Trust the throwaway CA both for the proxy's MITM leaf and the
        // upstream's own cert (same root signs both in this test).
        var tlsConfig = TLSConfiguration.makeClientConfiguration()
        let roots = try NIOSSLCertificate.fromPEMBytes(Array(trustRootPEM.utf8))
        tlsConfig.trustRoots = .certificates(roots)
        tlsConfig.certificateVerification = .fullVerification
        let sslContext = try NIOSSLContext(configuration: tlsConfig)

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)

        let collector = ResponseCollector()
        let extras = extraHeaders.map { "\($0.0): \($0.1)\r\n" }.joined()
        let channel = try await ClientBootstrap(group: group)
            .channelInitializer { ch in
                ch.pipeline.addHandler(ProxyConnectHandler(
                    upstreamHost: upstreamHost,
                    upstreamPort: upstreamPort,
                    sslContext: sslContext,
                    collector: collector,
                    requestLine: "\(method) \(path) HTTP/1.1\r\nHost: \(upstreamHost):\(upstreamPort)\r\nContent-Type: \(contentType)\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\(extras)\r\n\(body)"
                ))
            }
            .connect(host: proxyHost, port: proxyPort)
            .get()

        // Wait up to 5s for the response.
        for _ in 0..<50 {
            if let status = collector.status {
                try? await channel.close()
                try? await group.shutdownGracefully()
                return status
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
        try? await channel.close()
        try? await group.shutdownGracefully()
        throw ProxyDrivenError.timedOut
    }

    enum ProxyDrivenError: Error { case timedOut, badConnect(String) }
}

/// Shared status holder filled by the response-parsing handler.
private final class ResponseCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var _status: Int?
    var status: Int? {
        get { lock.lock(); defer { lock.unlock() }; return _status }
        set { lock.lock(); _status = newValue; lock.unlock() }
    }
}

/// Two-phase NIO handler. Phase 1: wait for the proxy's
/// `200 Connection Established` line, then install the NIOSSL handler.
/// Phase 2 (after the handshake): write the actual request and parse
/// the upstream response status line.
private final class ProxyConnectHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let upstreamHost: String
    private let upstreamPort: Int
    private let sslContext: NIOSSLContext
    private let collector: ResponseCollector
    private let requestLine: String

    private var phase: Phase = .connecting
    private var inboundBuffer = ""

    private enum Phase { case connecting, sendingRequest, readingResponse }

    init(upstreamHost: String, upstreamPort: Int, sslContext: NIOSSLContext, collector: ResponseCollector, requestLine: String) {
        self.upstreamHost = upstreamHost
        self.upstreamPort = upstreamPort
        self.sslContext = sslContext
        self.collector = collector
        self.requestLine = requestLine
    }

    func channelActive(context: ChannelHandlerContext) {
        let connect = "CONNECT \(upstreamHost):\(upstreamPort) HTTP/1.1\r\nHost: \(upstreamHost):\(upstreamPort)\r\n\r\n"
        var buf = context.channel.allocator.buffer(capacity: connect.utf8.count)
        buf.writeString(connect)
        context.writeAndFlush(wrapOutboundOut(buf), promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch phase {
        case .connecting:
            var buf = unwrapInboundIn(data)
            inboundBuffer += buf.readString(length: buf.readableBytes) ?? ""
            guard let _ = inboundBuffer.range(of: "\r\n\r\n") else { return }
            guard inboundBuffer.contains("200") else {
                context.close(promise: nil); return
            }
            inboundBuffer = ""
            phase = .sendingRequest
            installTLSAndSendRequest(context: context)
        case .sendingRequest, .readingResponse:
            // Bytes after TLS handshake arrive decrypted from the NIOSSL
            // handler above us; the same handler also intercepts our
            // outbound write. The response status arrives here.
            var buf = unwrapInboundIn(data)
            inboundBuffer += buf.readString(length: buf.readableBytes) ?? ""
            if collector.status == nil,
               let firstLine = inboundBuffer.components(separatedBy: "\r\n").first {
                let parts = firstLine.split(separator: " ")
                if parts.count >= 2, let code = Int(parts[1]) {
                    collector.status = code
                }
            }
        }
    }

    private func installTLSAndSendRequest(context: ChannelHandlerContext) {
        do {
            let ssl = try NIOSSLClientHandler(context: sslContext, serverHostname: upstreamHost)
            context.pipeline.addHandler(ssl, position: .first).whenSuccess { [self] in
                phase = .readingResponse
                var buf = context.channel.allocator.buffer(capacity: requestLine.utf8.count)
                buf.writeString(requestLine)
                context.writeAndFlush(wrapOutboundOut(buf), promise: nil)
            }
        } catch {
            context.close(promise: nil)
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }
}
