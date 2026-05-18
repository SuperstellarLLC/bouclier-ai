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
// NIO ensures every ChannelHandler instance is invoked from a single
// event loop, so capturing `self` into Task/EL closures is safe in
// practice even though the type isn't structurally Sendable. The
// `@unchecked Sendable` conformance documents that invariant for the
// Swift 6 region-isolation checker.
private final class HTTPInspectionHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart

    private let host: String
    private let port: Int
    private let filter: InjectionFilter
    private let onRequest: @Sendable (RequestLog) -> Void
    private let eventLoop: EventLoop

    /// Stateless redactor (compiled regexes only). Shared across all
    /// connections — see `PIIRedactor` for the rationale.
    private let piiRedactor = PIIRedactor()
    /// Per-connection session. One per HTTPInspectionHandler instance
    /// so each TLS connection has an independent token-mint domain.
    /// The session is plumbed into `UpstreamRelayHandler` at upstream
    /// connect so the response path can reverse tokens by exact match.
    private let piiSession = PIISession()

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
                rewritten: inspection.bodyRewritten,
                oversized: false,
                categories: inspection.categories,
                severities: inspection.severities
            )
        }

        let finalBody = inspection.sanitizedBody

        // Run the PII redactor on bodies the injection scanner didn't
        // already rewrite. Injection-rewritten bodies carry a
        // placeholder string — there's nothing left worth redacting,
        // and re-running CoreML/regex on the placeholder is waste.
        // Crucially we gate on `bodyRewritten`, not `detected`:
        // URI-only injection matches don't touch the body, so the
        // user's PII is still in there and must be redacted. Per-domain
        // policy short-circuits redaction when the host is on the deny
        // list (so internal LLM gateways can opt out without disabling
        // the feature globally).
        let piiEligible = FeatureFlags.piiRedaction
            && PIIPolicy.shared.shouldRedact(host: host)
            && !inspection.bodyRewritten
            && !inspection.bodyScanSkipped

        // Multimodal inspection is independent of text PII — an image
        // can carry an IBAN that the text scanners never see — and
        // runs whenever the flag is on and injection hasn't already
        // replaced the body bytes. Same Task as text PII so both
        // passes share one cooperative hop.
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
            && PIIPolicy.shared.shouldRedact(host: host)

        if piiEligible || mmEligible {
            let contentType = head.headers.first(name: "Content-Type") ?? ""
            let method = head.method
            let allocator = context.channel.allocator
            let redactor = piiRedactor
            let session = piiSession
            let eventLoop = context.eventLoop
            let headRef = head
            let baseBody = finalBody
            let inspectionRef = inspection
            let hostRef = host
            let sizeRef = bodySize
            Task {
                // Multimodal first so the text-PII pass sees the
                // post-rewrite body (text placeholders may themselves
                // contain entity names we still want to redact).
                let mmPass = mmEligible
                    ? await HTTPRequestInspector.applyMultimodalInspection(
                        body: baseBody,
                        contentType: contentType,
                        method: method,
                        allocator: allocator
                    )
                    : HTTPRequestInspector.MultimodalPass(
                        body: baseBody,
                        report: MultimodalPIIInspector.Report(
                            imagesScanned: 0, pdfsScanned: 0, audioScanned: 0, findings: [], latencyMs: 0
                        )
                    )

                let pass = piiEligible
                    ? await HTTPRequestInspector.applyPIIRedaction(
                        body: mmPass.body,
                        contentType: contentType,
                        method: method,
                        redactor: redactor,
                        session: session,
                        allocator: allocator
                    )
                    : HTTPRequestInspector.PIIPass(body: mmPass.body, audit: [])

                eventLoop.execute { [weak self] in
                    guard let self else { return }
                    self.emitRequestLog(
                        host: hostRef,
                        bodySize: sizeRef,
                        inspection: inspectionRef,
                        piiAudit: pass.audit,
                        multimodal: mmPass.report
                    )
                    self.forwardUpstream(head: headRef, body: pass.body, allocator: allocator)
                }
            }
        } else {
            emitRequestLog(host: host, bodySize: bodySize, inspection: inspection, piiAudit: [], multimodal: nil)
            forwardUpstream(head: head, body: finalBody, allocator: context.channel.allocator)
        }
    }

    /// Combine the injection inspection + the (optional) PII audit +
    /// the (optional) multimodal report into one RequestLog and emit
    /// it. The menu bar's counters and the audit-log table consume
    /// the unified shape.
    private func emitRequestLog(
        host: String,
        bodySize: Int,
        inspection: HTTPRequestInspector.InspectionResult,
        piiAudit: [PIIRedactor.AuditEntry],
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
            piiAudit: piiAudit,
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
                            UpstreamRelayHandler(
                                clientChannel: context.channel,
                                filter: self.filter,
                                piiSession: self.piiSession
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
        // Force-zeroize the session map. Released map memory is otherwise
        // dropped by ARC without bytes being overwritten — explicit close
        // ensures `memset_s` runs on every cleartext buffer before the
        // actor goes out of scope.
        let session = piiSession
        Task { await session.close() }

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
    private let piiSession: PIISession
    private var headersParsed = false
    private var isEventStream = false
    private var isJSON = false
    private var headerBuffer = ""

    /// Buffered response body when PII reversal is active. We accumulate
    /// the entire JSON body, reverse tokens, then emit. Capped at 1 MiB
    /// so a chunked / streaming-without-SSE response can't blow up
    /// memory; bodies beyond the cap fall back to raw forwarding (no
    /// reversal — the model output still leaves the LLM safely, the user
    /// just sees raw tokens in their client).
    private var jsonResponseBuffer = ""
    private var jsonContentLength: Int? = nil
    private var headerBytesForClient: ByteBuffer? = nil
    private static let maxBufferedJSON = 1 * 1024 * 1024

    init(clientChannel: Channel, filter: InjectionFilter, piiSession: PIISession) {
        self.clientChannel = clientChannel
        self.sseInspector = SSEStreamInspector(filter: filter)
        self.piiSession = piiSession
    }

    /// Holds the parsed-but-not-yet-forwarded response header block when
    /// we're in JSON-reversal mode. We delay emission so we can rewrite
    /// Content-Length after reversal (cleartext is usually longer than
    /// the placeholder token, so the body size changes).
    private var pendingHeaderBlock: String? = nil
    /// True while we're accumulating a JSON body that will be reversed.
    private var jsonReversalActive = false
    /// True once a JSON body has been emitted (so we ignore late bytes
    /// without re-buffering).
    private var jsonReversalCompleted = false

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buf = unwrapInboundIn(data)

        // Fast path: once headers are forwarded and we know there's no
        // JSON reversal in progress, relay raw bytes with zero conversion.
        if headersParsed && !isEventStream && !jsonReversalActive {
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
        // the upstream is sending text/event-stream or a reversable JSON.
        if !headersParsed {
            headerBuffer += chunk
            if let headerEnd = headerBuffer.range(of: "\r\n\r\n") {
                let headerBlock = String(headerBuffer[..<headerEnd.lowerBound])
                let bodyStart = String(headerBuffer[headerEnd.upperBound...])
                headersParsed = true
                let lowered = headerBlock.lowercased()
                isEventStream = lowered.contains("content-type: text/event-stream")
                isJSON = lowered.contains("content-type: application/json")
                jsonContentLength = parseContentLength(lowered)
                let isChunked = lowered.contains("transfer-encoding: chunked")

                let canReverse = FeatureFlags.piiRedaction
                    && isJSON
                    && !isEventStream
                    && !isChunked
                    && (jsonContentLength ?? Int.max) <= Self.maxBufferedJSON

                if canReverse {
                    // Hold headers until reversal is done — body size will
                    // change so Content-Length must be rewritten.
                    jsonReversalActive = true
                    pendingHeaderBlock = headerBlock
                    headerBuffer = ""
                    if !bodyStart.isEmpty {
                        ingestJSONBody(bodyStart, context: context)
                    }
                } else {
                    // Forward headers as-is.
                    var headBuf = context.channel.allocator.buffer(capacity: headerBlock.utf8.count + 4)
                    headBuf.writeString(headerBlock)
                    headBuf.writeString("\r\n\r\n")
                    clientChannel.writeAndFlush(NIOAny(headBuf), promise: nil)
                    headerBuffer = ""
                    if !bodyStart.isEmpty {
                        forwardBody(bodyStart, context: context)
                    }
                }
            }
            return
        }

        if jsonReversalActive {
            ingestJSONBody(chunk, context: context)
            return
        }

        forwardBody(chunk, context: context)
    }

    /// Buffer bytes belonging to a JSON response that will be reversed.
    /// When the buffer reaches Content-Length, reverse and emit; if it
    /// exceeds the cap or upstream sends more than Content-Length bytes,
    /// abort reversal and fall back to forwarding everything raw.
    private func ingestJSONBody(_ chunk: String, context: ChannelHandlerContext) {
        if jsonReversalCompleted { return }
        jsonResponseBuffer += chunk

        if jsonResponseBuffer.utf8.count > Self.maxBufferedJSON {
            // Abort: too large. Flush headers + buffer raw, switch off
            // reversal, and let subsequent bytes ride the fast path.
            abortReversalAndFlushRaw(context: context)
            return
        }

        if let expected = jsonContentLength,
           jsonResponseBuffer.utf8.count >= expected {
            emitReversedJSON(context: context)
        }
    }

    private func emitReversedJSON(context: ChannelHandlerContext) {
        jsonReversalCompleted = true
        guard let header = pendingHeaderBlock else { return }
        let body = jsonResponseBuffer
        let session = piiSession
        let channel = clientChannel
        let allocator = context.channel.allocator
        jsonResponseBuffer = ""
        pendingHeaderBlock = nil
        jsonReversalActive = false
        Task {
            await UpstreamRelayHandler.performReversalAndEmit(
                body: body,
                header: header,
                session: session,
                channel: channel,
                allocator: allocator
            )
        }
    }

    /// Pure-async helper: takes everything by value (Sendable), does the
    /// reversal off the event loop, then hops back onto the channel's
    /// loop to write the response. Static so the Swift 6 region-isolation
    /// checker doesn't have to reason about a nested closure that
    /// captures `self`.
    private static func performReversalAndEmit(
        body: String,
        header: String,
        session: PIISession,
        channel: Channel,
        allocator: ByteBufferAllocator
    ) async {
        let reversed = await PIIReverser.reverseString(body, with: session)
        let newLength = reversed.utf8.count
        let rewrittenHeader = replaceContentLength(in: header, with: newLength)
        let combined = rewrittenHeader + "\r\n\r\n" + reversed
        var buf = allocator.buffer(capacity: combined.utf8.count)
        buf.writeString(combined)
        let finalBuf = buf
        channel.eventLoop.execute {
            channel.writeAndFlush(NIOAny(finalBuf), promise: nil)
        }
    }

    /// Best-effort fallback when we couldn't complete reversal. Flush
    /// the original header block + whatever we've buffered, then ride
    /// the raw fast path for subsequent bytes.
    private func abortReversalAndFlushRaw(context: ChannelHandlerContext) {
        guard let header = pendingHeaderBlock else { return }
        let body = jsonResponseBuffer
        let allocator = context.channel.allocator
        var buf = allocator.buffer(capacity: header.utf8.count + 4 + body.utf8.count)
        buf.writeString(header)
        buf.writeString("\r\n\r\n")
        buf.writeString(body)
        clientChannel.writeAndFlush(NIOAny(buf), promise: nil)
        jsonResponseBuffer = ""
        pendingHeaderBlock = nil
        jsonReversalActive = false
        jsonReversalCompleted = true
    }

    private func parseContentLength(_ headersLower: String) -> Int? {
        // Header block is already lowercased here.
        guard let range = headersLower.range(of: "content-length:") else { return nil }
        let after = headersLower[range.upperBound...]
        let line = after.split(separator: "\r\n", maxSplits: 1).first ?? after[..<after.endIndex]
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        return Int(trimmed)
    }

    static func replaceContentLength(in headerBlock: String, with newLength: Int) -> String {
        // Case-insensitive replace of the Content-Length value; preserve
        // the original casing of the header name.
        let pattern = #"(?im)^(content-length\s*:\s*)\d+"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return headerBlock }
        let nsHeader = headerBlock as NSString
        let range = NSRange(location: 0, length: nsHeader.length)
        return regex.stringByReplacingMatches(
            in: headerBlock,
            range: range,
            withTemplate: "$1\(newLength)"
        )
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
    /// PII redaction audit for this request. Empty when the redactor
    /// didn't run (feature off, domain on deny list, body not scanned).
    /// Carries type + offsets + hash prefix per entry; never cleartext.
    let piiAudit: [PIIRedactor.AuditEntry]
    /// Multimodal scan report. Nil when multimodal inspection didn't
    /// run for this request (feature off, etc.); empty findings when
    /// it ran and the images were clean.
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
        piiAudit: [PIIRedactor.AuditEntry] = [],
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
        self.piiAudit = piiAudit
        self.multimodal = multimodal
    }
}
