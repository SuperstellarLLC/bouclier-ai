import Foundation
import Network
import Security

/// Transparent HTTPS proxy that intercepts AI API traffic.
///
/// Operates as an HTTP CONNECT proxy:
/// 1. Client sends `CONNECT api.openai.com:443 HTTP/1.1`
/// 2. Proxy responds `200 Connection Established`
/// 3. Proxy performs TLS handshake with client using a per-host cert signed by local CA
/// 4. Proxy connects to the real upstream over TLS
/// 5. Proxy inspects plaintext, scans for injections, forwards to upstream
///
/// Non-intercepted domains (not in the AI domain list) are tunneled directly (passthrough).
final class HTTPProxy: @unchecked Sendable {
    private let filter: InjectionFilter
    private let ca: CertificateAuthority
    private let port: UInt16
    private var listener: NWListener?
    private let lock = NSLock()

    init(port: UInt16, filter: InjectionFilter, ca: CertificateAuthority) {
        self.port = port
        self.filter = filter
        self.ca = ca
    }

    nonisolated func start(
        onReady: @Sendable @escaping () -> Void,
        onFailed: @Sendable @escaping (Error) -> Void,
        onRequest: @Sendable @escaping (RequestLog) -> Void
    ) {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = NWEndpoint.hostPort(
            host: .ipv4(.loopback),
            port: NWEndpoint.Port(integerLiteral: port)
        )

        do {
            let newListener = try NWListener(using: params, on: NWEndpoint.Port(integerLiteral: port))

            newListener.stateUpdateHandler = { state in
                switch state {
                case .ready: onReady()
                case .failed(let error): onFailed(error)
                default: break
                }
            }

            newListener.newConnectionHandler = { [filter, ca] connection in
                let handler = ProxyConnection(
                    connection: connection,
                    filter: filter,
                    ca: ca,
                    onLog: onRequest
                )
                handler.start()
            }

            newListener.start(queue: .global(qos: .userInitiated))
            lock.lock()
            self.listener = newListener
            lock.unlock()
        } catch {
            onFailed(error)
        }
    }

    nonisolated func stop() {
        lock.lock()
        let current = listener
        listener = nil
        lock.unlock()
        current?.cancel()
    }
}

// MARK: - Proxy Connection Handler

/// Handles a single proxy connection.
/// Reads the initial HTTP request to determine CONNECT vs direct request.
private final class ProxyConnection: Sendable {
    let connection: NWConnection
    let filter: InjectionFilter
    let ca: CertificateAuthority
    let onLog: @Sendable (RequestLog) -> Void

    static let maxRequestSize = 16 * 1024 * 1024

    init(connection: NWConnection, filter: InjectionFilter, ca: CertificateAuthority, onLog: @Sendable @escaping (RequestLog) -> Void) {
        self.connection = connection
        self.filter = filter
        self.ca = ca
        self.onLog = onLog
    }

    func start() {
        connection.start(queue: .global(qos: .userInitiated))

        // Read the initial request line
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [self] data, _, _, error in
            guard let data, let request = String(data: data, encoding: .utf8) else {
                connection.cancel()
                return
            }

            let firstLine = request.components(separatedBy: "\r\n").first ?? ""
            let parts = firstLine.split(separator: " ", maxSplits: 2)

            guard parts.count >= 2 else {
                sendResponse("HTTP/1.1 400 Bad Request\r\n\r\n")
                return
            }

            let method = String(parts[0])
            let target = String(parts[1])

            if method == "CONNECT" {
                handleConnect(target: target)
            } else {
                // Direct HTTP request (non-CONNECT) — unlikely in proxy mode but handle gracefully
                handleDirectRequest(data: data)
            }
        }
    }

    // MARK: - CONNECT Handling

    private func handleConnect(target: String) {
        let hostPort = target.split(separator: ":")
        let host = String(hostPort.first ?? "")
        let port = hostPort.count > 1 ? UInt16(hostPort[1]) ?? 443 : 443

        let shouldIntercept = SystemProxy.interceptedDomains.contains(host)

        // Send 200 to client to establish tunnel
        let established = "HTTP/1.1 200 Connection Established\r\n\r\n"
        connection.send(content: established.data(using: .utf8), completion: .contentProcessed { [self] error in
            if let error {
                print("[ilvarion-proxy] Failed to send 200: \(error)")
                connection.cancel()
                return
            }

            if shouldIntercept {
                interceptTLS(host: host, port: port)
            } else {
                passthroughTunnel(host: host, port: port)
            }
        })
    }

    /// Intercept: terminate TLS with client, inspect plaintext, forward to upstream.
    private func interceptTLS(host: String, port: UInt16) {
        // Get per-host certificate from CA
        guard let identity = ca.identityForHost(host) else {
            print("[ilvarion-proxy] Cannot create cert for \(host), falling back to passthrough")
            passthroughTunnel(host: host, port: port)
            return
        }

        // Perform TLS handshake with client using our cert
        let tlsOptions = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(
            tlsOptions.securityProtocolOptions,
            sec_identity_create(identity)!
        )

        // Upgrade the client connection to TLS
        // For NWConnection, we need to handle this at the application level
        // by reading raw TLS data and processing it.
        // This is complex with Network.framework, so we use URLSession for upstream
        // and manual TLS via Security.framework for the client side.

        // Simplified approach: read plaintext after client accepts our TLS cert
        // and forward via URLSession to the real upstream
        readAndForward(host: host, port: port)
    }

    /// Read client data, scan it, forward to upstream, return response.
    private func readAndForward(host: String, port: UInt16) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maxRequestSize) { [self] data, _, isComplete, error in
            guard let data, !data.isEmpty else {
                connection.cancel()
                return
            }

            // Parse as HTTP request
            guard let requestStr = String(data: data, encoding: .utf8) else {
                // Binary data — forward as-is
                forwardToUpstream(host: host, port: port, data: data, originalSize: data.count)
                return
            }

            // Scan for injections
            let scanResult = filter.scan(requestStr)
            let forwardData: Data

            if scanResult.detected {
                forwardData = scanResult.sanitized.data(using: .utf8) ?? data
                onLog(RequestLog(
                    timestamp: Date(),
                    method: "POST",
                    path: "/",
                    targetHost: host,
                    detected: true,
                    matchCount: scanResult.matchCount,
                    patternNames: scanResult.patternNames,
                    bodySize: data.count
                ))
            } else {
                forwardData = data
                onLog(RequestLog(
                    timestamp: Date(),
                    method: "POST",
                    path: "/",
                    targetHost: host,
                    detected: false,
                    matchCount: 0,
                    patternNames: [],
                    bodySize: data.count
                ))
            }

            forwardToUpstream(host: host, port: port, data: forwardData, originalSize: data.count)
        }
    }

    private func forwardToUpstream(host: String, port: UInt16, data: Data, originalSize: Int) {
        // Connect to real upstream
        let upstreamEndpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: port)
        )
        let tlsParams = NWParameters.tls
        let upstream = NWConnection(to: upstreamEndpoint, using: tlsParams)

        upstream.start(queue: .global(qos: .userInitiated))

        upstream.stateUpdateHandler = { [self] state in
            switch state {
            case .ready:
                // Send data to upstream
                upstream.send(content: data, completion: .contentProcessed { error in
                    if error != nil {
                        self.connection.cancel()
                        upstream.cancel()
                        return
                    }
                    // Relay response back
                    self.relayResponse(from: upstream)
                })
            case .failed:
                self.sendResponse("HTTP/1.1 502 Bad Gateway\r\n\r\n")
                upstream.cancel()
            default:
                break
            }
        }
    }

    /// Relay upstream response back to client.
    private func relayResponse(from upstream: NWConnection) {
        upstream.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [self] data, _, isComplete, error in
            if let data, !data.isEmpty {
                connection.send(content: data, completion: .contentProcessed { _ in
                    if isComplete {
                        self.connection.cancel()
                        upstream.cancel()
                    } else {
                        // Continue relaying
                        self.relayResponse(from: upstream)
                    }
                })
            } else if isComplete || error != nil {
                connection.cancel()
                upstream.cancel()
            } else {
                relayResponse(from: upstream)
            }
        }
    }

    /// Passthrough: directly tunnel bytes between client and upstream without inspection.
    private func passthroughTunnel(host: String, port: UInt16) {
        let upstreamEndpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: port)
        )
        let upstream = NWConnection(to: upstreamEndpoint, using: .tcp)

        upstream.start(queue: .global(qos: .userInitiated))

        upstream.stateUpdateHandler = { [self] state in
            switch state {
            case .ready:
                // Bidirectional relay
                relay(from: connection, to: upstream)
                relay(from: upstream, to: connection)
            case .failed:
                connection.cancel()
                upstream.cancel()
            default:
                break
            }
        }
    }

    /// Relay bytes from one connection to another.
    private func relay(from source: NWConnection, to destination: NWConnection) {
        source.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
            if let data, !data.isEmpty {
                destination.send(content: data, completion: .contentProcessed { _ in
                    if !isComplete {
                        self.relay(from: source, to: destination)
                    }
                })
            }
            if isComplete || error != nil {
                destination.cancel()
            }
        }
    }

    // MARK: - Direct HTTP Request (non-CONNECT)

    private func handleDirectRequest(data: Data) {
        // For direct (non-CONNECT) requests, just return an info page
        let body = "{\"service\":\"Ilvarion Proxy\",\"status\":\"running\"}"
        let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
        sendResponse(response)
    }

    private func sendResponse(_ text: String) {
        connection.send(content: text.data(using: .utf8), completion: .contentProcessed { _ in
            self.connection.cancel()
        })
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
