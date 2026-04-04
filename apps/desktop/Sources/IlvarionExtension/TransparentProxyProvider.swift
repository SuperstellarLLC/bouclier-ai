import Foundation
import Network
import NetworkExtension

/// System Extension: intercepts AI API domain TCP flows at the OS level
/// and routes them through the local NIO TLS proxy via CONNECT tunneling.
final class TransparentProxyProvider: NETransparentProxyProvider {

    private let proxyHost = "127.0.0.1"
    private let proxyPort: UInt16 = 8484

    private nonisolated static let interceptedDomains: Set<String> = [
        "api.openai.com",
        "api.anthropic.com",
        "api.cohere.com",
        "api.mistral.ai",
        "generativelanguage.googleapis.com",
        "api.together.xyz",
        "api.groq.com",
        "api.perplexity.ai",
        "api.fireworks.ai",
        "openrouter.ai",
    ]

    // MARK: - Lifecycle

    override func startProxy(options: [String: Any]?, completionHandler: @escaping @Sendable (Error?) -> Void) {
        NSLog("[ilvarion-ext] Proxy provider started")
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping @Sendable () -> Void) {
        NSLog("[ilvarion-ext] Proxy provider stopped")
        completionHandler()
    }

    // MARK: - Flow Handling

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcpFlow = flow as? NEAppProxyTCPFlow else { return false }

        // Get remote host from the flow's description or metadata
        let hostAndPort = extractHostPort(from: tcpFlow)
        guard let host = hostAndPort.host, let port = hostAndPort.port else {
            return false
        }

        guard (port == 443 || port == 8443), Self.shouldIntercept(host: host) else {
            return false
        }

        NSLog("[ilvarion-ext] Intercepting: \(host):\(port)")

        nonisolated(unsafe) let unsafeSelf = self
        tcpFlow.open(withLocalFlowEndpoint: nil) { error in
            if let error {
                NSLog("[ilvarion-ext] Open failed: \(error)")
                return
            }
            unsafeSelf.routeThroughProxy(flow: tcpFlow, host: host, port: port)
        }

        return true
    }

    // MARK: - Extract host info

    private func extractHostPort(from flow: NEAppProxyTCPFlow) -> (host: String?, port: Int?) {
        // The flow description typically contains the remote endpoint
        // NEAppProxyTCPFlow provides remoteEndpoint via its metaData
        let desc = flow.description
        // Parse from description or use metadata
        // Format varies but typically includes host:port info
        let _metadata = flow.metaData // Available but not Optional on newer SDKs

        // Fallback: parse from description string
        // NEAppProxyTCPFlow descriptions often contain "remote=host:port"
        return parseHostPort(from: desc)
    }

    private func parseHostPort(from description: String) -> (host: String?, port: Int?) {
        // Look for patterns like "host:port" or "remote endpoint: host port"
        let patterns = [
            try? NSRegularExpression(pattern: "remote[^:]*[:=]\\s*([\\w.\\-]+):(\\d+)"),
            try? NSRegularExpression(pattern: "([a-zA-Z][\\w.\\-]+\\.(?:com|ai|xyz|io)):(\\d+)"),
        ].compactMap { $0 }

        for regex in patterns {
            let range = NSRange(description.startIndex..., in: description)
            if let match = regex.firstMatch(in: description, range: range) {
                let hostRange = Range(match.range(at: 1), in: description)!
                let portRange = Range(match.range(at: 2), in: description)!
                return (String(description[hostRange]), Int(description[portRange]))
            }
        }
        return (nil, nil)
    }

    // MARK: - Route through local proxy

    private func routeThroughProxy(flow: NEAppProxyTCPFlow, host: String, port: Int) {
        nonisolated(unsafe) let unsafeSelf = self
        nonisolated(unsafe) let unsafeFlow = flow

        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(proxyHost),
            port: NWEndpoint.Port(integerLiteral: proxyPort)
        )
        let connection = NWConnection(to: endpoint, using: .tcp)

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                unsafeSelf.sendConnect(connection: connection, flow: unsafeFlow, host: host, port: port)
            case .failed(let error):
                NSLog("[ilvarion-ext] Proxy connection failed: \(error)")
                connection.cancel()
            default:
                break
            }
        }

        connection.start(queue: .global(qos: .userInitiated))
    }

    private func sendConnect(connection: NWConnection, flow: NEAppProxyTCPFlow, host: String, port: Int) {
        nonisolated(unsafe) let unsafeSelf = self
        nonisolated(unsafe) let unsafeFlow = flow

        let request = "CONNECT \(host):\(port) HTTP/1.1\r\nHost: \(host):\(port)\r\n\r\n"
        guard let data = request.data(using: .utf8) else { return }

        connection.send(content: data, completion: .contentProcessed { error in
            if error != nil { connection.cancel(); return }

            connection.receive(minimumIncompleteLength: 12, maximumLength: 4096) { data, _, _, _ in
                guard let data, let resp = String(data: data, encoding: .utf8), resp.contains("200") else {
                    NSLog("[ilvarion-ext] CONNECT rejected for \(host)")
                    connection.cancel()
                    return
                }

                NSLog("[ilvarion-ext] Tunnel: \(host)")
                unsafeSelf.relayFlowToConnection(flow: unsafeFlow, connection: connection)
                unsafeSelf.relayConnectionToFlow(connection: connection, flow: unsafeFlow)
            }
        })
    }

    // MARK: - Relay

    private func relayFlowToConnection(flow: NEAppProxyTCPFlow, connection: NWConnection) {
        nonisolated(unsafe) let unsafeSelf = self
        nonisolated(unsafe) let unsafeFlow = flow
        flow.readData { data, _ in
            guard let data, !data.isEmpty else {
                connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
                return
            }
            connection.send(content: data, completion: .contentProcessed { error in
                if error == nil { unsafeSelf.relayFlowToConnection(flow: unsafeFlow, connection: connection) }
            })
        }
    }

    private func relayConnectionToFlow(connection: NWConnection, flow: NEAppProxyTCPFlow) {
        nonisolated(unsafe) let unsafeSelf = self
        nonisolated(unsafe) let unsafeFlow = flow
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, _ in
            guard let data, !data.isEmpty else {
                unsafeFlow.closeReadWithError(nil)
                connection.cancel()
                return
            }
            unsafeFlow.write(data) { error in
                if error == nil && !isComplete {
                    unsafeSelf.relayConnectionToFlow(connection: connection, flow: unsafeFlow)
                } else {
                    unsafeFlow.closeReadWithError(nil)
                    connection.cancel()
                }
            }
        }
    }

    // MARK: - Domain check

    private nonisolated static func shouldIntercept(host: String) -> Bool {
        interceptedDomains.contains(host.lowercased())
    }
}
