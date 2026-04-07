import Foundation
import Network
@preconcurrency import NetworkExtension

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

    override func startProxy(options: [String: Any]?, completionHandler: @escaping @Sendable (Error?) -> Void) {
        NSLog("[bouclier.ai-ext] Proxy provider started")
        completionHandler(nil)
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping @Sendable () -> Void) {
        NSLog("[bouclier.ai-ext] Proxy provider stopped")
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcpFlow = flow as? NEAppProxyTCPFlow else { return false }

        let flowDesc = tcpFlow.description
        guard let host = extractHost(from: flowDesc),
              Self.interceptedDomains.contains(host.lowercased())
        else {
            return false
        }

        NSLog("[bouclier.ai-ext] Intercepting: \(host)")

        nonisolated(unsafe) let unsafeSelf = self
        tcpFlow.open(withLocalFlowEndpoint: nil) { error in
            if let error {
                NSLog("[bouclier.ai-ext] Open failed: \(error)")
                return
            }
            unsafeSelf.routeThroughProxy(flow: tcpFlow, host: host)
        }

        return true
    }

    // MARK: - Host extraction

    private func extractHost(from description: String) -> String? {
        // Match any of the known AI API domains directly in the description
        for domain in Self.interceptedDomains {
            if description.contains(domain) {
                return domain
            }
        }
        return nil
    }

    // MARK: - Route through proxy

    private func routeThroughProxy(flow: NEAppProxyTCPFlow, host: String) {
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(proxyHost),
            port: NWEndpoint.Port(integerLiteral: proxyPort)
        )
        let connection = NWConnection(to: endpoint, using: .tcp)

        nonisolated(unsafe) let unsafeSelf = self
        nonisolated(unsafe) let unsafeFlow = flow

        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                unsafeSelf.sendConnect(connection: connection, flow: unsafeFlow, host: host)
            case .failed(let error):
                NSLog("[bouclier.ai-ext] Proxy connection failed: \(error)")
                connection.cancel()
            default:
                break
            }
        }

        connection.start(queue: .global(qos: .userInitiated))
    }

    private func sendConnect(connection: NWConnection, flow: NEAppProxyTCPFlow, host: String) {
        let request = "CONNECT \(host):443 HTTP/1.1\r\nHost: \(host):443\r\n\r\n"
        guard let data = request.data(using: .utf8) else { return }

        nonisolated(unsafe) let unsafeSelf = self
        nonisolated(unsafe) let unsafeFlow = flow

        connection.send(content: data, completion: .contentProcessed { error in
            if error != nil { connection.cancel(); return }

            connection.receive(minimumIncompleteLength: 12, maximumLength: 4096) { data, _, _, _ in
                guard let data, let resp = String(data: data, encoding: .utf8),
                      resp.hasPrefix("HTTP/1.1 200") || resp.hasPrefix("HTTP/1.0 200")
                else {
                    NSLog("[bouclier.ai-ext] CONNECT rejected for \(host)")
                    connection.cancel()
                    return
                }

                unsafeSelf.relay(flow: unsafeFlow, connection: connection)
            }
        })
    }

    // MARK: - Relay

    private func relay(flow: NEAppProxyTCPFlow, connection: NWConnection) {
        relayFlowToConnection(flow: flow, connection: connection)
        relayConnectionToFlow(connection: connection, flow: flow)
    }

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
}
