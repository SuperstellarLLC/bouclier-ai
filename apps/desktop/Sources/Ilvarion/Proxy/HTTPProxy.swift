import Foundation
import Network

/// HTTP forward proxy that receives plaintext requests on localhost,
/// scans JSON bodies for prompt injections, and forwards to upstream APIs via HTTPS.
///
/// Supported routing:
/// - /openai/*  → https://api.openai.com/*
/// - /anthropic/* → https://api.anthropic.com/*
/// - /custom/{host}/* → https://{host}/*
///
/// Clients configure their SDK base URL to http://localhost:{port}/{provider}
final class HTTPProxy: @unchecked Sendable {
    private let filter: InjectionFilter
    private let port: UInt16
    private var listener: NWListener?
    private let lock = NSLock()

    /// Upstream API mappings
    static let routeMap: [String: String] = [
        "openai": "https://api.openai.com",
        "anthropic": "https://api.anthropic.com",
        "cohere": "https://api.cohere.com",
        "mistral": "https://api.mistral.ai",
    ]

    init(port: UInt16, filter: InjectionFilter) {
        self.port = port
        self.filter = filter
    }

    nonisolated func start(
        onReady: @Sendable @escaping () -> Void,
        onFailed: @Sendable @escaping (Error) -> Void,
        onRequest: @Sendable @escaping (RequestLog) -> Void
    ) {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true

        do {
            let listener = try NWListener(using: params, on: NWEndpoint.Port(integerLiteral: port))

            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    onReady()
                case .failed(let error):
                    onFailed(error)
                default:
                    break
                }
            }

            listener.newConnectionHandler = { [filter] connection in
                let handler = ConnectionHandler(connection: connection, filter: filter, onLog: onRequest)
                handler.start()
            }

            listener.start(queue: .global(qos: .userInitiated))
            lock.lock()
            self.listener = listener
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

// MARK: - Connection Handler

private final class ConnectionHandler: Sendable {
    let connection: NWConnection
    let filter: InjectionFilter
    let onLog: @Sendable (RequestLog) -> Void

    init(connection: NWConnection, filter: InjectionFilter, onLog: @Sendable @escaping (RequestLog) -> Void) {
        self.connection = connection
        self.filter = filter
        self.onLog = onLog
    }

    func start() {
        connection.start(queue: .global(qos: .userInitiated))
        receiveHTTPRequest()
    }

    private func receiveHTTPRequest() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 1_048_576) { [self] data, _, isComplete, error in
            guard let data, !data.isEmpty else {
                connection.cancel()
                return
            }

            guard let request = HTTPRequest.parse(data) else {
                sendError(status: 400, message: "Bad Request")
                return
            }

            handleRequest(request)
        }
    }

    private func handleRequest(_ request: HTTPRequest) {
        // Resolve upstream URL
        guard let upstream = resolveUpstream(path: request.path) else {
            sendError(status: 404, message: "Unknown route. Use /openai/, /anthropic/, etc.")
            return
        }

        // Scan the request body for injections
        var scanResult: FilterResult?
        var sanitizedBody = request.body

        if let body = request.body, !body.isEmpty {
            let bodyString = String(data: body, encoding: .utf8) ?? ""
            let result = filter.scan(bodyString)
            scanResult = result

            if result.detected {
                sanitizedBody = result.sanitized.data(using: .utf8)
            }
        }

        // Log
        onLog(RequestLog(
            timestamp: Date(),
            method: request.method,
            path: request.path,
            targetHost: upstream.host ?? "unknown",
            detected: scanResult?.detected ?? false,
            matchCount: scanResult?.matchCount ?? 0,
            patternNames: scanResult?.patternNames ?? [],
            bodySize: request.body?.count ?? 0
        ))

        // Forward to upstream
        forwardRequest(request: request, upstream: upstream, body: sanitizedBody)
    }

    private func resolveUpstream(path: String) -> URL? {
        let components = path.split(separator: "/", maxSplits: 2)
        guard let provider = components.first else { return nil }

        let providerKey = String(provider).lowercased()
        let remainingPath = components.count > 1 ? "/" + components.dropFirst().joined(separator: "/") : ""

        if let baseURL = HTTPProxy.routeMap[providerKey] {
            return URL(string: baseURL + remainingPath)
        }

        // Custom host: /custom/api.example.com/v1/chat
        if providerKey == "custom", components.count > 1 {
            let host = String(components[1])
            let rest = components.count > 2 ? "/" + String(components[2]) : ""
            return URL(string: "https://\(host)\(rest)")
        }

        return nil
    }

    private func forwardRequest(request: HTTPRequest, upstream: URL, body: Data?) {
        var urlRequest = URLRequest(url: upstream)
        urlRequest.httpMethod = request.method
        urlRequest.httpBody = body

        // Forward headers (except Host, which we override)
        for (key, value) in request.headers where key.lowercased() != "host" {
            urlRequest.setValue(value, forHTTPHeaderField: key)
        }
        urlRequest.setValue(upstream.host, forHTTPHeaderField: "Host")

        // Update content-length if body was modified
        if let body {
            urlRequest.setValue("\(body.count)", forHTTPHeaderField: "Content-Length")
        }

        let task = URLSession.shared.dataTask(with: urlRequest) { [self] data, response, error in
            if let error {
                sendError(status: 502, message: "Upstream error: \(error.localizedDescription)")
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                sendError(status: 502, message: "Invalid upstream response")
                return
            }

            // Build HTTP response to send back to client
            var responseLines = ["HTTP/1.1 \(httpResponse.statusCode) \(HTTPURLResponse.localizedString(forStatusCode: httpResponse.statusCode))"]

            for (key, value) in httpResponse.allHeaderFields {
                // Skip transfer-encoding as we send the full body
                let keyStr = "\(key)"
                if keyStr.lowercased() == "transfer-encoding" { continue }
                responseLines.append("\(key): \(value)")
            }

            let responseBody = data ?? Data()
            responseLines.append("Content-Length: \(responseBody.count)")
            responseLines.append("")
            responseLines.append("")

            let headerData = responseLines.joined(separator: "\r\n").data(using: .utf8) ?? Data()
            let fullResponse = headerData + responseBody

            connection.send(content: fullResponse, completion: .contentProcessed { _ in
                self.connection.cancel()
            })
        }

        task.resume()
    }

    private func sendError(status: Int, message: String) {
        let jsonBody: Data
        if let encoded = try? JSONSerialization.data(withJSONObject: ["error": message]) {
            jsonBody = encoded
        } else {
            jsonBody = "{\"error\":\"Internal error\"}".data(using: .utf8)!
        }
        let header = [
            "HTTP/1.1 \(status) \(HTTPURLResponse.localizedString(forStatusCode: status))",
            "Content-Type: application/json",
            "Content-Length: \(jsonBody.count)",
            "Connection: close",
            "",
            "",
        ].joined(separator: "\r\n")

        let response = (header.data(using: .utf8) ?? Data()) + jsonBody
        connection.send(content: response, completion: .contentProcessed { _ in
            self.connection.cancel()
        })
    }
}

// MARK: - HTTP Request Parser

struct HTTPRequest: Sendable {
    let method: String
    let path: String
    let headers: [(String, String)]
    let body: Data?

    static func parse(_ data: Data) -> HTTPRequest? {
        // Find header/body boundary (\r\n\r\n) as byte offset to avoid corrupting binary body data
        let separator: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
        guard let separatorRange = data.range(of: Data(separator)) else {
            // No body — try to parse headers only
            guard let raw = String(data: data, encoding: .utf8) else { return nil }
            return parseHeadersOnly(raw, fullData: data, bodyStart: nil)
        }

        let headerData = data[data.startIndex..<separatorRange.lowerBound]
        guard let headerString = String(data: headerData, encoding: .utf8) else { return nil }

        let bodyStart = separatorRange.upperBound
        let body = bodyStart < data.endIndex ? data[bodyStart...] : nil

        return parseHeadersOnly(headerString, fullData: data, bodyStart: body.map { Data($0) })
    }

    private static func parseHeadersOnly(_ headerString: String, fullData: Data, bodyStart: Data?) -> HTTPRequest? {
        let lines = headerString.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else { return nil }

        let requestParts = requestLine.split(separator: " ", maxSplits: 2)
        guard requestParts.count >= 2 else { return nil }

        let method = String(requestParts[0])
        let path = String(requestParts[1])

        var headers: [(String, String)] = []
        for line in lines.dropFirst() {
            if let colonIndex = line.firstIndex(of: ":") {
                let key = String(line[line.startIndex..<colonIndex]).trimmingCharacters(in: .whitespaces)
                let value = String(line[line.index(after: colonIndex)...]).trimmingCharacters(in: .whitespaces)
                headers.append((key, value))
            }
        }

        return HTTPRequest(method: method, path: path, headers: headers, body: bodyStart)
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
