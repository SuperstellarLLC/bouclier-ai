import Foundation
import Network

/// HTTP forward proxy that receives plaintext requests on localhost,
/// scans JSON bodies for prompt injections, and forwards to upstream APIs via HTTPS.
///
/// Features:
/// - SSE streaming: forwards chunks in real-time, scanning each for injections
/// - Full body accumulation: reads until Content-Length is satisfied or connection closes
/// - Loopback-only binding
/// - SSRF protection on /custom routes
final class HTTPProxy: @unchecked Sendable {
    private let filter: InjectionFilter
    private let port: UInt16
    private var listener: NWListener?
    private let lock = NSLock()

    static let routeMap: [String: String] = [
        "openai": "https://api.openai.com",
        "anthropic": "https://api.anthropic.com",
        "cohere": "https://api.cohere.com",
        "mistral": "https://api.mistral.ai",
    ]

    private static let blockedHosts = [
        "localhost", "127.0.0.1", "::1", "0.0.0.0",
        "169.254.169.254", "metadata.google.internal",
    ]

    init(port: UInt16, filter: InjectionFilter) {
        self.port = port
        self.filter = filter
    }

    static func isPrivateHost(_ host: String) -> Bool {
        let lower = host.lowercased()
        if blockedHosts.contains(lower) { return true }
        if lower.hasSuffix(".local") || lower.hasSuffix(".internal") { return true }
        if lower.hasPrefix("10.") || lower.hasPrefix("192.168.") { return true }
        if lower.hasPrefix("172.") {
            let parts = lower.split(separator: ".")
            if parts.count >= 2, let second = Int(parts[1]), (16...31).contains(second) { return true }
        }
        return false
    }

    nonisolated func start(
        onReady: @Sendable @escaping () -> Void,
        onFailed: @Sendable @escaping (Error) -> Void,
        onRequest: @Sendable @escaping (RequestLog) -> Void
    ) {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        params.requiredLocalEndpoint = NWEndpoint.hostPort(host: .ipv4(.loopback), port: NWEndpoint.Port(integerLiteral: port))

        do {
            let listener = try NWListener(using: params, on: NWEndpoint.Port(integerLiteral: port))

            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: onReady()
                case .failed(let error): onFailed(error)
                default: break
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

    // Max request size: 16MB (covers large context windows)
    static let maxRequestSize = 16 * 1024 * 1024

    init(connection: NWConnection, filter: InjectionFilter, onLog: @Sendable @escaping (RequestLog) -> Void) {
        self.connection = connection
        self.filter = filter
        self.onLog = onLog
    }

    func start() {
        connection.start(queue: .global(qos: .userInitiated))
        accumulateRequest()
    }

    /// Read data in a loop until we have the full HTTP request (headers + body per Content-Length).
    private func accumulateRequest() {
        var buffer = Data()

        func readMore() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { [self] data, _, isComplete, error in
                if let data, !data.isEmpty {
                    buffer.append(data)
                }

                // Safety limit
                if buffer.count > Self.maxRequestSize {
                    sendError(status: 413, message: "Request too large")
                    return
                }

                // Check if we have complete headers
                let separator: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
                guard let sepRange = buffer.range(of: Data(separator)) else {
                    if isComplete || error != nil {
                        // Connection closed before headers arrived
                        connection.cancel()
                        return
                    }
                    readMore()
                    return
                }

                // Parse headers to find Content-Length
                let headerData = buffer[buffer.startIndex..<sepRange.lowerBound]
                guard let headerString = String(data: headerData, encoding: .utf8) else {
                    sendError(status: 400, message: "Bad Request")
                    return
                }

                let bodyStart = sepRange.upperBound
                let currentBody = buffer[bodyStart...]

                // Determine expected body size
                let contentLength = parseContentLength(from: headerString)

                if let expected = contentLength {
                    if currentBody.count >= expected {
                        // Full request received
                        let fullBody = Data(currentBody.prefix(expected))
                        processFullRequest(headerString: headerString, body: fullBody)
                    } else if isComplete || error != nil {
                        // Connection closed early — process what we have
                        processFullRequest(headerString: headerString, body: Data(currentBody))
                    } else {
                        readMore()
                    }
                } else {
                    // No Content-Length — process with whatever body we have (or none)
                    if isComplete || error != nil || currentBody.isEmpty {
                        processFullRequest(headerString: headerString, body: currentBody.isEmpty ? nil : Data(currentBody))
                    } else {
                        readMore()
                    }
                }
            }
        }

        readMore()
    }

    private func parseContentLength(from headers: String) -> Int? {
        for line in headers.components(separatedBy: "\r\n") {
            let parts = line.split(separator: ":", maxSplits: 1)
            if parts.count == 2, parts[0].trimmingCharacters(in: .whitespaces).lowercased() == "content-length" {
                return Int(parts[1].trimmingCharacters(in: .whitespaces))
            }
        }
        return nil
    }

    private func processFullRequest(headerString: String, body: Data?) {
        guard let request = HTTPRequest.parse(headerString: headerString, body: body) else {
            sendError(status: 400, message: "Bad Request")
            return
        }
        handleRequest(request)
    }

    private func handleRequest(_ request: HTTPRequest) {
        guard let upstream = resolveUpstream(path: request.path) else {
            sendError(status: 404, message: "Unknown route. Use /openai/, /anthropic/, etc.")
            return
        }

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

        // Check if this is a streaming request
        let isStreaming = isStreamingRequest(body: sanitizedBody)

        if isStreaming {
            forwardStreaming(request: request, upstream: upstream, body: sanitizedBody)
        } else {
            forwardBuffered(request: request, upstream: upstream, body: sanitizedBody)
        }
    }

    /// Detect if the request asks for streaming (OpenAI/Anthropic `"stream": true`)
    private func isStreamingRequest(body: Data?) -> Bool {
        guard let body, let str = String(data: body, encoding: .utf8) else { return false }
        // Quick check without full JSON parse
        return str.contains("\"stream\"") && str.contains("true")
    }

    // MARK: - Streaming (SSE) Forward

    private func forwardStreaming(request: HTTPRequest, upstream: URL, body: Data?) {
        var urlRequest = URLRequest(url: upstream)
        urlRequest.httpMethod = request.method
        urlRequest.httpBody = body
        applyHeaders(from: request, to: &urlRequest, upstream: upstream, body: body)

        let delegate = StreamingDelegate(connection: connection, filter: filter)
        let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
        let task = session.dataTask(with: urlRequest)
        task.resume()
    }

    // MARK: - Buffered Forward

    private func forwardBuffered(request: HTTPRequest, upstream: URL, body: Data?) {
        var urlRequest = URLRequest(url: upstream)
        urlRequest.httpMethod = request.method
        urlRequest.httpBody = body
        applyHeaders(from: request, to: &urlRequest, upstream: upstream, body: body)

        let task = URLSession.shared.dataTask(with: urlRequest) { [self] data, response, error in
            if let error {
                sendError(status: 502, message: "Upstream error: \(error.localizedDescription)")
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                sendError(status: 502, message: "Invalid upstream response")
                return
            }

            var responseLines = ["HTTP/1.1 \(httpResponse.statusCode) \(HTTPURLResponse.localizedString(forStatusCode: httpResponse.statusCode))"]

            for (key, value) in httpResponse.allHeaderFields {
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

    private func applyHeaders(from request: HTTPRequest, to urlRequest: inout URLRequest, upstream: URL, body: Data?) {
        for (key, value) in request.headers where key.lowercased() != "host" {
            urlRequest.setValue(value, forHTTPHeaderField: key)
        }
        urlRequest.setValue(upstream.host, forHTTPHeaderField: "Host")
        if let body {
            urlRequest.setValue("\(body.count)", forHTTPHeaderField: "Content-Length")
        }
    }

    private func resolveUpstream(path: String) -> URL? {
        let components = path.split(separator: "/", maxSplits: 2)
        guard let provider = components.first else { return nil }

        let providerKey = String(provider).lowercased()
        let remainingPath = components.count > 1 ? "/" + components.dropFirst().joined(separator: "/") : ""

        if let baseURL = HTTPProxy.routeMap[providerKey] {
            return URL(string: baseURL + remainingPath)
        }

        if providerKey == "custom", components.count > 1 {
            let host = String(components[1])
            guard !HTTPProxy.isPrivateHost(host) else { return nil }
            let rest = components.count > 2 ? "/" + String(components[2]) : ""
            return URL(string: "https://\(host)\(rest)")
        }

        return nil
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

// MARK: - SSE Streaming Delegate

/// URLSession delegate that streams response data chunk-by-chunk to the client connection.
/// Scans each SSE data line for injections before forwarding.
private final class StreamingDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    let connection: NWConnection
    let filter: InjectionFilter
    private var headersSent = false
    private var sseBuffer = ""

    init(connection: NWConnection, filter: InjectionFilter) {
        self.connection = connection
        self.filter = filter
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse, completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        guard let httpResponse = response as? HTTPURLResponse else {
            completionHandler(.cancel)
            connection.cancel()
            return
        }

        // Send HTTP response headers to the client
        var lines = ["HTTP/1.1 \(httpResponse.statusCode) \(HTTPURLResponse.localizedString(forStatusCode: httpResponse.statusCode))"]

        for (key, value) in httpResponse.allHeaderFields {
            lines.append("\(key): \(value)")
        }
        lines.append("")
        lines.append("")

        let headerData = lines.joined(separator: "\r\n").data(using: .utf8) ?? Data()
        connection.send(content: headerData, completion: .contentProcessed { _ in })
        headersSent = true

        completionHandler(.allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        guard let chunk = String(data: data, encoding: .utf8) else {
            // Binary chunk — forward as-is
            connection.send(content: data, completion: .contentProcessed { _ in })
            return
        }

        // SSE format: "data: {...}\n\n"
        // Accumulate partial lines and process complete ones
        sseBuffer += chunk

        while let newlineRange = sseBuffer.range(of: "\n") {
            let line = String(sseBuffer[sseBuffer.startIndex..<newlineRange.lowerBound])
            sseBuffer = String(sseBuffer[newlineRange.upperBound...])

            let processedLine = scanSSELine(line)
            let lineData = (processedLine + "\n").data(using: .utf8) ?? Data()
            connection.send(content: lineData, completion: .contentProcessed { _ in })
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        // Flush any remaining buffer
        if !sseBuffer.isEmpty {
            let lineData = sseBuffer.data(using: .utf8) ?? Data()
            connection.send(content: lineData, completion: .contentProcessed { _ in
                self.connection.cancel()
            })
            sseBuffer = ""
        } else {
            connection.cancel()
        }
        session.invalidateAndCancel()
    }

    /// Scan an SSE data line for injections. Only scans the JSON content payload.
    private func scanSSELine(_ line: String) -> String {
        guard line.hasPrefix("data: ") else { return line }

        let jsonPart = String(line.dropFirst(6))
        if jsonPart == "[DONE]" { return line }

        // Scan the content field within the SSE JSON
        let result = filter.scan(jsonPart)
        if result.detected {
            return "data: " + result.sanitized
        }
        return line
    }
}

// MARK: - HTTP Request Parser

struct HTTPRequest: Sendable {
    let method: String
    let path: String
    let headers: [(String, String)]
    let body: Data?

    /// Parse from already-split header string and body data.
    static func parse(headerString: String, body: Data?) -> HTTPRequest? {
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

        return HTTPRequest(method: method, path: path, headers: headers, body: body)
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
