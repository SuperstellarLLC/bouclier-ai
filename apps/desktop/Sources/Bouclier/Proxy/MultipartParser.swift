import Foundation

/// Minimal RFC 7578 / RFC 2046 multipart parser sufficient for the
/// LLM-provider file-upload endpoints we proxy (OpenAI's
/// `/v1/files`, Anthropic's `/v1/files` once GA, etc.).
///
/// Design scope intentionally narrow:
///
/// * Handles the standard `multipart/form-data; boundary=...` Content-Type.
/// * Parses arbitrary number of parts; each part has its own headers
///   (most importantly Content-Disposition + Content-Type) and a body
///   slice into the original buffer.
/// * Body slices are stored as offsets so the rewriter can mutate
///   one part in place without re-serialising the whole multipart
///   on the common no-findings path.
/// * Tolerates LF-only line endings (most clients are well-behaved
///   and send CRLF, but `curl --data-binary @file` is famously LF).
///
/// Explicitly NOT in scope:
/// * Nested `multipart/mixed` parts (not used by file-upload APIs).
/// * Content-Transfer-Encoding: base64 / quoted-printable on parts —
///   modern HTTP clients send bytes as-is.
/// * Streaming / chunked parsing — the proxy buffers up to the 64 MB
///   request cap. Bodies past that cap are rejected at the proxy
///   rather than streamed through partially-inspected.
enum MultipartParser {
    /// One parsed part. Slices reference the source `Data` so the
    /// rewriter can rebuild a body without re-copying clean parts.
    struct Part: Sendable {
        let headers: [String: String]
        /// Offset into the source body where this part's body starts.
        let bodyStart: Int
        /// Length of the part's body in bytes (exclusive of the
        /// trailing CRLF and boundary).
        let bodyLength: Int

        /// Convenience: extract `name="..."` from Content-Disposition.
        var name: String? {
            headers.value(for: "Content-Disposition")
                .flatMap { Self.parameter("name", in: $0) }
        }

        /// Convenience: extract `filename="..."` if present.
        var filename: String? {
            headers.value(for: "Content-Disposition")
                .flatMap { Self.parameter("filename", in: $0) }
        }

        var contentType: String {
            // multipart parts default to text/plain per RFC 2046 §5.1.1
            // when no Content-Type header is present.
            headers.value(for: "Content-Type") ?? "text/plain"
        }

        /// Slice the part's body bytes out of the source buffer.
        func bodyData(in source: Data) -> Data {
            guard bodyStart >= 0, bodyStart + bodyLength <= source.count else {
                return Data()
            }
            return source.subdata(in: bodyStart..<(bodyStart + bodyLength))
        }

        private static func parameter(_ name: String, in header: String) -> String? {
            // Matches `name="value"` and `name=value` (bare). We don't
            // unescape RFC 5987 percent-encoded values — providers
            // don't emit them in file-upload Content-Disposition.
            let pattern = #"\#(name)=(?:"([^"]*)"|([^;\s]+))"#
            guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
                return nil
            }
            let range = NSRange(header.startIndex..., in: header)
            guard let m = regex.firstMatch(in: header, range: range) else { return nil }
            if let r = Range(m.range(at: 1), in: header) { return String(header[r]) }
            if let r = Range(m.range(at: 2), in: header) { return String(header[r]) }
            return nil
        }
    }

    /// Parse a multipart body. `contentType` is the request's full
    /// Content-Type header value (the parser fishes out the boundary
    /// from it). Returns nil if the body isn't multipart or the
    /// boundary is missing.
    static func parse(body: Data, contentType: String) -> [Part]? {
        guard let boundary = boundary(from: contentType) else { return nil }
        return parse(body: body, boundary: boundary)
    }

    static func boundary(from contentType: String) -> String? {
        // Content-Type: multipart/form-data; boundary=----abc
        let lower = contentType.lowercased()
        guard lower.contains("multipart/") else { return nil }
        let pattern = #"boundary=(?:"([^"]+)"|([^;\s]+))"#
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else {
            return nil
        }
        let range = NSRange(contentType.startIndex..., in: contentType)
        guard let m = regex.firstMatch(in: contentType, range: range) else { return nil }
        if let r = Range(m.range(at: 1), in: contentType) { return String(contentType[r]) }
        if let r = Range(m.range(at: 2), in: contentType) { return String(contentType[r]) }
        return nil
    }

    private static func parse(body: Data, boundary: String) -> [Part]? {
        // The boundary on the wire is "--" + the declared value.
        let delim = Data("--\(boundary)".utf8)
        guard !delim.isEmpty, body.count >= delim.count else { return nil }

        // Find every occurrence of the delimiter. RFC 7578 says a
        // boundary is only valid at start-of-body OR preceded by CRLF
        // / LF. Without that anchor, raw bytes matching the boundary
        // inside a file body (PNG IDAT chunks, PDF streams, etc.)
        // would be treated as part delimiters and cleave legitimate
        // file payloads at the first match — a P1 bug that combined
        // with an attacker-chosen short boundary becomes a DoS.
        // Anchoring collapses the occurrence set to legitimate
        // delimiters only.
        var occurrences: [Int] = []
        var searchFrom = 0
        while let r = body.range(of: delim, options: [], in: searchFrom..<body.count) {
            let pos = r.lowerBound
            let preceded = pos == 0
                || (pos >= 1 && body[pos - 1] == 0x0A)
                || (pos >= 2 && body[pos - 2] == 0x0D && body[pos - 1] == 0x0A)
            if preceded {
                occurrences.append(pos)
            }
            searchFrom = r.upperBound
        }
        guard occurrences.count >= 2 else { return nil }

        var parts: [Part] = []
        for i in 0..<(occurrences.count - 1) {
            let start = occurrences[i]
            let end = occurrences[i + 1]
            // Skip the delimiter line ("--boundary\r\n" or
            // "--boundary--\r\n"). Body starts after the first blank
            // line following the headers.
            let afterDelim = start + delim.count
            // Step past the trailing CRLF / "--" of the boundary line.
            let lineEnd = scanLineEnd(body, from: afterDelim, limit: end) ?? afterDelim
            let headersStart = lineEnd
            // Headers end at the first blank line (CRLFCRLF or LFLF).
            guard let headerEnd = scanHeaderEnd(body, from: headersStart, limit: end) else {
                continue
            }
            let headers = parseHeaderBlock(body, from: headersStart, to: headerEnd.headersEnd)
            let bodyStart = headerEnd.bodyStart
            // Strip the trailing CRLF that precedes the next boundary.
            var bodyEnd = end
            if bodyEnd >= 2,
               body[bodyEnd - 2] == 0x0D, body[bodyEnd - 1] == 0x0A {
                bodyEnd -= 2
            } else if bodyEnd >= 1, body[bodyEnd - 1] == 0x0A {
                bodyEnd -= 1
            }
            parts.append(Part(
                headers: headers,
                bodyStart: bodyStart,
                bodyLength: max(0, bodyEnd - bodyStart)
            ))
        }
        return parts
    }

    /// Find the end of a line starting at `from` (returns the byte
    /// index just past the CRLF / LF). Returns nil when no line end
    /// is found before `limit`.
    private static func scanLineEnd(_ body: Data, from: Int, limit: Int) -> Int? {
        var i = from
        while i < limit {
            if body[i] == 0x0A { return i + 1 }
            if body[i] == 0x0D, i + 1 < limit, body[i + 1] == 0x0A { return i + 2 }
            i += 1
        }
        return nil
    }

    /// Find the blank line separating headers from body. Returns
    /// (headersEnd, bodyStart) — the line break is consumed.
    private static func scanHeaderEnd(_ body: Data, from: Int, limit: Int) -> (headersEnd: Int, bodyStart: Int)? {
        var i = from
        while i < limit {
            // Look for CRLF CRLF
            if i + 3 < limit,
               body[i] == 0x0D, body[i + 1] == 0x0A,
               body[i + 2] == 0x0D, body[i + 3] == 0x0A {
                return (i, i + 4)
            }
            // Or LF LF (LF-only clients)
            if i + 1 < limit, body[i] == 0x0A, body[i + 1] == 0x0A {
                return (i, i + 2)
            }
            i += 1
        }
        return nil
    }

    private static func parseHeaderBlock(_ body: Data, from: Int, to: Int) -> [String: String] {
        guard from < to else { return [:] }
        let slice = body.subdata(in: from..<to)
        // Split on raw bytes, not Swift's grapheme-cluster-aware
        // String.split. Swift combines `\r\n` into a single Character
        // so the predicate `== "\r" || == "\n"` never matches a CRLF
        // sequence — leaving the entire headers block as one "line"
        // and only the first colon's key in the result dict.
        let lines = slice
            .split(separator: 0x0A, omittingEmptySubsequences: true)
            .map { line -> Data in
                // Trim trailing \r if present (CRLF case).
                if line.last == 0x0D {
                    return line.dropLast()
                }
                return Data(line)
            }
        var out: [String: String] = [:]
        for line in lines {
            guard let text = String(data: line, encoding: .utf8),
                  let colon = text.firstIndex(of: ":") else { continue }
            let name = String(text[..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(text[text.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            if !name.isEmpty { out[name] = value }
        }
        return out
    }
}

private extension Dictionary where Key == String, Value == String {
    /// Case-insensitive lookup for HTTP-style headers.
    func value(for key: String) -> String? {
        if let direct = self[key] { return direct }
        let lower = key.lowercased()
        for (k, v) in self where k.lowercased() == lower {
            return v
        }
        return nil
    }
}
