import Foundation

/// Walks an LLM API response and replaces minted PII placeholders
/// with the cleartext stored in the per-connection `PIISession`.
///
/// This pass handles non-streaming JSON responses. JSON-mode and
/// tool-call argument streaming reversal is handled by
/// `PIIStreamReverser` once boundary-safe streaming is wired into the
/// `SSEStreamInspector`. For any token the session doesn't recognise
/// (user-typed lookalikes, model-invented strings) the reverser is a
/// no-op — the HMAC-keyed token format makes forgery infeasible, so
/// pass-through is safe.
enum PIIReverser {
    /// Match the canonical token shape minted by `PIISession`.
    /// Mirrors `PIISession.tokenPattern`.
    private static let tokenRegex: NSRegularExpression = {
        // Pattern must match the documented shape. Fail fast if the
        // session source ever drifts from this regex.
        return try! NSRegularExpression(pattern: PIISession.tokenPattern)
    }()

    /// Reverse all minted placeholders in a raw JSON-shaped response.
    ///
    /// Strategy: parse the JSON, walk the tree, and substitute placeholders
    /// **inside string leaves only**. This avoids: (a) breaking JSON
    /// structure if a token's reversal contains a `"` or `}` character,
    /// (b) accidentally reversing a placeholder embedded in a numeric key,
    /// (c) corrupting JSON-mode constrained-decoded responses.
    ///
    /// If the body is not valid JSON we fall back to a flat string
    /// substitution — Anthropic and OpenAI both occasionally emit
    /// non-JSON envelopes (errors, plain-text endpoints) and we still
    /// want reversal there.
    static func reverseJSON(_ body: Data, with session: PIISession) async -> Data {
        if let obj = try? JSONSerialization.jsonObject(with: body, options: [.fragmentsAllowed]) {
            let reversed = await reverse(obj, with: session)
            if let out = try? JSONSerialization.data(withJSONObject: reversed, options: [.fragmentsAllowed]) {
                return out
            }
        }
        guard let text = String(data: body, encoding: .utf8) else { return body }
        let reversed = await reverseString(text, with: session)
        return Data(reversed.utf8)
    }

    /// Reverse placeholders in a single string. Exposed so the SSE
    /// inspector can call it on streamed content once boundary-safe
    /// streaming is wired up.
    static func reverseString(_ input: String, with session: PIISession) async -> String {
        let nsInput = input as NSString
        let range = NSRange(location: 0, length: nsInput.length)
        let matches = tokenRegex.matches(in: input, range: range)
        guard !matches.isEmpty else { return input }

        let out = NSMutableString(string: input)
        for match in matches.reversed() {
            let token = nsInput.substring(with: match.range)
            if let cleartext = await session.cleartext(for: token) {
                out.replaceCharacters(in: match.range, with: cleartext)
            }
            // Unknown tokens (user-typed lookalikes, foreign sessions)
            // pass through unchanged — this is the R6-part-2 safety
            // property of HMAC-keyed tokens.
        }
        return out as String
    }

    // MARK: - JSON tree walk

    private static func reverse(_ value: Any, with session: PIISession) async -> Any {
        if let s = value as? String {
            return await reverseString(s, with: session)
        }
        if let arr = value as? [Any] {
            var out: [Any] = []
            out.reserveCapacity(arr.count)
            for item in arr {
                out.append(await reverse(item, with: session))
            }
            return out
        }
        if let dict = value as? [String: Any] {
            var out: [String: Any] = [:]
            out.reserveCapacity(dict.count)
            for (key, val) in dict {
                // Keys are identifiers in API responses (e.g. "content",
                // "role"). Don't reverse them — only leaf string values.
                out[key] = await reverse(val, with: session)
            }
            return out
        }
        return value
    }
}
