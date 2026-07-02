import Foundation

/// Pure, NIO-free outbound secret **scrub** — the inverse of
/// `SecretInjectionPass` (dormant; see that type's doc comment).
///
/// Injection swaps a *placeholder* for a real value heading to a bound
/// third-party host. Scrub swaps a managed *real value* for its
/// placeholder heading to the **model provider**, so the secret never
/// reaches Anthropic/OpenAI. The matching `SecretRestore` reverses it in
/// the response stream so the local agent's tool calls still see the
/// real value. See `docs/secret-injection.md`.
///
/// Threat-model note: the agent legitimately holds real secrets locally —
/// we blind only the model vendor, not the agent.
enum SecretRedactionPass {
    struct Outcome: Sendable, Equatable {
        let uri: String
        let headers: [SecretInjectionPass.Header]
        let body: Data
        /// Rule names whose real value was replaced by its placeholder.
        let scrubbed: [String]
        var changed: Bool { !scrubbed.isEmpty }
    }

    /// Independent, deliberately-simple "is there any managed secret
    /// material to scrub here?" gate — mirrors
    /// `SecretInjectionPass.hasTrigger`. The rewriter runs ONLY when this
    /// is true, so clean LLM traffic (the overwhelming majority) is never
    /// touched and a bug in `apply` can't corrupt it.
    static func hasTrigger(
        uri: String,
        headers: [SecretInjectionPass.Header],
        body: Data,
        rules: [SecretRule],
        resolve: (String) -> String?
    ) -> Bool {
        guard !rules.isEmpty else { return false }
        let bodyString = String(data: body, encoding: .utf8)
        // Check the percent-decoded URI too, so a secret that appears
        // URL-encoded in a query value is still detected — mirrors
        // SecretInjectionPass and closes a real-secret-to-model gap.
        let decodedURI = uri.removingPercentEncoding ?? uri
        for rule in rules {
            guard let real = resolve(rule.name), SecretInjectionPass.isTripwireEligible(real) else { continue }
            if uri.contains(real) || decodedURI.contains(real) { return true }
            if headers.contains(where: { $0.value.contains(real) }) { return true }
            if bodyString?.contains(real) == true { return true }
        }
        return false
    }

    /// RFC 3986 unreserved set — used to reconstruct the aggressive
    /// percent-encoding a client is most likely to apply to a secret in a
    /// URI query value, so we can scrub the encoded form too.
    private static let unreserved: CharacterSet = {
        var s = CharacterSet.alphanumerics
        s.insert(charactersIn: "-._~")
        return s
    }()

    /// Replace every managed real secret value with its placeholder.
    ///
    /// Only **key-shaped** values (≥16 chars, no whitespace — the same
    /// floor the tripwire uses) are scrubbed: a short or low-entropy
    /// "secret" could occur in ordinary prompt text, and replacing it
    /// would corrupt the prompt. Longest value first, so a secret that is a
    /// substring of another isn't partially clobbered.
    static func apply(
        uri: String,
        headers: [SecretInjectionPass.Header],
        body: Data,
        rules: [SecretRule],
        resolve: (String) -> String?
    ) -> Outcome {
        let candidates = rules
            .compactMap { rule -> (placeholder: String, value: String, name: String)? in
                guard let v = resolve(rule.name), SecretInjectionPass.isTripwireEligible(v) else { return nil }
                return (rule.placeholder, v, rule.name)
            }
            .sorted { $0.value.count > $1.value.count }

        guard !candidates.isEmpty else {
            return Outcome(uri: uri, headers: headers, body: body, scrubbed: [])
        }

        var outURI = uri
        var outHeaders = headers
        var bodyString = String(data: body, encoding: .utf8)
        var bodyTouched = false
        var scrubbed: [String] = []

        for c in candidates {
            var hit = false
            if outURI.contains(c.value) {
                outURI = outURI.replacingOccurrences(of: c.value, with: c.placeholder)
                hit = true
            } else if let encoded = c.value.addingPercentEncoding(withAllowedCharacters: Self.unreserved),
                      encoded != c.value, outURI.contains(encoded) {
                // Secret present in percent-encoded form in the URI.
                outURI = outURI.replacingOccurrences(of: encoded, with: c.placeholder)
                hit = true
            }
            if outHeaders.contains(where: { $0.value.contains(c.value) }) {
                outHeaders = outHeaders.map {
                    $0.value.contains(c.value)
                        ? SecretInjectionPass.Header($0.name, $0.value.replacingOccurrences(of: c.value, with: c.placeholder))
                        : $0
                }
                hit = true
            }
            if let s = bodyString, s.contains(c.value) {
                bodyString = s.replacingOccurrences(of: c.value, with: c.placeholder)
                bodyTouched = true
                hit = true
            }
            if hit { scrubbed.append(c.name) }
        }

        let outBody = bodyTouched ? Data((bodyString ?? "").utf8) : body
        return Outcome(uri: outURI, headers: outHeaders, body: outBody, scrubbed: scrubbed)
    }
}
