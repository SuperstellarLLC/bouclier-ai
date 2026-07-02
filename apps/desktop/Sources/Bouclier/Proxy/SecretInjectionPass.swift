import Foundation

/// Pure, NIO-free secret-injection logic: swap a placeholder for the real
/// value heading to a secret's bound host.
///
/// **Dormant.** Its only production caller was `HTTPInspectionHandler`
/// inside `TLSProxy`, the CA-based interception engine removed with
/// extreme mode — the loopback `GatewayServer` never calls this. It's
/// kept, unmodified, rather than deleted: the logic is still correct and
/// still exercised directly by unit tests and `SecretKeeperMonitor`'s
/// self-test, so it remains available if destination-bound injection is
/// ever wired into the gateway. `SecretRule.allowedHosts` still validates
/// and stores host bindings, but nothing currently acts on them.
///
/// Enforces the core invariant from `docs/secret-injection.md`:
///
/// > A real secret value must never appear in an agent-originated
/// > request. Only Bouclier puts it there, only for the bound host,
/// > only on the final hop.
enum SecretInjectionPass {
    enum Action: Equatable {
        case forward
        case block
    }

    /// Why a request was blocked. Surfaced to the audit log so the user
    /// sees *which* secret and *why* — the whole point of a firewall.
    enum BlockReason: Sendable, Equatable {
        /// The real value of `rule` was found heading to `host`, which is
        /// NOT a host the secret is bound to. This is the third-party-key
        /// leak case: e.g. a Stripe key appearing in a request to an LLM
        /// provider, or being exfiltrated to an attacker endpoint. A
        /// secret reaching its OWN bound host is the intended destination
        /// and is never blocked here.
        case secretValueToDisallowedHost(rule: String, host: String)
        /// A placeholder for `rule` arrived at `host`, which is not in
        /// the rule's allowlist. Classic exfiltration shape: coax the
        /// agent into sending the credential somewhere it shouldn't go.
        case placeholderToDisallowedHost(rule: String, host: String)
        /// The placeholder is bound to this host, but the secret value
        /// couldn't be resolved (missing/empty in the store). Fail
        /// closed rather than forward a literal placeholder upstream.
        case secretUnavailable(rule: String)
    }

    struct Outcome: Sendable, Equatable {
        let action: Action
        /// Rewritten request URI. Equal to the input on the no-op /
        /// block paths. Secrets injected into the URI are percent-encoded
        /// for query-value context.
        let uri: String
        /// Rewritten headers (placeholder → real value applied). Equal
        /// to the input on the no-op / block paths.
        let headers: [Header]
        /// Rewritten body. Equal to the input on the no-op / block paths.
        let body: Data
        /// Names of rules whose secret was injected this request.
        let injected: [String]
        /// Populated iff `action == .block`.
        let blockReason: BlockReason?
    }

    struct Header: Sendable, Equatable {
        let name: String
        let value: String
        init(_ name: String, _ value: String) {
            self.name = name
            self.value = value
        }
    }

    /// Apply injection to one outbound request.
    ///
    /// - Parameters:
    ///   - host: the (already-validated) destination host, e.g. `api.stripe.com`.
    ///   - uri: outbound request URI (path + query). Placeholders here are
    ///     replaced with the percent-encoded secret value.
    ///   - headers: outbound header name/value pairs.
    ///   - body: outbound body bytes (may be binary; only scanned when valid UTF-8).
    ///   - rules: the managed secret rules.
    ///   - resolve: maps a rule name to its real secret value, or nil if unavailable.
    static func apply(
        host: String,
        uri: String,
        headers: [Header],
        body: Data,
        rules: [SecretRule],
        resolve: (String) -> String?
    ) -> Outcome {
        // Fast exit: nothing managed ⇒ byte-for-byte passthrough. Keeps
        // the hot path free when the feature is on but unconfigured.
        guard !rules.isEmpty else {
            return Outcome(action: .forward, uri: uri, headers: headers, body: body, injected: [], blockReason: nil)
        }

        let lowerHost = host.lowercased()
        // Decode the body once. A nil here means binary (e.g. multipart
        // upload) — we still scan URI + headers, just not the body.
        let bodyString = String(data: body, encoding: .utf8)

        // Replace longest placeholders first. If one rule's placeholder is
        // a prefix of another's (e.g. `__BOUCLIER_SECRET_a__` is a prefix
        // of `__BOUCLIER_SECRET_a___` for names `a` and `a_`), a naive
        // shortest-first pass would clobber the inner token of the longer
        // one — the single most-cited reversible-anonymization bug. The
        // tripwire shares the order harmlessly. Equal lengths fall back to
        // name for a stable, deterministic order.
        let sortedRules = rules.sorted {
            $0.placeholder.count != $1.placeholder.count
                ? $0.placeholder.count > $1.placeholder.count
                : $0.name < $1.name
        }

        // A JSON body needs the injected value escaped for JSON-string
        // context, the same way a URI value is percent-encoded — otherwise
        // a secret containing `"` or `\` (the store rejects CR/LF/NUL but
        // not these) would break the surrounding JSON. Detected from the
        // body's first non-space byte; form-encoded and other bodies are
        // left as raw replacements.
        let bodyLooksLikeJSON: Bool = {
            guard let first = bodyString?.drop(while: { $0.isWhitespace }).first else { return false }
            return first == "{" || first == "["
        }()

        func block(_ reason: BlockReason) -> Outcome {
            // Block leaves the request byte-identical — nothing injected.
            Outcome(action: .block, uri: uri, headers: headers, body: body, injected: [], blockReason: reason)
        }

        // ── 1. Tripwire: a real secret value heading to the WRONG host ──
        //
        // The destination-binding rule is what makes the two legitimate
        // cases work while blocking the dangerous one:
        //
        //   • A provider's own key reaching that provider (the bound
        //     host) is the intended destination — e.g. authenticating
        //     directly with the LLM. We must NOT break it, so a value at
        //     its own allowed host is skipped here.
        //   • The same value reaching ANY other host — an LLM provider it
        //     isn't bound to, an attacker endpoint, anywhere — is a leak
        //     of a third-party credential. Block it.
        //
        // The URI is scanned raw and percent-decoded so an encoded secret
        // can't slip past. Only "key-shaped" values (long, no whitespace)
        // arm the tripwire, so ordinary prose in a prompt can never cause
        // a false-positive block of a real request.
        let decodedURI = uri.removingPercentEncoding ?? uri
        for rule in sortedRules {
            guard let real = resolve(rule.name), Self.isTripwireEligible(real) else { continue }
            // Reaching its own bound host = intended destination, not a leak.
            guard !rule.allows(host: lowerHost) else { continue }
            let inURI = uri.contains(real) || decodedURI.contains(real)
            let inHeaders = headers.contains { $0.value.contains(real) }
            let inBody = bodyString?.contains(real) ?? false
            if inURI || inHeaders || inBody {
                return block(.secretValueToDisallowedHost(rule: rule.name, host: lowerHost))
            }
        }

        // ── 2. Placeholder handling, per rule ──
        var outURI = uri
        var outHeaders = headers
        var outBodyString = bodyString
        var bodyTouched = false
        var injected: [String] = []

        for rule in sortedRules {
            let token = rule.placeholder
            let inURI = outURI.contains(token)
            let inHeaders = outHeaders.contains { $0.value.contains(token) }
            let inBody = outBodyString?.contains(token) ?? false
            guard inURI || inHeaders || inBody else { continue }

            // Destination binding: placeholder at a non-allowlisted host
            // is an exfil attempt. Block the whole request.
            guard rule.allows(host: lowerHost) else {
                return block(.placeholderToDisallowedHost(rule: rule.name, host: lowerHost))
            }

            // Bound host, but no value to inject ⇒ fail closed.
            guard let real = resolve(rule.name), !real.isEmpty else {
                return block(.secretUnavailable(rule: rule.name))
            }

            if inURI {
                // A secret in the URI lands in query-value position, so it
                // must be percent-encoded — otherwise a value containing
                // `&`, `=`, `/`, or space would corrupt the request line
                // or smuggle extra parameters.
                let encoded = real.addingPercentEncoding(withAllowedCharacters: Self.queryValueAllowed) ?? real
                outURI = outURI.replacingOccurrences(of: token, with: encoded)
            }
            if inHeaders {
                outHeaders = outHeaders.map {
                    $0.value.contains(token)
                        ? Header($0.name, $0.value.replacingOccurrences(of: token, with: real))
                        : $0
                }
            }
            if inBody, let s = outBodyString {
                let replacement = bodyLooksLikeJSON ? Self.jsonStringEscaped(real) : real
                outBodyString = s.replacingOccurrences(of: token, with: replacement)
                bodyTouched = true
            }
            injected.append(rule.name)
        }

        let outBody = bodyTouched ? Data((outBodyString ?? "").utf8) : body
        return Outcome(action: .forward, uri: outURI, headers: outHeaders, body: outBody, injected: injected, blockReason: nil)
    }

    /// Independent, deliberately-simple "is there any secret material in
    /// this request at all?" check. Returns true if *any* managed
    /// placeholder OR *any* real secret value appears anywhere in the URI
    /// (raw or percent-decoded), headers, or body.
    ///
    /// This is the integrity gate that protects clean LLM traffic: the
    /// rewriter (`apply`) is only ever invoked when this returns true, so
    /// a request carrying no secret material — the overwhelming majority
    /// of provider traffic — never reaches the rewrite logic and cannot
    /// be altered or blocked by a bug in it.
    ///
    /// It is a strict SUPERSET of every condition under which `apply`
    /// acts (it ignores host-binding and value-length eligibility, which
    /// only ever make `apply` act *less*). So `hasTrigger == false`
    /// provably means `apply` would be a no-op — making the gate sound:
    /// it can never hide a legitimate injection or block, only ever
    /// refuse to touch a request that has nothing to act on. Kept
    /// intentionally separate from `apply`'s logic so a single bug can't
    /// defeat both.
    static func hasTrigger(
        uri: String,
        headers: [Header],
        body: Data,
        rules: [SecretRule],
        resolve: (String) -> String?
    ) -> Bool {
        guard !rules.isEmpty else { return false }
        let bodyString = String(data: body, encoding: .utf8)
        let decodedURI = uri.removingPercentEncoding ?? uri
        func present(_ needle: String) -> Bool {
            guard !needle.isEmpty else { return false }
            if uri.contains(needle) || decodedURI.contains(needle) { return true }
            if headers.contains(where: { $0.value.contains(needle) }) { return true }
            return bodyString?.contains(needle) ?? false
        }
        for rule in rules {
            if present(rule.placeholder) { return true }
            if let real = resolve(rule.name), present(real) { return true }
        }
        return false
    }

    /// RFC 3986 unreserved set — what's safe to leave un-escaped in a URL
    /// query value. Everything else in an injected secret is percent-encoded.
    private static let queryValueAllowed: CharacterSet = {
        var set = CharacterSet.alphanumerics
        set.insert(charactersIn: "-._~")
        return set
    }()

    /// Minimum length for a secret value to arm the plaintext tripwire.
    /// Real credentials are long, opaque tokens; a short or low-entropy
    /// "secret" (e.g. a dictionary word) could appear in ordinary prompt
    /// text and cause a false-positive block of a legitimate request.
    /// Gating on length + absence of whitespace makes that impossible
    /// without weakening protection for real keys (Stripe ≥32, OpenAI
    /// ~51, GitHub ~40, AWS 20 chars — all well above this floor).
    static let minTripwireSecretLength = 16

    /// Whether a value is "key-shaped" enough to scan for as plaintext.
    static func isTripwireEligible(_ value: String) -> Bool {
        value.count >= minTripwireSecretLength
            && !value.contains(where: { $0.isWhitespace })
    }

    /// Escape a secret for safe interpolation into a JSON string literal.
    /// The store already rejects CR/LF/NUL, but a value containing `"` or
    /// `\` — or any other control byte — would still break the JSON it's
    /// injected into. Mirrors the percent-encoding we apply for URI
    /// context. Real API keys are `[A-Za-z0-9_-]` so this is almost always
    /// a no-op, but correctness over assumptions.
    static func jsonStringEscaped(_ value: String) -> String {
        var out = ""
        out.reserveCapacity(value.count)
        for ch in value {
            switch ch {
            case "\\": out += "\\\\"
            case "\"": out += "\\\""
            case "\t": out += "\\t"
            default:
                let scalars = ch.unicodeScalars
                if let s = scalars.first, scalars.count == 1, s.value < 0x20 {
                    out += String(format: "\\u%04x", s.value)
                } else {
                    out.append(ch)
                }
            }
        }
        return out
    }
}

extension SecretInjectionPass.BlockReason {
    /// The rule this block concerns. Used by the audit log.
    var ruleName: String {
        switch self {
        case .secretValueToDisallowedHost(let r, _),
             .placeholderToDisallowedHost(let r, _),
             .secretUnavailable(let r):
            return r
        }
    }

    /// Human-readable one-liner for the activity feed and audit log.
    var auditDescription: String {
        switch self {
        case .secretValueToDisallowedHost(let r, let h):
            return "real value of secret '\(r)' was leaking to \(h) — blocked"
        case .placeholderToDisallowedHost(let r, let h):
            return "secret '\(r)' is not bound to \(h) — refused injection"
        case .secretUnavailable(let r):
            return "secret '\(r)' unavailable — failed closed"
        }
    }
}
