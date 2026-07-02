import Foundation
import Testing
@testable import Bouclier

/// Hardening regressions surfaced by the reversible-anonymization SOTA
/// review (2026-06-23): longest-placeholder-first replacement and
/// JSON-string escaping of injected secrets.
@Suite("SecretInjectionPass — hardening")
struct SecretInjectionHardeningTests {
    private func h(_ name: String, _ value: String) -> SecretInjectionPass.Header {
        SecretInjectionPass.Header(name, value)
    }

    /// `a` and `a_` produce placeholders where the shorter is a substring
    /// of the longer (`__BOUCLIER_SECRET_a__` ⊂ `__BOUCLIER_SECRET_a___`).
    /// A shortest-first pass would clobber the inner token; longest-first
    /// must inject both correctly.
    @Test("Prefix-colliding placeholders both inject correctly")
    func prefixCollision() {
        let host = "api.example.com"
        let rules = [
            SecretRule(name: "a", allowedHosts: [host]),
            SecretRule(name: "a_", allowedHosts: [host]),
        ]
        let values = ["a": "VALUE_AAAAAAAAAAAAA", "a_": "VALUE_BBBBBBBBBBBBB"]
        let body = Data(#"{"short":"\#(SecretRule.placeholder(for: "a"))","long":"\#(SecretRule.placeholder(for: "a_"))"}"#.utf8)

        let outcome = SecretInjectionPass.apply(
            host: host, uri: "/v1/x", headers: [], body: body,
            rules: rules, resolve: { values[$0] }
        )
        #expect(outcome.action == .forward)
        let s = String(data: outcome.body, encoding: .utf8) ?? ""
        #expect(s.contains(#""short":"VALUE_AAAAAAAAAAAAA""#), "short token clobbered: \(s)")
        #expect(s.contains(#""long":"VALUE_BBBBBBBBBBBBB""#), "long token not injected: \(s)")
        // No placeholder fragments left behind.
        #expect(!s.contains("__BOUCLIER_SECRET_"), "placeholder residue: \(s)")
    }

    /// A secret containing `"` and `\` must be JSON-escaped when injected
    /// into a JSON body, so the result is still valid JSON.
    @Test("Secret with JSON metacharacters is escaped in a JSON body")
    func jsonEscaping() {
        let host = "api.example.com"
        let rule = SecretRule(name: "weird", allowedHosts: [host])
        let value = #"ab"cd\ef"#  // contains a quote and a backslash
        let body = Data(#"{"key":"\#(SecretRule.placeholder(for: "weird"))"}"#.utf8)

        let outcome = SecretInjectionPass.apply(
            host: host, uri: "/v1/x", headers: [], body: body,
            rules: [rule], resolve: { _ in value }
        )
        #expect(outcome.action == .forward)
        let s = String(data: outcome.body, encoding: .utf8) ?? ""
        // Must remain parseable JSON with the original value recovered.
        let parsed = try? JSONSerialization.jsonObject(with: Data(s.utf8)) as? [String: String]
        #expect(parsed?["key"] == value, "value not recovered after JSON round-trip: \(s)")
    }

    /// In a non-JSON (form-encoded) body the value is injected raw — no
    /// spurious escaping.
    @Test("Non-JSON body injects the raw value")
    func nonJSONRaw() {
        let host = "api.example.com"
        let rule = SecretRule(name: "k", allowedHosts: [host])
        let value = "sk_live_RAWVALUE_000000"
        let body = Data("token=\(SecretRule.placeholder(for: "k"))&x=1".utf8)

        let outcome = SecretInjectionPass.apply(
            host: host, uri: "/v1/x", headers: [], body: body,
            rules: [rule], resolve: { _ in value }
        )
        let s = String(data: outcome.body, encoding: .utf8) ?? ""
        #expect(s == "token=\(value)&x=1", "form body altered unexpectedly: \(s)")
    }

    @Test("jsonStringEscaped handles quotes, backslashes, and control bytes")
    func escapeHelper() {
        #expect(SecretInjectionPass.jsonStringEscaped(#"a"b"#) == #"a\"b"#)
        #expect(SecretInjectionPass.jsonStringEscaped(#"a\b"#) == #"a\\b"#)
        #expect(SecretInjectionPass.jsonStringEscaped("a\tb") == #"a\tb"#)
        #expect(SecretInjectionPass.jsonStringEscaped("plain") == "plain")
    }
}
