import Foundation
import Testing
@testable import Bouclier

@Suite("SecretRedactionPass — outbound scrub")
struct SecretRedactionPassTests {
    private func H(_ n: String, _ v: String) -> SecretInjectionPass.Header { .init(n, v) }

    @Test("Managed real value in body is replaced by its placeholder")
    func scrubsBody() {
        let rule = SecretRule(name: "stripe", allowedHosts: [])
        let value = "sk_live_ABCDEFGHIJKLMNOP"
        let body = Data(#"{"text":"my key is \#(value) ok"}"#.utf8)
        let out = SecretRedactionPass.apply(uri: "/v1/messages", headers: [], body: body, rules: [rule], resolve: { _ in value })
        #expect(out.changed)
        #expect(out.scrubbed == ["stripe"])
        let s = String(data: out.body, encoding: .utf8) ?? ""
        #expect(!s.contains(value), "real value leaked: \(s)")
        #expect(s.contains(SecretRule.placeholder(for: "stripe")))
    }

    @Test("Managed real value in a header is replaced")
    func scrubsHeader() {
        let rule = SecretRule(name: "tok", allowedHosts: [])
        let value = "ghp_ABCDEFGHIJKLMNOPQRST"
        let out = SecretRedactionPass.apply(
            uri: "/v1/messages",
            headers: [H("X-Custom", "Bearer \(value)")],
            body: Data("{}".utf8),
            rules: [rule], resolve: { _ in value }
        )
        #expect(out.changed)
        #expect(out.headers.first?.value == "Bearer \(SecretRule.placeholder(for: "tok"))")
    }

    @Test("Short / low-entropy values are NOT scrubbed (would corrupt prose)")
    func ignoresShortValues() {
        let rule = SecretRule(name: "weak", allowedHosts: [])
        let value = "secret" // < 16 chars, not key-shaped
        let body = Data(#"{"text":"this is a secret message"}"#.utf8)
        let out = SecretRedactionPass.apply(uri: "/x", headers: [], body: body, rules: [rule], resolve: { _ in value })
        #expect(!out.changed)
        #expect(out.body == body)
    }

    @Test("No managed material ⇒ byte-identical passthrough")
    func cleanPassthrough() {
        let rule = SecretRule(name: "stripe", allowedHosts: [])
        let body = Data(#"{"text":"nothing secret here at all"}"#.utf8)
        #expect(!SecretRedactionPass.hasTrigger(uri: "/x", headers: [], body: body, rules: [rule], resolve: { _ in "sk_live_NOTPRESENT_000000" }))
        let out = SecretRedactionPass.apply(uri: "/x", headers: [H("a", "b")], body: body, rules: [rule], resolve: { _ in "sk_live_NOTPRESENT_000000" })
        #expect(!out.changed)
        #expect(out.body == body)
        #expect(out.uri == "/x")
    }

    @Test("Scrubs a secret present verbatim in the URI")
    func scrubsURIRaw() {
        let rule = SecretRule(name: "k", allowedHosts: [])
        let value = "sk_live_URITESTVALUE_123456"
        let out = SecretRedactionPass.apply(uri: "/v1/x?token=\(value)&a=1", headers: [], body: Data("{}".utf8), rules: [rule], resolve: { _ in value })
        #expect(out.changed)
        #expect(out.uri == "/v1/x?token=\(SecretRule.placeholder(for: "k"))&a=1")
        #expect(!out.uri.contains(value))
    }

    @Test("Detects + scrubs a percent-encoded secret in the URI (asymmetry fix)")
    func scrubsURIEncoded() {
        let rule = SecretRule(name: "k", allowedHosts: [])
        let value = "sklive#ABCDEFGH&IJKLMNOP"            // URL-special chars
        let encoded = "sklive%23ABCDEFGH%26IJKLMNOP"      // unreserved-only encoding
        let uri = "/x?t=\(encoded)"
        #expect(SecretRedactionPass.hasTrigger(uri: uri, headers: [], body: Data(), rules: [rule], resolve: { _ in value }))
        let out = SecretRedactionPass.apply(uri: uri, headers: [], body: Data(), rules: [rule], resolve: { _ in value })
        #expect(out.changed)
        #expect(!out.uri.contains(encoded), "encoded secret survived in URI: \(out.uri)")
        #expect(out.uri.contains(SecretRule.placeholder(for: "k")))
    }

    @Test("Secret appearing multiple times is fully scrubbed")
    func scrubsAllOccurrences() {
        let rule = SecretRule(name: "k", allowedHosts: [])
        let value = "sk_live_REPEATEDVALUE_999999"
        let body = Data(#"{"a":"\#(value)","b":"\#(value)"}"#.utf8)
        let out = SecretRedactionPass.apply(uri: "/x", headers: [], body: body, rules: [rule], resolve: { _ in value })
        let s = String(data: out.body, encoding: .utf8) ?? ""
        #expect(!s.contains(value), "a copy survived: \(s)")
    }

    @Test("Longest value first: a value that is a substring of another isn't partially clobbered")
    func longestFirst() {
        let shortV = "sk_live_AAAAAAAAAAAAAA"          // 22 chars
        let longV = shortV + "_BBBBBBBBBBBB"           // superstring of shortV
        let rules = [SecretRule(name: "short", allowedHosts: []), SecretRule(name: "long", allowedHosts: [])]
        let values = ["short": shortV, "long": longV]
        let body = Data(#"{"a":"\#(longV)","b":"\#(shortV)"}"#.utf8)
        let out = SecretRedactionPass.apply(uri: "/x", headers: [], body: body, rules: rules, resolve: { values[$0] })
        let s = String(data: out.body, encoding: .utf8) ?? ""
        #expect(s.contains(#""a":"\#(SecretRule.placeholder(for: "long"))""#), "long not fully scrubbed: \(s)")
        #expect(s.contains(#""b":"\#(SecretRule.placeholder(for: "short"))""#), "short not scrubbed: \(s)")
        #expect(!s.contains("sk_live_"), "residual real value: \(s)")
    }
}
