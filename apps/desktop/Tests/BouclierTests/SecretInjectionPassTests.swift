import Foundation
import Testing
@testable import Bouclier

@Suite("SecretInjectionPass")
struct SecretInjectionPassTests {
    // A Stripe secret bound to api.stripe.com.
    let stripe = SecretRule(name: "stripe", allowedHosts: ["api.stripe.com"])
    let resolve: (String) -> String? = { name in name == "stripe" ? "sk_live_REALSECRET123" : nil }

    private func header(_ n: String, _ v: String) -> SecretInjectionPass.Header { .init(n, v) }

    // MARK: - Happy path

    @Test("Injects the real secret into a header at the bound host")
    func injectsHeader() {
        let out = SecretInjectionPass.apply(
            host: "api.stripe.com",
            uri: "/v1/charges",
            headers: [header("Authorization", "Bearer \(stripe.placeholder)")],
            body: Data(),
            rules: [stripe],
            resolve: resolve
        )
        #expect(out.action == .forward)
        #expect(out.injected == ["stripe"])
        #expect(out.headers.first?.value == "Bearer sk_live_REALSECRET123")
        #expect(out.uri == "/v1/charges")
    }

    @Test("Injects the real secret into a JSON body field")
    func injectsBody() {
        let body = Data("{\"key\":\"\(stripe.placeholder)\"}".utf8)
        let out = SecretInjectionPass.apply(
            host: "api.stripe.com", uri: "/v1/charges", headers: [], body: body, rules: [stripe], resolve: resolve
        )
        #expect(out.action == .forward)
        #expect(out.injected == ["stripe"])
        #expect(String(data: out.body, encoding: .utf8) == "{\"key\":\"sk_live_REALSECRET123\"}")
    }

    @Test("No placeholder ⇒ byte-for-byte passthrough")
    func passthrough() {
        let body = Data("{\"hello\":\"world\"}".utf8)
        let headers = [header("Authorization", "Bearer something-unrelated")]
        let out = SecretInjectionPass.apply(
            host: "api.stripe.com", uri: "/v1/x", headers: headers, body: body, rules: [stripe], resolve: resolve
        )
        #expect(out.action == .forward)
        #expect(out.injected.isEmpty)
        #expect(out.body == body)
        #expect(out.headers == headers)
        #expect(out.uri == "/v1/x")
    }

    @Test("Empty rule set ⇒ passthrough")
    func emptyRules() {
        let body = Data("anything".utf8)
        let out = SecretInjectionPass.apply(
            host: "api.stripe.com", uri: "/v1/x", headers: [], body: body, rules: [], resolve: { _ in nil }
        )
        #expect(out.action == .forward)
        #expect(out.body == body)
    }

    // MARK: - URI injection

    @Test("Injects the real secret into a query parameter, percent-encoded")
    func injectsURIPercentEncoded() {
        let withSlash = SecretRule(name: "maps", allowedHosts: ["maps.googleapis.com"])
        let out = SecretInjectionPass.apply(
            host: "maps.googleapis.com",
            uri: "/geocode?key=\(withSlash.placeholder)",
            headers: [],
            body: Data(),
            rules: [withSlash],
            resolve: { $0 == "maps" ? "abc/d+e=f" : nil }
        )
        #expect(out.action == .forward)
        #expect(out.injected == ["maps"])
        // `/`, `+`, `=` must be percent-encoded in query-value position.
        #expect(out.uri == "/geocode?key=abc%2Fd%2Be%3Df")
    }

    @Test("Placeholder in URI to a disallowed host is blocked")
    func blocksURIDisallowedHost() {
        let out = SecretInjectionPass.apply(
            host: "evil.example.com",
            uri: "/leak?k=\(stripe.placeholder)",
            headers: [],
            body: Data(),
            rules: [stripe],
            resolve: resolve
        )
        #expect(out.action == .block)
        #expect(out.blockReason == .placeholderToDisallowedHost(rule: "stripe", host: "evil.example.com"))
    }

    @Test("Tripwire catches a real secret leaking via the URI to a foreign host")
    func tripwireURI() {
        let out = SecretInjectionPass.apply(
            host: "evil.example.com",
            uri: "/collect?k=sk_live_REALSECRET123",
            headers: [],
            body: Data(),
            rules: [stripe],
            resolve: resolve
        )
        #expect(out.action == .block)
        #expect(out.blockReason == .secretValueToDisallowedHost(rule: "stripe", host: "evil.example.com"))
    }

    // MARK: - Destination binding (exfil defense)

    @Test("Placeholder to a disallowed host is blocked as exfil")
    func blocksDisallowedHost() {
        let out = SecretInjectionPass.apply(
            host: "evil.example.com",
            uri: "/x",
            headers: [header("Authorization", "Bearer \(stripe.placeholder)")],
            body: Data(),
            rules: [stripe],
            resolve: resolve
        )
        #expect(out.action == .block)
        #expect(out.blockReason == .placeholderToDisallowedHost(rule: "stripe", host: "evil.example.com"))
        #expect(out.headers.first?.value == "Bearer \(stripe.placeholder)")
        #expect(out.injected.isEmpty)
    }

    @Test("Host match is case-insensitive")
    func hostCaseInsensitive() {
        let out = SecretInjectionPass.apply(
            host: "API.Stripe.Com",
            uri: "/x",
            headers: [header("Authorization", "Bearer \(stripe.placeholder)")],
            body: Data(),
            rules: [stripe],
            resolve: resolve
        )
        #expect(out.action == .forward)
        #expect(out.injected == ["stripe"])
    }

    // MARK: - Plaintext tripwire (host-aware)

    @Test("Real secret leaking to a foreign host is blocked")
    func blocksRealSecretToForeignHost() {
        let out = SecretInjectionPass.apply(
            host: "evil.example.com",
            uri: "/x",
            headers: [header("Authorization", "Bearer sk_live_REALSECRET123")],
            body: Data(),
            rules: [stripe],
            resolve: resolve
        )
        #expect(out.action == .block)
        #expect(out.blockReason == .secretValueToDisallowedHost(rule: "stripe", host: "evil.example.com"))
    }

    @Test("Real secret reaching its OWN bound host is forwarded (intended destination)")
    func forwardsRealSecretToBoundHost() {
        // A provider's own key reaching that provider is the intended use
        // (e.g. authenticating directly). Must not be broken.
        let body = Data("{\"key\":\"sk_live_REALSECRET123\"}".utf8)
        let out = SecretInjectionPass.apply(
            host: "api.stripe.com", uri: "/v1/charges", headers: [], body: body, rules: [stripe], resolve: resolve
        )
        #expect(out.action == .forward)
        #expect(out.injected.isEmpty)
        #expect(out.body == body)
    }

    @Test("A third-party key leaking into an LLM-provider request is blocked")
    func blocksThirdPartyKeyLeakingToLLM() {
        // The exact case: a Stripe key (bound to api.stripe.com) shows up
        // in a request to an LLM provider. The model must never receive a
        // third party's credential.
        let body = Data("{\"prompt\":\"is sk_live_REALSECRET123 valid?\"}".utf8)
        let out = SecretInjectionPass.apply(
            host: "api.anthropic.com", uri: "/v1/messages", headers: [], body: body, rules: [stripe], resolve: resolve
        )
        #expect(out.action == .block)
        #expect(out.blockReason == .secretValueToDisallowedHost(rule: "stripe", host: "api.anthropic.com"))
    }

    @Test("Authenticating directly with a provider injects its own key")
    func injectsProviderOwnKey() {
        // Secret bound to the provider's own host = auth-with-provider.
        let anthropic = SecretRule(name: "anthropic", allowedHosts: ["api.anthropic.com"])
        let out = SecretInjectionPass.apply(
            host: "api.anthropic.com",
            uri: "/v1/messages",
            headers: [header("x-api-key", anthropic.placeholder)],
            body: Data(),
            rules: [anthropic],
            resolve: { $0 == "anthropic" ? "sk-ant-REALKEY-0123456789" : nil }
        )
        #expect(out.action == .forward)
        #expect(out.injected == ["anthropic"])
        #expect(out.headers.first?.value == "sk-ant-REALKEY-0123456789")
    }

    @Test("Short/low-entropy secret values never arm the tripwire")
    func shortSecretNeverTripwires() {
        // A value shorter than the floor (or containing whitespace) must
        // not cause a false-positive block of ordinary content.
        let weak = SecretRule(name: "weak", allowedHosts: ["api.weak.com"])
        let out = SecretInjectionPass.apply(
            host: "evil.example.com",
            uri: "/x",
            headers: [],
            body: Data("the password is hunter2".utf8),
            rules: [weak],
            resolve: { $0 == "weak" ? "hunter2" : nil }   // 7 chars → not eligible
        )
        #expect(out.action == .forward)
        #expect(!SecretInjectionPass.isTripwireEligible("hunter2"))
        #expect(!SecretInjectionPass.isTripwireEligible("a value with spaces in it"))
        #expect(SecretInjectionPass.isTripwireEligible("sk_live_REALSECRET123"))
    }

    // MARK: - Fail closed

    @Test("Bound host but unresolvable secret fails closed")
    func failsClosedWhenUnresolvable() {
        let out = SecretInjectionPass.apply(
            host: "api.stripe.com",
            uri: "/x",
            headers: [header("Authorization", "Bearer \(stripe.placeholder)")],
            body: Data(),
            rules: [stripe],
            resolve: { _ in nil }
        )
        #expect(out.action == .block)
        #expect(out.blockReason == .secretUnavailable(rule: "stripe"))
    }

    // MARK: - Multiple rules / occurrences

    @Test("Injects multiple distinct placeholders in one request")
    func multipleRules() {
        let github = SecretRule(name: "github", allowedHosts: ["api.stripe.com"])
        let resolveBoth: (String) -> String? = { name in
            switch name {
            case "stripe": return "sk_live_REALSECRET123"
            case "github": return "ghp_REALTOKEN456"
            default: return nil
            }
        }
        let body = Data("{\"a\":\"\(stripe.placeholder)\",\"b\":\"\(github.placeholder)\"}".utf8)
        let out = SecretInjectionPass.apply(
            host: "api.stripe.com", uri: "/x", headers: [], body: body, rules: [stripe, github], resolve: resolveBoth
        )
        #expect(out.action == .forward)
        #expect(Set(out.injected) == ["stripe", "github"])
        let s = String(data: out.body, encoding: .utf8) ?? ""
        #expect(s.contains("sk_live_REALSECRET123"))
        #expect(s.contains("ghp_REALTOKEN456"))
        #expect(!s.contains("__BOUCLIER_SECRET"))
    }

    @Test("Replaces every occurrence of a repeated placeholder")
    func repeatedPlaceholder() {
        let body = Data("\(stripe.placeholder) and again \(stripe.placeholder)".utf8)
        let out = SecretInjectionPass.apply(
            host: "api.stripe.com", uri: "/x", headers: [], body: body, rules: [stripe], resolve: resolve
        )
        #expect(out.action == .forward)
        #expect(String(data: out.body, encoding: .utf8) == "sk_live_REALSECRET123 and again sk_live_REALSECRET123")
    }

    // MARK: - Block reason metadata

    @Test("BlockReason exposes rule name and audit description")
    func blockReasonMetadata() {
        let r = SecretInjectionPass.BlockReason.placeholderToDisallowedHost(rule: "stripe", host: "evil.example.com")
        #expect(r.ruleName == "stripe")
        #expect(r.auditDescription.contains("stripe"))
        #expect(r.auditDescription.contains("evil.example.com"))
    }

    // MARK: - Rule model

    @Test("Validates rule names")
    func validatesNames() {
        #expect(SecretRule.isValidName("stripe"))
        #expect(SecretRule.isValidName("stripe_live_2"))
        #expect(!SecretRule.isValidName(""))
        #expect(!SecretRule.isValidName("Stripe"))
        #expect(!SecretRule.isValidName("api-key"))
        #expect(!SecretRule.isValidName("a b"))
    }

    @Test("Placeholder is namespaced and stable")
    func placeholderShape() {
        #expect(SecretRule.placeholder(for: "stripe") == "__BOUCLIER_SECRET_stripe__")
    }

    @Test("Validates + normalizes bindable hosts")
    func validatesHosts() {
        #expect(SecretRule.validatedHost("api.stripe.com") == "api.stripe.com")
        #expect(SecretRule.validatedHost("  API.Stripe.com ") == "api.stripe.com")
        // SSRF / local targets must never be bindable.
        #expect(SecretRule.validatedHost("169.254.169.254") == nil)
        #expect(SecretRule.validatedHost("metadata.google.internal") == nil)
        #expect(SecretRule.validatedHost("localhost") == nil)
        #expect(SecretRule.validatedHost("127.0.0.1") == nil)
        // Malformed.
        #expect(SecretRule.validatedHost("not a host") == nil)
        #expect(SecretRule.validatedHost("") == nil)
    }

    @Test("Validates secret values (rejects control bytes and empties)")
    func validatesValues() {
        #expect(SecretRule.isValidValue("sk_live_REALSECRET123"))
        #expect(!SecretRule.isValidValue(""))
        #expect(!SecretRule.isValidValue("has\r\nCRLF"))   // header smuggling
        #expect(!SecretRule.isValidValue("has\u{00}null"))
        #expect(!SecretRule.isValidValue(String(repeating: "x", count: SecretRule.maxValueBytes + 1)))
    }
}

@Suite("SystemProxy egress policy")
struct EgressPolicyTests {
    @Test("Fail-open: every host tunnels by default")
    func failOpen() {
        #expect(SystemProxy.tunnelAllowed(host: "github.com", failClosed: false, allowlist: []))
    }

    @Test("Fail-closed: only allowlisted hosts tunnel")
    func failClosed() {
        let allow: Set<String> = ["github.com"]
        #expect(SystemProxy.tunnelAllowed(host: "github.com", failClosed: true, allowlist: allow))
        #expect(SystemProxy.tunnelAllowed(host: "GitHub.com", failClosed: true, allowlist: allow))
        #expect(!SystemProxy.tunnelAllowed(host: "evil.example.com", failClosed: true, allowlist: allow))
    }
}
