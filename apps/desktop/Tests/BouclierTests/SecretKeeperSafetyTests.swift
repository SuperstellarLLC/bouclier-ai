import Foundation
import Testing
@testable import Bouclier

// Deterministic, reproducible PRNG (SplitMix64) so fuzz failures are
// replayable from the seed rather than flaky.
private struct SeededRNG: RandomNumberGenerator {
    var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state = state &+ 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

private func randomString(_ rng: inout SeededRNG, maxLen: Int = 64) -> String {
    // Charset deliberately excludes the uppercase + double-underscore
    // shape of a placeholder and is short, so random output cannot form
    // `__BOUCLIER_SECRET_x__` or a long opaque key by accident.
    let alphabet = Array("abcdefghijklmnopqrstuvwxyz0123456789 .,:/?&=-{}\"'")
    let len = Int(rng.next() % UInt64(maxLen))
    var s = ""
    s.reserveCapacity(len)
    for _ in 0..<len {
        s.append(alphabet[Int(rng.next() % UInt64(alphabet.count))])
    }
    return s
}

@Suite("SecretKeeper safety — integrity gate")
struct SecretKeeperHasTriggerTests {
    let stripe = SecretRule(name: "stripe", allowedHosts: ["api.stripe.com"])
    let resolve: (String) -> String? = { $0 == "stripe" ? "sk_live_REALSECRET123" : nil }
    private func h(_ n: String, _ v: String) -> SecretInjectionPass.Header { .init(n, v) }

    @Test("hasTrigger is false for a request with no secret material")
    func noTrigger() {
        #expect(!SecretInjectionPass.hasTrigger(
            uri: "/v1/messages",
            headers: [h("authorization", "Bearer not-a-managed-key")],
            body: Data(#"{"prompt":"talk about stripe and secrets casually"}"#.utf8),
            rules: [stripe], resolve: resolve
        ))
    }

    @Test("hasTrigger is true when a placeholder is present")
    func triggerOnPlaceholder() {
        #expect(SecretInjectionPass.hasTrigger(
            uri: "/x", headers: [h("authorization", "Bearer \(stripe.placeholder)")],
            body: Data(), rules: [stripe], resolve: resolve
        ))
    }

    @Test("hasTrigger is true when a real secret value is present (any host)")
    func triggerOnValue() {
        #expect(SecretInjectionPass.hasTrigger(
            uri: "/x?k=sk_live_REALSECRET123", headers: [],
            body: Data(), rules: [stripe], resolve: resolve
        ))
    }

    @Test("hasTrigger is false with no rules")
    func noRulesNoTrigger() {
        #expect(!SecretInjectionPass.hasTrigger(
            uri: "/x", headers: [h("a", "\(stripe.placeholder)")],
            body: Data(), rules: [], resolve: { _ in nil }
        ))
    }
}

@Suite("SecretKeeper safety — runtime self-test & breaker")
struct SecretKeeperMonitorTests {
    @Test("Self-test passes against the live pass")
    func selfTestPasses() {
        let report = SecretKeeperMonitor.runSelfTest()
        #expect(report.passed, "Self-test failures: \(report.failures)")
        #expect(report.failures.isEmpty)
    }

    @Test("Breaker trips and resets")
    func breaker() {
        SecretKeeperMonitor.resetForTesting()
        #expect(!SecretKeeperMonitor.isTripped)
        SecretKeeperMonitor.trip(reason: "test")
        #expect(SecretKeeperMonitor.isTripped)
        #expect(SecretKeeperMonitor.trippedReason == "test")
        SecretKeeperMonitor.resetForTesting()
        #expect(!SecretKeeperMonitor.isTripped)
    }
}

@Suite("SecretKeeper safety — property/fuzz")
struct SecretKeeperFuzzTests {
    let stripe = SecretRule(name: "stripe", allowedHosts: ["api.stripe.com"])
    let realValue = "sk_live_REALSECRET1234567"   // tripwire-eligible
    private func resolve(_ name: String) -> String? { name == "stripe" ? realValue : nil }
    private func h(_ n: String, _ v: String) -> SecretInjectionPass.Header { .init(n, v) }

    /// THE catastrophic-prevention property: when a request carries no
    /// secret material, `apply` is a perfect identity — same URI, headers,
    /// and body. Run over thousands of randomized request shapes. This is
    /// what guarantees a clean LLM request is never altered.
    @Test("No secret material ⇒ apply is a byte-perfect identity (fuzz)")
    func noMaterialIsIdentity() {
        var rng = SeededRNG(seed: 0xB0FF_1E50_1234_5678)
        let rules = [stripe]
        var checked = 0
        for _ in 0..<4000 {
            let hostPool = ["api.anthropic.com", "api.openai.com", "api.stripe.com", "evil.example.com", "x.test"]
            let host = hostPool[Int(rng.next() % UInt64(hostPool.count))]
            let uri = "/" + randomString(&rng)
            let headers = [h("authorization", "Bearer " + randomString(&rng)), h("x-trace", randomString(&rng))]
            let body = Data(randomString(&rng, maxLen: 256).utf8)

            // Skip the (astronomically rare) random collision where the
            // fuzzed bytes happen to contain a placeholder or the value.
            if SecretInjectionPass.hasTrigger(uri: uri, headers: headers, body: body, rules: rules, resolve: resolve) {
                continue
            }
            let out = SecretInjectionPass.apply(host: host, uri: uri, headers: headers, body: body, rules: rules, resolve: resolve)
            #expect(out.action == .forward)
            #expect(out.injected.isEmpty)
            #expect(out.uri == uri)
            #expect(out.headers == headers)
            #expect(out.body == body)
            checked += 1
        }
        #expect(checked > 3500, "Fuzz coverage too low (\(checked)) — collisions shouldn't be common")
    }

    /// A placeholder is injected iff the host is bound, else blocked —
    /// across randomized hosts and surrounding noise.
    @Test("Placeholder ⇒ inject at bound host, block at any foreign host (fuzz)")
    func placeholderRouting() {
        var rng = SeededRNG(seed: 0x5EED_0F_FACE_1234)
        for i in 0..<800 {
            let bound = (rng.next() & 1) == 0
            let host = bound ? "api.stripe.com" : "h\(i).foreign-\(rng.next() % 9999).example"
            let body = Data((randomString(&rng) + stripe.placeholder + randomString(&rng)).utf8)
            let out = SecretInjectionPass.apply(host: host, uri: "/x", headers: [], body: body, rules: [stripe], resolve: resolve)
            if bound {
                #expect(out.action == .forward)
                #expect(out.injected == ["stripe"])
                let s = String(data: out.body, encoding: .utf8) ?? ""
                #expect(s.contains(realValue))
                #expect(!s.contains(stripe.placeholder))
            } else {
                #expect(out.action == .block)
                #expect(out.blockReason == .placeholderToDisallowedHost(rule: "stripe", host: host.lowercased()))
            }
        }
    }

    /// A real secret value is forwarded to its own host and blocked at any
    /// other — the third-party-leak guarantee, fuzzed over hosts.
    @Test("Real value ⇒ forward to own host, block to any foreign host (fuzz)")
    func valueRouting() {
        var rng = SeededRNG(seed: 0xC0DE_F00D_2026_0615)
        for i in 0..<800 {
            let own = (rng.next() & 1) == 0
            let host = own ? "api.stripe.com" : "llm\(i).provider-\(rng.next() % 9999).example"
            let body = Data((randomString(&rng) + realValue + randomString(&rng)).utf8)
            let out = SecretInjectionPass.apply(host: host, uri: "/x", headers: [], body: body, rules: [stripe], resolve: resolve)
            if own {
                #expect(out.action == .forward)
                #expect(out.injected.isEmpty)
            } else {
                #expect(out.action == .block)
                #expect(out.blockReason == .secretValueToDisallowedHost(rule: "stripe", host: host.lowercased()))
            }
        }
    }
}
