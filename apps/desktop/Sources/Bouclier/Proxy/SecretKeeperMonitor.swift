import Foundation

/// Runtime safety net for the secret keeper.
///
/// Two jobs:
///
///  1. **Self-test** — runs a battery of canonical vectors through the
///     real `SecretInjectionPass` (the same code the proxy uses) and
///     verifies every invariant holds in *this* binary: clean traffic is
///     untouched, provider auth injects, third-party leaks block, a
///     secret reaching its own host is forwarded. This is the
///     "keep monitoring it remains so" guarantee — it catches a logic
///     regression at process start, not just in CI.
///
///  2. **Circuit breaker** — if the self-test ever fails, the breaker
///     trips and the proxy skips ALL secret-keeper logic, forwarding
///     every request byte-for-byte. The catastrophic failure mode
///     (corrupting or wrongly blocking live LLM traffic) is contained by
///     turning the feature off rather than letting a broken rewriter run.
///
/// The breaker is process-global because the proxy's event-loop handlers
/// read it on the hot path; an `NSLock` guards the flag.
enum SecretKeeperMonitor {
    // MARK: - Circuit breaker

    private static let lock = NSLock()
    nonisolated(unsafe) private static var _tripped = false
    nonisolated(unsafe) private static var _reason: String?

    /// When true, the proxy forwards every request untouched and runs no
    /// secret-keeper logic at all.
    static var isTripped: Bool {
        lock.lock(); defer { lock.unlock() }
        return _tripped
    }

    static var trippedReason: String? {
        lock.lock(); defer { lock.unlock() }
        return _reason
    }

    static func trip(reason: String) {
        lock.lock()
        _tripped = true
        _reason = reason
        lock.unlock()
    }

    /// Test-only: clear the breaker between test cases.
    static func resetForTesting() {
        lock.lock()
        _tripped = false
        _reason = nil
        lock.unlock()
    }

    // MARK: - Self-test

    struct SelfTestReport: Sendable, Equatable {
        let passed: Bool
        /// One line per failed invariant; empty when `passed`.
        let failures: [String]
    }

    /// Canonical, hardcoded secrets used only by the self-test. Values
    /// are tripwire-eligible (long, no whitespace) but obviously fake.
    private static let selfTestStripe = SecretRule(name: "selftest_stripe", allowedHosts: ["api.stripe.com"])
    private static let selfTestAnthropic = SecretRule(name: "selftest_anthropic", allowedHosts: ["api.anthropic.com"])
    private static let selfTestRules = [selfTestStripe, selfTestAnthropic]
    private static let selfTestValues: [String: String] = [
        "selftest_stripe": "sk_live_selftest_0000000000",
        "selftest_anthropic": "sk-ant-selftest-00000000000",
    ]
    private static func selfTestResolve(_ name: String) -> String? { selfTestValues[name] }

    /// Run every invariant against the live pass. Pure and deterministic
    /// — safe to call at startup and from tests.
    static func runSelfTest() -> SelfTestReport {
        var failures: [String] = []
        let stripeValue = selfTestValues["selftest_stripe"]!
        let anthropicPlaceholder = selfTestAnthropic.placeholder
        let stripePlaceholder = selfTestStripe.placeholder

        func header(_ n: String, _ v: String) -> SecretInjectionPass.Header { .init(n, v) }

        // 1. Clean LLM request → no trigger, so the rewriter never runs.
        //    This is THE invariant that protects live LLM connections.
        if hasTrigger(host: "api.anthropic.com",
                      uri: "/v1/messages",
                      headers: [header("authorization", "Bearer sk-ant-userOWNkey-not-managed-123")],
                      body: #"{"model":"claude","messages":[{"role":"user","content":"hello, mention anthropic and stripe casually"}]}"#) {
            failures.append("clean LLM request falsely flagged as containing secret material")
        }

        // 2. Provider auth: own key bound to own host → injected.
        let auth = apply(host: "api.anthropic.com", uri: "/v1/messages",
                         headers: [header("x-api-key", anthropicPlaceholder)], body: "")
        if auth.action != .forward || auth.injected != ["selftest_anthropic"]
            || auth.headers.first?.value != selfTestValues["selftest_anthropic"] {
            failures.append("provider-auth injection did not produce the real key")
        }

        // 3. Third-party key leaking to an LLM provider → blocked.
        let leak = apply(host: "api.anthropic.com", uri: "/v1/messages",
                         headers: [], body: #"{"q":"\#(stripeValue)"}"#)
        if leak.action != .block
            || leak.blockReason != .secretValueToDisallowedHost(rule: "selftest_stripe", host: "api.anthropic.com") {
            failures.append("third-party key leaking to an LLM host was not blocked")
        }

        // 4. Secret reaching its OWN bound host → forwarded, not broken.
        let home = apply(host: "api.stripe.com", uri: "/v1/charges",
                         headers: [header("authorization", "Bearer \(stripeValue)")], body: "")
        if home.action != .forward {
            failures.append("a secret reaching its own bound host was not forwarded")
        }

        // 5. Placeholder to a foreign host → blocked (misdirected injection).
        let misdirect = apply(host: "api.anthropic.com", uri: "/v1/messages",
                              headers: [header("authorization", "Bearer \(stripePlaceholder)")], body: "")
        if misdirect.action != .block
            || misdirect.blockReason != .placeholderToDisallowedHost(rule: "selftest_stripe", host: "api.anthropic.com") {
            failures.append("a misdirected placeholder was not blocked")
        }

        return SelfTestReport(passed: failures.isEmpty, failures: failures)
    }

    // MARK: - Helpers

    private static func hasTrigger(host: String, uri: String, headers: [SecretInjectionPass.Header], body: String) -> Bool {
        SecretInjectionPass.hasTrigger(
            uri: uri, headers: headers, body: Data(body.utf8),
            rules: selfTestRules, resolve: selfTestResolve
        )
    }

    private static func apply(host: String, uri: String, headers: [SecretInjectionPass.Header], body: String) -> SecretInjectionPass.Outcome {
        SecretInjectionPass.apply(
            host: host, uri: uri, headers: headers, body: Data(body.utf8),
            rules: selfTestRules, resolve: selfTestResolve
        )
    }
}
