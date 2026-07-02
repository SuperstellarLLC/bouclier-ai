import Testing
@testable import BouclierSecretsCore

/// Pins the "re-provision can never widen a secret's policy" invariant — the
/// critical hole the agent-control review caught: an agent triggering a JIT
/// request for a LOCKED or host-bound secret must not be able to unlock it
/// or clear its allow-list.
@Suite("SecretReprovisionPolicy — no widening")
struct SecretReprovisionPolicyTests {
    @Test("brand-new secret → store, agent-usable, no host binding")
    func newSecret() {
        let d = SecretReprovisionPolicy.decide(existingAgentAccess: nil, existingAllowedHosts: nil)
        #expect(d == .init(store: true, agentAccess: true, allowedHosts: []))
    }

    @Test("LOCKED secret → refuse (must not unlock via re-provision)")
    func lockedRefused() {
        let d = SecretReprovisionPolicy.decide(existingAgentAccess: false, existingAllowedHosts: ["api.stripe.com"])
        #expect(d.store == false)
        #expect(d.agentAccess == false)
    }

    @Test("existing usable secret → keep its host binding, never reset to open")
    func preservesHosts() {
        let d = SecretReprovisionPolicy.decide(existingAgentAccess: true, existingAllowedHosts: ["api.stripe.com"])
        #expect(d == .init(store: true, agentAccess: true, allowedHosts: ["api.stripe.com"]))
    }
}
