import Foundation
import Testing
@testable import Bouclier

@Suite("SecretStore")
struct SecretStoreTests {
    // Uses the in-memory test constructor so nothing touches the Keychain
    // or disk (no auth prompts, no mutation of the user's store).

    @Test("Exposes rules, resolves values, and collects all hosts")
    func readApi() {
        let store = SecretStore(
            testing: [
                SecretRule(name: "stripe", allowedHosts: ["api.stripe.com"]),
                SecretRule(name: "github", allowedHosts: ["api.github.com", "uploads.github.com"]),
            ],
            values: ["stripe": "sk_live_x", "github": "ghp_y"]
        )

        #expect(Set(store.rules().map(\.name)) == ["stripe", "github"])
        #expect(store.resolve("stripe") == "sk_live_x")
        #expect(store.resolve("missing") == nil)
        #expect(store.allHosts() == ["api.stripe.com", "api.github.com", "uploads.github.com"])
    }

    @Test("A registered rule with no value resolves nil (fail-closed input)")
    func ruleWithoutValue() {
        let store = SecretStore(
            testing: [SecretRule(name: "stripe", allowedHosts: ["api.stripe.com"])],
            values: [:]
        )
        #expect(store.rules().count == 1)
        #expect(store.resolve("stripe") == nil)
    }

    @Test("Empty store has no hosts and no rules")
    func emptyStore() {
        let store = SecretStore(testing: [], values: [:])
        #expect(store.rules().isEmpty)
        #expect(store.allHosts().isEmpty)
    }

    // These exercise only the validation (early-return) path of
    // addSecret, which rejects before any Keychain/disk write — so they
    // never prompt for Keychain access or mutate the user's store.

    @Test("addSecret rejects invalid names, values, and all-invalid-host rules")
    func addSecretValidation() {
        let store = SecretStore(testing: [], values: [:])
        #expect(!store.addSecret(name: "BadName", value: "sk_live_x_123456", allowedHosts: ["api.stripe.com"]))
        #expect(!store.addSecret(name: "ok", value: "", allowedHosts: ["api.stripe.com"]))
        #expect(!store.addSecret(name: "ok", value: "has\r\nCRLF", allowedHosts: ["api.stripe.com"]))
        // Hosts PROVIDED but all SSRF/local ⇒ no valid host survives ⇒
        // rejected (don't silently downgrade an injectable secret).
        #expect(!store.addSecret(name: "ok", value: "sk_live_x_123456", allowedHosts: ["localhost", "169.254.169.254"]))
        // Nothing was stored.
        #expect(store.rules().isEmpty)
    }

    @Test("A host-less rule is scrub-only; a bound rule is injectable")
    func scrubOnlyRoleClassification() {
        #expect(SecretRule(name: "a", allowedHosts: []).isScrubOnly)
        #expect(!SecretRule(name: "b", allowedHosts: ["api.stripe.com"]).isScrubOnly)
    }

    @Test("Legacy rules JSON decodes with defaults + lowercased hosts, round-trips")
    func legacyDecodeAndRoundTrip() throws {
        // No agentAccess/envVar keys (pre-feature) + mixed-case host.
        let json = #"[{"name":"x","allowedHosts":["API.Stripe.COM"]}]"#
        let rules = try JSONDecoder().decode([SecretRule].self, from: Data(json.utf8))
        #expect(rules.first?.agentAccess == true)         // defaulted
        #expect(rules.first?.envVar == nil)
        #expect(rules.first?.allowedHosts == ["api.stripe.com"]) // lowercased like memberwise init
        // Re-encode → decode preserves everything.
        let again = try JSONDecoder().decode([SecretRule].self, from: JSONEncoder().encode(rules))
        #expect(again == rules)
    }
}
