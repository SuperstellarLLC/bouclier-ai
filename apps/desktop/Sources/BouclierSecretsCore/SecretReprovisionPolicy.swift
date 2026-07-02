import Foundation

/// Decides what happens when a secret is (re)provisioned through the
/// just-in-time dialog an AGENT triggered. The invariant: a re-provision can
/// never WIDEN a secret's policy. This is pure so the rule is locked down by
/// a unit test rather than living only inside the @MainActor coordinator.
public enum SecretReprovisionPolicy {
    public struct Decision: Equatable, Sendable {
        /// Whether to write the value at all. False ⇒ refuse (it's LOCKED).
        public let store: Bool
        public let agentAccess: Bool
        public let allowedHosts: [String]
        public init(store: Bool, agentAccess: Bool, allowedHosts: [String]) {
            self.store = store; self.agentAccess = agentAccess; self.allowedHosts = allowedHosts
        }
    }

    /// - `existingAgentAccess`/`existingAllowedHosts` are nil when no rule of
    ///   that name exists yet (a brand-new secret).
    public static func decide(existingAgentAccess: Bool?, existingAllowedHosts: [String]?) -> Decision {
        guard let access = existingAgentAccess else {
            // New secret: agent-usable, no host binding.
            return Decision(store: true, agentAccess: true, allowedHosts: [])
        }
        if !access {
            // LOCKED: refuse — the agent must not re-provision its way to unlock.
            return Decision(store: false, agentAccess: false, allowedHosts: existingAllowedHosts ?? [])
        }
        // Existing + usable: keep its host binding; never reset to open.
        return Decision(store: true, agentAccess: true, allowedHosts: existingAllowedHosts ?? [])
    }
}
