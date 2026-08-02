import Foundation
import Testing
@testable import BouclierSecretsCore

/// The `bouclier` CLI is how a Bash-driven agent uses Bouclier. These pin
/// the stable exit-code contract and the structural guarantee that there is
/// no CLI path to a RED operation (disable the firewall, read a value).
@Suite("CLICore — agent CLI contract")
struct CLICoreTests {
    private func env(
        status: StatusReader.State = .notRunning(reason: "Bouclier is not running"),
        rules: [SecretRuleMeta] = [],
        active: [String] = [],
        saveActive: @escaping @Sendable ([String]) -> Void = { _ in },
        requestSecrets: @escaping @Sendable ([String], String, Bool, TimeInterval) -> SecretResponseIPC? = { _, _, _, _ in nil },
        proposeEnable: @escaping @Sendable (String, String, TimeInterval) -> ActionResponseIPC? = { _, _, _ in nil }
    ) -> CLIEnv {
        CLIEnv(loadStatus: { status }, loadRules: { rules }, loadActive: { active },
               saveActive: saveActive, requestSecrets: requestSecrets, proposeEnable: proposeEnable)
    }

    @Test("status always exits 0 and is honest about not-running")
    func statusNotRunning() {
        let r = CLICore.run(["status"], env: env())
        #expect(r.exitCode == CLIExit.ok)
        #expect(r.stdout.contains("not running"))
        let j = CLICore.run(["status", "--json"], env: env())
        #expect(j.stdout.contains("\"state\":\"not_running\""))
    }

    @Test("status running surfaces mode + counts, never a value")
    func statusRunning() {
        let s = BouclierStatus(writtenAt: 1, pid: 1, appVersion: "9.0", running: true, mode: "standard",
            caInstalled: false, protectionEnabled: true,
            secretKeeper: .init(enabled: true, healthy: true, circuitBreakerTripped: false),
            secrets: .init(total: 1, agentAccessible: 1, active: 0),
            activity: .init(requestsScanned: 7, injectionsBlocked: 3, secretsScrubbed: 1, secretsInjected: 0, secretsBlocked: 0))
        let r = CLICore.run(["status"], env: env(status: .running(s)))
        #expect(r.exitCode == CLIExit.ok)
        #expect(r.stdout.contains("ON"))
        #expect(r.stdout.contains("standard"))
        // The flagship metric must be visible in `bouclier status` — it is
        // tracked and published to status.json but used to be printed
        // nowhere (the whole point of the firewall is a number, not a vibe).
        #expect(r.stdout.contains("3 injections blocked"))
    }

    @Test("secrets list shows names not values")
    func secretsList() {
        let rules = [SecretRuleMeta(name: "stripe", agentAccess: true, envVar: "STRIPE_KEY"),
                     SecretRuleMeta(name: "locked", agentAccess: false, envVar: "LOCKED_KEY")]
        let r = CLICore.run(["secrets", "list"], env: env(rules: rules, active: ["stripe"]))
        #expect(r.stdout.contains("STRIPE_KEY"))
        #expect(r.stdout.contains("LOCKED"))
    }

    @Test("env set activates allowed, denies locked/unknown (exit 7 when none)")
    func envSet() {
        let rules = [SecretRuleMeta(name: "ok", agentAccess: true, envVar: "OK")]
        final class Captured: @unchecked Sendable { var v: [String] = [] }
        let saved = Captured()
        let r = CLICore.run(["env", "set", "ok", "nope"], env: env(rules: rules, saveActive: { saved.v = $0 }))
        #expect(r.exitCode == CLIExit.ok)
        #expect(saved.v == ["ok"])

        let denied = CLICore.run(["env", "set", "nope"], env: env(rules: rules))
        #expect(denied.exitCode == CLIExit.denied)
    }

    @Test("protection enable maps approval outcomes to exit codes")
    func protectionEnable() {
        @Sendable func resp(_ s: ActionResponseIPC.Status) -> ActionResponseIPC { ActionResponseIPC(id: "x", action: "enable_protection", status: s, message: "m") }
        #expect(CLICore.run(["protection", "enable"], env: env(proposeEnable: { _, _, _ in resp(.approved) })).exitCode == CLIExit.ok)
        #expect(CLICore.run(["protection", "enable"], env: env(proposeEnable: { _, _, _ in resp(.declined) })).exitCode == CLIExit.declined)
        #expect(CLICore.run(["protection", "enable"], env: env(proposeEnable: { _, _, _ in resp(.timeout) })).exitCode == CLIExit.timeout)
        #expect(CLICore.run(["protection", "enable"], env: env(proposeEnable: { _, _, _ in nil })).exitCode == CLIExit.notRunning)
    }

    @Test("protection disable is structurally denied — no agent can turn off the firewall")
    func protectionDisableDenied() {
        let r = CLICore.run(["protection", "disable"], env: env())
        #expect(r.exitCode == CLIExit.denied)
        #expect(r.stdout.contains("isn't available to agents"))
    }

    @Test("secrets request maps outcomes to exit codes")
    func secretsRequest() {
        #expect(CLICore.run(["secrets", "request", "K"], env: env(requestSecrets: { _, _, _, _ in SecretResponseIPC(id: "x", status: .provided, provided: ["K"], skipped: []) })).exitCode == CLIExit.ok)
        #expect(CLICore.run(["secrets", "request", "K"], env: env(requestSecrets: { _, _, _, _ in SecretResponseIPC(id: "x", status: .cancelled, provided: [], skipped: ["K"]) })).exitCode == CLIExit.declined)
        #expect(CLICore.run(["secrets", "request", "K"], env: env(requestSecrets: { _, _, _, _ in SecretResponseIPC(id: "x", status: .timeout, provided: [], skipped: ["K"]) })).exitCode == CLIExit.timeout)
        #expect(CLICore.run(["secrets", "request", "K"], env: env(requestSecrets: { _, _, _, _ in nil })).exitCode == CLIExit.notRunning)
    }

    @Test("usage errors exit 2; version exits 0")
    func usageAndVersion() {
        #expect(CLICore.run(["bogus"], env: env()).exitCode == CLIExit.usage)
        #expect(CLICore.run(["secrets"], env: env()).exitCode == CLIExit.usage)   // missing subcommand
        #expect(CLICore.run(["--version"], env: env()).exitCode == CLIExit.ok)
        #expect(CLICore.run([], env: env()).exitCode == CLIExit.ok)               // bare → help
    }
}
