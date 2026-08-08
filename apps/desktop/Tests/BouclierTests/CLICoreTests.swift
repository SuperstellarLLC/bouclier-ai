import Foundation
import Testing
@testable import BouclierCore

/// The `bouclier` CLI is how a Bash-driven agent reads Bouclier's state.
/// These pin the stable exit-code contract and the structural guarantee that
/// the CLI is read-only — there is no path to a state-changing operation
/// (disable the firewall, install a CA).
@Suite("CLICore — agent CLI contract")
struct CLICoreTests {
    private func env(
        status: StatusReader.State = .notRunning(reason: "Bouclier is not running")
    ) -> CLIEnv {
        CLIEnv(loadStatus: { status })
    }

    @Test("status always exits 0 and is honest about not-running")
    func statusNotRunning() {
        let r = CLICore.run(["status"], env: env())
        #expect(r.exitCode == CLIExit.ok)
        #expect(r.stdout.contains("not running"))
        let j = CLICore.run(["status", "--json"], env: env())
        #expect(j.stdout.contains("\"state\":\"not_running\""))
    }

    @Test("status running surfaces mode + the injection count")
    func statusRunning() {
        let s = BouclierStatus(writtenAt: 1, pid: 1, appVersion: "9.0", running: true, mode: "standard",
            caInstalled: false, protectionEnabled: true,
            activity: .init(requestsScanned: 7, injectionsBlocked: 3))
        let r = CLICore.run(["status"], env: env(status: .running(s)))
        #expect(r.exitCode == CLIExit.ok)
        #expect(r.stdout.contains("ON"))
        #expect(r.stdout.contains("standard"))
        // The flagship metric must be visible in `bouclier status` — it is
        // tracked and published to status.json but used to be printed
        // nowhere (the whole point of the firewall is a number, not a vibe).
        #expect(r.stdout.contains("3 injections blocked"))
    }

    @Test("status --json embeds the full status object")
    func statusRunningJSON() {
        let s = BouclierStatus(writtenAt: 1, pid: 1, appVersion: "9.0", running: true, mode: "standard",
            caInstalled: false, protectionEnabled: true,
            activity: .init(requestsScanned: 7, injectionsBlocked: 3))
        let j = CLICore.run(["status", "--json"], env: env(status: .running(s)))
        #expect(j.stdout.contains("\"state\":\"running\""))
        #expect(j.stdout.contains("\"injectionsBlocked\":3"))
    }

    @Test("install prints the PATH + MCP commands, references the injection MCP")
    func install() {
        let r = CLICore.run(["install"], env: env())
        #expect(r.exitCode == CLIExit.ok)
        #expect(r.stdout.contains("bouclier-ai-mcp-wrapper"))
        #expect(r.stdout.contains("ln -sf"))
    }

    @Test("usage errors exit 2; version exits 0; removed commands are unknown")
    func usageAndVersion() {
        #expect(CLICore.run(["bogus"], env: env()).exitCode == CLIExit.usage)
        // The secret-keeper commands are gone: they resolve as unknown.
        #expect(CLICore.run(["secrets"], env: env()).exitCode == CLIExit.usage)
        #expect(CLICore.run(["env", "set", "x"], env: env()).exitCode == CLIExit.usage)
        #expect(CLICore.run(["--version"], env: env()).exitCode == CLIExit.ok)
        #expect(CLICore.run([], env: env()).exitCode == CLIExit.ok)  // bare → help
    }
}
