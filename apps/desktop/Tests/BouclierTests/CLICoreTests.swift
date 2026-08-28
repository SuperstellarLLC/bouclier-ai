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

    @Test("status exits 4 and is honest about not-running")
    func statusNotRunning() {
        let r = CLICore.run(["status"], env: env())
        #expect(r.exitCode == CLIExit.notRunning)
        #expect(r.stdout.contains("not running"))
        let j = CLICore.run(["status", "--json"], env: env())
        #expect(j.exitCode == CLIExit.notRunning)
        #expect(j.stdout.contains("\"ok\":false"))
        #expect(j.stdout.contains("\"state\":\"not_running\""))
    }

    @Test("status running surfaces mode + the injection count")
    func statusRunning() {
        let s = BouclierStatus(writtenAt: 1, pid: 1, appVersion: "9.0", running: true, mode: "standard",
            caInstalled: false, protectionEnabled: true, detectorEnabled: true,
            blockingEnabled: true,
            patternCount: 186, mlClassifierState: "active",
            activity: .init(requestsScanned: 7, injectionsBlocked: 3,
                            injectionFindingsFlagged: 2, requestsSkippedInspection: 1,
                            requestsBlockedByInspectionLimit: 1))
        let r = CLICore.run(["status"], env: env(status: .running(s)))
        #expect(r.exitCode == CLIExit.ok)
        #expect(r.stdout.contains("ON"))
        #expect(r.stdout.contains("blocking"))
        #expect(r.stdout.contains("standard"))
        #expect(r.stdout.contains("engine: 186 patterns, Prompt Guard 2 active"))
        // The flagship metric must be visible in `bouclier status` — it is
        // tracked and published to status.json but used to be printed
        // nowhere (the whole point of the firewall is a number, not a vibe).
        #expect(r.stdout.contains("3 requests blocked by the detector"))
        #expect(r.stdout.contains("2 monitor findings allowed"))
        #expect(r.stdout.contains("1 coverage refusal"))
        #expect(r.stdout.contains("1 inspection skip"))
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

    @Test("A live passthrough gateway is reported as protection OFF, not ON")
    func statusPassthroughIsNotProtection() {
        let s = BouclierStatus(
            writtenAt: 1, pid: 1, appVersion: "9.0", running: true,
            mode: "standard", caInstalled: false, protectionEnabled: false,
            detectorEnabled: false, blockingEnabled: false,
            activity: .init(requestsScanned: 7, injectionsBlocked: 0)
        )
        let r = CLICore.run(["status"], env: env(status: .running(s)))
        #expect(r.stdout.contains("protection OFF — gateway passthrough"))
        #expect(r.stdout.contains("gateway passthrough does not inspect request bodies"))
        #expect(!r.stdout.contains("protection ON"))
        #expect(!r.stdout.contains("ON — blocking"))
        #expect(!r.stdout.contains("ON — monitoring"))
        #expect(!r.stdout.contains("monitor finding"))
        #expect(!r.stdout.contains("blocked by the detector"))
    }

    @Test("Detector-disabled protection is explicitly degraded and not inspecting")
    func statusDetectorDisabledIsDegraded() {
        let s = BouclierStatus(
            writtenAt: 1, pid: 1, appVersion: "9.0", running: true,
            mode: "standard", caInstalled: false, protectionEnabled: true,
            detectorEnabled: false, blockingEnabled: true,
            patternCount: 186, mlClassifierState: "active",
            activity: .init(requestsScanned: 7, injectionsBlocked: 3,
                            injectionFindingsFlagged: 2, requestsSkippedInspection: 1,
                            requestsBlockedByInspectionLimit: 1)
        )
        let r = CLICore.run(["status"], env: env(status: .running(s)))
        #expect(r.stdout.contains("protection DEGRADED — detector disabled, not inspecting"))
        #expect(r.stdout.contains("request bodies are not inspected"))
        #expect(r.stdout.contains("detector currently disabled"))
        #expect(!r.stdout.contains("ON — blocking"))
        #expect(!r.stdout.contains("ON — monitoring"))
        #expect(!r.stdout.contains("monitor finding"))
        #expect(!r.stdout.contains("blocked by the detector"))

        let json = CLICore.run(["status", "--json"], env: env(status: .running(s)))
        #expect(json.stdout.contains("\"detectorEnabled\":false"))
        #expect(json.stdout.contains("\"blockingEnabled\":false"))
    }

    @Test("install prints the PATH + read-only MCP status commands")
    func install() {
        let r = CLICore.run(["install"], env: env())
        #expect(r.exitCode == CLIExit.ok)
        #expect(r.stdout.contains("bouclier-ai-mcp-wrapper"))
        #expect(r.stdout.contains("ln -sf"))
        #expect(r.stdout.contains("read-only Bouclier status MCP server"))
    }

    @Test("Shell commands quote app paths and embedded single quotes")
    func installCommandShellQuoting() {
        #expect(CLICore.shellQuoted("/Applications/Bouclier AI.app/bin") == "'/Applications/Bouclier AI.app/bin'")
        #expect(CLICore.shellQuoted("/tmp/O'Brien/app") == "'/tmp/O'\\''Brien/app'")
    }

    @Test("Install commands resolve the PATH symlink back into the app bundle")
    func installCommandsResolveSymlink() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("bouclier cli link \(UUID().uuidString)")
        let appBin = dir.appendingPathComponent("Bouclier AI.app/Contents/MacOS")
        let target = appBin.appendingPathComponent("bouclier-cli")
        let link = dir.appendingPathComponent("bin/bouclier")
        try FileManager.default.createDirectory(at: appBin, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: link.deletingLastPathComponent(), withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: target.path, contents: Data())
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: target)
        defer { try? FileManager.default.removeItem(at: dir) }

        let commands = CLICore.installCommands(executablePath: link.path)
        #expect(commands.cliPath == target.path)
        #expect(commands.mcpPath == appBin.appendingPathComponent("bouclier-ai-mcp-wrapper").path)
        #expect(commands.pathCommand.contains("Bouclier AI.app"))
        #expect(commands.mcpCommand.contains("Bouclier AI.app"))
        #expect(!commands.mcpPath.contains("/bin/bouclier-ai-mcp-wrapper"))
    }

    @Test("CLI version resolves from the containing app Info.plist")
    func versionComesFromContainingApp() throws {
        let app = FileManager.default.temporaryDirectory
            .appendingPathComponent("Bouclier Version \(UUID().uuidString).app")
        let contents = app.appendingPathComponent("Contents")
        let macOS = contents.appendingPathComponent("MacOS")
        try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: app) }

        let plist: [String: Any] = ["CFBundleShortVersionString": "0.9.10"]
        let data = try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
        try data.write(to: contents.appendingPathComponent("Info.plist"))

        #expect(CLICore.version(containingExecutableAt: macOS.appendingPathComponent("bouclier-cli")) == "0.9.10")
        #expect(CLICore.version(containingExecutableAt: URL(fileURLWithPath: "/tmp/bouclier-cli")) == nil)
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
