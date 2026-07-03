import Foundation
import Testing
@testable import Bouclier

/// The privileged half of `CLIInstaller` (`install()`, which shells out via
/// `NSAppleScript` and triggers a real administrator-privileges prompt)
/// isn't exercised here — it can't be, in CI, and shouldn't be. These pin
/// the pure logic: path construction, symlink detection, and the exact
/// shell command that would run, so a change to quoting or path-joining
/// can't silently point the symlink at the wrong binary.
@Suite("CLIInstaller — path + symlink logic")
struct CLIInstallerTests {
    @Test("Binary path joins bundle path with Contents/MacOS")
    func binaryPathJoin() {
        let path = CLIInstaller.binaryPath(named: "bouclier-cli", bundlePath: "/Applications/Bouclier-ai.app")
        #expect(path == "/Applications/Bouclier-ai.app/Contents/MacOS/bouclier-cli")
    }

    @Test("Install shell command creates the parent dir and symlinks the exact CLI path")
    func installShellCommandShape() {
        let cmd = CLIInstaller.installShellCommand(
            cliPath: "/Applications/Bouclier-ai.app/Contents/MacOS/bouclier-cli",
            symlinkPath: "/usr/local/bin/bouclier"
        )
        #expect(cmd.contains("mkdir -p '/usr/local/bin'"))
        #expect(cmd.contains("ln -sf '/Applications/Bouclier-ai.app/Contents/MacOS/bouclier-cli' '/usr/local/bin/bouclier'"))
    }

    @Test("Install shell command single-quote-escapes a path containing a quote")
    func installShellCommandEscapesQuotes() {
        let cmd = CLIInstaller.installShellCommand(cliPath: "/tmp/o'brien/bouclier-cli", symlinkPath: "/tmp/bin/bouclier")
        #expect(cmd.contains("'/tmp/o'\\''brien/bouclier-cli'"))
    }

    @Test("installedTarget is nil when no symlink exists")
    func installedTargetMissing() {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-installer-missing-\(UUID().uuidString)").path
        #expect(CLIInstaller.installedTarget(at: path) == nil)
    }

    @Test("installedTarget resolves an existing symlink")
    func installedTargetResolves() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-installer-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let target = dir.appendingPathComponent("bouclier-cli").path
        let link = dir.appendingPathComponent("bouclier").path
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: target)

        #expect(CLIInstaller.installedTarget(at: link) == target)
    }

    @Test("isInstalled is true only when the symlink points at the given CLI binary")
    func isInstalledMatchesExactTarget() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("cli-installer-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let realCLI = dir.appendingPathComponent("bouclier-cli").path
        let staleCLI = dir.appendingPathComponent("old-bouclier-cli").path
        let link = dir.appendingPathComponent("bouclier").path

        // No symlink yet.
        #expect(!CLIInstaller.isInstalled(cliBinaryPath: realCLI, symlinkPath: link))

        // Symlink points at a different (e.g. stale, pre-update) binary.
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: staleCLI)
        #expect(!CLIInstaller.isInstalled(cliBinaryPath: realCLI, symlinkPath: link))

        // Symlink points at the current binary.
        try FileManager.default.removeItem(atPath: link)
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: realCLI)
        #expect(CLIInstaller.isInstalled(cliBinaryPath: realCLI, symlinkPath: link))
    }
}
