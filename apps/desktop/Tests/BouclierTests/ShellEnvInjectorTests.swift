import Foundation
import Testing
@testable import Bouclier

/// `~/.zshenv` is sourced for every non-interactive zsh invocation —
/// corrupting it is "user can't open a terminal" territory. Each test
/// runs against a tmp file so we never touch the real home; the
/// assertions cover the cases that broke real users on similar tools:
/// duplicated blocks on re-apply, content loss on apply→strip, and
/// the recovery path when an end marker is missing.
@Suite("ShellEnvInjector — inject/strip semantics")
struct ShellEnvInjectorTests {
    private static func tmpFile(prefix: String) -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString).sh")
        try? FileManager.default.removeItem(at: url)
        return url
    }

    private static func read(_ url: URL) -> String {
        (try? String(contentsOf: url, encoding: .utf8)) ?? ""
    }

    @Test("Inject into empty file produces just the managed block")
    func injectIntoEmptyFile() {
        let url = Self.tmpFile(prefix: "empty")
        defer { try? FileManager.default.removeItem(at: url) }

        ShellEnvInjector.injectBlock(into: url, payload: "PAYLOAD")
        let content = Self.read(url)

        #expect(content.contains("PAYLOAD"))
        #expect(content.contains("# >>> bouclier.ai env (managed) >>>"))
        #expect(content.contains("# <<< bouclier.ai env (managed) <<<"))
    }

    @Test("Re-applying does not duplicate the block")
    func reapplyIsIdempotent() {
        let url = Self.tmpFile(prefix: "idempotent")
        defer { try? FileManager.default.removeItem(at: url) }
        try? "export FOO=bar\n".write(to: url, atomically: true, encoding: .utf8)

        ShellEnvInjector.injectBlock(into: url, payload: "FIRST")
        let afterFirst = Self.read(url)
        ShellEnvInjector.injectBlock(into: url, payload: "FIRST")
        let afterSecond = Self.read(url)

        #expect(afterFirst == afterSecond, "Second apply must not change anything when payload is identical")
        let beginCount = afterSecond.components(separatedBy: "# >>> bouclier.ai env (managed) >>>").count - 1
        #expect(beginCount == 1, "Exactly one managed block, never two")
    }

    @Test("Updated payload replaces the old block in place")
    func updatedPayloadReplacesBlock() {
        let url = Self.tmpFile(prefix: "replace")
        defer { try? FileManager.default.removeItem(at: url) }

        ShellEnvInjector.injectBlock(into: url, payload: "OLD_PAYLOAD")
        ShellEnvInjector.injectBlock(into: url, payload: "NEW_PAYLOAD")
        let content = Self.read(url)

        #expect(!content.contains("OLD_PAYLOAD"))
        #expect(content.contains("NEW_PAYLOAD"))
    }

    @Test("Strip after inject restores original content byte-for-byte")
    func stripRestoresOriginal() {
        let url = Self.tmpFile(prefix: "restore")
        defer { try? FileManager.default.removeItem(at: url) }
        let original = "export FOO=bar\nalias ll='ls -la'\n"
        try? original.write(to: url, atomically: true, encoding: .utf8)

        ShellEnvInjector.injectBlock(into: url, payload: "PAYLOAD")
        ShellEnvInjector.stripBlock(from: url)
        let after = Self.read(url)

        #expect(after == original, "Apply→strip must be a no-op for user content")
    }

    @Test("User's own additions outside the block survive a strip")
    func userContentSurvivesStrip() {
        let url = Self.tmpFile(prefix: "survive")
        defer { try? FileManager.default.removeItem(at: url) }
        try? "before user line\n".write(to: url, atomically: true, encoding: .utf8)

        ShellEnvInjector.injectBlock(into: url, payload: "PAYLOAD")
        // Simulate the user editing _after_ the block.
        if var content = try? String(contentsOf: url, encoding: .utf8) {
            content += "after user line\n"
            try? content.write(to: url, atomically: true, encoding: .utf8)
        }
        ShellEnvInjector.stripBlock(from: url)
        let after = Self.read(url)

        #expect(after.contains("before user line"))
        #expect(after.contains("after user line"))
        #expect(!after.contains("PAYLOAD"))
    }

    @Test("Strip removes the file entirely when nothing else was in it")
    func stripDeletesEmptyFile() {
        let url = Self.tmpFile(prefix: "delete")
        defer { try? FileManager.default.removeItem(at: url) }

        ShellEnvInjector.injectBlock(into: url, payload: "PAYLOAD")
        ShellEnvInjector.stripBlock(from: url)

        #expect(!FileManager.default.fileExists(atPath: url.path),
                "Stripping the only block in a file we created should leave no stray file behind")
    }

    @Test("Recovers gracefully when the end marker is missing")
    func recoversFromMalformedBlock() {
        let url = Self.tmpFile(prefix: "malformed")
        defer { try? FileManager.default.removeItem(at: url) }
        // User accidentally deletes the end marker line.
        let malformed = "user line\n# >>> bouclier.ai env (managed) >>>\nstale payload\n"
        try? malformed.write(to: url, atomically: true, encoding: .utf8)

        ShellEnvInjector.injectBlock(into: url, payload: "FRESH")
        let after = Self.read(url)

        #expect(after.contains("user line"))
        #expect(after.contains("FRESH"))
        #expect(!after.contains("stale payload"))
        let beginCount = after.components(separatedBy: "# >>> bouclier.ai env (managed) >>>").count - 1
        #expect(beginCount == 1, "Recovery must not leave a duplicate begin marker")
    }
}
