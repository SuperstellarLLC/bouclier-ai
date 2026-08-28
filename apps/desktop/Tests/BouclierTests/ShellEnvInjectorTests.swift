import Foundation
import Testing
@testable import Bouclier

/// `~/.zshenv` is sourced for every non-interactive zsh invocation —
/// corrupting it is "user can't open a terminal" territory. Each test
/// runs against a tmp file so we never touch the real home; the
/// assertions cover the cases that broke real users on similar tools:
/// duplicated blocks on re-apply, content loss on apply→strip, and
/// fail-closed handling when managed markers are malformed.
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

    private static func tmpDirectory(prefix: String) throws -> URL {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("\(prefix)-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    private struct POSIXEnvResult {
        let anthropicIsSet: Bool
        let anthropicValue: String
        let openAIIsSet: Bool
        let openAIValue: String
    }

    /// Execute the generated POSIX file with a deterministic health result.
    /// The production probe is an absolute-path curl pipeline, so replace only
    /// that exact generated command with `true`/`false`; all ownership logic is
    /// exercised by `/bin/sh` exactly as a sourced profile would execute it.
    private static func runPOSIXEnvFile(
        _ content: String,
        gatewayPort: Int,
        healthy: Bool,
        initial: [String: String]
    ) throws -> POSIXEnvResult {
        let probe = ShellEnvInjector.healthProbeCommand(port: gatewayPort)
        var script = content.replacingOccurrences(
            of: probe,
            with: healthy ? "true" : "false"
        )
        script += """

        printf '__BOUCLIER_A_SET__%s\n' "${ANTHROPIC_BASE_URL+x}"
        printf '__BOUCLIER_A_VALUE__%s\n' "${ANTHROPIC_BASE_URL-}"
        printf '__BOUCLIER_O_SET__%s\n' "${OPENAI_BASE_URL+x}"
        printf '__BOUCLIER_O_VALUE__%s\n' "${OPENAI_BASE_URL-}"
        """

        let process = Process()
        let stdout = Pipe()
        let stderr = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", script]
        var environment = ProcessInfo.processInfo.environment
        environment.removeValue(forKey: "ANTHROPIC_BASE_URL")
        environment.removeValue(forKey: "OPENAI_BASE_URL")
        for (key, value) in initial { environment[key] = value }
        process.environment = environment
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        let outputData = stdout.fileHandleForReading.readDataToEndOfFile()
        let errorData = stderr.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let output = String(data: outputData, encoding: .utf8) ?? ""
        let error = String(data: errorData, encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            throw NSError(
                domain: "ShellEnvInjectorTests",
                code: Int(process.terminationStatus),
                userInfo: [NSLocalizedDescriptionKey: "Generated POSIX file failed: \(error)\n\(output)"]
            )
        }

        func value(after prefix: String) -> String? {
            output.split(separator: "\n", omittingEmptySubsequences: false)
                .map(String.init)
                .first(where: { $0.hasPrefix(prefix) })
                .map { String($0.dropFirst(prefix.count)) }
        }
        guard let anthropicSet = value(after: "__BOUCLIER_A_SET__"),
              let anthropicValue = value(after: "__BOUCLIER_A_VALUE__"),
              let openAISet = value(after: "__BOUCLIER_O_SET__"),
              let openAIValue = value(after: "__BOUCLIER_O_VALUE__")
        else {
            throw NSError(
                domain: "ShellEnvInjectorTests",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Could not parse generated shell output: \(output)"]
            )
        }
        return POSIXEnvResult(
            anthropicIsSet: anthropicSet == "x",
            anthropicValue: anthropicValue,
            openAIIsSet: openAISet == "x",
            openAIValue: openAIValue
        )
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

    @Test("Strip surfaces a real read failure instead of claiming removal")
    func stripReportsReadFailure() {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("bouclier-strip-directory-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: directory) }

        #expect(!ShellEnvInjector.stripBlock(from: directory),
                "A directory cannot be read as a shell profile; cleanup must return partial failure")
        #expect(!ShellEnvInjector.injectBlock(into: directory, payload: "PAYLOAD"),
                "A directory cannot be treated as an empty shell profile during apply")
    }

    @Test("A non-UTF-8 profile is never overwritten as though it were empty")
    func invalidUTF8IsPreserved() throws {
        let url = Self.tmpFile(prefix: "invalid-utf8")
        defer { try? FileManager.default.removeItem(at: url) }
        let original = Data([0x65, 0x78, 0x70, 0x6F, 0x72, 0x74, 0x20, 0xFF, 0x0A])
        try original.write(to: url)

        #expect(!ShellEnvInjector.injectBlock(into: url, payload: "PAYLOAD"))
        #expect(!ShellEnvInjector.stripBlock(from: url))
        let after = try Data(contentsOf: url)
        #expect(after == original, "Failed decoding must leave every original byte untouched")
    }

    @Test("An absolute profile symlink survives inject and strip")
    func absoluteSymlinkIsPreserved() throws {
        let directory = try Self.tmpDirectory(prefix: "absolute-symlink")
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("profile-target")
        let link = directory.appendingPathComponent("profile-link")
        let original = "export USER_SETTING=kept\n"
        try original.write(to: target, atomically: false, encoding: .utf8)
        try FileManager.default.createSymbolicLink(
            atPath: link.path,
            withDestinationPath: target.path
        )

        #expect(ShellEnvInjector.injectBlock(into: link, payload: "PAYLOAD"))
        #expect(Self.read(target).contains("PAYLOAD"))
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == target.path)

        #expect(ShellEnvInjector.stripBlock(from: link))
        #expect(Self.read(target) == original)
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == target.path)
    }

    @Test("A relative profile symlink survives inject and strip")
    func relativeSymlinkIsPreserved() throws {
        let directory = try Self.tmpDirectory(prefix: "relative-symlink")
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("profile-target")
        let link = directory.appendingPathComponent("profile-link")
        let relativeDestination = target.lastPathComponent
        let original = "alias safe='true'\n"
        try original.write(to: target, atomically: false, encoding: .utf8)
        try FileManager.default.createSymbolicLink(
            atPath: link.path,
            withDestinationPath: relativeDestination
        )

        #expect(ShellEnvInjector.injectBlock(into: link, payload: "PAYLOAD"))
        #expect(Self.read(target).contains("PAYLOAD"))
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == relativeDestination)

        #expect(ShellEnvInjector.stripBlock(from: link))
        #expect(Self.read(target) == original)
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == relativeDestination)
    }

    @Test("Stripping a block-only symlink keeps the link and empties its target")
    func blockOnlySymlinkIsPreserved() throws {
        let directory = try Self.tmpDirectory(prefix: "empty-symlink")
        defer { try? FileManager.default.removeItem(at: directory) }
        let target = directory.appendingPathComponent("profile-target")
        let link = directory.appendingPathComponent("profile-link")
        try Data().write(to: target)
        try FileManager.default.createSymbolicLink(
            atPath: link.path,
            withDestinationPath: target.lastPathComponent
        )

        #expect(ShellEnvInjector.injectBlock(into: link, payload: "PAYLOAD"))
        #expect(ShellEnvInjector.stripBlock(from: link))
        #expect(FileManager.default.fileExists(atPath: target.path))
        #expect(Self.read(target).isEmpty)
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: link.path) == target.lastPathComponent)
    }

    @Test("A dangling profile symlink fails apply and strip without being replaced")
    func danglingSymlinkIsNotFalseSuccess() throws {
        let link = Self.tmpFile(prefix: "dangling")
        let missingTarget = Self.tmpFile(prefix: "missing-target")
        try FileManager.default.createSymbolicLink(
            at: link,
            withDestinationURL: missingTarget
        )
        defer { try? FileManager.default.removeItem(at: link) }

        #expect(!ShellEnvInjector.injectBlock(into: link, payload: "PAYLOAD"))
        #expect(!ShellEnvInjector.stripBlock(from: link))
        #expect(!FileManager.default.fileExists(atPath: missingTarget.path))
        _ = try FileManager.default.destinationOfSymbolicLink(atPath: link.path)
    }

    @Test("POSIX env file gates exports behind the Bouclier liveness check AND unsets stale values")
    func posixFileIsFailOpen() {
        let exports = ShellEnvInjector.buildStandardExports(gatewayPort: 8484)
        let ownership: [String: ShellEnvInjector.LaunchctlOwnershipRecord] = [
            "ANTHROPIC_BASE_URL": .init(ownedValues: ["http://127.0.0.1:7777"]),
            "OPENAI_BASE_URL": .init(ownedValues: ["http://127.0.0.1:7777/v1"]),
        ]
        let content = ShellEnvInjector.posixEnvFileContent(
            exports: exports,
            launchctlOwnership: ownership
        )

        // The guard line MUST come before the exports — otherwise the
        // exports happen unconditionally and we're back to "connection
        // refused for every command" when Bouclier isn't listening.
        guard let guardIdx = content.range(of: "http://127.0.0.1:8484/livez"),
              let exportIdx = content.range(of: "export ANTHROPIC_BASE_URL=")
        else {
            Issue.record("Expected both the `/livez` guard and `export ANTHROPIC_BASE_URL` in:\n\(content)")
            return
        }
        #expect(guardIdx.lowerBound < exportIdx.lowerBound,
                "Fail-open liveness check must precede the exports")
        #expect(content.contains("if [ \"${ANTHROPIC_BASE_URL+x}\" != \"x\" ]; then"),
                "A live gateway may claim an unset value")
        #expect(content.contains("elif [ \"${ANTHROPIC_BASE_URL-}\" = \"http://127.0.0.1:7777\" ] || [ \"${ANTHROPIC_BASE_URL-}\" = \"http://127.0.0.1:8484\" ]; then"),
                "A live gateway may replace only exact current/historical Bouclier values")
        // Explicit unset in the else branch is what makes fail-open
        // actually work — without it, a stale ANTHROPIC_BASE_URL inherited
        // from launchctl or the parent shell would survive even when
        // Bouclier is down. Caught during live QA on 2026-05-25.
        #expect(content.contains("else"))
        #expect(content.contains("if [ \"${ANTHROPIC_BASE_URL-}\" = \"http://127.0.0.1:7777\" ] || [ \"${ANTHROPIC_BASE_URL-}\" = \"http://127.0.0.1:8484\" ]; then unset ANTHROPIC_BASE_URL; fi"),
                "else-branch may unset only an exact Bouclier-owned value")
        #expect(content.contains("if [ \"${OPENAI_BASE_URL-}\" = \"http://127.0.0.1:7777/v1\" ] || [ \"${OPENAI_BASE_URL-}\" = \"http://127.0.0.1:8484/v1\" ]; then unset OPENAI_BASE_URL; fi"))
        #expect(!content.contains("unset ANTHROPIC_BASE_URL OPENAI_BASE_URL"),
                "a combined unconditional unset would erase a corporate/user endpoint")
        #expect(content.contains("fi"), "Guard block must be closed with `fi`")
    }

    @Test("Fish env file gates exports behind the Bouclier liveness check AND unsets stale values")
    func fishFileIsFailOpen() {
        let exports = ShellEnvInjector.buildStandardExports(gatewayPort: 9999)
        let corporate = "https://user:secret@corporate.example/v1"
        let ownership: [String: ShellEnvInjector.LaunchctlOwnershipRecord] = [
            "ANTHROPIC_BASE_URL": .init(ownedValues: [
                "http://127.0.0.1:8484",
                corporate,
            ]),
            "OPENAI_BASE_URL": .init(ownedValues: ["http://127.0.0.1:8484/v1"]),
        ]
        let content = ShellEnvInjector.fishEnvFileContent(
            exports: exports,
            launchctlOwnership: ownership
        )

        #expect(content.contains("http://127.0.0.1:9999/livez"),
                "Fish guard should pull the port from the configured gateway URL, not hardcode 8484")
        #expect(content.contains("if not set -q ANTHROPIC_BASE_URL"),
                "Fish may claim an unset variable")
        #expect(content.contains("else if test \"$ANTHROPIC_BASE_URL\" = \"http://127.0.0.1:8484\"; or test \"$ANTHROPIC_BASE_URL\" = \"http://127.0.0.1:9999\""),
                "Fish may replace only exact current/historical Bouclier values")
        #expect(content.contains("set -gx ANTHROPIC_BASE_URL"))
        #expect(content.contains("set -e ANTHROPIC_BASE_URL"),
                "Fish else-branch must explicitly erase, not just skip exports")
        #expect(content.contains("if test \"$ANTHROPIC_BASE_URL\" = \"http://127.0.0.1:8484\"; or test \"$ANTHROPIC_BASE_URL\" = \"http://127.0.0.1:9999\""),
                "Fish may erase only an exact Bouclier-owned value")
        #expect(content.contains("if test \"$OPENAI_BASE_URL\" = \"http://127.0.0.1:8484/v1\"; or test \"$OPENAI_BASE_URL\" = \"http://127.0.0.1:9999/v1\""))
        #expect(!content.contains(corporate),
                "foreign or credential-bearing URLs must never enter generated shell files")
        #expect(!content.contains("set -e ANTHROPIC_BASE_URL OPENAI_BASE_URL"),
                "a combined unconditional erase would destroy an unrelated endpoint")
        #expect(content.contains("end"), "Fish if/end block must close")
    }

    @Test("Generated POSIX env mutates unset or owned values and preserves foreign values per key")
    func posixOwnershipIsEnforcedAtRuntime() throws {
        let exports = ShellEnvInjector.buildStandardExports(gatewayPort: 9999)
        let ownership: [String: ShellEnvInjector.LaunchctlOwnershipRecord] = [
            "ANTHROPIC_BASE_URL": .init(ownedValues: ["http://127.0.0.1:8484"]),
            "OPENAI_BASE_URL": .init(ownedValues: ["http://127.0.0.1:8484/v1"]),
        ]
        let content = ShellEnvInjector.posixEnvFileContent(
            exports: exports,
            launchctlOwnership: ownership
        )
        let foreignAnthropic = "https://user:secret@corp.example/anthropic"
        let foreignOpenAI = "https://corp.example/openai/v1"
        #expect(!content.contains(foreignAnthropic))
        #expect(!content.contains(foreignOpenAI))

        let fillsOnlyUnset = try Self.runPOSIXEnvFile(
            content,
            gatewayPort: 9999,
            healthy: true,
            initial: ["ANTHROPIC_BASE_URL": foreignAnthropic]
        )
        #expect(fillsOnlyUnset.anthropicIsSet)
        #expect(fillsOnlyUnset.anthropicValue == foreignAnthropic,
                "a healthy gateway must preserve a foreign Anthropic endpoint")
        #expect(fillsOnlyUnset.openAIIsSet)
        #expect(fillsOnlyUnset.openAIValue == "http://127.0.0.1:9999/v1",
                "the other key is independent and may fill an unset value")

        let advancesOwnedPort = try Self.runPOSIXEnvFile(
            content,
            gatewayPort: 9999,
            healthy: true,
            initial: [
                "ANTHROPIC_BASE_URL": "http://127.0.0.1:8484",
                "OPENAI_BASE_URL": foreignOpenAI,
            ]
        )
        #expect(advancesOwnedPort.anthropicValue == "http://127.0.0.1:9999",
                "an exact historical Bouclier URL should advance to the live port")
        #expect(advancesOwnedPort.openAIValue == foreignOpenAI)

        let clearsOwnedHistory = try Self.runPOSIXEnvFile(
            content,
            gatewayPort: 9999,
            healthy: false,
            initial: [
                "ANTHROPIC_BASE_URL": "http://127.0.0.1:8484",
                "OPENAI_BASE_URL": "http://127.0.0.1:9999/v1",
            ]
        )
        #expect(!clearsOwnedHistory.anthropicIsSet)
        #expect(!clearsOwnedHistory.openAIIsSet)

        let preservesForeignWhenDead = try Self.runPOSIXEnvFile(
            content,
            gatewayPort: 9999,
            healthy: false,
            initial: [
                "ANTHROPIC_BASE_URL": foreignAnthropic,
                "OPENAI_BASE_URL": foreignOpenAI,
            ]
        )
        #expect(preservesForeignWhenDead.anthropicValue == foreignAnthropic)
        #expect(preservesForeignWhenDead.openAIValue == foreignOpenAI)
    }

    @Test("POSIX env file re-syncs on every interactive prompt so a live shell self-heals")
    func posixFileReSyncsPerPrompt() {
        // The bug this guards against: a terminal opened while Bouclier
        // was alive exports ANTHROPIC_BASE_URL into its process env.
        // Killing Bouclier can't touch that live shell, so the next
        // `claude` in the same tab hits the dead port → 'connection
        // refused'. Re-running the check before each prompt fixes it.
        // Reported by a user on 2026-06-04.
        let exports = ShellEnvInjector.buildStandardExports(gatewayPort: 8484)
        let content = ShellEnvInjector.posixEnvFileContent(exports: exports)

        #expect(content.contains("__bouclier_sync()"),
                "Check must be wrapped in a function so it can be both called once and re-bound to a prompt hook")
        #expect(content.contains("add-zsh-hook precmd __bouclier_sync"),
                "zsh interactive shells must re-sync via a precmd hook")
        #expect(content.contains("PROMPT_COMMAND="),
                "bash interactive shells must re-sync via PROMPT_COMMAND")
        // The function must also be invoked directly — non-interactive
        // shells (Claude Code, editor-spawned tools) never fire a prompt
        // hook, so defining the function alone would protect nothing.
        let lines = content.split(separator: "\n", omittingEmptySubsequences: false)
        #expect(lines.contains("__bouclier_sync"),
                "Function must be invoked once at source time for non-interactive shells")
    }

    @Test("Fish env file re-syncs on every prompt via fish_prompt event")
    func fishFileReSyncsPerPrompt() {
        let exports = ShellEnvInjector.buildStandardExports(gatewayPort: 8484)
        let content = ShellEnvInjector.fishEnvFileContent(exports: exports)

        #expect(content.contains("function __bouclier_sync"))
        #expect(content.contains("--on-event fish_prompt"),
                "Fish must re-sync on every prompt so a live shell self-heals when Bouclier dies")
    }

    @Test("Watchdog plist runs every minute and unsets env when the proxy port isn't reachable")
    func watchdogPlistShape() {
        let ownership: [String: ShellEnvInjector.LaunchctlOwnershipRecord] = [
            "ANTHROPIC_BASE_URL": .init(ownedValues: [
                "http://127.0.0.1:8484",
            ]),
            "OPENAI_BASE_URL": .init(ownedValues: [
                "http://127.0.0.1:8484/v1",
            ]),
        ]
        let plist = ShellEnvInjector.watchdogPlist(
            proxyPort: 8484,
            launchctlOwnership: ownership
        )

        #expect((try? PropertyListSerialization.propertyList(
            from: Data(plist.utf8), format: nil
        )) != nil, "the generated watchdog must remain valid XML plist data")

        #expect(plist.contains("<key>Label</key>"))
        #expect(plist.contains(ShellEnvInjector.watchdogLabel))
        #expect(plist.contains("<integer>60</integer>"),
                "Watchdog should tick at least every minute — that's the worst-case window of stale env after a crash")
        #expect(plist.contains("http://127.0.0.1:8484/livez"),
                "Probe must check Bouclier's exact liveness response, not merely whether some process owns the port")
        #expect(plist.contains("launchctl unsetenv ANTHROPIC_BASE_URL"))
        #expect(plist.contains("launchctl unsetenv OPENAI_BASE_URL"))
        #expect(plist.contains("launchctl getenv ANTHROPIC_BASE_URL"),
                "watchdog must verify the value is still Bouclier's before clearing it")
        #expect(!plist.contains("HTTPS_PROXY"),
                "standard-mode watchdog must preserve corporate proxy variables")
        #expect(!plist.contains("NODE_EXTRA_CA_CERTS"),
                "standard-mode watchdog must preserve corporate CA variables")
        #expect(!plist.contains("networksetup"),
                "standard mode never owns system PAC and must not sweep network services")
        #expect(plist.contains("RunAtLoad"),
                "Agent must run on load so a stale env from a previous boot is cleared at login")
    }

    @Test("Watchdog never clears an unrecorded exact-equal value")
    func watchdogPreservesUnownedValues() {
        let plist = ShellEnvInjector.watchdogPlist(
            proxyPort: 8484,
            launchctlOwnership: [:]
        )

        #expect(!plist.contains("launchctl unsetenv ANTHROPIC_BASE_URL"))
        #expect(!plist.contains("launchctl unsetenv OPENAI_BASE_URL"))
        #expect(plist.contains("|| { :; }"),
                "an empty ownership record must produce an explicit no-op cleanup branch")
    }

    @Test("Launchctl ownership spans partial port changes without storing foreign values")
    func launchctlOwnershipTransitions() throws {
        let first = try #require(ShellEnvInjector.updatedLaunchctlOwnership(
            existing: nil,
            currentValue: nil,
            installingValue: "http://127.0.0.1:8484"
        ))
        #expect(first.ownedValues == ["http://127.0.0.1:8484"])

        let portChange = try #require(ShellEnvInjector.updatedLaunchctlOwnership(
            existing: first,
            currentValue: "http://127.0.0.1:8484",
            installingValue: "http://127.0.0.1:9999"
        ))
        #expect(portChange.ownedValues == [
            "http://127.0.0.1:8484",
            "http://127.0.0.1:9999",
        ])
        #expect(ShellEnvInjector.launchctlCleanupAction(
            record: portChange,
            currentValue: "http://127.0.0.1:8484"
        ) == .unset, "a failed port-changing setenv can leave the old owned value behind")
        #expect(ShellEnvInjector.launchctlCleanupAction(
            record: portChange,
            currentValue: "http://127.0.0.1:9999"
        ) == .unset)

        let anotherPortChange = try #require(ShellEnvInjector.updatedLaunchctlOwnership(
            existing: portChange,
            currentValue: "http://127.0.0.1:9999",
            installingValue: "http://127.0.0.1:7777"
        ))
        #expect(anotherPortChange.ownedValues == [
            "http://127.0.0.1:8484",
            "http://127.0.0.1:9999",
            "http://127.0.0.1:7777",
        ], "verified port changes must retain history for already-running shells")

        let corporate = "https://token@corporate-gateway.example/v1"
        #expect(ShellEnvInjector.updatedLaunchctlOwnership(
            existing: anotherPortChange,
            currentValue: corporate,
            installingValue: "http://127.0.0.1:7777"
        ) == nil, "a foreign value must be preserved and never copied into the ownership record")
        #expect(ShellEnvInjector.launchctlCleanupAction(
            record: anotherPortChange,
            currentValue: corporate
        ) == .preserve)
    }

    @Test("Persisted launchctl ownership accepts only exact non-secret Bouclier URLs")
    func launchctlOwnershipSerializationIsNarrow() throws {
        let ownership: [String: ShellEnvInjector.LaunchctlOwnershipRecord] = [
            "ANTHROPIC_BASE_URL": .init(ownedValues: [
                "http://127.0.0.1:8484",
                "http://127.0.0.1:9999",
            ]),
            "OPENAI_BASE_URL": .init(ownedValues: [
                "http://127.0.0.1:8484/v1",
            ]),
        ]
        let data = try #require(ShellEnvInjector.encodedLaunchctlOwnership(ownership))
        #expect(ShellEnvInjector.decodedLaunchctlOwnership(data) == ownership)

        let credentialBearing = [
            "ANTHROPIC_BASE_URL": ShellEnvInjector.LaunchctlOwnershipRecord(
                ownedValues: ["https://token@corporate-gateway.example/v1"]
            ),
        ]
        #expect(ShellEnvInjector.encodedLaunchctlOwnership(credentialBearing) == nil,
                "foreign URLs must never enter UserDefaults through the ownership codec")
    }

    @Test("Launchctl cleanup clears only exact Bouclier-owned values")
    func launchctlOwnershipIsValueChecked() {
        #expect(ShellEnvInjector.ownsStandardLaunchctlValue(
            key: "ANTHROPIC_BASE_URL",
            value: "http://127.0.0.1:8484",
            gatewayPort: 8484
        ))
        #expect(ShellEnvInjector.ownsStandardLaunchctlValue(
            key: "OPENAI_BASE_URL",
            value: "http://127.0.0.1:8484/v1",
            gatewayPort: 8484
        ))
        #expect(!ShellEnvInjector.ownsStandardLaunchctlValue(
            key: "ANTHROPIC_BASE_URL",
            value: "https://corporate-gateway.example",
            gatewayPort: 8484
        ))
        #expect(!ShellEnvInjector.ownsStandardLaunchctlValue(
            key: "OPENAI_BASE_URL",
            value: "http://127.0.0.1:9999/v1",
            gatewayPort: 8484
        ))

        #expect(ShellEnvInjector.ownsLegacyLaunchctlValue(
            key: "HTTPS_PROXY",
            value: "http://127.0.0.1:8484",
            proxyPort: 8484,
            caCertPath: "/tmp/bouclier-ca.pem"
        ))
        for foreignProxy in [
            "http://localhost:8484",
            "https://127.0.0.1:8484",
            "socks5://127.0.0.1:8484",
            "http://user@127.0.0.1:8484",
            "http://127.0.0.1:8484/corporate",
            "http://127.0.0.1:8484?profile=corp",
        ] {
            #expect(!ShellEnvInjector.ownsLegacyLaunchctlValue(
                key: "HTTPS_PROXY",
                value: foreignProxy,
                proxyPort: 8484,
                caCertPath: "/tmp/bouclier-ca.pem"
            ), "Only the exact historic Bouclier proxy URL is owned: \(foreignProxy)")
        }
        #expect(!ShellEnvInjector.ownsLegacyLaunchctlValue(
            key: "HTTPS_PROXY",
            value: "https://proxy.corp.example:8443",
            proxyPort: 8484,
            caCertPath: "/tmp/bouclier-ca.pem"
        ))
        #expect(!ShellEnvInjector.ownsLegacyLaunchctlValue(
            key: "SSL_CERT_FILE",
            value: "/etc/corporate-ca.pem",
            proxyPort: 8484,
            caCertPath: "/tmp/bouclier-ca.pem"
        ))
    }

    @Test("Malformed managed markers fail closed without changing user content")
    func malformedBlocksArePreserved() throws {
        let cases = [
            "user line\n# >>> bouclier.ai env (managed) >>>\nstale payload\nuser tail\n",
            "user line\n# <<< bouclier.ai env (managed) <<<\nuser tail\n",
            "# >>> bouclier.ai env (managed) >>>\none\n# >>> bouclier.ai env (managed) >>>\ntwo\n# <<< bouclier.ai env (managed) <<<\n",
            "# <<< bouclier.ai env (managed) <<<\n# >>> bouclier.ai env (managed) >>>\n",
        ]

        for (index, malformed) in cases.enumerated() {
            let url = Self.tmpFile(prefix: "malformed-\(index)")
            defer { try? FileManager.default.removeItem(at: url) }
            try malformed.write(to: url, atomically: false, encoding: .utf8)

            #expect(!ShellEnvInjector.injectBlock(into: url, payload: "FRESH"))
            #expect(Self.read(url) == malformed)
            #expect(!ShellEnvInjector.stripBlock(from: url))
            #expect(Self.read(url) == malformed,
                    "apply and removal must both preserve an ambiguous file byte-for-byte")
        }
    }
}
