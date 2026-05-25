import Foundation

/// Wires the user's shells and GUI apps to route through the Bouclier
/// TLS proxy automatically — without the user pasting anything into a
/// dotfile.
///
/// **Why this exists.** The System Extension claims AI flows at the
/// socket level for any process, but TLS trust is a separate axis.
/// URLSession-based apps (ChatGPT/Claude Desktop) read the login
/// Keychain and accept our leaf cert transparently. Node, Python's
/// `requests`, and other runtimes ship their own CA bundle and ignore
/// the Keychain entirely — so without `NODE_EXTRA_CA_CERTS` /
/// `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` pointing at our root, every
/// Claude Code / Cursor / `openai` CLI invocation either errors on the
/// handshake or silently falls through to direct egress. The user
/// thinks they're protected; the LLM still sees cleartext. That is the
/// "seatbelt made of paper" failure mode we have to eliminate.
///
/// **What it does.** When the user enables protection we (a) write
/// canonical env files at `~/.config/bouclier-ai/env.sh` and
/// `env.fish`, (b) inject a delimited, idempotent block into
/// `~/.zshenv`, `~/.bash_profile`, `~/.bashrc`, `~/.profile`, and
/// `~/.config/fish/config.fish` that sources those files, and (c) call
/// `launchctl setenv` so GUI apps launched via Spotlight/Finder/Dock
/// inherit the same vars for the rest of the login session.
///
/// **Why `.zshenv` specifically.** Non-interactive shells (the ones
/// Claude Code and most editor-launched processes use) read `.zshenv`
/// only — `.zshrc` is interactive-only. Anything we want a CLI tool
/// to inherit has to live in `.zshenv` or in the launchctl session.
///
/// **Idempotency.** Each managed file is bracketed by sentinel
/// comments; reapply strips the old block before writing a new one,
/// so changing the proxy port or CA path doesn't accumulate stale
/// exports.
///
/// **Safety.** Every dotfile write is atomic via tmpfile + rename so
/// a power loss mid-write can't leave a half-written `.zshenv` (which
/// would lock the user out of zsh). Failures in any individual file
/// are logged and skipped — a missing `~/.config/fish` is fine.
enum ShellEnvInjector {
    /// User preference: ships on by default. Surface in Settings →
    /// General so a user with a corporate proxy that conflicts (or a
    /// Vim devotee with hand-tuned dotfiles) can opt out cleanly.
    static let autoConfigureKey = "autoConfigureShellEnv"

    static var isEnabled: Bool {
        UserDefaults.standard.object(forKey: autoConfigureKey) as? Bool ?? true
    }

    /// Apply the injection. Idempotent: safe to call on every launch.
    /// Returns true if any change was made (used for the activity log).
    @discardableResult
    static func apply(proxyPort: Int, caCertPath: String?) -> Bool {
        guard isEnabled else { return false }

        let proxyURL = "http://127.0.0.1:\(proxyPort)"
        let exports = buildExports(proxyURL: proxyURL, caCertPath: caCertPath)

        let envSh = configDir().appendingPathComponent("env.sh")
        let envFish = configDir().appendingPathComponent("env.fish")
        _ = ensureConfigDir()
        writeAtomically(content: posixEnvFileContent(exports: exports), to: envSh)
        writeAtomically(content: fishEnvFileContent(exports: exports), to: envFish)

        let posixSource = "[ -f \"\(envSh.path)\" ] && . \"\(envSh.path)\""
        let fishSource = "if test -f \"\(envFish.path)\"; source \"\(envFish.path)\"; end"

        injectBlock(into: home(".zshenv"), payload: posixSource)
        injectBlock(into: home(".bash_profile"), payload: posixSource)
        injectBlock(into: home(".bashrc"), payload: posixSource)
        injectBlock(into: home(".profile"), payload: posixSource)
        injectBlock(into: fishConfigPath(), payload: fishSource, createParent: true)

        applyLaunchctlSetenv(exports: exports)
        return true
    }

    /// Remove everything we injected. Called on uninstall and when
    /// the user flips the General toggle off. Best-effort: a missing
    /// dotfile is not an error.
    static func remove() {
        for path in [home(".zshenv"), home(".bash_profile"), home(".bashrc"), home(".profile"), fishConfigPath()] {
            stripBlock(from: path)
        }

        try? FileManager.default.removeItem(at: configDir().appendingPathComponent("env.sh"))
        try? FileManager.default.removeItem(at: configDir().appendingPathComponent("env.fish"))

        unsetLaunchctl()
    }

    /// Drop the launchctl session env vars without touching the dotfile
    /// blocks or the canonical env files. Called from `ProxyManager.stop`
    /// and the crash/exit handlers so a quit-or-crash leaves the user
    /// session unable to route through the now-dead proxy — paired with
    /// the shell scripts' fail-open TCP check, the user's CLI tools
    /// recover transparently instead of seeing `connection refused`.
    static func unsetLaunchctl() {
        for key in Self.envVarKeys {
            _ = runLaunchctl(["unsetenv", key])
        }
    }

    // MARK: - Content builders

    private static let envVarKeys = [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
    ]

    struct Exports {
        let pairs: [(String, String)]
    }

    static func buildExports(proxyURL: String, caCertPath: String?) -> Exports {
        var pairs: [(String, String)] = [
            ("HTTPS_PROXY", proxyURL),
            ("HTTP_PROXY", proxyURL),
        ]
        if let path = caCertPath {
            pairs.append(("NODE_EXTRA_CA_CERTS", path))
            pairs.append(("SSL_CERT_FILE", path))
            pairs.append(("REQUESTS_CA_BUNDLE", path))
        }
        return Exports(pairs: pairs)
    }

    /// Port the proxy is bound to. Used by the shell scripts'
    /// fail-open TCP check.
    private static func proxyPort(from url: String) -> Int {
        // Pull the port out of `http://127.0.0.1:8484`. If anything is
        // off, fall back to the well-known default — wrong answer here
        // just means a slightly slower failed connect on shell start.
        if let last = url.split(separator: ":").last, let p = Int(last) { return p }
        return 8484
    }

    static func posixEnvFileContent(exports: Exports) -> String {
        let port = proxyPort(from: exports.pairs.first(where: { $0.0 == "HTTPS_PROXY" })?.1 ?? "")
        let keys = exports.pairs.map(\.0).joined(separator: " ")
        var lines = [
            "# Bouclier.ai — auto-generated. Do not edit by hand.",
            "# Routes AI traffic through the local interception proxy and",
            "# extends the system CA bundle to trust Bouclier's leaf certs.",
            "#",
            "# Fail-open: if Bouclier isn't listening we *unset* the proxy",
            "# vars so CLI tools talk direct instead of erroring with",
            "# 'connection refused'. Explicit unset matters because a stale",
            "# value can be inherited from launchctl setenv, the parent",
            "# shell, or a previous Bouclier session — without the unset",
            "# the conditional `export` doesn't override it. ~5ms TCP probe,",
            "# runs once per shell start.",
            "if /usr/bin/nc -z 127.0.0.1 \(port) 2>/dev/null; then",
        ]
        for (k, v) in exports.pairs {
            lines.append("    export \(k)=\"\(shellEscape(v))\"")
        }
        lines.append("else")
        lines.append("    unset \(keys)")
        lines.append("fi")
        return lines.joined(separator: "\n") + "\n"
    }

    static func fishEnvFileContent(exports: Exports) -> String {
        let port = proxyPort(from: exports.pairs.first(where: { $0.0 == "HTTPS_PROXY" })?.1 ?? "")
        let keys = exports.pairs.map(\.0).joined(separator: " ")
        var lines = [
            "# Bouclier.ai — auto-generated. Do not edit by hand.",
            "# Fail-open: unset proxy vars when Bouclier isn't listening so",
            "# `git push`, `curl`, etc. don't break when the proxy is down.",
            "if /usr/bin/nc -z 127.0.0.1 \(port) 2>/dev/null",
        ]
        for (k, v) in exports.pairs {
            lines.append("    set -gx \(k) \"\(shellEscape(v))\"")
        }
        lines.append("else")
        lines.append("    set -e \(keys)")
        lines.append("end")
        return lines.joined(separator: "\n") + "\n"
    }

    private static func shellEscape(_ value: String) -> String {
        // Conservative: escape backslashes and double quotes. The values
        // we emit are paths and a `http://127.0.0.1:port` URL — neither
        // legitimately contains either character, but a paranoid escape
        // is cheaper than auditing every caller.
        value.replacingOccurrences(of: "\\", with: "\\\\")
             .replacingOccurrences(of: "\"", with: "\\\"")
    }

    // MARK: - Block management

    private static let blockBegin = "# >>> bouclier.ai env (managed) >>>"
    private static let blockEnd = "# <<< bouclier.ai env (managed) <<<"

    /// Insert or replace the managed block in `path`. Atomic write —
    /// a partial write to `.zshenv` would lock the user out of zsh, so
    /// we never overwrite the live file directly.
    static func injectBlock(into path: URL, payload: String, createParent: Bool = false) {
        if createParent {
            try? FileManager.default.createDirectory(
                at: path.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
        }

        let existing = (try? String(contentsOf: path, encoding: .utf8)) ?? ""
        let stripped = stripBlock(in: existing)
        let separator = stripped.isEmpty || stripped.hasSuffix("\n") ? "" : "\n"
        let block = "\(blockBegin)\n\(payload)\n\(blockEnd)\n"
        let next = stripped + separator + (stripped.isEmpty ? "" : "\n") + block
        writeAtomically(content: next, to: path)
    }

    /// Remove the managed block from `path` in-place. Atomic write.
    static func stripBlock(from path: URL) {
        guard let existing = try? String(contentsOf: path, encoding: .utf8) else { return }
        let stripped = stripBlock(in: existing)
        if stripped == existing { return }
        if stripped.isEmpty {
            // If the file was nothing but our block, remove it so we
            // don't leave a stray empty `.profile` behind.
            try? FileManager.default.removeItem(at: path)
            return
        }
        writeAtomically(content: stripped, to: path)
    }

    private static func stripBlock(in content: String) -> String {
        guard let beginRange = content.range(of: blockBegin) else { return content }
        // Walk back to include the newline before our block, if any,
        // so we don't leave a blank line.
        let blockStart: String.Index = {
            var idx = beginRange.lowerBound
            if idx > content.startIndex {
                let prev = content.index(before: idx)
                if content[prev] == "\n" { idx = prev }
            }
            return idx
        }()
        guard let endRange = content.range(of: blockEnd, range: beginRange.upperBound..<content.endIndex) else {
            // Malformed — only a begin marker. Drop everything from
            // begin to EOF to recover.
            return String(content[content.startIndex..<blockStart])
        }
        // Consume trailing newline after the end marker so consecutive
        // applies don't accumulate blank lines.
        var blockEndIdx = endRange.upperBound
        if blockEndIdx < content.endIndex, content[blockEndIdx] == "\n" {
            blockEndIdx = content.index(after: blockEndIdx)
        }
        let before = content[content.startIndex..<blockStart]
        let after = content[blockEndIdx..<content.endIndex]
        return String(before) + String(after)
    }

    // MARK: - launchctl

    private static func applyLaunchctlSetenv(exports: Exports) {
        for (k, v) in exports.pairs {
            _ = runLaunchctl(["setenv", k, v])
        }
    }

    @discardableResult
    private static func runLaunchctl(_ args: [String]) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            p.waitUntilExit()
            return p.terminationStatus == 0
        } catch {
            return false
        }
    }

    // MARK: - Filesystem helpers

    private static func home(_ component: String) -> URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(component)
    }

    private static func configDir() -> URL {
        home(".config/bouclier-ai")
    }

    private static func fishConfigPath() -> URL {
        home(".config/fish/config.fish")
    }

    @discardableResult
    private static func ensureConfigDir() -> Bool {
        do {
            try FileManager.default.createDirectory(at: configDir(), withIntermediateDirectories: true)
            return true
        } catch {
            return false
        }
    }

    private static func writeAtomically(content: String, to url: URL) {
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
        } catch {}
        guard let data = content.data(using: .utf8) else { return }
        do {
            try data.write(to: url, options: .atomic)
        } catch {
            // Best-effort: a single dotfile failing to write must not
            // abort the rest of the setup flow.
        }
    }
}
