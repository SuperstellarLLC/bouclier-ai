import Foundation

/// Wires the user's shells and GUI apps to route through the Bouclier
/// gateway automatically — without the user pasting anything into a
/// dotfile.
///
/// **Why this exists.** The gateway is certificate-free: an agent opts in
/// by pointing `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` at
/// `http://127.0.0.1:<port>`, and nothing that doesn't set those vars is
/// inspected. Expecting every user to export them by hand in every shell
/// is the "seatbelt made of paper" failure mode — they enable protection,
/// forget the export, and their agent talks straight to the provider
/// while the shield reads green. So enabling protection sets the vars for
/// them wherever a CLI or GUI-launched agent will look, unless an existing
/// foreign base URL is present; that value is preserved and setup reports
/// the conflict instead of taking ownership of it.
///
/// **What it does.** When the user enables protection we (a) write
/// canonical env files at `~/.config/bouclier-ai/env.sh` and
/// `env.fish` that export `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`,
/// (b) inject a delimited, idempotent block into `~/.zshenv`,
/// `~/.bash_profile`, `~/.bashrc`, `~/.profile`, and
/// `~/.config/fish/config.fish` that sources those files, and (c) call
/// `launchctl setenv` so GUI apps launched via Spotlight/Finder/Dock
/// inherit the same vars for the rest of the login session. No CA-bundle
/// vars and no `HTTPS_PROXY`: the front hop is plaintext loopback to an
/// LLM origin, not a CONNECT proxy or a TLS-terminating one.
///
/// **Routing is opt-in per process.** Only shells started *after* enable
/// (which source the new block) and GUI processes launched *after*
/// `launchctl setenv` pick the vars up. An already-running terminal,
/// tmux session, or editor keeps talking direct until it is restarted —
/// which is why "open a new terminal" is the one instruction onboarding
/// must give.
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
/// would lock the user out of zsh). A missing file is fine; real apply
/// or removal failures are returned to the caller so Settings cannot
/// report a complete configuration change while artifacts remain.
enum ShellEnvInjector {
    /// User preference: ships on by default. Surface in Settings →
    /// General so a user with a corporate proxy that conflicts (or a
    /// Vim devotee with hand-tuned dotfiles) can opt out cleanly.
    static let autoConfigureKey = "autoConfigureShellEnv"
    private static let lastAppliedGatewayPortKey = "bouclier.lastAppliedGatewayPort"
    private static let launchctlOwnershipKey = "bouclier.launchctlOwnership.v1"
    private static let launchctlOwnershipTrackingKey = "bouclier.launchctlOwnershipTracking.v1"

    static var isEnabled: Bool {
        UserDefaults.standard.object(forKey: autoConfigureKey) as? Bool ?? true
    }

    // The former `apply(proxyPort:caCertPath:)` + `buildExports` (which
    // exported HTTPS_PROXY/HTTP_PROXY and NODE_EXTRA_CA_CERTS/SSL_CERT_FILE/
    // REQUESTS_CA_BUNDLE for extreme mode's TLS-terminating proxy) were
    // removed in v0.9.0. Extreme mode is gone; `applyStandard` below is the
    // only live path and it sets base-URL vars only. Legacy keys are handled
    // by a one-shot, value-checked migration; routine stop/watchdog cleanup
    // must never clear proxy or CA variables owned by the user or employer.

    /// Remove the routing configuration Bouclier injected. Best-effort: a
    /// missing dotfile is not an error. This enforces the managed protection
    /// lock at the mutation boundary as well as in Settings, so another UI
    /// path cannot silently make newly launched tools bypass an active,
    /// organization-locked gateway.
    @discardableResult
    static func remove(gatewayPort: Int) -> Bool {
        guard !(ManagedConfig.preventDisable
                && ProxyManager.effectiveProtectionEnabled) else {
            return false
        }
        var complete = true
        for path in [home(".zshenv"), home(".bash_profile"), home(".bashrc"), home(".profile"), fishConfigPath()] {
            complete = stripBlock(from: path) && complete
        }

        complete = removeFileIfPresent(configDir().appendingPathComponent("env.sh")) && complete
        complete = removeFileIfPresent(configDir().appendingPathComponent("env.fish")) && complete

        complete = removeWatchdog() && complete
        let lastAppliedPort = UserDefaults.standard.object(
            forKey: lastAppliedGatewayPortKey
        ) as? Int
        let cleanupPorts = Set([lastAppliedPort, gatewayPort].compactMap { $0 })
        complete = unsetLaunchctl(
            gatewayPorts: cleanupPorts,
            clearOwnershipOnSuccess: true
        ) && complete
        if complete {
            UserDefaults.standard.removeObject(forKey: lastAppliedGatewayPortKey)
        }
        return complete
    }

    /// Drop the launchctl session env vars without touching the dotfile
    /// blocks or the canonical env files. Called from `ProxyManager.stop`
    /// and the crash/exit handlers so a quit-or-crash leaves the user
    /// session unable to route through the now-dead proxy — paired with
    /// the shell scripts' fail-open liveness check, the user's CLI tools
    /// recover transparently instead of seeing `connection refused`.
    @discardableResult
    static func unsetLaunchctl(gatewayPort: Int?) -> Bool {
        let ports = Set([gatewayPort].compactMap { $0 })
        return unsetLaunchctl(gatewayPorts: ports, clearOwnershipOnSuccess: false)
    }

    /// Durable ownership for a single launchctl variable. It contains only
    /// exact loopback values Bouclier attempted to install — never a foreign
    /// value, which could be a credential-bearing corporate endpoint. Keeping
    /// both old and new URLs closes the case where one of two independent
    /// `launchctl setenv` calls succeeds and the other does not. History is
    /// intentionally retained after a successful port change too: an already-
    /// running shell can still carry an older Bouclier URL, and the generated
    /// prompt hook needs exact ownership evidence before replacing or clearing
    /// that value.
    struct LaunchctlOwnershipRecord: Codable, Equatable {
        var ownedValues: [String]

        init(ownedValues: [String]) {
            self.ownedValues = ownedValues
        }
    }

    enum LaunchctlCleanupAction: Equatable {
        case preserve
        case unset
    }

    /// Pure transition used by the real launchctl mutation and regression
    /// tests. An absent value or one already in the ownership history can be
    /// replaced. Any other value is foreign: refuse to overwrite it, return nil
    /// to the caller, and keep it out of persisted preferences entirely.
    static func updatedLaunchctlOwnership(
        existing: LaunchctlOwnershipRecord?,
        currentValue: String?,
        installingValue: String
    ) -> LaunchctlOwnershipRecord? {
        if let currentValue,
           existing?.ownedValues.contains(currentValue) != true
        {
            return nil
        }
        var record = existing ?? LaunchctlOwnershipRecord(ownedValues: [])
        if !record.ownedValues.contains(installingValue) {
            record.ownedValues.append(installingValue)
        }
        return record
    }

    static func launchctlCleanupAction(
        record: LaunchctlOwnershipRecord,
        currentValue: String?
    ) -> LaunchctlCleanupAction {
        guard let currentValue,
              record.ownedValues.contains(currentValue)
        else { return .preserve }
        return .unset
    }

    private static func unsetLaunchctl(
        gatewayPorts: Set<Int>,
        clearOwnershipOnSuccess: Bool
    ) -> Bool {
        guard var ownership = loadLaunchctlOwnership() else { return false }
        let hadTrackedRecords = !ownership.isEmpty
        let usesTrackedOwnership = UserDefaults.standard.bool(
            forKey: launchctlOwnershipTrackingKey
        )
        var complete = true
        for key in Self.standardEnvVarKeys {
            switch launchctlValue(for: key) {
            case .absent:
                if clearOwnershipOnSuccess { ownership.removeValue(forKey: key) }
            case .failed:
                complete = false
            case .value(let value):
                if let record = ownership[key] {
                    let action = launchctlCleanupAction(
                        record: record,
                        currentValue: value
                    )
                    let restored: Bool
                    switch action {
                    case .preserve:
                        restored = true
                    case .unset:
                        _ = runLaunchctl(["unsetenv", key])
                        restored = launchctlValue(for: key) == .absent
                    }
                    complete = restored && complete
                    if restored, clearOwnershipOnSuccess {
                        ownership.removeValue(forKey: key)
                    }
                } else if !usesTrackedOwnership,
                          gatewayPorts.contains(where: {
                              ownsStandardLaunchctlValue(
                                  key: key,
                                  value: value,
                                  gatewayPort: $0
                              )
                          })
                {
                    // Compatibility cleanup for values installed before
                    // per-key ownership records existed. Once tracking has
                    // ever been enabled, never fall back to a port heuristic:
                    // the current value may be an exact-equal user value we
                    // deliberately restored.
                    _ = runLaunchctl(["unsetenv", key])
                    complete = (launchctlValue(for: key) == .absent) && complete
                }
            }
        }
        let shouldPersistOwnership = clearOwnershipOnSuccess
            ? (usesTrackedOwnership || hadTrackedRecords || complete)
            : (!usesTrackedOwnership && complete)
        if shouldPersistOwnership,
           !persistLaunchctlOwnership(ownership) {
            complete = false
        }
        return complete
    }

    /// Only a value equal to the base URL Bouclier installed is ours to
    /// clear. A user/administrator may replace either variable while the app
    /// runs; quit and watchdog cleanup must preserve that newer setting.
    static func ownsStandardLaunchctlValue(
        key: String, value: String, gatewayPort: Int
    ) -> Bool {
        let expected = Dictionary(
            uniqueKeysWithValues: buildStandardExports(gatewayPort: gatewayPort).pairs
        )
        return expected[key] == value
    }

    /// One-shot upgrade cleanup for values written by removed extreme mode.
    /// Each value must match Bouclier's exact historic proxy URL or CA path
    /// before it is unset; merely sharing a variable name, host, or port is not
    /// ownership.
    @discardableResult
    static func unsetLegacyLaunchctlIfOwned(proxyPort: Int, caCertPath: String) -> Bool {
        var complete = true
        for key in legacyEnvVarKeys {
            switch launchctlValue(for: key) {
            case .absent:
                continue
            case .failed:
                complete = false
            case .value(let value):
                guard ownsLegacyLaunchctlValue(
                    key: key, value: value,
                    proxyPort: proxyPort, caCertPath: caCertPath
                ) else { continue }
                complete = runLaunchctl(["unsetenv", key]) && complete
                switch launchctlValue(for: key) {
                case .absent:
                    break
                case .value(let remaining):
                    if remaining == value { complete = false }
                case .failed:
                    complete = false
                }
            }
        }
        return complete
    }

    static func ownsLegacyLaunchctlValue(
        key: String, value: String, proxyPort: Int, caCertPath: String
    ) -> Bool {
        switch key {
        case "HTTPS_PROXY", "HTTP_PROXY":
            // The retired implementation emitted this literal string. Do not
            // infer ownership from a shared loopback host/port: a developer's
            // SOCKS proxy or corporate local agent can legitimately use it.
            return value == "http://127.0.0.1:\(proxyPort)"
        case "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE":
            return URL(fileURLWithPath: value).standardizedFileURL.path
                == URL(fileURLWithPath: caCertPath).standardizedFileURL.path
        default:
            return false
        }
    }

    // MARK: - Content builders

    private static let standardEnvVarKeys = [
        "ANTHROPIC_BASE_URL",
        "OPENAI_BASE_URL",
    ]

    private static let legacyEnvVarKeys = [
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
    ]

    struct Exports {
        let pairs: [(String, String)]
    }

    /// Standard (non-CA) mode: point the agent's SDKs at the gateway via
    /// base-URL overrides instead of `HTTPS_PROXY`. We deliberately do NOT
    /// set `HTTPS_PROXY` — the gateway is an LLM origin, not a CONNECT
    /// proxy, so routing all HTTPS through it would break everything else.
    /// And no CA-bundle vars: the front hop is plaintext loopback, so
    /// there's no Bouclier cert for runtimes to trust.
    ///
    /// `ANTHROPIC_BASE_URL` is the host root (the SDK appends
    /// `/v1/messages`); `OPENAI_BASE_URL` conventionally includes `/v1`
    /// (the SDK appends `/chat/completions`). The gateway's router accepts
    /// both shapes.
    static func buildStandardExports(gatewayPort: Int) -> Exports {
        let base = "http://127.0.0.1:\(gatewayPort)"
        return Exports(pairs: [
            ("ANTHROPIC_BASE_URL", base),
            ("OPENAI_BASE_URL", base + "/v1"),
        ])
    }

    /// Apply standard-mode env injection. Mirrors `apply` (dotfiles +
    /// launchctl + watchdog, all fail-open) but with base-URL exports.
    @discardableResult
    static func applyStandard(gatewayPort: Int) -> Bool {
        guard isEnabled else { return false }
        let exports = buildStandardExports(gatewayPort: gatewayPort)
        // The same narrow ownership record used for launchctl cleanup also
        // constrains the generated shell scripts. A corrupt record must fail
        // closed: falling back to unconditional exports would overwrite a
        // user's or employer's provider endpoint when the profile is sourced.
        guard let launchctlOwnership = loadLaunchctlOwnership() else {
            return false
        }

        let envSh = configDir().appendingPathComponent("env.sh")
        let envFish = configDir().appendingPathComponent("env.fish")
        var complete = ensureConfigDir()
        complete = writeAtomically(
            content: posixEnvFileContent(
                exports: exports,
                launchctlOwnership: launchctlOwnership
            ),
            to: envSh
        ) && complete
        complete = writeAtomically(
            content: fishEnvFileContent(
                exports: exports,
                launchctlOwnership: launchctlOwnership
            ),
            to: envFish
        ) && complete

        let posixSource = "[ -f \"\(envSh.path)\" ] && . \"\(envSh.path)\""
        let fishSource = "if test -f \"\(envFish.path)\"; source \"\(envFish.path)\"; end"
        complete = injectBlock(into: home(".zshenv"), payload: posixSource) && complete
        complete = injectBlock(into: home(".bash_profile"), payload: posixSource) && complete
        complete = injectBlock(into: home(".bashrc"), payload: posixSource) && complete
        complete = injectBlock(into: home(".profile"), payload: posixSource) && complete
        complete = injectBlock(into: fishConfigPath(), payload: fishSource, createParent: true) && complete

        // Persist even for a partial apply: cleanup must remember which exact
        // values may have been written if Settings changes the next-run port.
        UserDefaults.standard.set(gatewayPort, forKey: lastAppliedGatewayPortKey)
        complete = applyLaunchctlSetenv(exports: exports) && complete
        complete = installWatchdog(proxyPort: gatewayPort) && complete
        return complete
    }

    /// Port the proxy is bound to. Used by the shell scripts'
    /// fail-open liveness check.
    private static func proxyPort(from url: String) -> Int {
        // Pull the port out of `http://127.0.0.1:8484`. If anything is
        // off, fall back to the well-known default — wrong answer here
        // just means a slightly slower failed connect on shell start.
        if let last = url.split(separator: ":").last, let p = Int(last) { return p }
        return 8484
    }

    static func posixEnvFileContent(
        exports: Exports,
        launchctlOwnership: [String: LaunchctlOwnershipRecord] = [:]
    ) -> String {
        let port = proxyPort(from: exports.pairs.first(where: { $0.1.contains("127.0.0.1:") })?.1 ?? "")
        var lines = [
            "# Bouclier.ai — auto-generated. Do not edit by hand.",
            "# Points AI SDKs at the local certificate-free gateway by",
            "# exporting ANTHROPIC_BASE_URL / OPENAI_BASE_URL.",
            "#",
            "# Ownership-safe: a live gateway claims only an unset variable or",
            "# an exact URL Bouclier previously installed. Corporate/user URLs",
            "# are preserved. If Bouclier isn't listening we unset only those",
            "# exact owned loopback values so CLI tools talk direct instead of",
            "# erroring with",
            "# 'connection refused'. Explicit unset matters because a stale",
            "# value can be inherited from launchctl setenv, the parent",
            "# shell, or a previous Bouclier session — without the unset",
            "# it can survive the conditional export. Bounded HTTP /livez probe.",
            "__bouclier_sync() {",
            "    if \(healthProbeCommand(port: port)); then",
        ]
        for (k, v) in exports.pairs {
            let owned = shellOwnedValues(
                key: k,
                installingValue: v,
                launchctlOwnership: launchctlOwnership
            )
            let comparisons = posixComparisons(key: k, ownedValues: owned)
            lines.append("        if [ \"${\(k)+x}\" != \"x\" ]; then")
            lines.append("            export \(k)=\"\(shellEscape(v))\"")
            lines.append("        elif \(comparisons); then")
            lines.append("            export \(k)=\"\(shellEscape(v))\"")
            lines.append("        fi")
        }
        lines.append("    else")
        for (k, v) in exports.pairs {
            // A parent profile or corporate launchctl domain may provide its
            // own endpoint. Fail-open cleanup owns only exact validated URLs
            // this or a prior generated file installed; preserve every other
            // value.
            let owned = shellOwnedValues(
                key: k,
                installingValue: v,
                launchctlOwnership: launchctlOwnership
            )
            lines.append(
                "        if \(posixComparisons(key: k, ownedValues: owned)); then unset \(k); fi"
            )
        }
        lines.append("    fi")
        lines.append("}")
        // Run once now (this is the only path non-interactive shells —
        // Claude Code, editor-spawned tools — ever take).
        lines.append("__bouclier_sync")
        // Re-sync before every interactive prompt so a *live* shell
        // self-heals when Bouclier is killed mid-session. Without this,
        // the vars exported at shell start keep pointing at the dead
        // gateway and the next `claude`/`curl` in that same tab fails with
        // 'connection refused' until the tab is closed. The probe is a
        // bounded loopback HTTP `/livez` check; add-zsh-hook de-dupes and the
        // bash branch guards
        // against double-registration on re-source.
        lines.append(contentsOf: [
            "if [ -n \"$ZSH_VERSION\" ]; then",
            "    autoload -Uz add-zsh-hook 2>/dev/null && add-zsh-hook precmd __bouclier_sync 2>/dev/null",
            "elif [ -n \"$BASH_VERSION\" ]; then",
            "    case \"$PROMPT_COMMAND\" in",
            "        *__bouclier_sync*) ;;",
            "        *) PROMPT_COMMAND=\"__bouclier_sync${PROMPT_COMMAND:+; $PROMPT_COMMAND}\" ;;",
            "    esac",
            "fi",
        ])
        return lines.joined(separator: "\n") + "\n"
    }

    static func fishEnvFileContent(
        exports: Exports,
        launchctlOwnership: [String: LaunchctlOwnershipRecord] = [:]
    ) -> String {
        let port = proxyPort(from: exports.pairs.first(where: { $0.1.contains("127.0.0.1:") })?.1 ?? "")
        var lines = [
            "# Bouclier.ai — auto-generated. Do not edit by hand.",
            "# Claim only unset or exactly Bouclier-owned base URLs; preserve",
            "# corporate/user endpoints. Fail-open erases only owned values.",
            "function __bouclier_sync",
            "    if \(healthProbeCommand(port: port))",
        ]
        for (k, v) in exports.pairs {
            let owned = shellOwnedValues(
                key: k,
                installingValue: v,
                launchctlOwnership: launchctlOwnership
            )
            lines.append("        if not set -q \(k)")
            lines.append("            set -gx \(k) \"\(shellEscape(v))\"")
            lines.append("        else if \(fishComparisons(key: k, ownedValues: owned))")
            lines.append("            set -gx \(k) \"\(shellEscape(v))\"")
            lines.append("        end")
        }
        lines.append("    else")
        for (k, v) in exports.pairs {
            let owned = shellOwnedValues(
                key: k,
                installingValue: v,
                launchctlOwnership: launchctlOwnership
            )
            lines.append("        if set -q \(k)")
            lines.append("            if \(fishComparisons(key: k, ownedValues: owned))")
            lines.append("                set -e \(k)")
            lines.append("            end")
            lines.append("        end")
        }
        lines.append("    end")
        lines.append("end")
        // Run once now, then re-sync on every prompt so a live shell
        // self-heals when Bouclier is killed mid-session (see the POSIX
        // file for the full rationale).
        lines.append("__bouclier_sync")
        lines.append(contentsOf: [
            "function __bouclier_sync_prompt --on-event fish_prompt",
            "    __bouclier_sync",
            "end",
        ])
        return lines.joined(separator: "\n") + "\n"
    }

    /// Values a generated shell script may treat as Bouclier-owned for one
    /// key. The installing value is included because the script itself owns it
    /// when it fills an unset variable. Persisted history lets a port-changing
    /// apply update already-running shells without using a broad loopback URL
    /// heuristic. Invalid/foreign values are filtered at this final embedding
    /// boundary even though the persistence codec validates them too.
    private static func shellOwnedValues(
        key: String,
        installingValue: String,
        launchctlOwnership: [String: LaunchctlOwnershipRecord]
    ) -> [String] {
        var seen = Set<String>()
        var values = (launchctlOwnership[key]?.ownedValues ?? []).filter {
            isExactStandardLaunchctlValue(key: key, value: $0)
                && seen.insert($0).inserted
        }
        if isExactStandardLaunchctlValue(key: key, value: installingValue),
           seen.insert(installingValue).inserted
        {
            values.append(installingValue)
        }
        // A decoded record contains at most 64 entries; the installing value
        // can add one more during a port transition. Never accept unbounded
        // caller-supplied material into generated startup scripts.
        return Array(values.prefix(65))
    }

    private static func posixComparisons(
        key: String,
        ownedValues: [String]
    ) -> String {
        // `shellOwnedValues` always includes the controlled installing URL.
        // Keep a defensive false predicate so malformed internal input cannot
        // turn this into an unconditional branch.
        guard !ownedValues.isEmpty else { return "false" }
        return ownedValues.map {
            "[ \"${\(key)-}\" = \"\(shellEscape($0))\" ]"
        }.joined(separator: " || ")
    }

    private static func fishComparisons(
        key: String,
        ownedValues: [String]
    ) -> String {
        guard !ownedValues.isEmpty else { return "false" }
        return ownedValues.map {
            "test \"$\(key)\" = \"\(shellEscape($0))\""
        }.joined(separator: "; or ")
    }

    private static func shellEscape(_ value: String) -> String {
        // Conservative: escape backslashes and double quotes. The values
        // we emit are paths and a `http://127.0.0.1:port` URL — neither
        // legitimately contains either character, but a paranoid escape
        // is cheaper than auditing every caller.
        value.replacingOccurrences(of: "\\", with: "\\\\")
             .replacingOccurrences(of: "\"", with: "\\\"")
    }

    /// Quote a controlled value for `/bin/sh`. Kept robust even though owned
    /// launchctl values are validated loopback URLs before they reach the
    /// watchdog generator.
    private static func shellSingleQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Probe the gateway's own liveness endpoint, not merely whether some
    /// process owns the port. After a crash an unrelated listener reusing the
    /// port must not receive provider credentials/bodies from exported base
    /// URLs. This is an identity hint rather than authentication, but avoids
    /// the common accidental port-reuse failure and sends no secrets itself.
    static func healthProbeCommand(port: Int) -> String {
        "/usr/bin/curl --silent --fail --noproxy '*' --max-time 1 "
            + "'http://127.0.0.1:\(port)/livez' 2>/dev/null "
            + "| /usr/bin/grep -qx 'ok'"
    }

    private static func xmlEscaped(_ value: String) -> String {
        value.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }

    // MARK: - Block management

    private static let blockBegin = "# >>> bouclier.ai env (managed) >>>"
    private static let blockEnd = "# <<< bouclier.ai env (managed) <<<"

    /// Insert or replace the managed block in `path`. Atomic write —
    /// a partial write to `.zshenv` would lock the user out of zsh, so
    /// we never overwrite the live file directly. Existing profiles must
    /// also be readable UTF-8: treating a failed read as an empty file would
    /// destroy user content. A final-component symlink is resolved before the
    /// atomic rename so the link itself survives the update.
    @discardableResult
    static func injectBlock(into path: URL, payload: String, createParent: Bool = false) -> Bool {
        if createParent {
            try? FileManager.default.createDirectory(
                at: path.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
        }

        guard let resolved = resolveMutationPath(path, allowMissing: true) else {
            return false
        }
        let existing: String
        if resolved.targetExists {
            guard let contents = readUTF8File(at: resolved.target) else {
                return false
            }
            existing = contents
        } else {
            existing = ""
        }
        guard let stripped = stripBlock(in: existing) else { return false }
        let separator = stripped.isEmpty || stripped.hasSuffix("\n") ? "" : "\n"
        let block = "\(blockBegin)\n\(payload)\n\(blockEnd)\n"
        let next = stripped + separator + (stripped.isEmpty ? "" : "\n") + block
        return writeAtomically(content: next, to: resolved.target)
    }

    /// Remove the managed block from `path` in-place. Atomic write.
    @discardableResult
    static func stripBlock(from path: URL) -> Bool {
        switch pathEntryKind(at: path) {
        case .missing:
            return true
        case .unavailable:
            return false
        case .regularFile, .symbolicLink, .other:
            break
        }
        guard let resolved = resolveMutationPath(path, allowMissing: false),
              let existing = readUTF8File(at: resolved.target)
        else { return false }
        guard let stripped = stripBlock(in: existing) else { return false }
        if stripped == existing { return true }
        if stripped.isEmpty {
            // If the file was nothing but our block, remove it so we
            // don't leave a stray empty `.profile` behind. A symlink was
            // necessarily user-owned before injection, though, so retain it
            // and empty its resolved target instead of deleting the link.
            if resolved.originalWasSymbolicLink {
                return writeAtomically(content: "", to: resolved.target)
            }
            return removeFileIfPresent(path)
        }
        return writeAtomically(content: stripped, to: resolved.target)
    }

    private static func stripBlock(in content: String) -> String? {
        let beginRanges = markerRanges(of: blockBegin, in: content)
        let endRanges = markerRanges(of: blockEnd, in: content)
        if beginRanges.isEmpty, endRanges.isEmpty { return content }
        // A missing, reversed, or duplicate marker makes ownership ambiguous.
        // Never "recover" by dropping an unbounded tail: it may contain user
        // configuration added after a damaged managed block.
        guard beginRanges.count == 1,
              endRanges.count == 1,
              let beginRange = beginRanges.first,
              let endRange = endRanges.first,
              beginRange.upperBound <= endRange.lowerBound
        else { return nil }
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

    private static func markerRanges(
        of marker: String,
        in content: String
    ) -> [Range<String.Index>] {
        var ranges: [Range<String.Index>] = []
        var searchStart = content.startIndex
        while searchStart < content.endIndex,
              let range = content.range(
                  of: marker,
                  range: searchStart..<content.endIndex
              )
        {
            ranges.append(range)
            searchStart = range.upperBound
        }
        return ranges
    }

    // MARK: - launchctl

    private static func applyLaunchctlSetenv(exports: Exports) -> Bool {
        guard var ownership = loadLaunchctlOwnership() else { return false }
        // Establish the tracked-ownership epoch even when every current value
        // conflicts. Otherwise a later removal could fall back to the legacy
        // port heuristic and delete an exact-looking value we refused to own.
        if !UserDefaults.standard.bool(forKey: launchctlOwnershipTrackingKey),
           !persistLaunchctlOwnership(ownership)
        {
            return false
        }
        var complete = true
        for (k, v) in exports.pairs {
            let currentValue: String?
            switch launchctlValue(for: k) {
            case .absent:
                currentValue = nil
            case .value(let current):
                currentValue = current
            case .failed:
                complete = false
                continue
            }

            guard let record = updatedLaunchctlOwnership(
                existing: ownership[k],
                currentValue: currentValue,
                installingValue: v
            ) else {
                // Never overwrite an untracked value. Besides preserving a
                // user's configuration, this avoids persisting a potentially
                // credential-bearing corporate URL merely so it can be
                // restored later. The partial apply is surfaced by the caller.
                complete = false
                continue
            }

            // Persist ownership before the external mutation. If the process
            // exits after `setenv` but before verification, the next cleanup
            // still knows every exact value Bouclier may have installed.
            ownership[k] = record
            guard persistLaunchctlOwnership(ownership) else {
                complete = false
                continue
            }
            _ = runLaunchctl(["setenv", k, v])
            let installed = launchctlValue(for: k) == .value(v)
            complete = installed && complete
            // Retain the full validated history after success. Although the
            // launchctl key now contains only `v`, an already-running shell can
            // still carry an older value and needs exact ownership evidence to
            // update or fail open safely on its next prompt.
        }
        return complete
    }

    private static func loadLaunchctlOwnership() -> [String: LaunchctlOwnershipRecord]? {
        guard let stored = UserDefaults.standard.object(
            forKey: launchctlOwnershipKey
        ) else {
            return [:]
        }
        guard let data = stored as? Data else { return nil }
        return decodedLaunchctlOwnership(data)
    }

    static func decodedLaunchctlOwnership(
        _ data: Data
    ) -> [String: LaunchctlOwnershipRecord]? {
        // This record must never become a general environment-variable store.
        // Bound its size and validate every decoded value against an exact URL
        // shape emitted by `buildStandardExports` before using it in cleanup or
        // embedding it in the watchdog shell command.
        guard data.count <= 64 * 1024,
              let decoded = try? JSONDecoder().decode(
                  [String: LaunchctlOwnershipRecord].self,
                  from: data
              ),
              decoded.allSatisfy({ key, record in
                  standardEnvVarKeys.contains(key)
                      && !record.ownedValues.isEmpty
                      && record.ownedValues.count <= 64
                      && record.ownedValues.allSatisfy {
                          isExactStandardLaunchctlValue(key: key, value: $0)
                      }
              })
        else { return nil }
        return decoded
    }

    static func encodedLaunchctlOwnership(
        _ ownership: [String: LaunchctlOwnershipRecord]
    ) -> Data? {
        guard ownership.allSatisfy({ key, record in
            standardEnvVarKeys.contains(key)
                && !record.ownedValues.isEmpty
                && record.ownedValues.count <= 64
                && record.ownedValues.allSatisfy {
                    isExactStandardLaunchctlValue(key: key, value: $0)
                }
        }),
        let data = try? JSONEncoder().encode(ownership),
        data.count <= 64 * 1024
        else { return nil }
        return data
    }

    @discardableResult
    private static func persistLaunchctlOwnership(
        _ ownership: [String: LaunchctlOwnershipRecord]
    ) -> Bool {
        guard let data = encodedLaunchctlOwnership(ownership) else { return false }

        if ownership.isEmpty {
            UserDefaults.standard.removeObject(forKey: launchctlOwnershipKey)
        } else {
            UserDefaults.standard.set(data, forKey: launchctlOwnershipKey)
        }
        // Keep this tombstone after records are cleared. It prevents a later
        // retry from falling back to a port-only heuristic and deleting an
        // exact-equal value that was never recorded as ours.
        UserDefaults.standard.set(true, forKey: launchctlOwnershipTrackingKey)
        return UserDefaults.standard.synchronize()
    }

    private static func isExactStandardLaunchctlValue(
        key: String,
        value: String
    ) -> Bool {
        guard let url = URL(string: value),
              url.scheme == "http",
              url.host == "127.0.0.1",
              let port = url.port,
              (1...65_535).contains(port)
        else { return false }
        return ownsStandardLaunchctlValue(
            key: key,
            value: value,
            gatewayPort: port
        )
    }

    // MARK: - Crash-resilient watchdog (LaunchAgent)

    /// Label for the LaunchAgent. macOS uses this to identify the
    /// loaded job; must match the plist's `Label` key.
    static let watchdogLabel = "ai.bouclier.proxy-env-watchdog"

    /// Path to the per-user LaunchAgent plist. We install at the user
    /// level (no admin password) and only act on per-user launchctl
    /// state, so the privileges line up.
    static func watchdogPlistPath() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(watchdogLabel).plist")
    }

    /// Generate the LaunchAgent plist content. Hoisted out for testing.
    ///
    /// The agent runs every minute. On each tick it checks the gateway's
    /// liveness endpoint; if it fails, it clears only launchctl values present
    /// in Bouclier's durable ownership record. This catches the hard-crash
    /// / force-quit / SIGKILL case where Bouclier's own atexit + SIGTERM
    /// handlers never fire, leaving stale env pointing at a dead port.
    /// One minute of staleness is the worst-case window — paired with
    /// the shell-level fail-open guard for new shells, that's tolerable.
    static func watchdogPlist(
        proxyPort: Int,
        launchctlOwnership: [String: LaunchctlOwnershipRecord] = [:]
    ) -> String {
        // Single-line shell command so we don't have to externalise a
        // separate script — keeps install/uninstall self-contained.
        //
        // The probe tests Bouclier's exact `/livez` response rather than
        // merely "is some listener reachable". `pgrep -f` false-positives
        // on commands that mention the bundle, while a bare TCP probe lets
        // an unrelated process that reused the port receive AI traffic.
        //
        // Standard mode owns only the two base-URL variables and never
        // configures system PAC. Clearing unrelated proxy/CA variables or
        // sweeping every network service would destroy corporate settings.
        let unsetCmd = Self.standardEnvVarKeys.enumerated().compactMap {
            index, key -> String? in
            guard let record = launchctlOwnership[key],
                  !record.ownedValues.isEmpty,
                  record.ownedValues.allSatisfy({
                      isExactStandardLaunchctlValue(key: key, value: $0)
                  })
            else { return nil }
            let variable = "__bouclier_value_\(index)"
            let comparisons = record.ownedValues.map {
                "[ \"$\(variable)\" = \(shellSingleQuoted($0)) ]"
            }.joined(separator: " || ")
            return "\(variable)=\"$(launchctl getenv \(key))\"; if \(comparisons); then launchctl unsetenv \(key); fi"
        }.joined(separator: "; ")
        let probe = healthProbeCommand(port: proxyPort)
        let script = "\(probe) || { \(unsetCmd.isEmpty ? ":" : unsetCmd); }"
        let xmlScript = xmlEscaped(script)
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(watchdogLabel)</string>
            <key>ProgramArguments</key>
            <array>
                <string>/bin/sh</string>
                <string>-c</string>
                <string>\(xmlScript)</string>
            </array>
            <key>StartInterval</key>
            <integer>60</integer>
            <key>RunAtLoad</key>
            <true/>
            <key>StandardOutPath</key>
            <string>/dev/null</string>
            <key>StandardErrorPath</key>
            <string>/dev/null</string>
        </dict>
        </plist>
        """
    }

    /// Install the watchdog: write the plist, load it via `launchctl`.
    /// Idempotent — re-installing first unloads any existing copy so
    /// changes to the plist body take effect on the next apply().
    @discardableResult
    static func installWatchdog(proxyPort: Int) -> Bool {
        guard let ownership = loadLaunchctlOwnership() else { return false }
        let path = watchdogPlistPath()
        do {
            try FileManager.default.createDirectory(
                at: path.deletingLastPathComponent(), withIntermediateDirectories: true
            )
        } catch {}
        let wrote = writeAtomically(
            content: watchdogPlist(
                proxyPort: proxyPort,
                launchctlOwnership: ownership
            ),
            to: path
        )
        // Never sacrifice a working watchdog when its replacement could not
        // be written. Once the file is durable, unload only if a job actually
        // exists and verify each launchd postcondition rather than trusting an
        // exit status alone.
        guard wrote else { return false }
        let service = "gui/\(uid())/\(watchdogLabel)"
        switch launchctlServiceState(service) {
        case .notLoaded:
            break
        case .loaded:
            _ = runLaunchctl(["bootout", service])
            guard launchctlServiceState(service) == .notLoaded else {
                return false
            }
        case .failed:
            return false
        }
        _ = runLaunchctl(["bootstrap", "gui/\(uid())", path.path])
        return launchctlServiceState(service) == .loaded
    }

    /// Uninstall the watchdog: unload the agent and remove the plist.
    @discardableResult
    static func removeWatchdog() -> Bool {
        let path = watchdogPlistPath()
        let service = "gui/\(uid())/\(watchdogLabel)"
        let unloaded: Bool
        switch launchctlServiceState(service) {
        case .notLoaded:
            unloaded = true
        case .loaded:
            unloaded = runLaunchctl(["bootout", service])
        case .failed:
            // Do not turn an inability to inspect the launchd domain into a
            // false "removed" result. Still remove what is safely removable
            // so retrying this operation remains idempotent.
            unloaded = false
        }
        let fileRemoved = removeFileIfPresent(path)
        let noLongerLoaded = launchctlServiceState(service) == .notLoaded
        return unloaded && fileRemoved && noLongerLoaded
    }

    private static func uid() -> String {
        String(getuid())
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

    private enum LaunchctlValue: Equatable {
        case value(String)
        case absent
        case failed
    }

    /// `launchctl getenv` exits successfully with empty output for an unset
    /// key. Keep that distinct from a process/launchd failure: cleanup may
    /// treat the former as complete, but must surface the latter as partial.
    private static func launchctlValue(for key: String) -> LaunchctlValue {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["getenv", key]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return .failed }
            guard var value = String(data: data, encoding: .utf8) else {
                return .failed
            }
            // `launchctl getenv` terminates output with one newline. Preserve
            // every other byte, especially leading/trailing spaces in a
            // foreign value we must compare without normalizing.
            if value.hasSuffix("\n") { value.removeLast() }
            if value.hasSuffix("\r") { value.removeLast() }
            return value.isEmpty ? .absent : .value(value)
        } catch {
            return .failed
        }
    }

    private enum LaunchctlServiceState: Equatable {
        case loaded
        case notLoaded
        case failed
    }

    /// A non-zero `launchctl print` is not automatically proof that a job is
    /// absent: an inaccessible launchd domain and a missing service both fail.
    /// Recognize launchctl's explicit not-found diagnostic and otherwise fail
    /// closed so removal remains honest.
    private static func launchctlServiceState(_ service: String) -> LaunchctlServiceState {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = ["print", service]
        process.standardOutput = output
        process.standardError = output
        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            if process.terminationStatus == 0 { return .loaded }
            let message = String(data: data, encoding: .utf8)?.lowercased() ?? ""
            if message.contains("could not find service")
                || message.contains("service not found")
            {
                return .notLoaded
            }
            return .failed
        } catch {
            return .failed
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

    @discardableResult
    private static func writeAtomically(content: String, to url: URL) -> Bool {
        // Foundation's `.atomic` implementation renames a temporary file
        // over `url`. If `url` is a symlink this replaces the directory entry
        // rather than updating its target. Resolve only the final-component
        // link (including chains) and write the regular target instead.
        guard let resolved = resolveMutationPath(url, allowMissing: true) else {
            return false
        }
        do {
            try FileManager.default.createDirectory(
                at: resolved.target.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
        } catch { return false }
        guard let data = content.data(using: .utf8) else { return false }
        do {
            try data.write(to: resolved.target, options: .atomic)
            return true
        } catch {
            // Best-effort: a single dotfile failing to write must not
            // abort the rest of the setup flow.
            return false
        }
    }

    private static func removeFileIfPresent(_ url: URL) -> Bool {
        // `fileExists` follows symlinks and reports a dangling link as absent,
        // which would leave a real routing artifact behind while claiming
        // cleanup success. lstat checks the directory entry itself.
        guard pathEntryExists(url) else { return true }
        do {
            try FileManager.default.removeItem(at: url)
            return true
        } catch {
            return false
        }
    }

    private static func pathEntryExists(_ url: URL) -> Bool {
        switch pathEntryKind(at: url) {
        case .missing:
            return false
        case .regularFile, .symbolicLink, .other, .unavailable:
            return true
        }
    }

    /// The final path component is the only one an atomic rename could
    /// replace. Parent-directory symlinks are traversed by the filesystem and
    /// remain intact. Distinguish a genuinely absent entry from an lstat
    /// failure so an inaccessible profile is never treated as safe to create.
    private enum PathEntryKind {
        case missing
        case regularFile
        case symbolicLink
        case other
        case unavailable
    }

    private static func pathEntryKind(at url: URL) -> PathEntryKind {
        var info = stat()
        let result = url.path.withCString { lstat($0, &info) }
        guard result == 0 else {
            return errno == ENOENT || errno == ENOTDIR ? .missing : .unavailable
        }
        let fileType = info.st_mode & mode_t(S_IFMT)
        if fileType == mode_t(S_IFREG) { return .regularFile }
        if fileType == mode_t(S_IFLNK) { return .symbolicLink }
        return .other
    }

    private struct ResolvedMutationPath {
        let target: URL
        let targetExists: Bool
        let originalWasSymbolicLink: Bool
    }

    /// Resolve a final-component symbolic-link chain without asking
    /// `resolvingSymlinksInPath()` to canonicalize unrelated parent links.
    /// A symlink must end at an existing regular file; following a dangling
    /// link by creating its target would silently turn a broken user setting
    /// into Bouclier-owned state. The depth/visited guards reject loops.
    private static func resolveMutationPath(
        _ original: URL,
        allowMissing: Bool
    ) -> ResolvedMutationPath? {
        var current = original.standardizedFileURL
        var followedSymbolicLink = false
        var visited = Set<String>()

        for _ in 0..<40 {
            switch pathEntryKind(at: current) {
            case .missing:
                guard allowMissing, !followedSymbolicLink else { return nil }
                return ResolvedMutationPath(
                    target: current,
                    targetExists: false,
                    originalWasSymbolicLink: false
                )
            case .regularFile:
                return ResolvedMutationPath(
                    target: current,
                    targetExists: true,
                    originalWasSymbolicLink: followedSymbolicLink
                )
            case .symbolicLink:
                guard visited.insert(current.path).inserted,
                      let destination = try? FileManager.default
                          .destinationOfSymbolicLink(atPath: current.path)
                else { return nil }
                followedSymbolicLink = true
                if (destination as NSString).isAbsolutePath {
                    current = URL(fileURLWithPath: destination).standardizedFileURL
                } else {
                    current = current.deletingLastPathComponent()
                        .appendingPathComponent(destination)
                        .standardizedFileURL
                }
            case .other, .unavailable:
                return nil
            }
        }
        return nil
    }

    private static func readUTF8File(at url: URL) -> String? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
