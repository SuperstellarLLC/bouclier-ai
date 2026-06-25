import Foundation
import Security

/// Dependency-free core shared by the main app's siblings — the secrets
/// MCP server (`bouclier-ai-secrets-mcp`) and the shell helper
/// (`bouclier-ai-env`). It is the bridge that lets an AI agent **use** a
/// secret without ever **seeing** its value:
///
///   1. The MCP server reads rule metadata (names, `agentAccess`, env-var
///      names — never values) and writes an *active manifest* of secret
///      names the agent has requested. It returns env-var names to the
///      model, never values.
///   2. The shell helper reads that manifest, looks up the real values in
///      the Keychain at shell-init time, and `export`s them into the
///      agent's subprocess environment.
///
/// Values live only in the Keychain (at rest) and in the subprocess env
/// (at execution). They are never written to the manifest, returned to the
/// MCP client, or placed in the model's context.
public enum SecretEnvPaths {
    public static var appSupportDir: URL {
        // Test/CI override so the sibling binaries can run against a
        // throwaway directory without touching the user's real store.
        let base: URL
        if let override = ProcessInfo.processInfo.environment["BOUCLIER_APP_SUPPORT_DIR"], !override.isEmpty {
            base = URL(fileURLWithPath: override, isDirectory: true)
        } else {
            base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
                .first!.appendingPathComponent("ai.bouclier.app", isDirectory: true)
        }
        try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
        return base
    }
    /// Written by the main app's `SecretStore` (rule metadata, no values).
    public static var rulesFile: URL { appSupportDir.appendingPathComponent("secret-rules.json") }
    /// Active env secrets the agent has requested (names only, no values).
    public static var manifestFile: URL { appSupportDir.appendingPathComponent("active-env-secrets.json") }
    /// Read-only state snapshot the app publishes for the MCP server / CLI
    /// to answer "is Bouclier installed/running/healthy?" (no values).
    public static var statusFile: URL { appSupportDir.appendingPathComponent("status.json") }

    // MARK: - Just-in-time secret request IPC (agent ↔ app)
    //
    // The MCP server drops a request file (names + reason, NEVER a value);
    // the app watches `requests/`, shows a dialog, and writes a response
    // file (status + names, NEVER a value). Separate subdirs so the app's
    // own response writes don't wake its requests watcher.
    public static var ipcDir: URL {
        let d = appSupportDir.appendingPathComponent("ipc", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return d
    }
    public static var ipcRequestsDir: URL {
        let d = ipcDir.appendingPathComponent("requests", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return d
    }
    public static var ipcResponsesDir: URL {
        let d = ipcDir.appendingPathComponent("responses", isDirectory: true)
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return d
    }
    /// The app writes its pid here at launch so the MCP client can fail
    /// fast (kill(pid,0)) instead of waiting the full timeout when the app
    /// isn't running.
    public static var responderPidFile: URL { ipcDir.appendingPathComponent("responder.pid") }
}

/// Read-only view of a `SecretStore` rule — only the non-secret metadata.
/// Decodes the same `secret-rules.json` the app writes; backward-compatible
/// with rules saved before `agentAccess`/`envVar` existed.
public struct SecretRuleMeta: Codable, Sendable, Equatable {
    public let name: String
    public let allowedHosts: [String]
    public let agentAccess: Bool
    public let envVar: String?

    public init(name: String, allowedHosts: [String] = [], agentAccess: Bool = true, envVar: String? = nil) {
        self.name = name
        self.allowedHosts = allowedHosts
        self.agentAccess = agentAccess
        self.envVar = envVar
    }

    enum CodingKeys: String, CodingKey { case name, allowedHosts, agentAccess, envVar }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        allowedHosts = (try c.decodeIfPresent([String].self, forKey: .allowedHosts)) ?? []
        agentAccess = (try c.decodeIfPresent(Bool.self, forKey: .agentAccess)) ?? true
        envVar = try c.decodeIfPresent(String.self, forKey: .envVar)
    }

    /// The environment variable the agent's shell exports for this secret.
    public var environmentVariable: String {
        if let v = envVar, !v.isEmpty { return v }
        return name.uppercased()
    }
}

public enum SecretRulesReader {
    public static func load(from url: URL = SecretEnvPaths.rulesFile) -> [SecretRuleMeta] {
        guard let data = try? Data(contentsOf: url),
              let rules = try? JSONDecoder().decode([SecretRuleMeta].self, from: data)
        else { return [] }
        return rules
    }
}

/// The active manifest: the set of secret *names* the agent has asked to
/// have in its environment. Names only — never values.
public enum SecretEnvManifest {
    public static func load(from url: URL = SecretEnvPaths.manifestFile) -> [String] {
        guard let data = try? Data(contentsOf: url),
              let names = try? JSONDecoder().decode([String].self, from: data)
        else { return [] }
        // De-dupe, preserve order.
        var seen = Set<String>()
        return names.filter { seen.insert($0).inserted }
    }

    @discardableResult
    public static func save(_ names: [String], to url: URL = SecretEnvPaths.manifestFile) -> Bool {
        var seen = Set<String>()
        let unique = names.filter { seen.insert($0).inserted }
        guard let data = try? JSONEncoder().encode(unique) else { return false }
        do {
            try data.write(to: url, options: [.atomic])
            chmod(url.path, 0o600)
            return true
        } catch { return false }
    }

    public static func clear(at url: URL = SecretEnvPaths.manifestFile) {
        try? FileManager.default.removeItem(at: url)
    }
}

/// Pure resolution of active secret names → environment exports, gated by
/// `agentAccess`. No I/O — the value provider is injected so this is fully
/// unit-testable (and the MCP server, which has no value access, can run it
/// with a nil provider to compute allow/deny without ever touching values).
public enum SecretEnvResolver {
    public struct Export: Equatable, Sendable {
        public let envVar: String
        public let value: String
        public init(envVar: String, value: String) { self.envVar = envVar; self.value = value }
    }
    public struct Result: Equatable, Sendable {
        /// Allowed + resolved, ready to export.
        public let exports: [Export]
        /// Requested but unknown or `agentAccess == false`.
        public let denied: [String]
        /// Allowed but no value available (Keychain miss).
        public let unresolved: [String]
        public init(exports: [Export], denied: [String], unresolved: [String]) {
            self.exports = exports; self.denied = denied; self.unresolved = unresolved
        }
    }

    public static func resolve(
        active: [String],
        metas: [SecretRuleMeta],
        value: (String) -> String?
    ) -> Result {
        let byName = Dictionary(metas.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        var exports: [Export] = []
        var denied: [String] = []
        var unresolved: [String] = []
        var seenEnv = Set<String>()
        for name in active {
            guard let meta = byName[name], meta.agentAccess else { denied.append(name); continue }
            // Defense-in-depth: the env-var name is interpolated UNQUOTED
            // into a shell `export`/`set` line, so re-validate it here at the
            // privileged executor rather than trusting the rules file. A
            // crafted/corrupt rule (e.g. envVar "X; rm -rf ~ #") is denied.
            let env = meta.environmentVariable
            guard isValidEnvName(env) else { denied.append(name); continue }
            guard let v = value(name), !v.isEmpty else { unresolved.append(name); continue }
            // A value with CR/LF would break the single-line shell export
            // (the store forbids these, but don't trust that across modules).
            guard !v.contains("\n"), !v.contains("\r") else { unresolved.append(name); continue }
            // First occurrence wins on env-var collision; don't emit twice.
            if seenEnv.insert(env).inserted {
                exports.append(Export(envVar: env, value: v))
            }
        }
        return Result(exports: exports, denied: denied, unresolved: unresolved)
    }

    /// Env-var names must be `[A-Za-z_][A-Za-z0-9_]*` — safe to `export`
    /// and impossible to use to smuggle shell syntax.
    public static func isValidEnvName(_ s: String) -> Bool {
        guard let first = s.first, first.isLetter || first == "_" else { return false }
        return s.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }
    }

    /// POSIX-safe `export` lines (zsh/bash). Single-quote the value and
    /// escape any embedded single quote (`'\''`) so arbitrary key bytes
    /// can't break out of the quoting or inject shell syntax.
    public static func exportLines(_ exports: [Export]) -> String {
        exports.map { "export \($0.envVar)=\(singleQuote($0.value));" }.joined(separator: "\n")
    }

    /// fish-shell equivalent: `set -gx NAME 'value'`. fish single-quoted
    /// strings only treat `\'` and `\\` as escapes, so backslash-escape
    /// both — different from the POSIX `'\''` dance.
    public static func exportLinesFish(_ exports: [Export]) -> String {
        exports.map { "set -gx \($0.envVar) \(fishQuote($0.value));" }.joined(separator: "\n")
    }

    static func singleQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func fishQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "'", with: "\\'") + "'"
    }
}

/// Reads a secret value from the Keychain — the ONLY place values are read.
/// Mirrors `SecretStore`'s `SecItem` usage (service `ai.bouclier.app`,
/// account `secret-<name>`). No-prompt cross-binary access requires the
/// helper to share the app's keychain-access-group entitlement; without it
/// macOS prompts the user (acceptable: explicit consent, never silent).
public enum KeychainSecretReader {
    /// Keychain service. Overridable for tests via
    /// `BOUCLIER_KEYCHAIN_SERVICE`; production is always `ai.bouclier.app`.
    static var service: String {
        let env = ProcessInfo.processInfo.environment["BOUCLIER_KEYCHAIN_SERVICE"]
        return (env?.isEmpty == false ? env! : nil) ?? "ai.bouclier.app"
    }

    public static func value(forName name: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "secret-\(name)",
            kSecReturnData as String: true,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
