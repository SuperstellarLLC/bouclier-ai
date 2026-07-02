import Foundation

/// Generates a random secret value by running a user-configurable shell
/// command (1Password-style "generate"). Default is an `openssl` command;
/// the user can change it in Settings. The generated value is materialized
/// only inside the app and goes straight to the Keychain — it is never
/// shown to the agent, the same as a pasted value.
public enum SecretGenerator {
    public static let defaultCommand = "openssl rand -base64 32"
    public static let commandKey = "bouclier.secretGenCommand"

    /// The configured generator command (falls back to the default).
    public static var command: String {
        let c = UserDefaults.standard.string(forKey: commandKey)
        return (c?.isEmpty == false ? c! : nil) ?? defaultCommand
    }

    /// Run `command` (or the configured one) via `/bin/sh -c` and return the
    /// trimmed stdout. Returns nil if it fails, produces nothing, or the
    /// output isn't a storable secret (CR/LF/NUL or too long).
    public static func generate(command: String? = nil) -> String? {
        let cmd = command ?? self.command
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/sh")
        p.arguments = ["-c", cmd]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0,
              let raw = String(data: data, encoding: .utf8)
        else { return nil }
        let value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isStorable(value) else { return nil }
        return value
    }

    /// A generated value must be non-empty, single-line, and within the
    /// secret size bound (mirrors SecretRule.isValidValue without depending
    /// on the app target).
    static func isStorable(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 8 * 1024 else { return false }
        for b in value.utf8 where b == 0x00 || b == 0x0A || b == 0x0D { return false }
        return true
    }
}
