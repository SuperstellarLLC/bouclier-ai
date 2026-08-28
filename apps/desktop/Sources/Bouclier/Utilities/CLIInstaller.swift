import Foundation

/// Puts the `bouclier` CLI on `PATH` via a user-authorized symlink into
/// `/usr/local/bin`, instead of the old print-only flow that made a human
/// copy a `sudo ln -sf …` command into Terminal (see `CLICore.installCmd`,
/// still there as the Bash-first fallback).
///
/// `/usr/local/bin` needs root to write to, so this can't be an unattended
/// write — but "unattended" was never the actual requirement, only "a
/// human approves it." The macOS administrator-privileges prompt (Touch
/// ID / password) is that same approval gate, without requiring anyone to
/// open Terminal.
enum CLIInstaller {
    static let symlinkPath = "/usr/local/bin/bouclier"

    static func binaryPath(named name: String, bundlePath: String = Bundle.main.bundlePath) -> String {
        bundlePath + "/Contents/MacOS/" + name
    }

    static var cliBinaryPath: String { binaryPath(named: "bouclier-cli") }
    static var mcpBinaryPath: String { binaryPath(named: "bouclier-ai-mcp-wrapper") }

    static func mcpRegistrationCommand(mcpPath: String = mcpBinaryPath) -> String {
        "claude mcp add bouclier -- \(shellQuoted(mcpPath))"
    }

    /// What the symlink currently resolves to, or nil if it doesn't exist
    /// (or isn't a symlink at all).
    static func installedTarget(at path: String = symlinkPath) -> String? {
        try? FileManager.default.destinationOfSymbolicLink(atPath: path)
    }

    static func isInstalled(cliBinaryPath: String = cliBinaryPath, symlinkPath: String = symlinkPath) -> Bool {
        installedTarget(at: symlinkPath) == cliBinaryPath
    }

    /// The shell command the privileged install actually runs — separated
    /// out so it's testable without invoking `NSAppleScript`.
    static func installShellCommand(cliPath: String, symlinkPath: String = symlinkPath) -> String {
        "mkdir -p \(shellQuoted((symlinkPath as NSString).deletingLastPathComponent)) && " +
            "ln -sf \(shellQuoted(cliPath)) \(shellQuoted(symlinkPath))"
    }

    private static func shellQuoted(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    enum InstallError: Error, LocalizedError {
        case declined
        case scriptFailed(String)

        var errorDescription: String? {
            switch self {
            case .declined: return "Installation was cancelled."
            case .scriptFailed(let message): return message
            }
        }
    }

    /// Shows the standard macOS administrator-privileges prompt and, once
    /// approved, creates the PATH symlink. Runs synchronously (the prompt
    /// is itself modal) — call off the main thread.
    @discardableResult
    static func install() throws -> String {
        let shellCommand = installShellCommand(cliPath: cliBinaryPath)
        let escaped = shellCommand
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges"

        guard let appleScript = NSAppleScript(source: script) else {
            throw InstallError.scriptFailed("Could not construct the install script.")
        }
        var errorDict: NSDictionary?
        let result = appleScript.executeAndReturnError(&errorDict)
        if let errorDict {
            let number = errorDict[NSAppleScript.errorNumber] as? Int
            if number == -128 {
                throw InstallError.declined
            }
            throw InstallError.scriptFailed(errorDict[NSAppleScript.errorMessage] as? String ?? "Unknown error.")
        }
        return result.stringValue ?? ""
    }
}
