import Foundation

/// `interceptedDomains` is the mode-agnostic "which AI hosts does
/// Bouclier care about" set, still used by the diagnostics export and
/// the secret-keeper's host bookkeeping. `disableAll()` is a
/// cleanup-only remnant of the PAC-based system proxy that used to back
/// "extreme mode" (removed) — kept so `ProxyManager`'s one-shot
/// migration can sweep any stale PAC configuration left on a machine
/// that had extreme mode enabled before it was removed.
enum SystemProxy {
    /// Built-in AI API domains.
    static let builtinDomains: Set<String> = [
        "api.openai.com",
        "api.anthropic.com",
        "api.cohere.com",
        "api.mistral.ai",
        "generativelanguage.googleapis.com",
        "api.together.xyz",
        "api.groq.com",
        "api.perplexity.ai",
        "api.fireworks.ai",
        "openrouter.ai",
    ]

    /// All intercepted domains (built-in + MDM-configured + secret-rule
    /// hosts). Reported by the diagnostics export and used for the
    /// secret-keeper's host bookkeeping.
    static var interceptedDomains: Set<String> {
        var domains = builtinDomains
        for domain in ManagedConfig.additionalDomains {
            domains.insert(domain.lowercased())
        }
        // Secret-keeper: hosts bound to a managed secret are reported
        // alongside the built-in set. Gated on the flag so the default
        // posture is unchanged.
        if FeatureFlags.secretInjection {
            for host in SecretStore.shared.allHosts() {
                domains.insert(host)
            }
        }
        return domains
    }

    /// Nuclear PAC sweep: turns auto-proxy *and* manual HTTP/HTTPS
    /// proxy off on every configured network service. Cleanup-only —
    /// used by the extreme-mode-removal migration and the Settings →
    /// Reset all proxies escape hatch to strip any PAC configuration a
    /// pre-removal install may have left behind.
    @discardableResult
    static func disableAll() -> Bool {
        let interfaces = allNetworkInterfaces()
        guard !interfaces.isEmpty else { return false }
        var ok = true
        for iface in interfaces {
            if !runNetworkSetup(["-setautoproxystate", iface, "off"]) { ok = false }
            _ = runNetworkSetup(["-setwebproxystate", iface, "off"])
            _ = runNetworkSetup(["-setsecurewebproxystate", iface, "off"])
        }
        return ok
    }

    // MARK: - Private

    private static func allNetworkInterfaces() -> [String] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = ["-listallnetworkservices"]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            return output.components(separatedBy: "\n")
                .filter { !$0.hasPrefix("An asterisk") && !$0.isEmpty }
        } catch {
            return []
        }
    }

    private static func runNetworkSetup(_ args: [String]) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = args
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationStatus == 0
        } catch {
            return false
        }
    }
}
