import Foundation

/// Configures macOS system proxy settings to route traffic through Bouclier.
/// Uses `networksetup` to set HTTP/HTTPS proxy on the active network interface.
/// Only intercepts AI API domains via PAC (Proxy Auto-Config).
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

    /// All intercepted domains (built-in + MDM-configured).
    static var interceptedDomains: Set<String> {
        var domains = builtinDomains
        for domain in ManagedConfig.additionalDomains {
            domains.insert(domain.lowercased())
        }
        return domains
    }

    static func pacFileContent(port: Int) -> String {
        let domainChecks = interceptedDomains
            .map { "    if (dnsDomainIs(host, \"\($0)\")) return PROXY;" }
            .joined(separator: "\n")

        return """
        function FindProxyForURL(url, host) {
            var PROXY = "PROXY 127.0.0.1:\(port)";
        \(domainChecks)
            return "DIRECT";
        }
        """
    }

    /// Write PAC file and configure system to use it.
    static func enable(port: Int) -> Bool {
        let pacDir = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!.appendingPathComponent("com.bouclier.Bouclier", isDirectory: true)

        try? FileManager.default.createDirectory(at: pacDir, withIntermediateDirectories: true)
        let pacPath = pacDir.appendingPathComponent("proxy.pac")

        do {
            try pacFileContent(port: port).write(to: pacPath, atomically: true, encoding: .utf8)
        } catch {
            print("[bouclier-proxy] Failed to write PAC file: \(error)")
            return false
        }

        // Get active network interface
        guard let interface = activeNetworkInterface() else {
            print("[bouclier-proxy] No active network interface found")
            return false
        }

        // Set proxy auto-config URL
        let pacURL = "file://\(pacPath.path)"
        return runNetworkSetup(["-setautoproxyurl", interface, pacURL])
            && runNetworkSetup(["-setautoproxystate", interface, "on"])
    }

    /// Remove system proxy configuration.
    static func disable() -> Bool {
        guard let interface = activeNetworkInterface() else { return false }
        return runNetworkSetup(["-setautoproxystate", interface, "off"])
    }

    /// Check if system proxy is currently enabled.
    static func isEnabled() -> Bool {
        guard let interface = activeNetworkInterface() else { return false }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = ["-getautoproxyurl", interface]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            let output = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            return output.contains("Enabled: Yes") && output.contains("bouclier")
        } catch {
            return false
        }
    }

    // MARK: - Private

    private static func activeNetworkInterface() -> String? {
        // Get the primary network service (usually Wi-Fi or Ethernet)
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
            let services = output.components(separatedBy: "\n")
                .filter { !$0.hasPrefix("An asterisk") && !$0.isEmpty }

            // Prefer Wi-Fi, then Ethernet, then first available
            for preferred in ["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"] {
                if services.contains(preferred) { return preferred }
            }
            return services.first
        } catch {
            return nil
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
