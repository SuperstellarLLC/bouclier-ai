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

    /// Test-only additions to the SSRF allowlist. The e2e test stands
    /// up an in-process upstream on `localhost`; the proxy's CONNECT
    /// handler refuses any host not in `interceptedDomains`, so the
    /// test seeds this set before driving traffic. Always empty in
    /// production builds.
    ///
    /// `nonisolated(unsafe)` rather than an actor or lock: the value
    /// is mutated exactly once per test in the synchronous setup phase
    /// and read by handler instances on event-loop threads thereafter.
    /// A lock would be overkill; an actor would force the read path
    /// async for production code that never touches this property.
    nonisolated(unsafe) static var testAdditionalDomains: Set<String> = []

    /// All intercepted domains (built-in + MDM-configured + secret-rule
    /// hosts). A host is MITM'd and PAC-routed iff it appears here.
    static var interceptedDomains: Set<String> {
        var domains = builtinDomains
        for domain in ManagedConfig.additionalDomains {
            domains.insert(domain.lowercased())
        }
        for domain in testAdditionalDomains {
            domains.insert(domain.lowercased())
        }
        // Secret-keeper: hosts bound to a managed secret must be
        // intercepted so the injection pass can swap the placeholder for
        // the real value at egress. Gated on the flag so the default
        // posture is unchanged — no rule, no extra MITM.
        if FeatureFlags.secretInjection {
            for host in SecretStore.shared.allHosts() {
                domains.insert(host)
            }
        }
        return domains
    }

    /// Fail-closed egress decision for a non-intercepted host (i.e. one
    /// we don't MITM and would normally blind-tunnel). Pure so it's unit
    /// testable without MDM defaults or a live channel.
    ///
    /// - When `failClosed` is off (the default, single-dev posture) every
    ///   host tunnels — the proxy stays out of the way of git/npm/brew.
    /// - When an MDM profile turns it on, only hosts on the operator's
    ///   `allowlist` may tunnel; everything else is refused. This closes
    ///   the "agent unsets HTTPS_PROXY isn't the only bypass — it can
    ///   also just talk to an un-inspected host" exfiltration gap that
    ///   Agent Vault flags as inherent to credential proxies.
    static func tunnelAllowed(host: String, failClosed: Bool, allowlist: Set<String>) -> Bool {
        guard failClosed else { return true }
        return allowlist.contains(host.lowercased())
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
        ).first!.appendingPathComponent("ai.bouclier.app", isDirectory: true)

        try? FileManager.default.createDirectory(at: pacDir, withIntermediateDirectories: true)
        let pacPath = pacDir.appendingPathComponent("proxy.pac")

        do {
            try pacFileContent(port: port).write(to: pacPath, atomically: true, encoding: .utf8)
        } catch {
            print("[bouclier.ai-proxy] Failed to write PAC file: \(error)")
            return false
        }

        // Get active network interface
        guard let interface = activeNetworkInterface() else {
            print("[bouclier.ai-proxy] No active network interface found")
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

    /// Nuclear PAC sweep: turns auto-proxy *and* manual HTTP/HTTPS
    /// proxy off on every configured network service. `disable()` only
    /// touches the active interface, which leaves stale Bouclier PAC
    /// configs on every other location/service after a crash — so when
    /// the user switches Wi-Fi networks the browser starts pointing at
    /// a dead 127.0.0.1 port again. Used by the Settings → Reset all
    /// proxies escape hatch.
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
        let services = allNetworkInterfaces()
        // Prefer Wi-Fi, then Ethernet, then first available
        for preferred in ["Wi-Fi", "Ethernet", "USB 10/100/1000 LAN"] {
            if services.contains(preferred) { return preferred }
        }
        return services.first
    }

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
