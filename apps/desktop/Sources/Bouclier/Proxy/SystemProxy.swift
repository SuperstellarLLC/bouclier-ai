import Foundation

/// `diagnosticAllowedHosts` is the set of hostnames that a diagnostics
/// export may retain rather than redact. It does not control gateway
/// interception. The narrow `disableLegacyBouclierPAC` migration removes
/// only a positively owned stale PAC configuration. The intentionally broad
/// `disableAll` escape hatch is reserved for the user's explicit Reset action.
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

    /// Built-in and MDM-configured hostnames allowed in diagnostics output.
    static var diagnosticAllowedHosts: Set<String> {
        var domains = builtinDomains
        for domain in ManagedConfig.additionalDomains {
            domains.insert(domain.lowercased())
        }
        return domains
    }

    /// Explicit recovery action: turns automatic PAC configuration and manual
    /// HTTP/HTTPS web proxies off on every configured network service. This is
    /// intentionally broad within those three categories and is called only by
    /// the clearly-labelled Settings recovery action. SOCKS, FTP, and proxy
    /// auto-discovery/WPAD are outside its promise and remain untouched.
    ///
    /// `networksetup` returning zero is not enough: policy software can reject
    /// or immediately re-assert a setting. Re-read all three states and report
    /// success only when the promised postcondition is observable.
    @discardableResult
    static func disableAll() -> Bool {
        let interfaces = allNetworkInterfaces()
        guard !interfaces.isEmpty else { return false }
        var ok = true
        for iface in interfaces {
            if !runNetworkSetup(["-setautoproxystate", iface, "off"]) { ok = false }
            if !runNetworkSetup(["-setwebproxystate", iface, "off"]) { ok = false }
            if !runNetworkSetup(["-setsecurewebproxystate", iface, "off"]) { ok = false }
            if !settingIsDisabled(query: ["-getautoproxyurl", iface]) { ok = false }
            if !settingIsDisabled(query: ["-getwebproxy", iface]) { ok = false }
            if !settingIsDisabled(query: ["-getsecurewebproxy", iface]) { ok = false }
        }
        return ok
    }

    /// Remove only a PAC URL that can be positively attributed to the retired
    /// Bouclier listener. Other vendors' PAC URLs and every manual proxy remain
    /// untouched. Returns false when network-service state could not be read or
    /// an owned setting could not be disabled, allowing the migration to retry
    /// instead of recording a false-success sentinel.
    @discardableResult
    static func disableLegacyBouclierPAC(proxyPort: Int) -> Bool {
        disableLegacyBouclierPAC(proxyPorts: [proxyPort])
    }

    /// Candidate ports preserve the cleanup API used by migration retries. The
    /// shipped PAC URL did not contain the listener port: v0.6.0 wrote the file
    /// to the app-owned Application Support directory and configured its exact
    /// `file://` URL. Ownership therefore comes from that exact path, not from
    /// treating another loopback PAC on a previously used port as ours.
    @discardableResult
    static func disableLegacyBouclierPAC(proxyPorts: [Int]) -> Bool {
        let candidates = Set(proxyPorts)
        guard !candidates.isEmpty else { return false }
        guard let expectedPACFileURL = legacyPACFileURL else { return false }
        let interfaces = allNetworkInterfaces()
        guard !interfaces.isEmpty else { return false }

        var ok = true
        for interface in interfaces {
            guard let output = runNetworkSetupCapture(["-getautoproxyurl", interface]) else {
                ok = false
                continue
            }
            guard let rawURL = autoProxyURL(from: output) else { continue }
            guard isOwnedLegacyPACURL(
                rawURL,
                expectedPACFileURL: expectedPACFileURL
            ) else { continue }
            guard let enabled = settingEnabled(from: output) else {
                ok = false
                continue
            }
            if enabled,
               !runNetworkSetup(["-setautoproxystate", interface, "off"])
            {
                ok = false
            }

            guard let verification = runNetworkSetupCapture(
                ["-getautoproxyurl", interface]
            ) else {
                ok = false
                continue
            }
            // A concurrent administrator may replace the URL. If the exact
            // Bouclier URL remains, it must now be observably disabled.
            if let remainingURL = autoProxyURL(from: verification),
               isOwnedLegacyPACURL(
                   remainingURL,
                   expectedPACFileURL: expectedPACFileURL
               ),
               settingEnabled(from: verification) != false
            {
                ok = false
            }
        }
        return ok
    }

    /// Pure ownership decision kept internal for regression tests. The shipped
    /// v0.6.0 generator used:
    ///
    /// `~/Library/Application Support/ai.bouclier.app/proxy.pac`
    ///
    /// and passed `file://` plus that file's path to `networksetup`. Require the
    /// same app-owned path with an empty authority and no URL decorations so a
    /// user's local PAC cannot be mistaken for Bouclier's.
    static func isOwnedLegacyPACURL(
        _ raw: String,
        expectedPACFileURL: URL
    ) -> Bool {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let components = URLComponents(string: trimmed),
              components.scheme == "file",
              components.user == nil,
              components.password == nil,
              components.host == nil || components.host?.isEmpty == true,
              components.port == nil,
              components.query == nil,
              components.fragment == nil,
              let url = components.url
        else { return false }

        // Refuse alternate spellings with dot segments even if Foundation can
        // resolve them to the expected file path.
        for segment in components.percentEncodedPath.split(
            separator: "/",
            omittingEmptySubsequences: false
        ) {
            guard let decoded = segment.removingPercentEncoding,
                  decoded != ".",
                  decoded != ".."
            else { return false }
        }

        return url.path == expectedPACFileURL.path
    }

    static func autoProxyURL(from networkSetupOutput: String) -> String? {
        for line in networkSetupOutput.components(separatedBy: .newlines) {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let label = line[..<colon].trimmingCharacters(in: .whitespacesAndNewlines)
            guard label.caseInsensitiveCompare("URL") == .orderedSame else { continue }
            let value = line[line.index(after: colon)...]
                .trimmingCharacters(in: .whitespacesAndNewlines)
            return value.isEmpty || value.caseInsensitiveCompare("(null)") == .orderedSame
                ? nil
                : value
        }
        return nil
    }

    /// Parse the common `networksetup -get*proxy` `Enabled: Yes/No` field.
    /// Unknown/localized output is intentionally not guessed: destructive
    /// recovery cannot claim a verified result when state is unreadable.
    static func settingEnabled(from networkSetupOutput: String) -> Bool? {
        for line in networkSetupOutput.components(separatedBy: .newlines) {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let label = line[..<colon].trimmingCharacters(in: .whitespacesAndNewlines)
            guard label.caseInsensitiveCompare("Enabled") == .orderedSame else { continue }
            let value = line[line.index(after: colon)...]
                .trimmingCharacters(in: .whitespacesAndNewlines)
                .lowercased()
            switch value {
            case "yes", "on", "1", "true":
                return true
            case "no", "off", "0", "false":
                return false
            default:
                return nil
            }
        }
        return nil
    }

    /// Parse `networksetup -listallnetworkservices`. Its first line explains
    /// that `*` marks a disabled service, and disabled service rows themselves
    /// carry that display marker. Commands still take the underlying service
    /// name, so strip only that one output marker while preserving all other
    /// whitespace and punctuation in user-defined names.
    static func networkServices(from networkSetupOutput: String) -> [String] {
        networkSetupOutput.components(separatedBy: .newlines).compactMap { rawLine in
            guard !rawLine.isEmpty,
                  !rawLine.hasPrefix("An asterisk")
            else { return nil }
            if rawLine.hasPrefix("*") {
                return String(rawLine.dropFirst())
            }
            return rawLine
        }
    }

    // MARK: - Private

    private static var legacyPACFileURL: URL? {
        FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first?
            .appendingPathComponent("ai.bouclier.app", isDirectory: true)
            .appendingPathComponent("proxy.pac", isDirectory: false)
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
            guard process.terminationStatus == 0 else { return [] }
            let output = String(
                data: pipe.fileHandleForReading.readDataToEndOfFile(),
                encoding: .utf8
            ) ?? ""
            return networkServices(from: output)
        } catch {
            return []
        }
    }

    private static func settingIsDisabled(query: [String]) -> Bool {
        guard let output = runNetworkSetupCapture(query) else { return false }
        return settingEnabled(from: output) == false
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

    private static func runNetworkSetupCapture(_ args: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = args

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()
            guard process.terminationStatus == 0 else { return nil }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8)
        } catch {
            return nil
        }
    }
}
