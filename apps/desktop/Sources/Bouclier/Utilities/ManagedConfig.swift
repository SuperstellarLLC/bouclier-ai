import Foundation

/// Reads MDM-managed app configuration pushed via configuration profiles.
///
/// Enterprise IT can push these keys via MDM (Jamf, Mosyle, Kandji, etc.):
///
/// ```xml
/// <key>com.apple.configuration.managed</key>
/// <dict>
///   <key>proxyPort</key><integer>8484</integer>
///   <key>enforcementPolicy</key><string>block</string>
///   <key>additionalDomains</key><array><string>api.custom.ai</string></array>
///   <key>webhookURL</key><string>https://siem.corp.com/bouclier</string>
///   <key>preventUninstall</key><true/>
///   <key>preventDisable</key><true/>
/// </dict>
/// ```
enum ManagedConfig {
    private nonisolated(unsafe) static let managedDefaults = UserDefaults(suiteName: "com.apple.configuration.managed")

    /// Whether MDM configuration is present.
    static var isManaged: Bool {
        managedDefaults?.dictionaryRepresentation().isEmpty == false
    }

    /// Proxy port override from MDM. Rejects privileged or out-of-range
    /// values so a hostile configuration profile can't point Bouclier at
    /// an arbitrary unprivileged service.
    static var port: Int? {
        ManagedConfigValidator.validatedPort(managedDefaults?.object(forKey: "proxyPort") as? Int)
    }

    /// Optional legacy finding-action policy. `block` refuses findings;
    /// `monitor`, `warn`, and `log` keep an already-enabled gateway
    /// monitor-only. This key chooses an action but does not enable capture
    /// or start the gateway on a fresh/disabled install. Invalid or absent
    /// values are ignored rather than silently turning blocking on.
    static var enforcementPolicy: String? {
        ManagedConfigValidator.validatedEnforcementPolicy(
            managedDefaults?.string(forKey: "enforcementPolicy")
        )
    }

    /// Additional hosts whose names may remain visible in a diagnostics
    /// export. This is a legacy compatibility key: it does not configure
    /// gateway routing or cause Bouclier to intercept those domains.
    /// Malformed hostnames (wildcards, paths, whitespace, CR/LF) are
    /// silently dropped so a typoed profile never weakens the allowlist.
    static var additionalDomains: [String] {
        let raw = (managedDefaults?.array(forKey: "additionalDomains") as? [String]) ?? []
        return ManagedConfigValidator.validatedHostnames(raw)
    }

    /// Optional webhook URL for SIEM forwarding. Only HTTPS is accepted;
    /// `file://`, `http://`, and custom schemes are rejected so a
    /// hostile profile can't turn the audit pipeline into a local-file
    /// exfiltration channel.
    static var webhookURL: String? {
        let raw = managedDefaults?.string(forKey: "webhookURL")
        return ManagedConfigValidator.validatedWebhookURL(raw)?.absoluteString
    }

    /// Whether Bouclier's explicit configuration-removal control is locked.
    /// The profile key keeps its historical `preventUninstall` spelling for
    /// deployment compatibility, but it does not stop app deletion, proxy
    /// recovery, or process termination. Use `preventDisable` for the normal
    /// disable/reset/quit controls, and MDM installation policy for the app.
    static var preventConfigurationRemoval: Bool {
        managedDefaults?.bool(forKey: "preventUninstall") ?? false
    }

    /// Whether the app's normal disable, reset, and quit controls are locked
    /// while protection is active. This does not activate protection itself.
    /// This is an in-app policy guard, not an OS-level process-availability
    /// guarantee: an administrator can still delete the app or send SIGKILL.
    /// Fleet tooling should monitor availability and relaunch the app.
    static var preventDisable: Bool {
        managedDefaults?.bool(forKey: "preventDisable") ?? false
    }
}
