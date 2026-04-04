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
///   <key>syslogEnabled</key><true/>
///   <key>webhookURL</key><string>https://siem.corp.com/ilvarion</string>
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

    /// Proxy port override from MDM.
    static var port: Int? {
        managedDefaults?.object(forKey: "proxyPort") as? Int
    }

    /// Enforcement policy: "block" (default), "warn", or "log"
    static var enforcementPolicy: String {
        (managedDefaults?.string(forKey: "enforcementPolicy")) ?? "block"
    }

    /// Additional AI domains to intercept (beyond the built-in list).
    static var additionalDomains: [String] {
        (managedDefaults?.array(forKey: "additionalDomains") as? [String]) ?? []
    }

    /// Whether syslog (os_log) output is enabled.
    static var syslogEnabled: Bool {
        managedDefaults?.bool(forKey: "syslogEnabled") ?? false
    }

    /// Optional webhook URL for SIEM forwarding.
    static var webhookURL: String? {
        managedDefaults?.string(forKey: "webhookURL")
    }

    /// Whether users are prevented from uninstalling/disabling protection.
    static var preventUninstall: Bool {
        managedDefaults?.bool(forKey: "preventUninstall") ?? false
    }

    static var preventDisable: Bool {
        managedDefaults?.bool(forKey: "preventDisable") ?? false
    }

    /// Merge MDM domains with built-in domains.
    static var allInterceptedDomains: Set<String> {
        var domains = SystemProxy.interceptedDomains
        for domain in additionalDomains {
            domains.insert(domain.lowercased())
        }
        return domains
    }
}
