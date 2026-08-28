import Foundation

/// Validation helpers for every piece of untrusted input that reaches
/// Bouclier from outside the signed app bundle: MDM configuration,
/// environment variables, and other unsandboxed data sources.
///
/// Each validator is pure and returns `nil` on failure so callers can
/// fall back to a safe default instead of acting on bad input. The
/// threat model (`docs/THREAT_MODEL.md`) enumerates why each check
/// exists.
enum ManagedConfigValidator {
    // MARK: - Ports

    /// Acceptable proxy ports. Excludes the privileged 1-1023 range
    /// (requires root) and 0/negative.
    static let validPortRange: ClosedRange<Int> = 1024...65535

    static func validatedPort(_ value: Int?) -> Int? {
        guard let v = value, validPortRange.contains(v) else { return nil }
        return v
    }

    static func validatedEnforcementPolicy(_ value: String?) -> String? {
        guard let policy = value?.lowercased(), ["block", "monitor", "warn", "log"].contains(policy) else {
            return nil
        }
        return policy
    }

    // MARK: - Hostnames

    /// Validate a hostname string. Matches RFC 1123: letters, digits,
    /// hyphens, and dots; labels 1-63 chars; total length ≤ 253.
    /// Rejects CR/LF, whitespace, wildcards, and IP-literal forms.
    static func validatedHostname(_ raw: String) -> String? {
        let host = raw.lowercased()
        guard !host.isEmpty, host.count <= 253 else { return nil }

        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return nil }
        for label in labels {
            if label.isEmpty || label.count > 63 { return nil }
            if label.first == "-" || label.last == "-" { return nil }
            for scalar in label.unicodeScalars {
                let v = scalar.value
                let isAlnum = (v >= 0x30 && v <= 0x39) || (v >= 0x61 && v <= 0x7A)
                let isAllowed = isAlnum || v == 0x2D /* - */
                if !isAllowed { return nil }
            }
        }
        return host
    }

    /// Filter an MDM-provided additional-domains array, returning only
    /// well-formed hostnames.
    static func validatedHostnames(_ raw: [String]) -> [String] {
        raw.compactMap { validatedHostname($0) }
    }

    // MARK: - Webhooks

    /// Validate a webhook URL. Only HTTPS is accepted — never `file://`,
    /// `javascript:`, `http://`, or any custom scheme. The URL must have
    /// a valid hostname and no fragment (fragments have no meaning for
    /// a server POST endpoint and are usually a copy-paste mistake).
    static func validatedWebhookURL(_ raw: String?) -> URL? {
        guard let s = raw, let url = URL(string: s) else { return nil }
        guard url.scheme?.lowercased() == "https" else { return nil }
        guard let host = url.host, validatedHostname(host) != nil else { return nil }
        if let frag = url.fragment, !frag.isEmpty { return nil }
        return url
    }

}
