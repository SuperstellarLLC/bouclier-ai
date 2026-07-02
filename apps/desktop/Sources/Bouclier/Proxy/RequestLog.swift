import Foundation

// MARK: - Cloud Metadata Guard

/// Hosts that point at cloud-instance metadata services — never
/// tunnelled or proxied to, regardless of mode. SSRF guard shared by
/// `GatewayServer`'s base-URL override validation and `SecretRule`'s
/// host-binding validation.
enum NetworkGuards {
    static func isCloudMetadataHost(_ host: String) -> Bool {
        let h = host.lowercased()
        return h == "169.254.169.254"
            || h == "metadata.google.internal"
            || h == "metadata.azure.com"
            || h == "[fd00:ec2::254]"
    }
}

// MARK: - Corporate Proxy Detection

enum CorporateProxy {
    struct Config {
        let host: String
        let port: Int
    }

    /// Detect upstream corporate proxy from environment variables.
    /// Only URLs that pass `ManagedConfigValidator.validatedProxyURL`
    /// are accepted — scheme must be http/https, host must be a valid
    /// RFC 1123 hostname, port must be in the unprivileged range.
    ///
    /// Loopback hosts are deliberately ignored. With v0.5.0's
    /// `ShellEnvInjector`, the Bouclier process itself inherits
    /// `HTTPS_PROXY=http://127.0.0.1:8484` from the launchctl session,
    /// and naively trusting that env would make the proxy try to relay
    /// every upstream request *through itself* — an instant TLS-handshake
    /// loop that times out every API call. A real corporate proxy is by
    /// definition not on the loopback, so dropping these candidates
    /// costs nothing legitimate.
    static func detect() -> Config? {
        let env = ProcessInfo.processInfo.environment
        let candidates = [
            env["HTTPS_PROXY"], env["https_proxy"],
            env["HTTP_PROXY"], env["http_proxy"],
        ]
        for raw in candidates {
            guard let url = ManagedConfigValidator.validatedProxyURL(raw),
                  let host = url.host,
                  !isLoopbackHost(host)
            else { continue }
            return Config(host: host, port: url.port ?? 8080)
        }
        return nil
    }

    static func isLoopbackHost(_ host: String) -> Bool {
        let h = host.lowercased()
        return h == "localhost"
            || h == "127.0.0.1"
            || h.hasPrefix("127.")
            || h == "::1"
            || h == "[::1]"
    }
}

// MARK: - Request Log

/// A secret-keeper outcome for one request: either the real value was
/// injected for the bound host, or the request was blocked by a tripwire.
/// Surfaced through `RequestLog.secret` so the existing
/// `ProxyManager.handleRequestLog` pipeline drives the activity feed,
/// notifications, SIEM audit log, and on-disk stats uniformly.
struct SecretEvent: Sendable, Equatable {
    enum Kind: Sendable, Equatable {
        case injected(names: [String])
        case blocked(reason: SecretInjectionPass.BlockReason)
        /// Standard-mode scrub: a managed real secret value was replaced
        /// with its placeholder on the request to the model provider, so
        /// the model never sees the secret. Restored in the response.
        case scrubbed(names: [String])
    }
    let host: String
    let kind: Kind
}

struct RequestLog: Sendable {
    let timestamp: Date
    let targetHost: String
    let detected: Bool
    let matchCount: Int
    let patternNames: [String]
    let bodySize: Int
    // Fused scoring telemetry — populated by InjectionFilter.scan().
    // mlScore is nil when the classifier wasn't consulted; mlAvailable
    // distinguishes "ML cleared this" from "ML never ran".
    let mlScore: Float?
    let entropyAnomaly: Double
    let fusedScore: Double
    let mlAvailable: Bool
    /// Multimodal scan report. Nil when multimodal inspection didn't
    /// run for this request (feature off, etc.); empty findings when
    /// it ran and the attachments were clean.
    let multimodal: MultimodalPIIInspector.Report?
    /// Secret-keeper event. Non-nil only on the dedicated secret-event
    /// emissions, which carry no scan telemetry — `handleRequestLog`
    /// routes these separately so they don't double-count requests.
    let secret: SecretEvent?

    init(
        timestamp: Date,
        targetHost: String,
        detected: Bool,
        matchCount: Int,
        patternNames: [String],
        bodySize: Int,
        mlScore: Float?,
        entropyAnomaly: Double,
        fusedScore: Double,
        mlAvailable: Bool,
        multimodal: MultimodalPIIInspector.Report? = nil,
        secret: SecretEvent? = nil
    ) {
        self.timestamp = timestamp
        self.targetHost = targetHost
        self.detected = detected
        self.matchCount = matchCount
        self.patternNames = patternNames
        self.bodySize = bodySize
        self.mlScore = mlScore
        self.entropyAnomaly = entropyAnomaly
        self.fusedScore = fusedScore
        self.mlAvailable = mlAvailable
        self.multimodal = multimodal
        self.secret = secret
    }

    /// Dedicated initializer for a secret-keeper event. All scan fields
    /// are zeroed — this log is a side-channel, not a scanned request.
    init(secretEvent: SecretEvent, timestamp: Date = Date()) {
        self.init(
            timestamp: timestamp,
            targetHost: secretEvent.host,
            detected: false,
            matchCount: 0,
            patternNames: [],
            bodySize: 0,
            mlScore: nil,
            entropyAnomaly: 0,
            fusedScore: 0,
            mlAvailable: false,
            multimodal: nil,
            secret: secretEvent
        )
    }
}
