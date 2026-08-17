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
            // Unspecified / wildcard addresses route to loopback on macOS, so
            // they must be rejected too — otherwise `http://0.0.0.0:<port>` in
            // a `*_TARGET_API_URL` slips past this guard and repoints
            // credential-bearing traffic at a local listener.
            || h == "0.0.0.0"
            || h == "0"
            || h == "::"
            || h == "[::]"
    }
}

// MARK: - Request Log

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
    /// Detection categories and severities that fired on this request,
    /// aggregated across findings. Feed the diagnostics metrics registry's
    /// per-category / per-severity tallies. Empty when nothing matched.
    let categories: [String]
    let severities: [String]
    /// Time spent scanning this request, in seconds. Feeds the metrics
    /// latency histogram. Zero for requests that skipped inspection (no
    /// untrusted content, or the engine wasn't ready).
    let scanDurationSeconds: TimeInterval
    /// Multimodal scan report. Nil when multimodal inspection didn't
    /// run for this request (feature off, etc.); empty findings when
    /// it ran and the attachments were clean.
    let multimodal: MultimodalPIIInspector.Report?

    /// Salted fingerprint of the untrusted span that drove a block, when
    /// this request was refused. Lets the UI offer "release this span"
    /// (add to `SpanAllowlist`) so a persistent false positive can be
    /// recovered from. Nil for non-block logs and ML/entropy blocks that
    /// left no fingerprint.
    let spanFingerprint: String?

    /// JSON path of the untrusted span that drove a block (e.g.
    /// `messages[2].content[0].tool_result`) — structural metadata, never
    /// the span's content. Surfaced in the block notification so the
    /// operator can locate the offending span without the adversarial text
    /// being broadcast. Nil for non-block logs.
    let locator: String?

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
        spanFingerprint: String? = nil,
        locator: String? = nil,
        categories: [String] = [],
        severities: [String] = [],
        scanDurationSeconds: TimeInterval = 0
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
        self.categories = categories
        self.severities = severities
        self.scanDurationSeconds = scanDurationSeconds
        self.multimodal = multimodal
        self.spanFingerprint = spanFingerprint
        self.locator = locator
    }
}
