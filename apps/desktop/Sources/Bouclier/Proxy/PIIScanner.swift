import Foundation

/// Swift port of the `@bouclier-ai/patterns` PII regex tier.
///
/// Detector list, validator logic, and overlap-resolution rules are
/// kept in lockstep with the TypeScript source — same offsets, same
/// precedence, same false-positive suppression. Cross-platform parity
/// matters because the site playground (TS) and the desktop proxy
/// (Swift) must reach identical conclusions about a given payload.
///
/// An optional ML tier (Piiranha mDeBERTa on CoreML) plugs in via the
/// process-wide registry below — the same pattern `MLClassifier` uses
/// against `InjectionFilter`.
///
/// Process-wide registry for the active PIIScanner.
///
/// The scanner is mutable across the app's lifetime because the ML
/// tier (Piiranha) loads asynchronously after startup. We can't bake
/// the classifier into the multimodal handler chain at construction
/// because by then no model has loaded yet; threading a provider
/// closure through every scanner would be boilerplate for a single
/// swap that happens exactly once per process.
///
/// Instead PatternManager owns the lifecycle and calls
/// `PIIScanner.active.install(_:)` when the classifier is ready.
/// Multimodal scans (`MediaPIIScanner` / `PDFPIIScanner` /
/// `AudioPIIScanner`) read `PIIScanner.active.current()` lazily, so
/// requests in flight before the swap automatically pick up the ML
/// tier on their next attachment.
final class ActivePIIScannerRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var scanner = PIIScanner()

    func current() -> PIIScanner {
        lock.lock(); defer { lock.unlock() }
        return scanner
    }

    func install(_ new: PIIScanner) {
        lock.lock(); defer { lock.unlock() }
        scanner = new
    }
}

final class PIIScanner: @unchecked Sendable {
    /// The process-wide active scanner. See `ActivePIIScannerRegistry`
    /// for the rationale.
    static let active = ActivePIIScannerRegistry()

    /// A single PII span found in the input.
    struct Detection: Sendable, Equatable {
        let type: String
        let start: Int   // UTF-16 offset (NSRegularExpression natively)
        let end: Int
        let value: String
    }

    /// One detector: a compiled regex + the matching validator hook.
    private struct Detector {
        let type: String
        let regex: NSRegularExpression
        let validate: (@Sendable (String) -> Bool)?
        let contextOk: (@Sendable (String, NSRange) -> Bool)?
    }

    private let detectors: [Detector]

    /// Native NSDataDetector pass — PHONE + ADDRESS. Always-on, free.
    private let nativeDetector: PIINativeDetector

    /// Optional ML classifier (Piiranha). Nil until the bundled
    /// `.mlpackage` is converted and loaded; managed by PatternManager,
    /// then handed back via `withMLClassifier(_:)` so the scanner can
    /// stay value-typey at construction.
    private let mlClassifier: PIIClassifier?

    /// Whether the ML tier is currently active. Diagnostic surface for
    /// the menu bar / settings.
    var hasMLClassifier: Bool { mlClassifier != nil }

    init(mlClassifier: PIIClassifier? = nil, nativeDetector: PIINativeDetector = .shared) {
        self.detectors = Self.buildDetectors()
        self.nativeDetector = nativeDetector
        self.mlClassifier = mlClassifier
    }

    /// Return a copy of this scanner with the ML classifier attached.
    /// Lets PatternManager swap classifiers in once the async load
    /// completes without rebuilding the regex list each time.
    func withMLClassifier(_ classifier: PIIClassifier?) -> PIIScanner {
        PIIScanner(mlClassifier: classifier, nativeDetector: nativeDetector)
    }

    /// Synchronous scan — regex + native only. ML is excluded from this
    /// path because CoreML inference is async; callers that need ML
    /// recall should use `scanWithML(_:)`. Used everywhere the proxy
    /// is on a sync code path (most of v0.3.x).
    func scan(_ content: String) -> [Detection] {
        guard !content.isEmpty else { return [] }
        let raw = collectRegexDetections(content)
        let native = nativeDetector.scan(content)
        let nativeRank = detectors.count
        var all = raw
        all.append(contentsOf: native.map { Raw(d: $0, rank: nativeRank) })
        return resolveOverlaps(all)
    }

    /// Async scan that includes the ML classifier when loaded. Falls
    /// back to the regex+native result if the ML pass throws — a
    /// per-request failure must never block a redaction.
    func scanWithML(_ content: String) async -> [Detection] {
        guard !content.isEmpty else { return [] }
        let regexRaw = collectRegexDetections(content)
        let native = nativeDetector.scan(content)
        let nativeRank = detectors.count

        var all = regexRaw
        all.append(contentsOf: native.map { Raw(d: $0, rank: nativeRank) })

        if let classifier = mlClassifier {
            do {
                let mlHits = try await classifier.classify(content)
                let mlRank = detectors.count + 1
                all.append(contentsOf: mlHits.map { Raw(d: $0, rank: mlRank) })
            } catch {
                // Per-request ML failure is non-fatal: regex+native
                // already gave us a useful result; the upstream relay
                // sees the same redacted body it would have without ML.
            }
        }
        return resolveOverlaps(all)
    }

    // MARK: - Internals

    private struct Raw {
        let d: Detection
        let rank: Int
    }

    /// Run the full regex detector list. Same logic as before — kept
    /// in a helper so both the sync and async public APIs share it.
    private func collectRegexDetections(_ content: String) -> [Raw] {
        let nsContent = content as NSString
        let fullRange = NSRange(location: 0, length: nsContent.length)
        var raw: [Raw] = []
        for (rank, det) in detectors.enumerated() {
            det.regex.enumerateMatches(in: content, range: fullRange) { result, _, _ in
                guard let result, result.range.length > 0 else { return }
                let value = nsContent.substring(with: result.range)
                if let validate = det.validate, !validate(value) { return }
                if let contextOk = det.contextOk, !contextOk(content, result.range) { return }
                let det = Detection(
                    type: det.type,
                    start: result.range.location,
                    end: result.range.location + result.range.length,
                    value: value
                )
                raw.append(Raw(d: det, rank: rank))
            }
        }
        return raw
    }

    /// Sort + dedupe overlapping spans. Ordering rule: earliest start
    /// wins; on ties, lower rank wins; on further ties, longer span
    /// wins so we never leave a PII residue in the tail.
    private func resolveOverlaps(_ raw: [Raw]) -> [Detection] {
        var raw = raw
        raw.sort { a, b in
            if a.d.start != b.d.start { return a.d.start < b.d.start }
            if a.rank != b.rank { return a.rank < b.rank }
            return a.d.end > b.d.end
        }
        var out: [Detection] = []
        var lastEnd = -1
        for item in raw where item.d.start >= lastEnd {
            out.append(item.d)
            lastEnd = item.d.end
        }
        return out
    }

    // MARK: - Detector list (mirrors PII_DETECTORS in TS)

    private static func buildDetectors() -> [Detector] {
        func re(_ pattern: String, _ flags: NSRegularExpression.Options = []) -> NSRegularExpression {
            try! NSRegularExpression(pattern: pattern, options: flags)
        }
        let multiline: NSRegularExpression.Options = [.dotMatchesLineSeparators]

        let highPrecisionSecrets: [Detector] = [
            // LLM providers — order matters: specific sk-… variants first.
            Detector(type: "ANTHROPIC_KEY", regex: re(#"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{86,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "OPENROUTER_KEY", regex: re(#"\bsk-or-(?:v\d+-)?[A-Za-z0-9]{40,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "DEEPSEEK_KEY", regex: re(#"\bsk-[A-Fa-f0-9]{32}\b"#), validate: nil, contextOk: nil),
            Detector(type: "OPENAI_KEY", regex: re(#"\bsk-(?!ant-|or-|live_|test_)(?:proj-|admin-|svcacct-)?[A-Za-z0-9_-]{32,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "XAI_KEY", regex: re(#"\bxai-[A-Za-z0-9]{80}\b"#), validate: nil, contextOk: nil),
            Detector(type: "GOOGLE_API_KEY", regex: re(#"\bAIza[A-Za-z0-9_-]{35}\b"#), validate: nil, contextOk: nil),
            Detector(type: "GROQ_KEY", regex: re(#"\bgsk_[A-Za-z0-9]{52}\b"#), validate: nil, contextOk: nil),
            Detector(type: "FIREWORKS_KEY", regex: re(#"\bfw_[A-Za-z0-9]{24,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "COHERE_KEY", regex: re(#"\bco_[A-Za-z0-9]{40}\b"#), validate: nil, contextOk: nil),
            Detector(type: "PERPLEXITY_KEY", regex: re(#"\bpplx-[A-Za-z0-9]{48,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "TOGETHER_KEY", regex: re(#"\btogether_[A-Za-z0-9]{40,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "MISTRAL_KEY", regex: re(#"\b[A-Za-z0-9]{32}\b"#), validate: PIIValidators.validateMistral, contextOk: PIIValidators.requireContext(PIIValidators.keyContextLookback)),

            // Source control.
            Detector(type: "GITHUB_FINE_GRAINED_PAT", regex: re(#"\bgithub_pat_[A-Za-z0-9_]{82}\b"#), validate: nil, contextOk: nil),
            Detector(type: "GITHUB_PAT", regex: re(#"\bghp_[A-Za-z0-9]{36}\b"#), validate: nil, contextOk: nil),
            Detector(type: "GITHUB_OAUTH", regex: re(#"\bgho_[A-Za-z0-9]{36}\b"#), validate: nil, contextOk: nil),
            Detector(type: "GITHUB_APP", regex: re(#"\b(?:ghu|ghs|ghr)_[A-Za-z0-9]{36}\b"#), validate: nil, contextOk: nil),
            Detector(type: "GITLAB_PAT", regex: re(#"\bglpat-[A-Za-z0-9_-]{20}\b"#), validate: nil, contextOk: nil),
            Detector(type: "BITBUCKET_APP_PASSWORD", regex: re(#"\bATBB[A-Za-z0-9]{32}[A-Fa-f0-9]{8}\b"#), validate: nil, contextOk: nil),

            // Communication.
            Detector(type: "SLACK_TOKEN", regex: re(#"\bxox[abprs]-(?:\d+-){2,}[A-Za-z0-9-]+\b"#), validate: nil, contextOk: nil),
            Detector(type: "SLACK_WEBHOOK", regex: re(#"\bhttps://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "DISCORD_WEBHOOK", regex: re(#"\bhttps://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "DISCORD_BOT_TOKEN", regex: re(#"\b[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "TELEGRAM_BOT_TOKEN", regex: re(#"\b\d{8,10}:[A-Za-z0-9_-]{35}\b"#), validate: nil, contextOk: nil),

            // Payments.
            Detector(type: "STRIPE_KEY", regex: re(#"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{24,99}\b"#), validate: nil, contextOk: nil),
            Detector(type: "SQUARE_TOKEN", regex: re(#"\bsq0(?:atp|csp|idp)-[A-Za-z0-9_-]{22,43}\b"#), validate: nil, contextOk: nil),
            Detector(type: "PAYPAL_BRAINTREE", regex: re(#"\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}\b"#), validate: nil, contextOk: nil),
            Detector(type: "SHOPIFY_TOKEN", regex: re(#"\b(?:shpat|shpca|shpss|shppa)_[a-fA-F0-9]{32}\b"#), validate: nil, contextOk: nil),

            // Email & SaaS.
            Detector(type: "SENDGRID_KEY", regex: re(#"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"#), validate: nil, contextOk: nil),
            Detector(type: "MAILGUN_KEY", regex: re(#"\bkey-[a-f0-9]{32}\b"#), validate: nil, contextOk: nil),
            Detector(type: "MAILCHIMP_KEY", regex: re(#"\b[a-f0-9]{32}-us\d{1,2}\b"#), validate: nil, contextOk: nil),
            Detector(type: "TWILIO_API_KEY", regex: re(#"\bSK[a-f0-9]{32}\b"#), validate: nil, contextOk: nil),
            Detector(type: "TWILIO_ACCOUNT_SID", regex: re(#"\bAC[a-f0-9]{32}\b"#), validate: nil, contextOk: nil),
            Detector(type: "POSTMARK_TOKEN", regex: re(#"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b"#), validate: nil, contextOk: PIIValidators.requireContext(PIIValidators.postmarkLookback)),

            // Cloud infra.
            Detector(type: "GCP_OAUTH_CLIENT", regex: re(#"\b\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b"#), validate: nil, contextOk: nil),
            Detector(type: "GCP_SERVICE_ACCOUNT_KEY", regex: re(#""type"\s*:\s*"service_account"[\s\S]{0,500}"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----"#, multiline), validate: nil, contextOk: nil),
            Detector(type: "AZURE_STORAGE_KEY", regex: re(#"\bDefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{60,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "CLOUDFLARE_TOKEN", regex: re(#"\bcf-[A-Za-z0-9_-]{40}\b"#), validate: nil, contextOk: nil),
            Detector(type: "DIGITALOCEAN_TOKEN", regex: re(#"\bdop_v1_[a-f0-9]{64}\b"#), validate: nil, contextOk: nil),
            Detector(type: "HEROKU_KEY", regex: re(#"\bHRKU-[A-Za-z0-9_-]{36,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "FLY_API_TOKEN", regex: re(#"\bfly_[A-Za-z0-9_-]{40,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "AWS_SECRET_KEY", regex: re(#"\b[A-Za-z0-9+/]{40}\b"#), validate: PIIValidators.validateAWSSecretEntropy, contextOk: PIIValidators.requireContext(PIIValidators.awsSecretLookback)),

            // Observability.
            Detector(type: "SENTRY_DSN", regex: re(#"\bhttps://[a-f0-9]{32}@(?:o\d+\.)?ingest(?:\.[a-z]+)?\.sentry\.io/\d+\b"#), validate: nil, contextOk: nil),
            Detector(type: "NEW_RELIC_KEY", regex: re(#"\bNRAK-[A-Z0-9]{27}\b"#), validate: nil, contextOk: nil),
            Detector(type: "DATADOG_API_KEY", regex: re(#"\b[a-f0-9]{32}\b"#), validate: nil, contextOk: PIIValidators.requireContext(PIIValidators.datadogLookback)),

            // Packaging.
            Detector(type: "NPM_TOKEN", regex: re(#"\bnpm_[A-Za-z0-9]{36}\b"#), validate: nil, contextOk: nil),
            Detector(type: "PYPI_TOKEN", regex: re(#"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b"#), validate: nil, contextOk: nil),

            // Productivity.
            Detector(type: "NOTION_TOKEN", regex: re(#"\bsecret_[A-Za-z0-9]{43}\b"#), validate: nil, contextOk: nil),
            Detector(type: "LINEAR_KEY", regex: re(#"\blin_api_[A-Za-z0-9]{40}\b"#), validate: nil, contextOk: nil),
            Detector(type: "ASANA_PAT", regex: re(#"\b\d{1,4}/\d{16,}:[a-f0-9]{32}\b"#), validate: nil, contextOk: nil),
            Detector(type: "ATLASSIAN_TOKEN", regex: re(#"\bATATT[A-Za-z0-9_-]{180,}\b"#), validate: nil, contextOk: nil),
            Detector(type: "HUBSPOT_KEY", regex: re(#"\bpat-(?:na1|eu1|na2)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b"#), validate: nil, contextOk: nil),

            // PEM / SSH (multi-line).
            Detector(type: "SSH_PRIVATE_KEY", regex: re(#"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{20,8000}?-----END OPENSSH PRIVATE KEY-----"#, multiline), validate: nil, contextOk: nil),
            Detector(type: "PEM_PRIVATE_KEY", regex: re(#"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |PRIVATE )?PRIVATE KEY-----[\s\S]{20,8000}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |PRIVATE )?PRIVATE KEY-----"#, multiline), validate: nil, contextOk: nil),

            // DB connection strings.
            Detector(type: "POSTGRES_URL", regex: re(#"\bpostgres(?:ql)?://[^\s:@/]+:[^\s@/]+@[^\s/]+(?::\d+)?/[^\s?]+\b"#), validate: nil, contextOk: nil),
            Detector(type: "MYSQL_URL", regex: re(#"\bmysql://[^\s:@/]+:[^\s@/]+@[^\s/]+(?::\d+)?/[^\s?]+\b"#), validate: nil, contextOk: nil),
            Detector(type: "MONGODB_URL", regex: re(#"\bmongodb(?:\+srv)?://[^\s:@/]+:[^\s@/]+@[^\s/]+\b"#), validate: nil, contextOk: nil),
            Detector(type: "REDIS_URL", regex: re(#"\bredis://(?:[^\s:@/]*:)?[^\s@/]+@[^\s/]+(?::\d+)?\b"#), validate: nil, contextOk: nil),
        ]

        let genericSecrets: [Detector] = [
            Detector(type: "BEARER_TOKEN", regex: re(#"\b(?:Bearer|Token)\s+[A-Za-z0-9_\-.=:]{20,}\b"#), validate: PIIValidators.validateBearerEntropy, contextOk: nil),
            Detector(type: "GENERIC_API_KEY", regex: re(#"[A-Za-z0-9+/_-]{32,}"#), validate: PIIValidators.genericKeyValueOk, contextOk: PIIValidators.requireContext(PIIValidators.keyContextLookback)),
        ]

        let structured: [Detector] = [
            // High-precision first.
            Detector(
                type: "JWT",
                regex: re(#"\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"#),
                validate: PIIValidators.isPlausibleJWT,
                contextOk: nil
            ),
            Detector(
                type: "AWS_ACCESS_KEY",
                regex: re(#"\b(?:AKIA|ASIA|AIDA|AGPA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b"#),
                validate: nil, contextOk: nil
            ),
            Detector(
                type: "EMAIL",
                regex: re(#"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b"#),
                validate: nil, contextOk: nil
            ),
            Detector(
                type: "IBAN",
                regex: re(#"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b"#),
                validate: PIIValidators.ibanMod97,
                contextOk: nil
            ),
            Detector(
                type: "FR_NIR",
                regex: re(#"\b[12][ ]?\d{2}[ ]?\d{2}[ ]?[0-9AB]\d[ ]?\d{3}[ ]?\d{3}[ ]?\d{2}\b"#),
                validate: PIIValidators.isPlausibleNIR,
                contextOk: nil
            ),
            Detector(
                type: "FR_SIRET",
                regex: re(#"\b\d{3}[ ]?\d{3}[ ]?\d{3}[ ]?\d{5}\b"#),
                validate: PIIValidators.isPlausibleSIRET,
                contextOk: nil
            ),
            Detector(
                type: "CREDIT_CARD",
                regex: re(#"\b\d(?:[ -]?\d){12,18}\b"#),
                validate: PIIValidators.luhn,
                contextOk: PIIValidators.creditCardContextOk
            ),
            Detector(
                type: "UK_NHS",
                regex: re(#"\b\d{3}[ -]\d{3}[ -]\d{4}\b"#),
                validate: PIIValidators.isPlausibleNHS,
                contextOk: nil
            ),
            Detector(
                type: "US_NPI",
                regex: re(#"\b\d{10}\b"#),
                validate: PIIValidators.isPlausibleNPI,
                contextOk: nil
            ),
            Detector(
                type: "FR_SIREN",
                regex: re(#"\b\d{3}[ ]?\d{3}[ ]?\d{3}\b"#),
                validate: PIIValidators.isPlausibleSIREN,
                contextOk: nil
            ),
            Detector(
                type: "US_SSN",
                regex: re(#"\b\d{3}-?\d{2}-?\d{4}\b"#),
                validate: PIIValidators.isPlausibleSSN,
                contextOk: nil
            ),
            Detector(
                type: "UK_NINO",
                regex: re(#"\b[A-Z]{2}[ ]?\d{2}[ ]?\d{2}[ ]?\d{2}[ ]?[A-D]\b"#),
                validate: PIIValidators.isPlausibleNINO,
                contextOk: nil
            ),
            Detector(
                type: "UK_POSTCODE",
                regex: re(#"\b[A-PR-UWYZ][A-Z0-9]{1,3}[ ]?\d[A-Z]{2}\b"#, [.caseInsensitive]),
                validate: PIIValidators.isPlausibleUKPostcode,
                contextOk: nil
            ),
            Detector(
                type: "IPV6",
                regex: re(
                    #"\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{0,4}\b"#
                ),
                validate: PIIValidators.isPlausibleIPv6,
                contextOk: nil
            ),
            Detector(
                type: "IPV4",
                regex: re(#"\b(?:\d{1,3}\.){3}\d{1,3}\b"#),
                validate: PIIValidators.isPlausibleIPv4,
                contextOk: nil
            ),
        ]

        return highPrecisionSecrets + structured + genericSecrets
    }
}
