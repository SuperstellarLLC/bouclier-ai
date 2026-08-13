import Foundation

/// A false-positive report, ready for the operator to review and send.
///
/// Built from a captured `BlockSample`. The two content-bearing fields
/// (`spanExcerpt`, `topWindow`) are **already redacted** when the draft is
/// constructed, so what the preview shows is exactly what would be sent —
/// there is no second, un-redacted copy hiding behind the UI.
struct FalsePositiveDraft: Identifiable, Sendable {
    let id = UUID()
    let appVersion: String
    let targetHost: String
    let locator: String
    let patternNames: [String]
    let fusedScore: Double
    let mlScore: Float?
    let entropyAnomaly: Double
    let benignMultiplier: Double
    let matchCount: Int
    /// Redacted excerpt of the offending span — the exact text that will be sent.
    let spanExcerpt: String
    /// Redacted highest-scoring ML window, when ML drove the block.
    let topWindow: String?
    let topWindowScore: Float?
    let fingerprint: String
}

/// An anti-abuse proof-of-work stamp attached to the wire body at send time.
/// Not report content — a fresh timestamp plus a mined nonce, carrying no
/// personal data — so it is added only on `send`, never shown in the preview.
private struct ReportPowStamp: Encodable {
    let timestamp: Int64
    let nonce: String
}

/// The wire payload POSTed to `/api/report`. Keys match the site's
/// `FalsePositiveReportInput` exactly (camelCase, no `ts` — the server
/// stamps receipt time). Nil optionals are omitted; the server treats an
/// absent field as null. `pow` is present only on an actual send.
private struct FalsePositiveReportPayload: Encodable {
    let appVersion: String
    let targetHost: String
    let locator: String
    let patternNames: [String]
    let fusedScore: Double
    let mlScore: Float?
    let entropyAnomaly: Double
    let benignMultiplier: Double
    let matchCount: Int
    let spanExcerpt: String
    let topWindow: String?
    let topWindowScore: Float?
    let fingerprint: String
    let note: String?
    let pow: ReportPowStamp?
}

/// Builds and sends a false-positive report. The build step redacts; the
/// send step is a plain HTTPS POST to bouclier.ai — the app's own traffic,
/// never routed through its gateway (that only fronts the LLM providers).
enum FalsePositiveReporter {
    /// Production intake. `www` matches the deployed canonical host.
    static let endpoint = URL(string: "https://www.bouclier.ai/api/report")!

    /// A dedicated session for reports that **never routes through a proxy** —
    /// including Bouclier's own loopback gateway. The report body is, by
    /// definition, the flagged (injection-shaped) span; were it tunnelled back
    /// through the gateway it would be inspected and blocked, defeating the
    /// report. Ephemeral so the one-off POST is never cached, cookied, or
    /// persisted. (`HTTPEnable`/`HTTPSEnable` are the CFNetwork proxy keys;
    /// setting them false pins the connection to a direct route.)
    private static let session: URLSession = {
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = [
            "HTTPEnable": 0,
            "HTTPSEnable": 0,
        ]
        config.timeoutIntervalForRequest = 15
        config.waitsForConnectivity = false
        return URLSession(configuration: config)
    }()

    /// Build a review-ready draft from a captured sample, redacting the two
    /// content fields up front (async — redaction runs the ML PII tier off
    /// the main actor).
    static func draft(from sample: BlockSample, appVersion: String) async -> FalsePositiveDraft {
        let excerpt = await ReportRedactor.redact(sample.spanExcerpt)
        let topWindow: String?
        if let tw = sample.topWindow {
            topWindow = await ReportRedactor.redact(tw)
        } else {
            topWindow = nil
        }
        return FalsePositiveDraft(
            appVersion: appVersion,
            targetHost: sample.targetHost,
            locator: sample.locator,
            patternNames: sample.patternNames,
            fusedScore: sample.fusedScore,
            mlScore: sample.mlScore,
            entropyAnomaly: sample.entropyAnomaly,
            benignMultiplier: sample.benignMultiplier,
            matchCount: sample.matchCount,
            spanExcerpt: excerpt,
            topWindow: topWindow,
            topWindowScore: sample.topWindowScore,
            fingerprint: sample.fingerprint
        )
    }

    /// Pretty, key-sorted JSON encoder shared by preview and send, so the
    /// preview is byte-for-byte the report *content* the wire carries.
    private static func encode(_ payload: FalsePositiveReportPayload) -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return (try? encoder.encode(payload)) ?? Data("{}".utf8)
    }

    /// The exact report *content* bytes — everything the preview shows and the
    /// send transmits, minus the anti-abuse `pow` stamp (added only on send and
    /// carrying no personal data). So the preview shows all content that leaves
    /// the Mac; the only thing it omits is a proof-of-work nonce.
    static func encodedBody(for draft: FalsePositiveDraft, note: String) -> Data {
        encode(payload(for: draft, note: note, pow: nil))
    }

    /// The report content, as text, for the review window.
    static func previewJSON(for draft: FalsePositiveDraft, note: String) -> String {
        String(data: encodedBody(for: draft, note: note), encoding: .utf8) ?? "{}"
    }

    private static func payload(
        for draft: FalsePositiveDraft, note: String, pow: ReportPowStamp?
    ) -> FalsePositiveReportPayload {
        let trimmed = note.trimmingCharacters(in: .whitespacesAndNewlines)
        return FalsePositiveReportPayload(
            appVersion: draft.appVersion,
            targetHost: draft.targetHost,
            locator: draft.locator,
            patternNames: draft.patternNames,
            fusedScore: draft.fusedScore,
            mlScore: draft.mlScore,
            entropyAnomaly: draft.entropyAnomaly,
            benignMultiplier: draft.benignMultiplier,
            matchCount: draft.matchCount,
            spanExcerpt: draft.spanExcerpt,
            topWindow: draft.topWindow,
            topWindowScore: draft.topWindowScore,
            fingerprint: draft.fingerprint,
            note: trimmed.isEmpty ? nil : trimmed,
            pow: pow
        )
    }

    /// POST the report. Returns true on a 200 from the endpoint. Any network
    /// or non-200 outcome returns false so the UI can offer a retry — a
    /// failed report must never crash or block anything.
    static func send(draft: FalsePositiveDraft, note: String) async -> Bool {
        // Mine the proof-of-work at send time — a fresh timestamp bound to the
        // report's fingerprint — so a slow review can't stale the stamp.
        let timestamp = ReportProofOfWork.nowMillis()
        let material = ReportProofOfWork.material(timestamp: timestamp, fingerprint: draft.fingerprint)
        let nonce = ReportProofOfWork.solve(material: material, bits: ReportProofOfWork.difficultyBits)
        let stamp = ReportPowStamp(timestamp: timestamp, nonce: nonce)

        var req = URLRequest(url: endpoint)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = encode(payload(for: draft, note: note, pow: stamp))
        do {
            let (_, resp) = try await session.data(for: req)
            return (resp as? HTTPURLResponse)?.statusCode == 200
        } catch {
            return false
        }
    }
}
