import Foundation
import Testing
@testable import Bouclier

/// Pins the contract that `ProxyManager` initialises its storage and
/// auto-start side effects at *construction* time, not on first
/// menubar-open. The earlier design deferred this to
/// `MenuBarView.onAppear`, which only fires when the user clicks the
/// menubar icon — so the shield rendered "off" at launch and the
/// auto-start-when-CA-installed change was effectively a no-op until
/// the user happened to interact. The QA pass against the installed
/// app caught it; this test pins the fix so it can't regress silently.
@Suite("ProxyManager lifecycle", .serialized)
@MainActor
struct ProxyManagerLifecycleTests {
    @Test("initializeStorage runs at construction, not deferred to first menu open")
    func initRanAtConstruction() {
        let pm = ProxyManager()
        #expect(pm.didInitializeStorage,
                "ProxyManager.init() must call initializeStorage() so the menubar shield reflects state at launch — not after the user happens to click the menu")
    }

    /// Pins the v0.6.1 fix for the "Blocked 0 injection(s):" mystery
    /// log line. When the ML / entropy fusion fires without any
    /// individual regex matching, `matchCount` is 0 and `patternNames`
    /// is empty — the old message read as a bug to anyone watching the
    /// log feed. The two branches below must produce honest, distinct
    /// messages with distinct `blocked` flags.
    @Test("Regex-driven and ML-only detections both log as blocks — detected means the 403 fired")
    func detectionMessagesDistinguishRegexFromMLOnly() {
        // Suppress macOS UserNotifications — `UNUserNotificationCenter`
        // crashes under `swift test` because there's no app bundle to
        // anchor the singleton against. The production guard in
        // `sendBlockNotification` reads `showNotifications` from
        // UserDefaults and bails when it's false; flip it false for
        // this suite. (Restored on `defer`.)
        let prevNotifications = UserDefaults.standard.object(forKey: "showNotifications")
        UserDefaults.standard.set(false, forKey: "showNotifications")
        defer {
            if let prev = prevNotifications {
                UserDefaults.standard.set(prev, forKey: "showNotifications")
            } else {
                UserDefaults.standard.removeObject(forKey: "showNotifications")
            }
        }

        // Regex-driven: matchCount > 0, patternNames non-empty.
        let regexLog = RequestLog(
            timestamp: Date(),
            targetHost: "api.openai.com",
            detected: true,
            matchCount: 2,
            patternNames: ["INSTRUCTION_OVERRIDE", "ROLE_HIJACK"],
            bodySize: 512,
            mlScore: 0.91,
            entropyAnomaly: 0.4,
            fusedScore: 0.93,
            mlAvailable: true,
            multimodal: nil
        )
        let pmRegex = ProxyManager()
        let initialBlocked = pmRegex.stats.injectionsBlocked
        pmRegex.handleRequestLog(regexLog)
        #expect(pmRegex.stats.injectionsBlocked == initialBlocked + 2,
                "Regex-driven block must increment injectionsBlocked by matchCount")
        let regexEntry = pmRegex.logs.first
        #expect(regexEntry != nil)
        #expect(regexEntry?.blocked == true,
                "Regex-driven detection lights the red shield in the menu bar")
        #expect(regexEntry?.message.contains("Blocked 2 injection(s)") == true,
                "Block message must carry the match count")
        #expect(regexEntry?.message.contains("INSTRUCTION_OVERRIDE") == true,
                "Block message must name the matching patterns")
        #expect(regexEntry?.message.contains("[score 0.93]") == true,
                "Block message must surface the fused score so an operator can triage")

        // ML-only block: matchCount == 0, patternNames empty, but
        // detected=true — the gateway only ever sets `detected` on its
        // refusal path, so this request WAS 403'd even though no named
        // pattern fired. (An earlier version of handleRequestLog labeled
        // this shape a forwarded "flag": no red shield, no notification,
        // counter unmoved — mislabeling a real block. This is the shape
        // of the 2026-08-11 12:05 block that the activity feed denied.)
        let mlLog = RequestLog(
            timestamp: Date(),
            targetHost: "api.anthropic.com",
            detected: true,
            matchCount: 0,
            patternNames: [],
            bodySize: 256,
            mlScore: 0.62,
            entropyAnomaly: 0.5,
            fusedScore: 0.55,
            mlAvailable: true,
            multimodal: nil
        )
        let pmML = ProxyManager()
        let initialML = pmML.stats.injectionsBlocked
        pmML.handleRequestLog(mlLog)
        #expect(pmML.stats.injectionsBlocked == initialML + 1,
                "An ML-only block must still move the counter — the request was refused; count it as one")
        let mlEntry = pmML.logs.first
        #expect(mlEntry != nil)
        #expect(mlEntry?.blocked == true,
                "An ML-only block must light the red shield — detected is only ever set by the gateway's 403 path")
        #expect(mlEntry?.message.contains("Blocked request") == true,
                "ML-only message must read as the block it is")
        #expect(mlEntry?.message.contains("no named pattern") == true,
                "ML-only message must say why there are no pattern names — lower-confidence signal, same enforcement")
        #expect(mlEntry?.message.contains("score 0.55") == true,
                "ML-only message must carry the fused score for triage")
        #expect(mlEntry?.message.contains("Blocked 0") == false,
                "The original bug: 'Blocked 0 injection(s)' must never appear in the log feed")
    }

    /// Pins the new (v0.6) wiring: with the text-PII path gone, every
    /// counter and audit row that used to come from `RequestLog.piiAudit`
    /// must now come from the `.multimodal.findings[].textPII` branch
    /// in `handleRequestLog`. A regression here would silently zero
    /// out the menu-bar "Redacted" stat and the audit PDF — both
    /// user-visible — without any test catching it.
    @Test("Multimodal findings drive stats.piiRedacted, mediaBlocked, and audit rows")
    func multimodalFindingsDriveStats() {
        let pm = ProxyManager()
        let initial = pm.stats

        // Two distinct attachments. Attachment A carries two text-PII
        // findings (an email + an IBAN) AND a face finding (which must
        // not count toward `piiRedacted`). Attachment B carries one
        // text-PII finding. Total expected:
        //   stats.piiRedacted: 3 textPII items
        //   stats.mediaBlocked: 2 unique attachments
        let attachmentA: [MultimodalImageExtractor.Image.PathComponent] = [
            .key("messages"), .index(0), .key("content"), .index(0), .key("image_url"), .key("url"),
        ]
        let attachmentB: [MultimodalImageExtractor.Image.PathComponent] = [
            .key("messages"), .index(0), .key("content"), .index(1), .key("image_url"), .key("url"),
        ]
        let blockA = Array(attachmentA.dropLast(2))
        let blockB = Array(attachmentB.dropLast(2))

        func textPII(type: String, path: [MultimodalImageExtractor.Image.PathComponent], block: [MultimodalImageExtractor.Image.PathComponent], cleartext: String) -> MultimodalPIIInspector.Finding {
            MultimodalPIIInspector.Finding(
                imagePath: path,
                contentBlockPath: block,
                mediaType: "image/png",
                provider: .openai,
                category: .textPII(type: type),
                cleartextValue: cleartext
            )
        }
        let findings: [MultimodalPIIInspector.Finding] = [
            textPII(type: "EMAIL", path: attachmentA, block: blockA, cleartext: "alice@example.com"),
            textPII(type: "IBAN",  path: attachmentA, block: blockA, cleartext: "GB82WEST12345698765432"),
            MultimodalPIIInspector.Finding(
                imagePath: attachmentA, contentBlockPath: blockA,
                mediaType: "image/png", provider: .openai,
                category: .face(confidence: 0.97),
                cleartextValue: "face"
            ),
            textPII(type: "EMAIL", path: attachmentB, block: blockB, cleartext: "bob@example.com"),
        ]
        let report = MultimodalPIIInspector.Report(
            imagesScanned: 2, pdfsScanned: 0, audioScanned: 0,
            findings: findings, latencyMs: 12.3
        )
        let log = RequestLog(
            timestamp: Date(),
            targetHost: "api.openai.com",
            detected: false,
            matchCount: 0,
            patternNames: [],
            bodySize: 1024,
            mlScore: nil,
            entropyAnomaly: 0,
            fusedScore: 0,
            mlAvailable: false,
            multimodal: report
        )

        pm.handleRequestLog(log)

        #expect(pm.stats.piiRedacted == initial.piiRedacted + 3,
                "stats.piiRedacted must count one per .textPII finding (3), not per attachment, and must ignore .face findings")
        #expect(pm.stats.mediaBlocked == initial.mediaBlocked + 2,
                "stats.mediaBlocked must count unique imagePaths (2), not total findings")
        #expect(pm.stats.requestsScanned == initial.requestsScanned + 1,
                "Every handled request bumps requestsScanned")

        // Log feed must surface a "Redacted N PII item(s) from
        // attachments" line — the menu-bar live log is the only
        // place a power user sees what just happened in real time.
        let recentMessages = pm.logs.prefix(5).map(\.message)
        #expect(recentMessages.contains(where: { $0.contains("Redacted 3 PII item(s) from attachments") }),
                "Expected the log feed to mention the per-request PII count from attachments; got: \(recentMessages)")
        #expect(recentMessages.contains(where: { $0.contains("Stripped 2 attachment(s)") }),
                "Expected the log feed to mention the unique-attachment strip count; got: \(recentMessages)")
    }
}
