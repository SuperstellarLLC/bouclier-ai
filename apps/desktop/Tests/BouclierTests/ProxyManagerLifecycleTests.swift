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
    @Test("Detector health requires protection and the detector feature")
    func effectiveDetectorHealth() {
        for gatewayRunning in [false, true] {
            for protectionEnabled in [false, true] {
                for featureEnabled in [false, true] {
                    #expect(ProxyManager.effectiveDetectorEnabled(
                        gatewayRunning: gatewayRunning,
                        protectionEnabled: protectionEnabled,
                        featureEnabled: featureEnabled
                    ) == (gatewayRunning && protectionEnabled && featureEnabled))
                }
            }
        }
    }

    @Test("Managed termination is vetoed only while protection is active")
    func managedTerminationPolicy() {
        #expect(
            AppDelegate.terminationReply(preventDisable: true, protectionActive: true)
                == .terminateCancel
        )
        #expect(
            AppDelegate.terminationReply(preventDisable: true, protectionActive: false)
                == .terminateNow
        )
        #expect(
            AppDelegate.terminationReply(preventDisable: false, protectionActive: true)
                == .terminateNow
        )
    }

    @Test("Managed active protection locks capture and login continuity controls")
    func managedContinuityPolicy() {
        #expect(ProxyManager.managedContinuityLocked(
            preventDisable: true, protectionActive: true
        ))
        #expect(!ProxyManager.managedContinuityLocked(
            preventDisable: true, protectionActive: false
        ))
        #expect(!ProxyManager.managedContinuityLocked(
            preventDisable: false, protectionActive: true
        ))
    }

    @Test("Explicit cleanup and automatic migration both lock configuration mutation")
    func cleanupMutationLock() {
        #expect(!ProxyManager.configurationMutationLocked(
            cleanupInProgress: false, migrationInProgress: false
        ))
        #expect(ProxyManager.configurationMutationLocked(
            cleanupInProgress: true, migrationInProgress: false
        ))
        #expect(ProxyManager.configurationMutationLocked(
            cleanupInProgress: false, migrationInProgress: true
        ))
        #expect(ProxyManager.configurationMutationLocked(
            cleanupInProgress: true, migrationInProgress: true
        ))
    }

    @Test("Configuration cleanup reports success only when every artifact is verified absent")
    func configurationCleanupReportIsAllOrNothing() {
        let components: [ConfigurationCleanupComponent] = [
            .launchAtLogin,
            .shellRouting,
            .legacyPAC,
            .legacyCertificate,
            .legacyExtension,
            .systemProxy,
        ]
        let complete = ConfigurationCleanupReport(components.map { ($0, true) })
        #expect(complete.isComplete)
        #expect(complete.failed.isEmpty)

        for failedComponent in components {
            let report = ConfigurationCleanupReport(
                components.map { ($0, $0 != failedComponent) }
            )
            #expect(!report.isComplete)
            #expect(report.failed == [failedComponent])
            let message = report.partialFailureMessage(action: "Configuration removal")
            #expect(message.contains(failedComponent.rawValue))
            #expect(message.contains("safe to retry"))
            #expect(!message.contains("configuration removed"))
        }
    }

    @Test("Cleanup retries every exact port Bouclier may have owned")
    func cleanupCandidatePortsAreValidatedAndDeduplicated() {
        #expect(ProxyManager.cleanupCandidatePorts(
            boundPort: 9000,
            managedPort: 9443,
            preferredPort: 8484,
            lastAppliedPort: 9000
        ) == [9000, 9443, 8484])

        #expect(ProxyManager.cleanupCandidatePorts(
            boundPort: 80,
            managedPort: 0,
            preferredPort: 65_536,
            lastAppliedPort: nil
        ) == [8484], "invalid or privileged ports must never become cleanup ownership evidence")
    }

    @Test("Configuration notices distinguish verified success from partial failure")
    func configurationNoticeKinds() {
        let success = ConfigurationNotice(
            kind: .success, title: "Removed", message: "Verified absent"
        )
        let attention = ConfigurationNotice(
            kind: .attention, title: "Incomplete", message: "Retry"
        )
        #expect(success.kind == .success)
        #expect(attention.kind == .attention)
        #expect(success != attention)
    }

    @Test("Legacy CA PEM parsing rejects missing envelopes and invalid DER")
    func legacyCAPEMParsingRejectsInvalidIdentity() {
        let der = Data([0x30, 0x01, 0x00])
        let pem = """
        -----BEGIN CERTIFICATE-----
        \(der.base64EncodedString())
        -----END CERTIFICATE-----
        """
        #expect(CertificateAuthority.certificateDER(fromPEM: pem) == nil)
        #expect(CertificateAuthority.certificateDER(fromPEM: der.base64EncodedString()) == nil)
        #expect(CertificateAuthority.certificateDER(
            fromPEM: "-----BEGIN CERTIFICATE-----\n!not-base64!\n-----END CERTIFICATE-----"
        ) == nil)
    }

    @Test("Login-item removal verifies registration state")
    func loginItemRemovalPostcondition() {
        #expect(ProxyManager.launchAtLoginRegistrationIsAbsent(.notRegistered))
        #expect(ProxyManager.launchAtLoginRegistrationIsAbsent(.notFound))
        #expect(!ProxyManager.launchAtLoginRegistrationIsAbsent(.enabled))
        #expect(!ProxyManager.launchAtLoginRegistrationIsAbsent(.requiresApproval))
    }

    @Test("initializeStorage runs at construction, not deferred to first menu open")
    func initRanAtConstruction() {
        let pm = ProxyManager()
        #expect(pm.didInitializeStorage,
                "ProxyManager.init() must call initializeStorage() so the menubar shield reflects state at launch — not after the user happens to click the menu")
    }

    /// The block notification must surface *safe metadata only* — matched
    /// pattern name(s) + JSON locator — and never the adversarial span
    /// content. `blockNotificationBody` takes no span text as a parameter,
    /// so this pins both the phrasing and the structural guarantee that
    /// content can't leak onto a broadcast surface (Notification Center,
    /// Continuity mirroring, a screen-reading agent) the gateway can't see.
    @Test("Block notification body is safe metadata only — pattern + locator, never span content")
    func blockNotificationBodyIsMetadataOnly() {
        // Named pattern + locator: leads with the detector label and the
        // JSON path, not the payload.
        #expect(
            ProxyManager.blockNotificationBody(
                patternNames: ["system-prompt-extraction"],
                locator: "messages[2].content[0].tool_result",
                host: "api.anthropic.com"
            ) == "system-prompt-extraction in messages[2].content[0].tool_result → api.anthropic.com"
        )

        // More than two patterns: first two (sorted) + a "+N more" tail so
        // the banner can't run long.
        #expect(
            ProxyManager.blockNotificationBody(
                patternNames: ["delta", "alpha", "charlie", "bravo"],
                locator: "messages[0].tool_result",
                host: "h"
            ) == "alpha, bravo +2 more in messages[0].tool_result → h"
        )

        // ML/entropy-only block: no named pattern → generic phrasing, still
        // naming where it came from.
        #expect(
            ProxyManager.blockNotificationBody(
                patternNames: [],
                locator: "messages[1].tool_result",
                host: "h"
            ) == "Suspicious content in messages[1].tool_result → h"
        )

        // Missing locator falls back to a structural placeholder, never the
        // span text.
        #expect(
            ProxyManager.blockNotificationBody(
                patternNames: ["p"], locator: nil, host: "h"
            ) == "p in tool output → h"
        )
    }

    /// Pins the v0.6.1 fix for the "Blocked 0 injection(s):" mystery
    /// log line. When the ML / entropy fusion fires without any
    /// individual regex matching, `matchCount` is 0 and `patternNames`
    /// is empty — the old message read as a bug to anyone watching the
    /// log feed. The two branches below must produce honest, distinct
    /// messages with distinct `blocked` flags.
    @Test("Regex-driven and ML-only detections both log as blocks — detected means the refusal fired")
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
        #expect(pmRegex.stats.injectionsBlocked == initialBlocked + 1,
                "One refused request must increment the request-level block counter once")
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
        // refusal path, so this request WAS refused even though no named
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
                "An ML-only block must light the red shield — detected is only ever set by the gateway's refusal path")
        #expect(mlEntry?.message.contains("Blocked request") == true,
                "ML-only message must read as the block it is")
        #expect(mlEntry?.message.contains("no named pattern") == true,
                "ML-only message must say why there are no pattern names — lower-confidence signal, same enforcement")
        #expect(mlEntry?.message.contains("score 0.55") == true,
                "ML-only message must carry the fused score for triage")
        #expect(mlEntry?.message.contains("Blocked 0") == false,
                "The original bug: 'Blocked 0 injection(s)' must never appear in the log feed")
    }

    @Test("Monitor findings are visible and skipped traffic is not counted as inspected")
    func flaggedAndSkippedRequestsStayHonest() {
        let previousNotifications = UserDefaults.standard.object(forKey: "showNotifications")
        UserDefaults.standard.set(false, forKey: "showNotifications")
        defer {
            if let previousNotifications {
                UserDefaults.standard.set(previousNotifications, forKey: "showNotifications")
            } else {
                UserDefaults.standard.removeObject(forKey: "showNotifications")
            }
        }
        let pm = ProxyManager()
        let initial = pm.stats

        pm.handleRequestLog(RequestLog(
            timestamp: Date(),
            targetHost: "api.anthropic.com",
            detected: false,
            matchCount: 2,
            patternNames: ["ROLE_HIJACK", "INSTRUCTION_OVERRIDE"],
            bodySize: 512,
            mlScore: nil,
            entropyAnomaly: 0,
            fusedScore: 0.81,
            mlAvailable: false,
            injectionFlagged: true,
            inspectionPerformed: true
        ))
        pm.handleRequestLog(RequestLog(
            timestamp: Date(),
            targetHost: "api.openai.com",
            detected: false,
            matchCount: 0,
            patternNames: [],
            bodySize: InjectionInspectionPass.maxScanBytes + 1,
            mlScore: nil,
            entropyAnomaly: 0,
            fusedScore: 0,
            mlAvailable: false,
            inspectionPerformed: false,
            scanSkippedReason: .oversized
        ))
        pm.handleRequestLog(RequestLog(
            timestamp: Date(),
            targetHost: "api.openai.com",
            detected: false,
            matchCount: 0,
            patternNames: [],
            bodySize: 128,
            mlScore: nil,
            entropyAnomaly: 0,
            fusedScore: 0,
            mlAvailable: false,
            inspectionPerformed: false,
            scanSkippedReason: .unsupportedContentEncoding
        ))
        pm.handleRequestLog(RequestLog(
            timestamp: Date(),
            targetHost: "api.openai.com",
            detected: true,
            matchCount: 0,
            patternNames: [],
            bodySize: 128,
            mlScore: nil,
            entropyAnomaly: 0,
            fusedScore: 0,
            mlAvailable: false,
            inspectionPerformed: false,
            scanSkippedReason: .unsupportedContentEncoding
        ))

        #expect(pm.stats.requestsScanned == initial.requestsScanned + 1)
        #expect(pm.stats.requestsSkippedInspection == initial.requestsSkippedInspection + 3)
        #expect(pm.stats.injectionFindingsFlagged == initial.injectionFindingsFlagged + 1)
        #expect(pm.stats.injectionsBlocked == initial.injectionsBlocked,
                "monitor findings must never inflate the blocked count")
        #expect(pm.stats.requestsBlockedByInspectionLimit == initial.requestsBlockedByInspectionLimit + 1)
        #expect(pm.logs.contains {
            !$0.blocked && $0.message.contains("allowed for forwarding, not blocked")
        })
        #expect(pm.logs.contains {
            !$0.blocked && $0.message.contains("Inspection skipped") && $0.message.contains("allowed for forwarding")
        })
        #expect(pm.logs.contains {
            $0.blocked && $0.message.contains("no injection verdict was produced")
        })
        #expect(pm.logs.contains {
            !$0.blocked && $0.message.contains("compressed request bodies are unsupported")
        })
        #expect(pm.logs.contains {
            $0.blocked && $0.message.contains("compressed body could not be inspected")
        })
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
