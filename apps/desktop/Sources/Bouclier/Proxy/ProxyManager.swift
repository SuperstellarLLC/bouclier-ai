import AppKit
import BouclierCore
import Foundation
import NIOCore
import ServiceManagement
import SwiftUI
import UserNotifications

enum ConfigurationCleanupComponent: String, Equatable, Sendable {
    case launchAtLogin = "launch at login"
    case shellRouting = "shell, watchdog, or launchctl routing"
    case legacyPAC = "legacy Bouclier PAC routing"
    case legacyCertificate = "legacy certificate"
    case legacyExtension = "legacy extension"
    case systemProxy = "macOS HTTP/HTTPS and PAC settings"

    var recovery: String {
        switch self {
        case .launchAtLogin:
            "Quit other copies of Bouclier and retry."
        case .shellRouting:
            "Check permissions for your shell profiles and ~/Library/LaunchAgents, then retry."
        case .legacyPAC:
            "Check macOS Network settings permissions, then retry."
        case .legacyCertificate:
            "Allow Keychain changes, or remove the legacy Bouclier certificate in Keychain Access, then retry. If its identity file is damaged, also remove the ai.bouclier.app / ca-private-key item and legacy ca.pem/ca.key files."
        case .legacyExtension:
            "Approve removal in System Settings if prompted, restart if requested, then retry."
        case .systemProxy:
            "Check Network settings permissions, then retry."
        }
    }
}

struct ConfigurationNotice: Equatable, Sendable {
    enum Kind: Equatable, Sendable {
        case success
        case attention
    }

    let kind: Kind
    let title: String
    let message: String
}

struct ConfigurationCleanupReport: Equatable, Sendable {
    let failed: [ConfigurationCleanupComponent]

    init(_ results: [(ConfigurationCleanupComponent, Bool)]) {
        failed = results.compactMap { component, succeeded in
            succeeded ? nil : component
        }
    }

    var isComplete: Bool { failed.isEmpty }

    func partialFailureMessage(action: String) -> String {
        let artifacts = failed.map(\.rawValue).joined(separator: ", ")
        let recovery = failed.map(\.recovery).joined(separator: " ")
        return "\(action) is incomplete. Still needs attention: \(artifacts). \(recovery) Completed steps are safe to retry."
    }
}

@MainActor
final class ProxyManager: ObservableObject {
    @Published var isRunning = false
    /// Always false in production now — extreme mode (the only feature
    /// that ever installed a CA) was removed. Kept as published state
    /// (rather than deleted outright) because `BouclierStatus.caInstalled`
    /// is a stable, external field read by the CLI/MCP status surface;
    /// see `migrateAwayFromExtremeModeIfNeeded()` for the one-time
    /// cleanup of a CA a pre-removal install may have left behind.
    @Published var caInstalled = false
    /// Whether inspection/enforcement is on — the *protection* state, as
    /// distinct from `isRunning` (the *gateway* state). They diverge in
    /// passthrough: protection off, gateway still relaying so active
    /// agent sessions holding our base URL keep working. UI shield state
    /// and the protection toggle key off this, never off `isRunning`.
    /// Seeded from persisted state in `init` (stored-property initializers
    /// cannot reference `Self`).
    @Published var protectionActive = false
    @Published var errorMessage: String?
    @Published var stats = ProxyStats()
    @Published var logs: [LogEntry] = []
    @Published private(set) var configurationCleanupInProgress = false
    @Published private(set) var legacyMigrationInProgress = false
    @Published private(set) var configurationCleanupNotice: ConfigurationNotice?
    @Published private(set) var migrationCleanupNotice: ConfigurationNotice?
    @Published private(set) var cliCaptureIssue: String?
    @Published private(set) var legacyCLICleanupIssue: String?
    /// Changes whenever a pattern reload or classifier-load outcome changes
    /// the active detection tier, prompting SwiftUI to recompute its summary.
    @Published private(set) var patternRevision = 0

    /// The port actually bound by the live gateway. Kept separate from the
    /// configured preference: editing Settings while the gateway is running
    /// must not make status claim it moved ports, or repoint shell capture at
    /// a listener that does not exist. The new preference takes effect on the
    /// next start.
    @Published private(set) var boundPort: Int?

    var port: Int {
        boundPort ?? configuredPort
    }

    private var configuredPort: Int {
        if let managed = ManagedConfig.port { return managed }
        let preferred = UserDefaults.standard.object(forKey: "proxyPort") as? Int
        return ManagedConfigValidator.validatedPort(preferred) ?? 8484
    }

    /// Owns the live prompt-injection engine: loads `patterns.json`,
    /// publishes to `InjectionFilter.active`, hot-reloads, and swaps in
    /// the CoreML classifier if one is present. Held for the app's
    /// lifetime — the registry it feeds is what the gateway reads.
    private var patternManager: PatternManager?

    /// Number of enabled detection patterns currently loaded. Shown in
    /// the menu bar so "protected" is a number, not a vibe.
    var patternCount: Int { InjectionFilter.active.current()?.patternCount ?? 0 }

    /// False when resource loading fell back to the intentionally tiny
    /// emergency set. Protection still runs, but the UI must say degraded.
    var patternTierHealthy: Bool {
        patternCount >= InjectionFilter.expectedBundledPatternCount
    }

    /// Whether the bundled on-device Prompt Guard tier has finished loading.
    /// False during startup or when the model cannot load.
    var mlTierActive: Bool { InjectionFilter.active.current()?.hasMLClassifier ?? false }

    /// Distinguishes a brief startup load from a permanent regex-only
    /// fallback so the product never silently implies its bundled ML tier is
    /// active after a load failure.
    var mlTierUnavailable: Bool { patternManager?.classifierLoadError != nil }

    /// Effective request-detector health. Protection can be requested while
    /// managed policy disables `injectionDetection`; that state is a degraded
    /// relay and must never be described as monitor or block mode.
    var detectorEnabled: Bool {
        Self.effectiveDetectorEnabled(
            gatewayRunning: isRunning,
            protectionEnabled: Self.effectiveProtectionEnabled,
            featureEnabled: FeatureFlags.injectionDetection
        )
    }

    var detectionEngineDegraded: Bool {
        !detectorEnabled || !patternTierHealthy || mlTierUnavailable
    }

    /// Pure policy join used by both live health publication and focused
    /// tests. Keeping the conjunction here prevents future status surfaces
    /// from treating the protection toggle alone as proof of inspection.
    static func effectiveDetectorEnabled(
        gatewayRunning: Bool,
        protectionEnabled: Bool,
        featureEnabled: Bool
    ) -> Bool {
        gatewayRunning && protectionEnabled && featureEnabled
    }

    /// True when normal user controls that would break capture or persistence
    /// are locked by an active managed protection policy.
    var managedContinuityLockActive: Bool {
        Self.managedContinuityLocked(protectionActive: protectionActive)
    }

    /// Configuration mutation stays locked for both an explicit reset/removal
    /// and the automatic retired-extension migration. Otherwise a user can
    /// re-create an artifact while an OS approval sheet is still outstanding,
    /// after its cleanup result was already captured.
    var configurationMutationLocked: Bool {
        Self.configurationMutationLocked(
            cleanupInProgress: configurationCleanupInProgress,
            migrationInProgress: legacyMigrationInProgress
        )
    }

    static func configurationMutationLocked(
        cleanupInProgress: Bool,
        migrationInProgress: Bool
    ) -> Bool {
        cleanupInProgress || migrationInProgress
    }

    var cliCaptureHealthy: Bool {
        ShellEnvInjector.isEnabled && cliCaptureHealthIssue == nil
    }

    var cliCaptureHealthIssue: String? {
        cliCaptureIssue ?? legacyCLICleanupIssue
    }

    private var persistentConfigurationAttention: String? {
        if configurationCleanupNotice?.kind == .attention {
            return configurationCleanupNotice?.message
        }
        if migrationCleanupNotice?.kind == .attention {
            return migrationCleanupNotice?.message
        }
        return cliCaptureHealthIssue
    }

    private var gatewayServer: GatewayServer?
    private var statusPublisher: StatusPublisher?
    private var proxyChannel: Channel?
    /// Cleanup-only remnants of extreme mode (CA + System Extension),
    /// kept solely so `migrateAwayFromExtremeModeIfNeeded()` can detect
    /// and remove state a pre-removal install left behind. See their
    /// doc comments.
    let ca = CertificateAuthority()
    let extensionManager = ExtensionManager()
    private(set) var storage: StorageManager?
    /// Delegate for the block-notification "Release this span" action.
    /// Strongly held here because `UNUserNotificationCenter.delegate` is weak.
    private var notificationHandler: NotificationActionHandler?
    /// Delivers SIGTERM on the main queue so shutdown can use normal AppKit
    /// lifecycle hooks. A raw C signal handler must not call Foundation,
    /// launch `Process`, or touch files.
    private var terminationSignalSource: DispatchSourceSignal?
    private var migrationIssues: [String] = []

    /// Coalesces bursts of block notifications so a false-positive storm (many
    /// tool_results blocked in one agent session) shows a throttled summary
    /// instead of one banner per block.
    private var blockNotificationCoalescer = NotificationCoalescer()
    /// True once `initializeStorage()` has run. Exposed so a regression
    /// test can pin "this runs at construction time" without depending
    /// on storage actually succeeding (SQLite init can fail in sandbox/CI
    /// environments — that's expected, but the *gate* must still fire).
    private(set) var didInitializeStorage = false

    /// The port the gateway is currently bound to, or nil when nothing is
    /// listening. Read from `AppDelegate.applicationWillTerminate` (a
    /// non-isolated context) to decide whether to hand the port off to a
    /// passthrough relay on quit. Stays set in passthrough mode too, so a
    /// quit while protection is paused still keeps the session alive.
    nonisolated(unsafe) static var liveGatewayPort: Int?
    /// The live decision is process-owned and synchronized. UserDefaults
    /// seeds/persists it, but NIO never re-reads that writable domain per
    /// request: a Bash-capable process using `defaults write` must not turn a
    /// green, active shield into silent passthrough. All legitimate changes
    /// flow through the guarded MainActor methods below.
    private nonisolated static let protectionStateLock = NSLock()
    private nonisolated(unsafe) static var effectiveProtectionState = false

    nonisolated static var effectiveProtectionEnabled: Bool {
        protectionStateLock.lock()
        defer { protectionStateLock.unlock() }
        return effectiveProtectionState
    }

    private static func setEffectiveProtection(_ enabled: Bool) {
        protectionStateLock.lock()
        effectiveProtectionState = enabled
        protectionStateLock.unlock()
    }

    init() {
        protectionActive = Self.protectionEnabled
        Self.setEffectiveProtection(protectionActive)

        // The detection engine is live again as of v0.9.0, this time
        // hanging off the certificate-free gateway rather than the
        // removed extreme mode. PatternManager loads patterns.json,
        // publishes the regex-only filter to `InjectionFilter.active`
        // immediately, watches for hot-reloads, and swaps in the fused
        // engine if the CoreML classifier ever loads. The gateway reads
        // the registry per request; see `InjectionInspectionPass`.
        //
        // `loadPIITier: false` — the Piiranha model has been unbundled
        // since v0.7.0 and nothing calls the PII path. The injection-tier
        // callback publishes reload/load changes so the menu doesn't remain
        // stuck on the startup tier until some unrelated state changes.
        patternManager = PatternManager(onChange: { [weak self] in
            Task { @MainActor in
                guard let self else { return }
                self.patternRevision &+= 1
                self.statusPublisher?.refresh()
            }
        }, loadPIITier: false)

        // Register lifecycle cleanup so a quit/crash withdraws the exact
        // launchctl values and status snapshot this process owned.
        registerCleanupHandlers()

        // Auto-init at construction. The previous design deferred this
        // to MenuBarView.onAppear, but that fires only when the user
        // *opens* the menu — so on launch the shield icon read "off"
        // until the user clicked it, defeating automatic protection startup.
        // Calling it here makes
        // the gate fire as soon as the App's body builds the
        // MenuBarExtra scene (which forces @StateObject construction).
        initializeStorage()
    }

    func initializeStorage() {
        guard !didInitializeStorage else { return }
        didInitializeStorage = true

        // Undo any relay left behind by a previous quit BEFORE we bind:
        // kill it, free the port, drop its pidfile. This is the launch-
        // time cleanup that keeps the handoff residue-free — after this
        // the system looks exactly as if no relay ever ran.
        RelaySupport.reclaim()
        do {
            storage = try StorageManager()
        } catch {
            // A dead audit store must be loud. Every `storage?.recordScan`
            // silently no-ops without it — which is exactly how a broken
            // v1 migration shipped unnoticed while the activity feed and
            // os_log kept working. One feed line + one os_log event at
            // startup; the app itself stays fully functional.
            storage = nil
            log("Audit database unavailable — scan history will NOT be recorded: \(error)", blocked: false)
            AuditLogger.shared.logEvent("storage_init_failed", detail: "\(error)")
        }
        caInstalled = ca.isInstalled

        // Install the notification action handler so the "Release this
        // span" button on a block notification routes back to the
        // allowlist. Held for the app's lifetime (the delegate is weakly
        // held by UNUserNotificationCenter). Only in the packaged .app:
        // touching UNUserNotificationCenter's delegate/categories throws
        // an NSException in the SwiftPM test host, which has no bundle
        // entitlement — and construction must stay crash-free there.
        if Self.isRunningInPackagedApp {
            let handler = NotificationActionHandler(proxyManager: self)
            notificationHandler = handler
            UNUserNotificationCenter.current().delegate = handler
            NotificationActionHandler.registerCategories()
        }

        // One-shot cleanup for installs that had extreme mode (CA +
        // System Extension + PAC) active before it was removed. Must run
        // before anything else touches `ca`/`extensionManager` state.
        migrateLegacyLaunchctlEnvironmentIfNeeded()
        migrateAwayFromExtremeModeIfNeeded()

        // A managed "cannot disable" deployment must not leave two quiet
        // bypasses open: turning off shell capture means new CLI processes
        // never reach the gateway, and turning off the login item means the
        // gateway disappears after logout. Enforce both preferences before
        // auto-start so startStandard() sees shell capture enabled.
        enforceManagedContinuityControlsIfNeeded()

        // Publish the read-only status snapshot for the CLI so an agent can
        // check whether protection is on before it runs.
        statusPublisher = StatusPublisher(snapshot: { [weak self] in self?.statusSnapshot() ?? Self.emptyStatus() })
        statusPublisher?.start()

        // If the user has already gone through onboarding, turn protection
        // on at launch — the menu-bar shield otherwise shows the disarmed
        // icon and the user has to manually re-arm every restart, which the
        // "seatbelt made of paper" feedback called out as a credibility
        // risk. launchctl setenv values don't survive logout, so re-apply
        // env every launch (the dotfile portion is idempotent, so cheap).
        // start() only kicks off the async bind; startStandard() applies
        // the shell/GUI env itself once the listener actually accepts
        // connections, so nothing here points CLI tools at a not-yet-bound
        // port. Only auto-start if the user has explicitly enabled
        // protection before (the Protection tab's "Enable Protection"
        // button) — we don't reconfigure the user's shell/GUI env on
        // first launch without consent.
        // Also auto-start when protection is *disabled* but the user's
        // shell env was ever pointed at the gateway: the gateway then runs
        // as an allow-all passthrough, so agent sessions holding
        // `ANTHROPIC_BASE_URL=127.0.0.1:<port>` keep working instead of
        // dying on a connection refused. First-launch users have neither
        // flag set, so nothing starts without consent.
        if (Self.protectionEnabled || Self.envConfigured) && !isRunning {
            start()
        }
    }

    /// One-shot migration for installs that had extreme mode (CA-based TLS
    /// interception + System Extension + PAC) active before it was removed
    /// from the product entirely. Without this, those users would be left
    /// with an orphaned root CA trusted in Keychain and, in extreme mode's
    /// "full interception" variant, a System Extension still redirecting
    /// AI-host traffic to a proxy path that no longer exists in that form.
    /// Gated by a version-suffixed sentinel key, mirroring
    /// `LegacyDefaultsCleanup`'s pattern — a future migration would mint a
    /// new `.v2` key rather than reuse this one.
    // v2 replaces v1's broad, false-success-prone cleanup. It touches only an
    // exact Bouclier PAC URL/extension and records completion only after state
    // can be read and no retired manager remains.
    private static let extremeModeMigrationKey = "bouclier.extremeModeRemoved.v2"
    private static let legacyLaunchctlMigrationKey = "bouclier.legacyLaunchctlCleanup.v1"
    // ShellEnvInjector persists this value before any partial apply so cleanup
    // can still target the exact launchctl value after the preference changes.
    // Keep the spelling in sync without widening ShellEnvInjector's API solely
    // for a one-release migration helper.
    private static let lastAppliedGatewayPortKey = "bouclier.lastAppliedGatewayPort"

    static func cleanupCandidatePorts(
        boundPort: Int?,
        managedPort: Int?,
        preferredPort: Int?,
        lastAppliedPort: Int?
    ) -> [Int] {
        var seen = Set<Int>()
        let candidates = [boundPort, managedPort, preferredPort, lastAppliedPort]
            .compactMap { candidate -> Int? in
                guard let candidate,
                      let valid = ManagedConfigValidator.validatedPort(candidate),
                      seen.insert(valid).inserted
                else { return nil }
                return valid
            }
        // 8484 is ownership evidence only when it is the effective fallback,
        // not as a speculative historical port beside an unrelated setting.
        return candidates.isEmpty ? [8484] : candidates
    }

    private var cleanupCandidatePorts: [Int] {
        Self.cleanupCandidatePorts(
            boundPort: boundPort,
            managedPort: ManagedConfig.port,
            preferredPort: UserDefaults.standard.object(forKey: "proxyPort") as? Int,
            lastAppliedPort: UserDefaults.standard.object(
                forKey: Self.lastAppliedGatewayPortKey
            ) as? Int
        )
    }

    private func removeOwnedLegacyLaunchctl(for ports: [Int]) -> Bool {
        ports.reduce(true) { complete, candidate in
            ShellEnvInjector.unsetLegacyLaunchctlIfOwned(
                proxyPort: candidate,
                caCertPath: CertificateAuthority.caCertPath.path
            ) && complete
        }
    }

    private func recordMigrationIssue(_ message: String) {
        if !migrationIssues.contains(message) { migrationIssues.append(message) }
        publishMigrationIssues()
        errorMessage = message
        log(message, blocked: false)
    }

    private func publishMigrationIssues() {
        guard !migrationIssues.isEmpty else {
            migrationCleanupNotice = nil
            return
        }
        migrationCleanupNotice = ConfigurationNotice(
            kind: .attention,
            title: "Legacy cleanup needs attention",
            message: migrationIssues.joined(separator: " ")
        )
    }

    private func migrateLegacyLaunchctlEnvironmentIfNeeded() {
        guard !UserDefaults.standard.bool(forKey: Self.legacyLaunchctlMigrationKey) else { return }
        let complete = removeOwnedLegacyLaunchctl(for: cleanupCandidatePorts)
        if complete {
            legacyCLICleanupIssue = nil
            UserDefaults.standard.set(true, forKey: Self.legacyLaunchctlMigrationKey)
        } else {
            let message = "Bouclier could not verify removal of its retired launchctl proxy variables. Quit other copies, check session permissions, and reopen Bouclier to retry."
            legacyCLICleanupIssue = message
            recordMigrationIssue(message)
        }
    }

    private func migrateAwayFromExtremeModeIfNeeded() {
        guard !UserDefaults.standard.bool(forKey: Self.extremeModeMigrationKey) else { return }
        let ports = cleanupCandidatePorts
        let hadCA = ca.isInstalled
        legacyMigrationInProgress = true
        Task {
            defer {
                self.legacyMigrationInProgress = false
                if (Self.protectionEnabled || Self.envConfigured), !self.isRunning {
                    self.start()
                }
            }

            // Keep local retry material in place until systemextensiond has
            // finished. This avoids declaring local cleanup complete while a
            // retired transparent proxy remains active pending approval.
            let extensionComplete = await extensionManager.removeLegacyConfiguration {
                [weak self] message in
                guard let self else { return }
                self.migrationCleanupNotice = ConfigurationNotice(
                    kind: .attention,
                    title: "Legacy extension removal requires action",
                    message: message
                )
                self.errorMessage = message
                self.log(message, blocked: false)
            }
            let caCleanupComplete = ca.uninstallCA()
            caInstalled = ca.isInstalled
            let pacCleanupComplete = await Task.detached {
                SystemProxy.disableLegacyBouclierPAC(proxyPorts: ports)
            }.value

            if !extensionComplete {
                let detail = extensionManager.errorMessage ?? "unknown cleanup error"
                recordMigrationIssue(
                    "Bouclier could not finish removing its retired System Extension. \(detail)"
                )
            }
            if !caCleanupComplete {
                recordMigrationIssue(
                    "Bouclier could not verify removal of its retired certificate. Allow Keychain changes or remove the Bouclier certificate in Keychain Access, then reopen Bouclier. If its identity file is damaged, also remove the ai.bouclier.app / ca-private-key item and legacy ca.pem/ca.key files."
                )
            }
            if !pacCleanupComplete {
                recordMigrationIssue(
                    "Bouclier could not verify removal of its retired PAC URL. Check macOS Network settings permissions, then reopen Bouclier."
                )
            }

            let complete = extensionComplete && caCleanupComplete && pacCleanupComplete
            if complete {
                UserDefaults.standard.set(true, forKey: Self.extremeModeMigrationKey)
                publishMigrationIssues()
                if hadCA && migrationIssues.isEmpty {
                    migrationCleanupNotice = ConfigurationNotice(
                        kind: .success,
                        title: "Legacy security configuration removed",
                        message: "Bouclier removed the retired local certificate and verified that its old extension and PAC routing are absent."
                    )
                }
                if hadCA {
                    log("Removed the local CA left by extreme mode, which no longer exists in this version", blocked: false)
                }
            } else {
                UserDefaults.standard.removeObject(forKey: Self.extremeModeMigrationKey)
            }
        }

        // The stored mode may still be the literal string "extreme" from
        // a pre-removal install — `ProxyMode(rawValue:)` no longer parses
        // that, so `current` already falls back to `.standard`, but write
        // it explicitly so the stale value doesn't linger in defaults.
        UserDefaults.standard.set(ProxyMode.standard.rawValue, forKey: ProxyMode.userDefaultsKey)
    }

    /// One-time opt-in: persists across launches so standard mode can
    /// auto-start without surprising a brand-new user on first run.
    nonisolated static let protectionEnabledKey = "protectionEnabled"
    static var protectionEnabled: Bool {
        UserDefaults.standard.bool(forKey: protectionEnabledKey)
    }

    /// True only in the shipping `.app` bundle. The SwiftPM test host runs
    /// inside an `.xctest` bundle and `swift run` inside a bare binary;
    /// UserNotifications APIs that need an entitlement throw there. Guards
    /// notification setup so unit tests can construct `ProxyManager`.
    static var isRunningInPackagedApp: Bool {
        Bundle.main.bundleURL.pathExtension == "app"
    }

    /// True once the user's shell/GUI env has ever been pointed at the
    /// gateway (set by enable, kept by disable, cleared only by
    /// explicit configuration removal/proxy reset). Distinct from
    /// `protectionEnabled` so "protection
    /// off" can mean *allow-all passthrough* rather than *dead port*:
    /// as long as env may reference our port, the gateway must answer.
    static let envConfiguredKey = "gatewayEnvConfigured"
    static var envConfigured: Bool {
        UserDefaults.standard.bool(forKey: envConfiguredKey)
    }

    /// Enable standard (non-CA) protection: start the gateway and point the
    /// agent's SDKs at it. No CA, no PAC, no system extension. This is the
    /// frictionless default path from the Protection tab.
    func enableStandard() {
        guard !configurationMutationLocked else {
            log("Protection cannot be enabled while configuration cleanup is in progress", blocked: false)
            return
        }
        clearSuccessfulConfigurationCleanupNotice()
        UserDefaults.standard.set(true, forKey: Self.protectionEnabledKey)
        UserDefaults.standard.set(true, forKey: Self.envConfiguredKey)
        protectionActive = true
        Self.setEffectiveProtection(true)
        statusPublisher?.refresh()
        enforceManagedContinuityControlsIfNeeded()
        UserDefaults.standard.set(ProxyMode.standard.rawValue, forKey: ProxyMode.userDefaultsKey)
        requestBlockNotificationAuthorizationIfNeeded()
        if isRunning {
            // Gateway is already bound — safe to re-point the env immediately.
            if ShellEnvInjector.isEnabled {
                _ = applyShellCapture(gatewayPort: port)
            }
        } else {
            // start() only kicks off the async bind; startStandard() applies
            // the env itself once isRunning flips true, so CLI tools are
            // never pointed at a port before anything is listening on it.
            start()
        }
        log("Standard protection enabled (no CA)", blocked: false)
    }

    /// Ask for Notification Center access only after the user has chosen a
    /// mode that can actually create block banners. Prompting at process
    /// launch put a permission dialog in front of first-run onboarding with
    /// no explanation — and monitor-only users never need this permission.
    func requestBlockNotificationAuthorizationIfNeeded() {
        guard Self.isRunningInPackagedApp,
              FeatureFlags.injectionBlock,
              UserDefaults.standard.object(forKey: "showNotifications") as? Bool ?? true
        else { return }
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    /// Turn off standard protection WITHOUT killing the gateway: the
    /// listener stays bound and relays everything as an allow-all
    /// passthrough (inspection skipped per request via the
    /// `inspectionEnabled` closure handed to `GatewayServer`).
    ///
    /// Stopping the listener here was the old behaviour, and it broke
    /// every *active* agent session: a running Claude Code process holds
    /// `ANTHROPIC_BASE_URL=127.0.0.1:<port>` for its lifetime — the shell
    /// dotfile's fail-open TCP probe only helps shells launched later.
    /// Disable must degrade to "no protection", never to "no API".
    /// Full teardown remains available via explicit configuration removal or
    /// proxy reset; quitting hands the live port to a short-lived passthrough
    /// relay.
    func disableStandard() {
        guard !configurationMutationLocked else {
            log("Protection cannot be changed while configuration cleanup is in progress", blocked: false)
            return
        }
        guard !ManagedConfig.preventDisable else {
            log("Protection stays enabled — disabling is prevented by your organization", blocked: false)
            return
        }
        UserDefaults.standard.set(false, forKey: Self.protectionEnabledKey)
        protectionActive = false
        Self.setEffectiveProtection(false)
        statusPublisher?.refresh()
        if isRunning {
            log("Protection disabled — gateway stays up as allow-all passthrough so active agent sessions keep working", blocked: false)
        } else {
            log("Standard protection disabled", blocked: false)
        }
    }

    /// Build the read-only snapshot the StatusPublisher writes. Counts only —
    /// never request content.
    func statusSnapshot() -> BouclierStatus {
        let detectorEnabled = self.detectorEnabled
        return BouclierStatus(
            writtenAt: Date().timeIntervalSince1970,
            pid: getpid(),
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—",
            running: isRunning,
            mode: ProxyMode.current.rawValue,
            caInstalled: caInstalled,
            protectionEnabled: Self.effectiveProtectionEnabled,
            detectorEnabled: detectorEnabled,
            blockingEnabled: detectorEnabled && FeatureFlags.injectionBlock,
            patternCount: patternCount,
            mlClassifierState: mlTierActive
                ? "active"
                : (mlTierUnavailable ? "unavailable" : "loading"),
            activity: .init(requestsScanned: stats.requestsScanned,
                            injectionsBlocked: stats.injectionsBlocked,
                            injectionFindingsFlagged: stats.injectionFindingsFlagged,
                            requestsSkippedInspection: stats.requestsSkippedInspection,
                            requestsBlockedByInspectionLimit: stats.requestsBlockedByInspectionLimit))
    }

    static func emptyStatus() -> BouclierStatus {
        BouclierStatus(
            writtenAt: Date().timeIntervalSince1970, pid: getpid(), appVersion: "—",
            running: false, mode: ProxyMode.current.rawValue, caInstalled: false, protectionEnabled: false,
            detectorEnabled: false, blockingEnabled: false,
            patternCount: 0, mlClassifierState: "unknown",
            activity: .init(requestsScanned: 0, injectionsBlocked: 0,
                            injectionFindingsFlagged: 0, requestsSkippedInspection: 0,
                            requestsBlockedByInspectionLimit: 0))
    }

    func start() {
        // `isRunning` is only set true asynchronously after bind, so also
        // guard on the server ivar (assigned synchronously by
        // startStandard()) to prevent a second start() — e.g.
        // enableStandard() racing the initializeStorage auto-start — from
        // binding twice and orphaning a channel.
        guard !configurationMutationLocked,
              !isRunning,
              gatewayServer == nil
        else { return }
        errorMessage = persistentConfigurationAttention
        startStandard()
    }

    /// Standard (non-CA) mode: bind the base-URL gateway. No CA, no PAC,
    /// no system extension — the agent reaches us via `ANTHROPIC_BASE_URL`.
    private func startStandard() {
        let requestedPort = configuredPort
        // Captured outside the closure: the static key lives on a
        // @MainActor type and can't be touched from a @Sendable closure.
        let gateway = GatewayServer(
            port: requestedPort,
            // Read the synchronized, process-owned effective state per
            // request, so a guarded UI change applies immediately without
            // trusting the writable preferences domain on NIO threads.
            inspectionEnabled: { ProxyManager.effectiveProtectionEnabled },
            onResponseAction: { [weak self] findings in
                Task { @MainActor in self?.handleResponseActions(findings) }
            },
            onRequest: { [weak self] requestLog in
                Task { @MainActor in self?.handleRequestLog(requestLog) }
            }
        )
        gatewayServer = gateway

        Task.detached { [weak self] in
            guard let self else { return }
            do {
                let channel = try await gateway.start()
                await MainActor.run {
                    // stop()/removeConfiguration() may have run while bind was in
                    // flight. Never resurrect a gateway the user already
                    // stopped; close this now-stale listener instead.
                    guard self.gatewayServer === gateway else {
                        channel.close(mode: .all, promise: nil)
                        return
                    }
                    self.proxyChannel = channel
                    self.isRunning = true
                    self.boundPort = requestedPort
                    // Publish the live port so a quit can hand it off to a
                    // passthrough relay before the listener goes away.
                    Self.liveGatewayPort = requestedPort
                    self.statusPublisher?.refresh()
                    channel.closeFuture.whenComplete { [weak self, weak gateway] _ in
                        guard let gateway else { return }
                        Task { @MainActor [weak self] in
                            guard let self, self.gatewayServer === gateway else { return }
                            // Intentional stop/removal clears gatewayServer
                            // before this callback reaches MainActor. If it is
                            // still current, the listener died unexpectedly;
                            // immediately withdraw every operational claim and
                            // clear only the exact launchctl values it owned.
                            self.proxyChannel = nil
                            self.gatewayServer = nil
                            self.isRunning = false
                            self.boundPort = nil
                            Self.liveGatewayPort = nil
                            ShellEnvInjector.unsetLaunchctl(gatewayPort: requestedPort)
                            self.errorMessage = "Gateway listener stopped unexpectedly. Protection is not currently operational; turn it off and on to retry."
                            self.log("Gateway listener stopped unexpectedly", blocked: true)
                            self.statusPublisher?.refresh()
                            Task.detached { gateway.shutdown() }
                        }
                    }
                    self.log("Gateway (standard mode) listening on 127.0.0.1:\(requestedPort)", blocked: false)
                    // Only wire shells/GUI apps to the gateway once the
                    // listener is actually bound and accepting. Applying
                    // this before bind() resolves points CLI tools
                    // (Claude Code, etc.) at a port nothing is listening
                    // on yet — the exact "connection refused at startup"
                    // race this ordering closes.
                    if ShellEnvInjector.isEnabled {
                        _ = self.applyShellCapture(gatewayPort: requestedPort)
                    }
                }
            } catch {
                gateway.shutdown()
                await MainActor.run {
                    guard self.gatewayServer === gateway else { return }
                    self.gatewayServer = nil
                    self.isRunning = false
                    self.boundPort = nil
                    let msg = Self.friendlyError(error)
                    self.errorMessage = msg
                    self.log("Gateway failed: \(msg)", blocked: true)
                    self.statusPublisher?.refresh()
                }
            }
        }
    }

    func stop() {
        // Preserve the authority before clearing published state. Settings
        // may already contain a different next-launch port; cleanup must
        // value-check against the port this listener actually owned.
        let stoppedPort = boundPort
        // Close channel first (non-blocking)
        proxyChannel?.close(mode: .all, promise: nil)
        proxyChannel = nil

        // Shutdown NIO on a background thread to avoid deadlock.
        let gateway = gatewayServer
        gatewayServer = nil
        Task.detached {
            gateway?.shutdown()
        }

        isRunning = false
        boundPort = nil
        Self.liveGatewayPort = nil
        errorMessage = nil
        statusPublisher?.refresh()

        // Current standard mode never changes macOS system-proxy settings.
        // Do not run the legacy "disable all proxies" escape hatch here:
        // it also disables unrelated corporate/manual proxy configuration.
        // That destructive sweep is limited to the explicit Reset action;
        // the old extreme-mode migration removes only an exactly owned PAC.
        // Drop the launchctl proxy env so processes spawned via `open`
        // / Spotlight don't keep pointing at a port we no longer listen
        // on. The dotfile block stays (fail-open TCP probe handles that
        // case); we only fix the GUI-launch path here.
        ShellEnvInjector.unsetLaunchctl(gatewayPort: stoppedPort)

        log("Proxy stopped", blocked: false)
    }

    /// Stop Bouclier and remove the local routing artifacts it configured.
    /// This intentionally does not claim to uninstall/delete the app bundle;
    /// Finder, MDM, or the user's software-management tool owns that action.
    @discardableResult
    func removeConfiguration() async -> Bool {
        guard !ManagedConfig.preventConfigurationRemoval else {
            log("Configuration removal is prevented by your organization", blocked: false)
            return false
        }
        guard !(ManagedConfig.preventDisable && protectionActive) else {
            log("Configuration removal is unavailable while disabling protection is prevented by your organization", blocked: false)
            return false
        }
        guard !configurationMutationLocked else {
            log("Configuration cleanup is already in progress", blocked: false)
            return false
        }
        configurationCleanupInProgress = true
        configurationCleanupNotice = nil
        defer { configurationCleanupInProgress = false }

        // Preserve the live authority before stop() clears boundPort. A user
        // may already have edited the next-launch preference; shell cleanup
        // must target values written for the listener that actually ran.
        let cleanupPort = port
        let candidatePorts = cleanupCandidatePorts
        stop()
        UserDefaults.standard.set(false, forKey: Self.protectionEnabledKey)
        protectionActive = false
        Self.setEffectiveProtection(false)
        statusPublisher?.refresh()

        // Let systemextensiond finish first, then remove and verify every
        // process-local artifact. Mutators stay locked for the whole interval,
        // so a successful result cannot be invalidated while approval is open.
        let extensionComplete = await extensionManager.removeLegacyConfiguration {
            [weak self] message in
            self?.errorMessage = message
            self?.log(message, blocked: false)
        }
        let loginItemComplete = Self.setLaunchAtLogin(false, protectionActive: false)
        let standardShellComplete = ShellEnvInjector.remove(gatewayPort: cleanupPort)
        let legacyLaunchctlComplete = removeOwnedLegacyLaunchctl(for: candidatePorts)
        let shellComplete = standardShellComplete && legacyLaunchctlComplete
        let pacComplete = await Task.detached {
            SystemProxy.disableLegacyBouclierPAC(proxyPorts: candidatePorts)
        }.value
        let caComplete = ca.uninstallCA()
        caInstalled = ca.isInstalled
        cliCaptureIssue = standardShellComplete ? nil : "Bouclier could not verify removal of its CLI capture files or watchdog. Check General ▸ CLI capture and filesystem permissions, then retry configuration removal."
        legacyCLICleanupIssue = legacyLaunchctlComplete ? nil : "Bouclier could not verify removal of its retired launchctl proxy variables. Quit other copies and retry configuration removal."

        // Keep passthrough auto-start armed only while some shell/session
        // routing may still point at the local port. A partial cleanup must not
        // turn stale routing into connection-refused on the next launch.
        UserDefaults.standard.set(!shellComplete, forKey: Self.envConfiguredKey)

        let report = ConfigurationCleanupReport([
            (.launchAtLogin, loginItemComplete),
            (.shellRouting, shellComplete),
            (.legacyPAC, pacComplete),
            (.legacyCertificate, caComplete),
            (.legacyExtension, extensionComplete),
        ])
        guard report.isComplete else {
            if !caComplete || !extensionComplete || !pacComplete {
                UserDefaults.standard.removeObject(forKey: Self.extremeModeMigrationKey)
            }
            if !legacyLaunchctlComplete {
                UserDefaults.standard.removeObject(forKey: Self.legacyLaunchctlMigrationKey)
            }
            var message = report.partialFailureMessage(action: "Configuration removal")
            if !extensionComplete, let detail = extensionManager.errorMessage {
                message += " \(detail)"
            }
            errorMessage = message
            configurationCleanupNotice = ConfigurationNotice(
                kind: .attention,
                title: "Configuration removal is incomplete",
                message: message
            )
            log(message, blocked: false)
            return false
        }

        errorMessage = nil
        UserDefaults.standard.set(true, forKey: Self.extremeModeMigrationKey)
        UserDefaults.standard.set(true, forKey: Self.legacyLaunchctlMigrationKey)
        migrationIssues.removeAll()
        migrationCleanupNotice = nil
        legacyCLICleanupIssue = nil
        configurationCleanupNotice = ConfigurationNotice(
            kind: .success,
            title: "Bouclier configuration removed",
            message: "The gateway and Bouclier-owned routing, login item, retired PAC, certificate, and extension state are verified absent. The app and audit history remain installed."
        )
        log("Bouclier configuration removed; the app and audit history remain installed", blocked: false)
        return true
    }

    /// Nuclear reset for the cases where an unclean shutdown (or a
    /// stale install from an older Bouclier build) leaves the user
    /// unable to reach LLM APIs even with the app quit. Stops the
    /// proxy, sweeps PAC + manual HTTP/HTTPS proxy off every network
    /// service, drops the launchctl session env, removes the watchdog
    /// LaunchAgent, and strips the shell-startup blocks. Protection is
    /// off afterwards — re-enable from the Protection tab.
    @discardableResult
    func resetAllProxies() async -> Bool {
        guard !(ManagedConfig.preventDisable && protectionActive) else {
            log("Proxy reset is unavailable while disabling protection is prevented by your organization", blocked: false)
            return false
        }
        guard !configurationMutationLocked else {
            log("Configuration cleanup is already in progress", blocked: false)
            return false
        }
        configurationCleanupInProgress = true
        configurationCleanupNotice = nil
        defer { configurationCleanupInProgress = false }

        let cleanupPort = port
        let candidatePorts = cleanupCandidatePorts
        // stop() also cancels an in-flight bind represented by gatewayServer
        // while isRunning is still false; checking only the published flag can
        // otherwise let a listener appear after reset has reported completion.
        stop()
        UserDefaults.standard.set(false, forKey: Self.protectionEnabledKey)
        protectionActive = false
        Self.setEffectiveProtection(false)
        statusPublisher?.refresh()

        let extensionComplete = await extensionManager.removeLegacyConfiguration {
            [weak self] message in
            self?.errorMessage = message
            self?.log(message, blocked: false)
        }
        let loginItemComplete = Self.setLaunchAtLogin(false, protectionActive: false)
        let systemProxyComplete = await Task.detached {
            SystemProxy.disableAll()
        }.value
        let standardShellComplete = ShellEnvInjector.remove(gatewayPort: cleanupPort)
        let legacyLaunchctlComplete = removeOwnedLegacyLaunchctl(for: candidatePorts)
        let shellComplete = standardShellComplete && legacyLaunchctlComplete
        let caComplete = ca.uninstallCA()
        caInstalled = ca.isInstalled
        cliCaptureIssue = standardShellComplete ? nil : "Bouclier could not verify removal of its CLI capture files or watchdog. Check General ▸ CLI capture and filesystem permissions, then retry proxy recovery."
        legacyCLICleanupIssue = legacyLaunchctlComplete ? nil : "Bouclier could not verify removal of its retired launchctl proxy variables. Quit other copies and retry proxy recovery."
        UserDefaults.standard.set(!shellComplete, forKey: Self.envConfiguredKey)

        let report = ConfigurationCleanupReport([
            (.launchAtLogin, loginItemComplete),
            (.systemProxy, systemProxyComplete),
            (.shellRouting, shellComplete),
            (.legacyCertificate, caComplete),
            (.legacyExtension, extensionComplete),
        ])
        guard report.isComplete else {
            if !caComplete || !extensionComplete || !systemProxyComplete {
                UserDefaults.standard.removeObject(forKey: Self.extremeModeMigrationKey)
            }
            if !legacyLaunchctlComplete {
                UserDefaults.standard.removeObject(forKey: Self.legacyLaunchctlMigrationKey)
            }
            var message = report.partialFailureMessage(action: "Proxy reset")
            if !extensionComplete, let detail = extensionManager.errorMessage {
                message += " \(detail)"
            }
            errorMessage = message
            configurationCleanupNotice = ConfigurationNotice(
                kind: .attention,
                title: "Proxy recovery is incomplete",
                message: message
            )
            log(message, blocked: false)
            return false
        }

        errorMessage = nil
        UserDefaults.standard.set(true, forKey: Self.extremeModeMigrationKey)
        UserDefaults.standard.set(true, forKey: Self.legacyLaunchctlMigrationKey)
        migrationIssues.removeAll()
        migrationCleanupNotice = nil
        legacyCLICleanupIssue = nil
        configurationCleanupNotice = ConfigurationNotice(
            kind: .success,
            title: "HTTP/HTTPS and PAC recovery completed",
            message: "Manual web proxies and automatic PAC configuration are verified off on every readable network service, and Bouclier-owned routing is removed."
        )
        log("HTTP/HTTPS and PAC proxy settings were reset", blocked: false)
        return true
    }

    /// Managed protection includes the normal capture/availability controls,
    /// not merely the shield toggle. Returns false when a requested mutation
    /// would create a bypass and restores the persisted preference so SwiftUI
    /// cannot display a state the app rejected.
    @discardableResult
    func setCLICaptureEnabled(_ enabled: Bool) -> Bool {
        guard !configurationMutationLocked else {
            log("CLI capture cannot be changed while configuration cleanup is in progress", blocked: false)
            return false
        }
        if !enabled && Self.managedContinuityLocked(protectionActive: protectionActive) {
            UserDefaults.standard.set(true, forKey: ShellEnvInjector.autoConfigureKey)
            log("CLI capture stays enabled — disabling is prevented by your organization", blocked: false)
            return false
        }
        clearSuccessfulConfigurationCleanupNotice()

        UserDefaults.standard.set(enabled, forKey: ShellEnvInjector.autoConfigureKey)
        if enabled {
            if isRunning { return applyShellCapture(gatewayPort: port) }
        } else if !ShellEnvInjector.remove(gatewayPort: port) {
            UserDefaults.standard.set(true, forKey: ShellEnvInjector.autoConfigureKey)
            let message = "CLI capture could not be fully turned off. Bouclier left the preference enabled because a shell block, watchdog, or launchctl value may remain; check shell-profile and ~/Library/LaunchAgents permissions, then retry."
            cliCaptureIssue = message
            errorMessage = message
            log(message, blocked: false)
            return false
        }
        clearCLICaptureIssue()
        return true
    }

    @discardableResult
    private func applyShellCapture(gatewayPort: Int) -> Bool {
        let complete = ShellEnvInjector.applyStandard(gatewayPort: gatewayPort)
        if complete {
            clearCLICaptureIssue()
        } else {
            let message = "Gateway is running, but automatic CLI capture could not be fully configured. Some new AI tools may bypass Bouclier; review General ▸ CLI capture and filesystem permissions."
            cliCaptureIssue = message
            errorMessage = message
            log(message, blocked: false)
        }
        return complete
    }

    private func clearCLICaptureIssue() {
        let resolvedIssue = cliCaptureIssue
        cliCaptureIssue = nil
        if let resolvedIssue, errorMessage == resolvedIssue {
            errorMessage = nil
        }
    }

    @discardableResult
    func setLaunchAtLoginEnabled(_ enabled: Bool) -> Bool {
        guard !configurationMutationLocked else {
            log("Launch at login cannot be changed while configuration cleanup is in progress", blocked: false)
            return false
        }
        let complete = Self.setLaunchAtLogin(enabled, protectionActive: protectionActive)
        if complete { clearSuccessfulConfigurationCleanupNotice() }
        return complete
    }

    func clearSuccessfulConfigurationCleanupNotice() {
        if configurationCleanupNotice?.kind == .success {
            configurationCleanupNotice = nil
        }
    }

    func clearLogs() { logs.removeAll() }

    static let launchAtLoginKey = "launchAtLogin"

    /// Keep the UI preference and the Service Management registration in
    /// lockstep. Removal/reset call this directly rather than merely clearing
    /// the preference, because a registered login item survives that change.
    @discardableResult
    static func setLaunchAtLogin(
        _ enabled: Bool,
        protectionActive: Bool? = nil
    ) -> Bool {
        let active = protectionActive ?? Self.effectiveProtectionEnabled
        guard enabled || !managedContinuityLocked(protectionActive: active) else {
            UserDefaults.standard.set(true, forKey: launchAtLoginKey)
            return false
        }
        let previous = UserDefaults.standard.object(forKey: launchAtLoginKey)
        if !enabled, launchAtLoginRegistrationIsAbsent(SMAppService.mainApp.status) {
            UserDefaults.standard.set(false, forKey: launchAtLoginKey)
            return true
        }
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
            if !enabled,
               !launchAtLoginRegistrationIsAbsent(SMAppService.mainApp.status)
            {
                if let previous { UserDefaults.standard.set(previous, forKey: launchAtLoginKey) }
                else { UserDefaults.standard.removeObject(forKey: launchAtLoginKey) }
                return false
            }
            UserDefaults.standard.set(enabled, forKey: launchAtLoginKey)
        } catch {
            if let previous { UserDefaults.standard.set(previous, forKey: launchAtLoginKey) }
            else { UserDefaults.standard.removeObject(forKey: launchAtLoginKey) }
            return false
        }
        return true
    }

    static func launchAtLoginRegistrationIsAbsent(_ status: SMAppService.Status) -> Bool {
        switch status {
        case .notRegistered, .notFound:
            true
        case .enabled, .requiresApproval:
            false
        @unknown default:
            false
        }
    }

    static func managedContinuityLocked(
        preventDisable: Bool = ManagedConfig.preventDisable,
        protectionActive: Bool
    ) -> Bool {
        preventDisable && protectionActive
    }

    private func enforceManagedContinuityControlsIfNeeded() {
        guard Self.managedContinuityLocked(protectionActive: protectionActive) else { return }
        UserDefaults.standard.set(true, forKey: ShellEnvInjector.autoConfigureKey)
        _ = Self.setLaunchAtLogin(true, protectionActive: true)
    }

    // MARK: - Crash Recovery

    private func registerCleanupHandlers() {
        // The SwiftPM test host constructs several ProxyManagers and is not
        // an application whose process-level signal handlers we may own.
        guard Self.isRunningInPackagedApp else { return }

        // Route SIGTERM through the normal AppKit lifecycle. The previous C
        // signal callback launched processes and touched Foundation/file APIs,
        // none of which are async-signal-safe and could deadlock precisely
        // during crash recovery. AppDelegate can now perform the same relay
        // handoff as a menu-bar quit before the atexit cleanup runs.
        signal(SIGTERM, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
        source.setEventHandler {
            NSApplication.shared.terminate(nil)
        }
        source.resume()
        terminationSignalSource = source

        // Same cleanup on normal exit (menubar Quit, ⌘Q, etc.).
        atexit {
            ShellEnvInjector.unsetLaunchctl(gatewayPort: ProxyManager.liveGatewayPort)
            // Drop the status snapshot so readers fail fast.
            try? FileManager.default.removeItem(at: BouclierPaths.statusFile)
        }
    }

    // MARK: - Private

    /// Drive the stats counters, the in-memory log feed, and the
    /// audit-table writes for a single completed request. Internal
    /// rather than private so the wiring test in
    /// `ProxyManagerLifecycleTests` can exercise it without standing
    /// up a full proxy + upstream.
    func handleRequestLog(_ requestLog: RequestLog) {
        let coveragePolicyRefusal = requestLog.detected
            && requestLog.scanSkippedReason == .unsupportedContentEncoding
        if requestLog.inspectionPerformed {
            stats.requestsScanned += 1
        } else {
            stats.requestsSkippedInspection += 1
        }

        if requestLog.detected {
            // `detected` is only ever set by the gateway's refusal path:
            // this request WAS refused. Unsupported Content-Encoding is a
            // coverage-policy refusal with no verdict; otherwise the signal
            // was a named pattern or fused ML/entropy. Oversized sampled
            // positives clear their skip reason in the gateway and arrive as
            // ordinary detector blocks; clean/inconclusive samples forward.
            // (An earlier
            // version of this branch treated matchCount == 0 as a
            // forwarded "flag" — true under the pre-gateway wiring, but
            // after enforcement moved into `forwardUpstream` it mislabeled
            // real blocks: no feed entry marked blocked, no notification,
            // and an understated SIEM severity.) This is a request-level
            // counter: one refused request is one block, regardless of how
            // many overlapping detector patterns explained that decision.
            if coveragePolicyRefusal {
                stats.requestsBlockedByInspectionLimit += 1
            } else {
                stats.injectionsBlocked += 1
            }

            let score = String(format: "%.2f", requestLog.fusedScore)
            if requestLog.scanSkippedReason == .unsupportedContentEncoding {
                log(
                    "Blocked encoded request → \(requestLog.targetHost): its compressed body could not be inspected safely; no injection verdict was produced",
                    blocked: true
                )
            } else if requestLog.matchCount > 0 {
                let names = requestLog.patternNames.joined(separator: ", ")
                log(
                    "Blocked \(requestLog.matchCount) injection(s) → \(requestLog.targetHost): \(names) [score \(score)]",
                    blocked: true,
                    fingerprint: requestLog.spanFingerprint
                )
            } else {
                // ML/entropy-only: Prompt Guard 2 or the entropy heuristic
                // pushed the fused score past the block bar with no named
                // pattern. Lower-confidence signal, same enforcement.
                log(
                    "Blocked request → \(requestLog.targetHost): ML/entropy score \(score), no named pattern",
                    blocked: true,
                    fingerprint: requestLog.spanFingerprint
                )
            }

            // One block notification for either signal type — coalesced so a
            // false-positive storm (many tool_results blocked in one session)
            // doesn't fire a banner per block. The individual body is safe
            // metadata only (matched pattern name(s) + JSON locator, never span
            // content — a notification is a broadcast surface a screen-reading
            // agent could re-ingest); the verbatim span stays in the opt-in,
            // local-only block explainer.
            switch blockNotificationCoalescer.onBlock(at: Date().timeIntervalSinceReferenceDate) {
            case .individual:
                if requestLog.scanSkippedReason == .unsupportedContentEncoding {
                    sendBlockNotification(
                        title: "Request Refused — Unsupported Encoding",
                        body: "Compressed request body could not be inspected safely → \(requestLog.targetHost)"
                    )
                } else {
                    sendBlockNotification(
                        body: Self.blockNotificationBody(
                            patternNames: requestLog.patternNames,
                            locator: requestLog.locator,
                            host: requestLog.targetHost
                        ),
                        fingerprint: requestLog.spanFingerprint
                    )
                }
            case .summary(let count):
                sendSummaryNotification(count: count, host: requestLog.targetHost)
            case .suppress:
                break
            }

            // SIEM audit log (os_log + optional webhook). Severity is
            // "high" for both signal types — it describes the action (an
            // enforced refusal), not the confidence; matchCount/patterns let
            // an analyst tell regex-driven from ML-only.
            if coveragePolicyRefusal {
                AuditLogger.shared.logEvent(
                    "injection_inspection_limit_block",
                    detail: "host=\(requestLog.targetHost) reason=\(requestLog.scanSkippedReason?.rawValue ?? "unknown") bytes=\(requestLog.bodySize) verdict=none refused=true"
                )
            } else {
                AuditLogger.shared.logDetection(
                    host: requestLog.targetHost,
                    matchCount: requestLog.matchCount,
                    patterns: requestLog.patternNames,
                    severity: "high",
                    bodySize: requestLog.bodySize
                )
            }
        } else if requestLog.injectionFlagged {
            // Request-level count: one monitored request with several pattern
            // hits is one visible finding event, and is never relabelled as a
            // block. This is the core value proposition of Monitoring mode.
            stats.injectionFindingsFlagged += 1
            let score = String(format: "%.2f", requestLog.fusedScore)
            let signals = requestLog.patternNames.isEmpty
                ? "ML/entropy signal"
                : requestLog.patternNames.joined(separator: ", ")
            log(
                "⚠︎ Injection finding → \(requestLog.targetHost): \(signals) [score \(score)] — allowed for forwarding, not blocked",
                blocked: false
            )
            AuditLogger.shared.logEvent(
                "injection_flagged",
                detail: "host=\(requestLog.targetHost) patterns=\(requestLog.patternNames.sorted().joined(separator: ",")) score=\(score) allowed=true"
            )
        }

        if !requestLog.inspectionPerformed, !requestLog.detected {
            switch requestLog.scanSkippedReason {
            case .oversized:
                log(
                    "⚠︎ Inspection skipped → \(requestLog.targetHost): \(requestLog.bodySize) byte request exceeds the bounded inspection limit; its body was allowed for forwarding unchanged by Bouclier",
                    blocked: false
                )
                AuditLogger.shared.logEvent(
                    "injection_scan_skipped",
                    detail: "host=\(requestLog.targetHost) reason=oversized bytes=\(requestLog.bodySize) allowed=true"
                )
            case .unsupportedContentEncoding:
                log(
                    "⚠︎ Inspection skipped → \(requestLog.targetHost): compressed request bodies are unsupported; its body was allowed for forwarding unchanged by Bouclier",
                    blocked: false
                )
                AuditLogger.shared.logEvent(
                    "injection_scan_skipped",
                    detail: "host=\(requestLog.targetHost) reason=unsupported-content-encoding allowed=true"
                )
            case .engineUnavailable:
                log(
                    "⚠︎ Inspection skipped → \(requestLog.targetHost): detection engine unavailable; its body was allowed for forwarding unchanged by Bouclier",
                    blocked: false
                )
                AuditLogger.shared.logEvent(
                    "injection_scan_skipped",
                    detail: "host=\(requestLog.targetHost) reason=engine-unavailable allowed=true"
                )
            case .protectionDisabled, .none:
                // Passthrough is an explicit user state. Count it accurately
                // in the summary without adding one noisy feed row per call.
                break
            }
        }

        // File-PII findings drive both counters and the audit log.
        // `piiRedacted` counts individual entities (one IBAN inside an
        // image is one) while `mediaBlocked` counts unique attachments
        // (an image with five emails inside is still one strip event).
        if let mm = requestLog.multimodal, !mm.findings.isEmpty {
            let textPIIFindings = mm.findings.filter {
                if case .textPII = $0.category { return true }
                return false
            }
            if !textPIIFindings.isEmpty {
                stats.piiRedacted += textPIIFindings.count
                let types = textPIIFindings.compactMap { f -> String? in
                    if case let .textPII(type) = f.category { return type }
                    return nil
                }.joined(separator: ", ")
                log(
                    "Redacted \(textPIIFindings.count) PII item(s) from attachments → \(requestLog.targetHost): \(types)",
                    blocked: false
                )
            }

            let attachmentsWithFindings = Set(mm.findings.map { $0.imagePath })
            stats.mediaBlocked += attachmentsWithFindings.count
            log(
                "Stripped \(attachmentsWithFindings.count) attachment(s) → \(requestLog.targetHost): \(mm.findings.count) finding(s)",
                blocked: false
            )
        }

        storage?.recordScan(
            source: requestLog.inspectionPerformed
                ? "gateway"
                : "gateway-uninspected-\(requestLog.scanSkippedReason?.rawValue ?? "unknown")",
            targetHost: requestLog.targetHost,
            // An inspection-limit refusal is a policy block with no detector
            // verdict; don't persist it as an injection detection.
            detected: requestLog.detected && !coveragePolicyRefusal,
            matchCount: requestLog.matchCount,
            patternIds: requestLog.patternNames,
            severity: requestLog.detected && !coveragePolicyRefusal ? "high" : nil,
            requestSize: requestLog.bodySize,
            mlScore: requestLog.mlScore,
            entropyAnomaly: requestLog.entropyAnomaly,
            fusedScore: requestLog.fusedScore,
            mlAvailable: requestLog.mlAvailable,
            countAsScanned: requestLog.inspectionPerformed
        )

        // Feed the in-process metrics registry that the diagnostics bundle
        // reports (`metrics` block). Fire-and-forget: metric counters are
        // commutative, so hopping to the actor must never delay the funnel.
        if FeatureFlags.telemetryEnabled {
            let metricsSample = Metrics.sample(for: requestLog)
            Task { await Metrics.shared.record(metricsSample) }
        }

        // Per-entity audit rows for file-PII findings. Stored after
        // the parent scan_logs insert so the cascade FK is satisfied.
        // Batched into one SQLite transaction. Type + hash prefix only;
        // cleartext never reaches the database. Offsets are 0/0 because
        // they were defined relative to a request-body byte range — for
        // file PII (OCR'd from an image / PDF / audio transcript), no
        // such body offset exists.
        if let mm = requestLog.multimodal {
            let rows: [StorageManager.PIIRedactionRow] = mm.findings.compactMap { finding in
                guard case let .textPII(type) = finding.category else { return nil }
                return StorageManager.PIIRedactionRow(
                    targetHost: requestLog.targetHost,
                    entityType: type,
                    startOffset: 0,
                    endOffset: 0,
                    valueHashPrefix: PIIHash.prefix(of: finding.cleartextValue),
                    scanLogId: nil
                )
            }
            if !rows.isEmpty {
                storage?.recordPIIRedactions(rows)
            }
        }
    }

    /// Surface output-side injected-action findings. Monitor-only: these
    /// are never blocked (the response relay is byte-faithful), so they are
    /// logged as warnings, not blocks, and don't touch the block counter —
    /// the same honesty rule the flag/block split follows.
    func handleResponseActions(_ findings: [ResponseActionInspector.Finding]) {
        for f in findings {
            let cats = f.categories.joined(separator: ", ")
            let tool = f.toolName.isEmpty ? "(unnamed tool)" : f.toolName
            if f.trifecta {
                stats.actionsFlagged += 1
                log("⚠︎ Injected action: \(tool) tried \(cats) right after untrusted input — monitor only, not blocked", blocked: false)
            } else {
                log("Outbound action flagged: \(tool) → \(cats) (no untrusted input in request) — monitor only", blocked: false)
            }
            AuditLogger.shared.logEvent(
                "response_action",
                detail: "tool=\(tool) categories=\(cats) trifecta=\(f.trifecta) patterns=\(f.patternNames.sorted().joined(separator: ","))"
            )
        }
    }

    private func log(_ message: String, blocked: Bool, fingerprint: String? = nil) {
        let entry = LogEntry(message: message, blocked: blocked, spanFingerprint: fingerprint)
        logs.insert(entry, at: 0)
        if logs.count > 500 { logs.removeLast(logs.count - 500) }
    }

    /// Release a blocked span: add its fingerprint to the allowlist so the
    /// gateway forwards future requests carrying it. The escape hatch for a
    /// false positive that would otherwise block an agent session on every
    /// resume. Re-arm from Settings. No-op for a nil/empty fingerprint
    /// (e.g. a principal-strict block, which carries none).
    func allowlistSpan(_ fingerprint: String?) {
        guard let fingerprint, !fingerprint.isEmpty else { return }
        SpanAllowlist.add(fingerprint)
        log("Released a flagged span — future requests carrying it are forwarded. Re-arm in Settings ▸ Allowlist.", blocked: false)
    }

    /// Count of released spans, for the Settings allowlist control.
    var allowlistedSpanCount: Int { SpanAllowlist.all().count }

    /// Re-arm every released span.
    func clearAllowlist() {
        SpanAllowlist.clear()
        log("Re-armed all released spans — the detector will block them again.", blocked: false)
    }

    /// Build the block-notification body from **safe metadata only** — the
    /// matched pattern name(s) and the JSON locator — never the adversarial
    /// span content, which stays in the opt-in, local-only block explainer.
    /// The signature takes no span text, so it structurally *cannot* leak
    /// content onto a broadcast surface a screen-reading agent could
    /// re-ingest. `nonisolated static` so it is a pure unit under test. An
    /// empty `patternNames` (an ML/entropy-only block, no named pattern)
    /// yields the generic "Suspicious content" phrasing; pattern names are
    /// shown two at a time with a "+N more" tail so the banner can't run long.
    nonisolated static func blockNotificationBody(
        patternNames: [String], locator: String?, host: String
    ) -> String {
        let where_ = locator ?? "tool output"
        let shown = patternNames.sorted().prefix(2).joined(separator: ", ")
        guard !shown.isEmpty else {
            return "Suspicious content in \(where_) → \(host)"
        }
        let extra = patternNames.count > 2 ? " +\(patternNames.count - 2) more" : ""
        return "\(shown)\(extra) in \(where_) → \(host)"
    }

    /// Held for the app's lifetime so a report window survives the menu-bar
    /// popover closing under it, and a notification-triggered report can
    /// raise it from any state.
    private let reportPresenter = ReportPresenter()

    /// App version string for the report payload (CFBundleShortVersionString).
    static var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
    }

    /// Report a blocked span as a false positive. Looks up the captured
    /// `BlockSample` by fingerprint, redacts it, and presents the review-and-
    /// confirm window (nothing is sent until the operator clicks Send there).
    /// A report *requires* a captured sample — the redacted excerpt is the
    /// whole point, and the intake rejects a report without it — so when
    /// capture was off for this block we explain that instead of sending
    /// something empty.
    func reportFalsePositive(fingerprint: String?) {
        guard let fingerprint, !fingerprint.isEmpty else {
            presentNoSampleNotice()
            return
        }
        // Look up + redact off the main actor: redaction runs the full PII
        // scan (incl. the CoreML tier) over adversarial content, which must
        // not block the UI. Presenting hops back to the main actor.
        Task {
            guard let sample = BlockSampleStore.find(byFingerprint: fingerprint) else {
                presentNoSampleNotice()
                return
            }
            let draft = await FalsePositiveReporter.draft(from: sample, appVersion: Self.appVersion)
            reportPresenter.present(draft) { note in
                await FalsePositiveReporter.send(draft: draft, note: note)
            }
        }
    }

    /// Explain that a report needs the block to have been captured. There is
    /// nothing to send retroactively, but future blocks become reportable
    /// once the operator turns capture on.
    private func presentNoSampleNotice() {
        let alert = NSAlert()
        alert.messageText = "Nothing captured for this block"
        alert.informativeText = "Reporting a false positive sends the flagged content so we can tune the detector — but that content is only kept when \u{201C}Capture blocked content for tuning\u{201D} is on (Settings ▸ Diagnostics, off by default). Turn it on, and the next time this is blocked you can report it."
        alert.addButton(withTitle: "OK")
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    private func sendBlockNotification(
        title: String = "Injection Blocked",
        body: String,
        fingerprint: String? = nil
    ) {
        guard UserDefaults.standard.object(forKey: "showNotifications") as? Bool ?? true else { return }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        // Default to quiet when the user hasn't made a choice —
        // notification sounds on every blocked request get noisy fast on
        // heavy AI workflows. SettingsView's @AppStorage mirrors the
        // same default so the Settings toggle renders consistently.
        let quiet = UserDefaults.standard.object(forKey: "quietMode") as? Bool ?? true
        content.sound = quiet ? nil : .default
        // Attach the "Release this span" action only when we have a
        // fingerprint to release — a one-tap recovery from a false positive
        // straight off the notification, without opening the app.
        if let fingerprint, !fingerprint.isEmpty {
            content.categoryIdentifier = NotificationActionHandler.blockCategoryID
            content.userInfo = ["spanFingerprint": fingerprint]
        }
        let request = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    /// A coalesced banner for a burst of blocks, shown instead of a per-block
    /// banner once the coalescer trips. Fixed identifier so a repeated summary
    /// replaces the previous one rather than stacking. No per-span action: it
    /// stands for several spans; the details live in the activity log and the
    /// opt-in block explainer.
    private func sendSummaryNotification(count: Int, host: String) {
        guard UserDefaults.standard.object(forKey: "showNotifications") as? Bool ?? true else { return }
        let content = UNMutableNotificationContent()
        content.title = "Requests Refused"
        content.body = "Bouclier refused \(count) requests in the last minute → \(host)"
        let quiet = UserDefaults.standard.object(forKey: "quietMode") as? Bool ?? true
        content.sound = quiet ? nil : .default
        let request = UNNotificationRequest(identifier: "injection_block_summary", content: content, trigger: nil)
        UNUserNotificationCenter.current().add(request)
    }

    private static func friendlyError(_ error: Error) -> String {
        let desc = "\(error)"
        if desc.contains("Address already in use") || desc.contains("bind") {
            return "Port is already in use. Change the port in Settings or close the other app."
        }
        if desc.contains("Permission denied") {
            return "Permission denied. Ports below 1024 require admin privileges."
        }
        return desc
    }
}

struct ProxyStats {
    var requestsScanned: Int = 0
    var injectionsBlocked: Int = 0
    /// Oversized requests refused by Blocking's coverage policy. Kept
    /// separate because no injection verdict was produced.
    var requestsBlockedByInspectionLimit: Int = 0
    /// Request-level monitored injection findings that were forwarded.
    var injectionFindingsFlagged: Int = 0
    /// Requests relayed or policy-refused without running the detector.
    var requestsSkippedInspection: Int = 0
    /// Cumulative count of PII entities (emails, IBANs, NHS numbers,
    /// etc.) detected inside outbound *attachments* — images, PDFs,
    /// audio. Text prompts are never modified, so this counter only
    /// ever reflects the file-inspection path.
    var piiRedacted: Int = 0
    /// Cumulative count of attachments (images, PDFs, audio) that
    /// were inspected and stripped of PII before forwarding.
    var mediaBlocked: Int = 0
    /// Cumulative count of injected outbound actions observed on the
    /// response leg (trifecta completions). Monitor-only — these were not
    /// blocked, so they are counted separately from `injectionsBlocked`.
    var actionsFlagged: Int = 0
    mutating func reset() {
        requestsScanned = 0
        injectionsBlocked = 0
        requestsBlockedByInspectionLimit = 0
        injectionFindingsFlagged = 0
        requestsSkippedInspection = 0
        piiRedacted = 0
        mediaBlocked = 0
        actionsFlagged = 0
    }
}

struct LogEntry: Identifiable {
    let id = UUID()
    let timestamp = Date()
    let message: String
    let blocked: Bool
    /// Set on a block entry whose span can be released via the allowlist;
    /// the activity row shows an "Unblock" affordance targeting this span.
    /// Nil for non-block entries and blocks with no fingerprint.
    let spanFingerprint: String?
}
