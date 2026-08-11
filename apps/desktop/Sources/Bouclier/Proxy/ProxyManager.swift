import BouclierCore
import Foundation
import NIOCore
import ServiceManagement
import SwiftUI
import UserNotifications

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

    var port: Int {
        let p = UserDefaults.standard.object(forKey: "proxyPort") as? Int ?? 8484
        return (1...65535).contains(p) ? p : 8484
    }

    /// Owns the live prompt-injection engine: loads `patterns.json`,
    /// publishes to `InjectionFilter.active`, hot-reloads, and swaps in
    /// the CoreML classifier if one is present. Held for the app's
    /// lifetime — the registry it feeds is what the gateway reads.
    private var patternManager: PatternManager?

    /// Number of enabled detection patterns currently loaded. Shown in
    /// the menu bar so "protected" is a number, not a vibe.
    var patternCount: Int { InjectionFilter.active.current()?.patternCount ?? 0 }

    /// Whether the on-device ML tier is attached. False in the shipped
    /// DMG — the Prompt Guard 2 weights were unbundled in v0.7.0 and the
    /// engine runs regex-only unless a model is supplied locally.
    var mlTierActive: Bool { InjectionFilter.active.current()?.hasMLClassifier ?? false }

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

    init() {
        protectionActive = Self.protectionEnabled

        // The detection engine is live again as of v0.9.0, this time
        // hanging off the certificate-free gateway rather than the
        // removed extreme mode. PatternManager loads patterns.json,
        // publishes the regex-only filter to `InjectionFilter.active`
        // immediately, watches for hot-reloads, and swaps in the fused
        // engine if the CoreML classifier ever loads. The gateway reads
        // the registry per request; see `InjectionInspectionPass`.
        //
        // `loadPIITier: false` — the Piiranha model has been unbundled
        // since v0.7.0 and nothing calls the PII path.
        patternManager = PatternManager(loadPIITier: false)

        // Register crash cleanup — disable system proxy if we die unexpectedly
        registerCleanupHandlers()

        // Auto-init at construction. The previous design deferred this
        // to MenuBarView.onAppear, but that fires only when the user
        // *opens* the menu — so on launch the shield icon read "off"
        // until the user clicked it, defeating the whole point of the
        // auto-start-when-CA-installed change. Calling it here makes
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
        migrateAwayFromExtremeModeIfNeeded()

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
    private static let extremeModeMigrationKey = "bouclier.extremeModeRemoved.v1"
    private func migrateAwayFromExtremeModeIfNeeded() {
        guard !UserDefaults.standard.bool(forKey: Self.extremeModeMigrationKey) else { return }
        UserDefaults.standard.set(true, forKey: Self.extremeModeMigrationKey)

        let hadCA = ca.isInstalled
        if hadCA {
            ca.uninstallCA()
            caInstalled = false
            _ = SystemProxy.disableAll()
            log("Removed the local CA and system proxy config left by extreme mode, which no longer exists in this version", blocked: false)
        }

        Task {
            await extensionManager.checkStatus()
            guard extensionManager.extensionInstalled else { return }
            await extensionManager.disableProxy()
            extensionManager.removeExtension()
            await MainActor.run {
                self.log("Deactivated the System Extension left by extreme mode, which no longer exists in this version", blocked: false)
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
    static let protectionEnabledKey = "protectionEnabled"
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
    /// uninstall/reset). Distinct from `protectionEnabled` so "protection
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
        UserDefaults.standard.set(true, forKey: Self.protectionEnabledKey)
        UserDefaults.standard.set(true, forKey: Self.envConfiguredKey)
        protectionActive = true
        UserDefaults.standard.set(ProxyMode.standard.rawValue, forKey: ProxyMode.userDefaultsKey)
        if isRunning {
            // Gateway is already bound — safe to re-point the env immediately.
            ShellEnvInjector.applyStandard(gatewayPort: port)
        } else {
            // start() only kicks off the async bind; startStandard() applies
            // the env itself once isRunning flips true, so CLI tools are
            // never pointed at a port before anything is listening on it.
            start()
        }
        log("Standard protection enabled (no CA)", blocked: false)
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
    /// Full teardown remains available via quit / uninstall / reset.
    func disableStandard() {
        UserDefaults.standard.set(false, forKey: Self.protectionEnabledKey)
        protectionActive = false
        if isRunning {
            log("Protection disabled — gateway stays up as allow-all passthrough so active agent sessions keep working", blocked: false)
        } else {
            log("Standard protection disabled", blocked: false)
        }
    }

    /// Build the read-only snapshot the StatusPublisher writes. Counts only —
    /// never request content.
    func statusSnapshot() -> BouclierStatus {
        BouclierStatus(
            writtenAt: Date().timeIntervalSince1970,
            pid: getpid(),
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "—",
            running: isRunning,
            mode: ProxyMode.current.rawValue,
            caInstalled: caInstalled,
            protectionEnabled: UserDefaults.standard.bool(forKey: Self.protectionEnabledKey),
            activity: .init(requestsScanned: stats.requestsScanned,
                            injectionsBlocked: stats.injectionsBlocked))
    }

    static func emptyStatus() -> BouclierStatus {
        BouclierStatus(
            writtenAt: Date().timeIntervalSince1970, pid: getpid(), appVersion: "—",
            running: false, mode: ProxyMode.current.rawValue, caInstalled: false, protectionEnabled: false,
            activity: .init(requestsScanned: 0, injectionsBlocked: 0))
    }

    func start() {
        // `isRunning` is only set true asynchronously after bind, so also
        // guard on the server ivar (assigned synchronously by
        // startStandard()) to prevent a second start() — e.g.
        // enableStandard() racing the initializeStorage auto-start — from
        // binding twice and orphaning a channel.
        guard !isRunning, gatewayServer == nil else { return }
        errorMessage = nil
        startStandard()
    }

    /// Standard (non-CA) mode: bind the base-URL gateway. No CA, no PAC,
    /// no system extension — the agent reaches us via `ANTHROPIC_BASE_URL`.
    private func startStandard() {
        let boundPort = port
        // Captured outside the closure: the static key lives on a
        // @MainActor type and can't be touched from a @Sendable closure.
        let protectionKey = Self.protectionEnabledKey
        let gateway = GatewayServer(
            port: boundPort,
            // Read per request (UserDefaults is thread-safe and cached),
            // so flipping protection on/off takes effect immediately on a
            // *running* gateway — disable degrades to allow-all
            // passthrough instead of tearing the listener down under
            // active agent sessions.
            inspectionEnabled: { UserDefaults.standard.bool(forKey: protectionKey) },
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
                    self.proxyChannel = channel
                    self.isRunning = true
                    // Publish the live port so a quit can hand it off to a
                    // passthrough relay before the listener goes away.
                    Self.liveGatewayPort = boundPort
                    self.log("Gateway (standard mode) listening on 127.0.0.1:\(boundPort)", blocked: false)
                    // Only wire shells/GUI apps to the gateway once the
                    // listener is actually bound and accepting. Applying
                    // this before bind() resolves points CLI tools
                    // (Claude Code, etc.) at a port nothing is listening
                    // on yet — the exact "connection refused at startup"
                    // race this ordering closes.
                    ShellEnvInjector.applyStandard(gatewayPort: boundPort)
                }
            } catch {
                await MainActor.run {
                    self.isRunning = false
                    let msg = Self.friendlyError(error)
                    self.errorMessage = msg
                    self.log("Gateway failed: \(msg)", blocked: true)
                }
            }
        }
    }

    func stop() {
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
        Self.liveGatewayPort = nil
        errorMessage = nil

        // disableAll, not disable: the active interface check only
        // sweeps one service. On a multi-network setup (Wi-Fi + Ethernet,
        // VPN profiles) the stale Bouclier PAC was surviving on the
        // services we didn't touch, then re-biting the user when they
        // swapped networks. Sweeping all services on every quit is the
        // robust fix.
        _ = SystemProxy.disableAll()
        // Drop the launchctl proxy env so processes spawned via `open`
        // / Spotlight don't keep pointing at a port we no longer listen
        // on. The dotfile block stays (fail-open TCP probe handles that
        // case); we only fix the GUI-launch path here.
        ShellEnvInjector.unsetLaunchctl()

        log("Proxy stopped", blocked: false)
    }

    func uninstall() {
        stop()
        UserDefaults.standard.set(false, forKey: Self.protectionEnabledKey)
        UserDefaults.standard.set(false, forKey: Self.envConfiguredKey)
        protectionActive = false
        // Belt-and-suspenders: the one-shot migration already cleans up
        // extreme mode's CA/extension for installs that go through
        // `initializeStorage()`, but a full uninstall should leave zero
        // trace regardless of whether that migration has run yet.
        extensionManager.removeExtension()
        ca.uninstallCA()
        ShellEnvInjector.remove()
        caInstalled = false
        log("Bouclier fully uninstalled", blocked: false)
    }

    /// Nuclear reset for the cases where an unclean shutdown (or a
    /// stale install from an older Bouclier build) leaves the user
    /// unable to reach LLM APIs even with the app quit. Stops the
    /// proxy, sweeps PAC + manual HTTP/HTTPS proxy off every network
    /// service, drops the launchctl session env, removes the watchdog
    /// LaunchAgent, and strips the shell-startup blocks. Protection is
    /// off afterwards — re-enable from the Protection tab.
    func resetAllProxies() {
        if isRunning { stop() }
        UserDefaults.standard.set(false, forKey: Self.protectionEnabledKey)
        UserDefaults.standard.set(false, forKey: Self.envConfiguredKey)
        protectionActive = false
        SystemProxy.disableAll()
        ShellEnvInjector.remove()
        log("All proxy settings reset", blocked: false)
    }

    func clearLogs() { logs.removeAll() }

    static func setLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        } catch {}
    }

    // MARK: - Crash Recovery

    private nonisolated func registerCleanupHandlers() {
        // Disable system proxy AND drop launchctl proxy env on SIGTERM
        // (e.g. force quit from Activity Monitor). Without the env drop,
        // every GUI-launched process spawned after the crash inherits a
        // dead `HTTPS_PROXY=127.0.0.1:8484` pointer.
        signal(SIGTERM) { _ in
            _ = SystemProxy.disableAll()
            ShellEnvInjector.unsetLaunchctl()
            try? FileManager.default.removeItem(at: BouclierPaths.statusFile)
            exit(0)
        }

        // Same cleanup on normal exit (menubar Quit, ⌘Q, etc.).
        atexit {
            _ = SystemProxy.disableAll()
            ShellEnvInjector.unsetLaunchctl()
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
        stats.requestsScanned += 1

        if requestLog.detected {
            // `detected` is only ever set by the gateway's refusal path:
            // this request WAS 403'd, whether the signal was a named
            // pattern or the fused ML/entropy score alone. (An earlier
            // version of this branch treated matchCount == 0 as a
            // forwarded "flag" — true under the pre-gateway wiring, but
            // after enforcement moved into `forwardUpstream` it mislabeled
            // real blocks: no feed entry marked blocked, no notification,
            // and an understated SIEM severity.) Count at least 1 so an
            // ML-only block still moves the menu-bar counter.
            stats.injectionsBlocked += max(1, requestLog.matchCount)

            let score = String(format: "%.2f", requestLog.fusedScore)
            if requestLog.matchCount > 0 {
                let names = requestLog.patternNames.joined(separator: ", ")
                log(
                    "Blocked \(requestLog.matchCount) injection(s) → \(requestLog.targetHost): \(names) [score \(score)]",
                    blocked: true,
                    fingerprint: requestLog.spanFingerprint
                )
                sendBlockNotification(
                    body: "Blocked \(requestLog.matchCount) injection\(requestLog.matchCount > 1 ? "s" : "") → \(requestLog.targetHost)",
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
                sendBlockNotification(
                    body: "Blocked suspicious request → \(requestLog.targetHost)",
                    fingerprint: requestLog.spanFingerprint
                )
            }

            // SIEM audit log (os_log + optional webhook). Severity is
            // "high" for both signal types — it describes the action (an
            // enforced 403), not the confidence; matchCount/patterns let
            // an analyst tell regex-driven from ML-only.
            AuditLogger.shared.logDetection(
                host: requestLog.targetHost,
                matchCount: requestLog.matchCount,
                patterns: requestLog.patternNames,
                severity: "high",
                bodySize: requestLog.bodySize
            )
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
            source: "tls-proxy",
            targetHost: requestLog.targetHost,
            detected: requestLog.detected,
            matchCount: requestLog.matchCount,
            patternIds: requestLog.patternNames,
            severity: requestLog.detected ? "high" : nil,
            requestSize: requestLog.bodySize,
            mlScore: requestLog.mlScore,
            entropyAnomaly: requestLog.entropyAnomaly,
            fusedScore: requestLog.fusedScore,
            mlAvailable: requestLog.mlAvailable
        )

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
    /// false positive that would otherwise 403 an agent session on every
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

    private func sendBlockNotification(body: String, fingerprint: String? = nil) {
        guard UserDefaults.standard.object(forKey: "showNotifications") as? Bool ?? true else { return }
        let content = UNMutableNotificationContent()
        content.title = "Injection Blocked"
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
