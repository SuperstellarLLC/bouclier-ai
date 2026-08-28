import AppKit
import SwiftUI

/// Process entry point. Before the SwiftUI app spins up, check for the
/// headless `--relay <port> <token>` mode: when the app hands the loopback port to
/// a transient passthrough relay on quit, it re-spawns *this same binary*
/// with that flag, and we run the relay instead of the menu-bar UI. See
/// `RelaySupport` for the full lifecycle (and why there's no daemon).
@main
enum AppEntry {
    static func main() {
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--relay"), i + 1 < args.count,
           let port = Int(args[i + 1]), (1...65535).contains(port),
           let tokenIndex = args.firstIndex(of: "--relay-token"), tokenIndex + 1 < args.count,
           UUID(uuidString: args[tokenIndex + 1]) != nil {
            RelayMode.run(port: port, token: args[tokenIndex + 1].lowercased()) // never returns
        }
        BouclierApp.main()
    }
}

/// Cleans up the transient passthrough relay boundary at the two moments
/// it matters: hand the port off on quit, and (via `ProxyManager`) reclaim
/// it on launch.
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// Enforce the managed quit lock at AppKit's process boundary. Disabling
    /// the visible menu item alone would still leave Command-Q, SIGTERM, and
    /// other normal termination requests able to bypass the policy.
    ///
    /// This can only veto cooperative AppKit termination. macOS deliberately
    /// offers no in-process way to survive SIGKILL, administrator deletion,
    /// or a crash; fleet policy must monitor and relaunch the app.
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        Self.terminationReply(
            preventDisable: ManagedConfig.preventDisable,
            protectionActive: ProxyManager.effectiveProtectionEnabled
                && ProxyManager.liveGatewayPort != nil
        )
    }

    /// Pure policy seam so lifecycle behavior remains testable without
    /// constructing or terminating the shared NSApplication test host.
    static func terminationReply(
        preventDisable: Bool,
        protectionActive: Bool
    ) -> NSApplication.TerminateReply {
        preventDisable && protectionActive ? .terminateCancel : .terminateNow
    }

    func applicationWillTerminate(_ notification: Notification) {
        // If a gateway is up (protecting or in passthrough), keep the port
        // alive for any running agent session by handing it to a relay.
        // Runs in normal process context, so a plain Process launch is safe.
        if let port = ProxyManager.liveGatewayPort {
            RelaySupport.handOff(port: port)
        }
    }
}

struct BouclierApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var proxyManager = ProxyManager()
    @StateObject private var updater = AutoUpdater()
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @AppStorage("injectionBlockEnabled") private var userBlockingEnabled = false
    @Environment(\.openWindow) private var openWindow

    init() {
        // One-shot scrub of UserDefaults keys orphaned by the v0.6
        // scope cut (pre-v0.6 text-PII toggles, pause TTLs, per-host
        // policy lists). Self-gates on a sentinel so subsequent
        // launches are no-ops.
        LegacyDefaultsCleanup.runIfNeeded()
    }

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(proxyManager: proxyManager, updater: updater)
                .onAppear {
                    proxyManager.initializeStorage()
                    if !hasCompletedOnboarding {
                        openWindow(id: "onboarding")
                    }
                }
        } label: {
            Image(systemName: menuBarIcon)
                .symbolRenderingMode(.hierarchical)
                .accessibilityLabel(menuBarAccessibilityLabel)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(proxyManager: proxyManager, updater: updater)
        }

        Window("Welcome to Bouclier.ai", id: "onboarding") {
            OnboardingView(proxyManager: proxyManager)
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)
    }

    private var blockingEnabled: Bool {
        FeatureFlags.managedInjectionBlock ?? userBlockingEnabled
    }

    private var protectionState: DesktopProtectionState {
        .resolve(
            protectionActive: proxyManager.protectionActive,
            gatewayRunning: proxyManager.isRunning,
            detectionEngineDegraded: proxyManager.detectionEngineDegraded
        )
    }

    private var menuBarPresentation: DesktopMenuBarPresentation {
        .resolve(
            state: protectionState,
            blockingEnabled: blockingEnabled,
            errorMessage: proxyManager.errorMessage
        )
    }

    private var menuBarIcon: String {
        menuBarPresentation.iconName
    }

    private var menuBarAccessibilityLabel: String {
        menuBarPresentation.accessibilityLabel
    }
}
