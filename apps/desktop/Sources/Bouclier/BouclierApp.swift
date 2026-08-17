import AppKit
import SwiftUI
import UserNotifications

/// Process entry point. Before the SwiftUI app spins up, check for the
/// headless `--relay <port>` mode: when the app hands the loopback port to
/// a transient passthrough relay on quit, it re-spawns *this same binary*
/// with that flag, and we run the relay instead of the menu-bar UI. See
/// `RelaySupport` for the full lifecycle (and why there's no daemon).
@main
enum AppEntry {
    static func main() {
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--relay"), i + 1 < args.count, let port = Int(args[i + 1]) {
            RelayMode.run(port: port) // never returns
        }
        BouclierApp.main()
    }
}

/// Cleans up the transient passthrough relay boundary at the two moments
/// it matters: hand the port off on quit, and (via `ProxyManager`) reclaim
/// it on launch.
final class AppDelegate: NSObject, NSApplicationDelegate {
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
    @Environment(\.openWindow) private var openWindow

    init() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
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
            Image(systemName: proxyManager.isRunning ? "shield.checkered" : "shield.slash")
                .symbolRenderingMode(.hierarchical)
                .accessibilityLabel(proxyManager.isRunning ? "Bouclier.ai — protection active" : "Bouclier.ai — protection inactive")
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
}
