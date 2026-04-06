import SwiftUI
import UserNotifications

@main
struct BouclierApp: App {
    @StateObject private var proxyManager = ProxyManager()
    @StateObject private var updater = AutoUpdater()
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @Environment(\.openWindow) private var openWindow

    init() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
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
