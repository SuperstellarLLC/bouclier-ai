import SwiftUI
import UserNotifications

@main
struct BouclierApp: App {
    @StateObject private var proxyManager = ProxyManager()
    @StateObject private var updater = AutoUpdater()

    init() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(proxyManager: proxyManager, updater: updater)
                .onAppear {
                    proxyManager.initializeStorage()
                }
        } label: {
            Image(systemName: proxyManager.isRunning ? "shield.checkered" : "shield.slash")
                .symbolRenderingMode(.hierarchical)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(proxyManager: proxyManager, updater: updater)
        }

        Window("Welcome to Bouclier", id: "onboarding") {
            OnboardingView(proxyManager: proxyManager)
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)
    }
}
