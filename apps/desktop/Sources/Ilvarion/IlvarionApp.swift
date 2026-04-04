import SwiftUI
import UserNotifications

@main
struct IlvarionApp: App {
    @StateObject private var proxyManager = ProxyManager()

    init() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
    }

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(proxyManager: proxyManager)
                .onAppear {
                    proxyManager.initializeStorage()
                }
        } label: {
            Image(systemName: proxyManager.isRunning ? "shield.checkered" : "shield.slash")
                .symbolRenderingMode(.hierarchical)
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView(proxyManager: proxyManager)
        }

        Window("Welcome to Ilvarion", id: "onboarding") {
            OnboardingView(proxyManager: proxyManager)
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)
    }
}
