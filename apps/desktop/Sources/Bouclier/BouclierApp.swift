import SwiftUI
import UserNotifications

@main
struct BouclierApp: App {
    @StateObject private var proxyManager = ProxyManager()
    @StateObject private var updater = AutoUpdater()
    @AppStorage("hasCompletedOnboarding") private var hasCompletedOnboarding = false
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings

    init() {
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound]) { _, _ in }
        // Pause TTLs from a previous run should never outlive a fresh
        // launch — clear here so a paused app that was force-quit comes
        // up unpaused. RedactionPause's stale-cleanup runs on read too,
        // but this guarantees the menu bar shows the correct state
        // immediately at launch.
        RedactionPause.resume()
    }

    var body: some Scene {
        MenuBarExtra {
            MenuBarView(proxyManager: proxyManager, updater: updater)
                .onAppear {
                    proxyManager.initializeStorage()
                    if !hasCompletedOnboarding {
                        openWindow(id: "onboarding")
                    } else if ReleaseNotes.shouldShow() {
                        openWindow(id: "release-notes")
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

        Window("What's new", id: "release-notes") {
            ReleaseNotesModal(
                version: ReleaseNotes.currentVersion,
                onOpenPrivacySettings: {
                    NSApp.activate(ignoringOtherApps: true)
                    openSettings()
                },
                onDismiss: {
                    ReleaseNotes.markSeen()
                    NSApp.keyWindow?.close()
                }
            )
        }
        .windowResizability(.contentSize)
        .defaultPosition(.center)
    }
}
