import Combine
import Foundation
import Sparkle
import SwiftUI

/// Manages automatic updates via Sparkle.
@MainActor
final class AutoUpdater: ObservableObject {
    private let updaterController: SPUStandardUpdaterController

    @Published var canCheckForUpdates = false

    init() {
        updaterController = SPUStandardUpdaterController(
            startingUpdater: true,
            updaterDelegate: nil,
            userDriverDelegate: nil
        )
        // Bridge Sparkle's own canCheckForUpdates into the @Published so
        // the menu-bar button enables as soon as Sparkle is ready. Without
        // this KVO mirror the flag stays false forever and the button is
        // permanently disabled.
        updaterController.updater.publisher(for: \.canCheckForUpdates)
            .receive(on: DispatchQueue.main)
            .assign(to: &$canCheckForUpdates)
    }

    func checkForUpdates() {
        updaterController.checkForUpdates(nil)
    }
}
