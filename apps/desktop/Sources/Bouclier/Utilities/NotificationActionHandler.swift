import Foundation
import UserNotifications

/// Routes the "Release this span" action on a block notification back to
/// the `SpanAllowlist`, so an operator can recover a session a false
/// positive would otherwise block on every resume — without opening the app.
///
/// `NSObject` because `UNUserNotificationCenterDelegate` requires it.
/// `UNUserNotificationCenter.delegate` is a weak reference, so
/// `ProxyManager` holds this instance strongly for the app's lifetime.
final class NotificationActionHandler: NSObject, UNUserNotificationCenterDelegate {
    static let blockCategoryID = "injection_block"
    static let releaseActionID = "release_span"

    private weak var proxyManager: ProxyManager?

    init(proxyManager: ProxyManager) {
        self.proxyManager = proxyManager
        super.init()
    }

    /// Register the block-notification category and its single action.
    /// Called once at startup; setting categories is idempotent.
    static func registerCategories() {
        let release = UNNotificationAction(
            identifier: releaseActionID,
            title: "Release this span",
            options: []
        )
        let category = UNNotificationCategory(
            identifier: blockCategoryID,
            actions: [release],
            intentIdentifiers: [],
            options: []
        )
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        defer { completionHandler() }
        guard response.actionIdentifier == Self.releaseActionID,
              let fingerprint = response.notification.request.content.userInfo["spanFingerprint"] as? String
        else { return }
        Task { @MainActor [weak proxyManager] in
            proxyManager?.allowlistSpan(fingerprint)
        }
    }

    /// Menu-bar app: present block banners even when frontmost, so a block
    /// during active use isn't silently swallowed.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}
