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
    static let reportActionID = "report_fp"

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
        // `.foreground` brings the app forward so the review-and-confirm
        // window can be shown — a report is never sent straight off the
        // notification; the operator always sees the payload first.
        let report = UNNotificationAction(
            identifier: reportActionID,
            title: "Report false positive",
            options: [.foreground]
        )
        let category = UNNotificationCategory(
            identifier: blockCategoryID,
            actions: [release, report],
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
        let fingerprint = response.notification.request.content.userInfo["spanFingerprint"] as? String
        switch response.actionIdentifier {
        case Self.releaseActionID:
            Task { @MainActor [weak proxyManager] in
                proxyManager?.allowlistSpan(fingerprint)
            }
        case Self.reportActionID:
            Task { @MainActor [weak proxyManager] in
                proxyManager?.reportFalsePositive(fingerprint: fingerprint)
            }
        default:
            break
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
