import SwiftUI

/// One-time "what's new" sheet shown the first time the app launches
/// on a freshly-installed version. Triggered by comparing the bundle
/// `CFBundleShortVersionString` against a UserDefaults watermark; on
/// mismatch the sheet appears once and the watermark advances.
///
/// This release removed "extreme mode" (the CA-based TLS-intercepting
/// proxy + System Extension) entirely, which also took the
/// prompt-injection/attachment-PII detection engine with it — that
/// engine had no caller outside extreme mode's proxy path. This sheet
/// is what tells a returning user those features are gone and the
/// secret keeper (the part that was actually load-bearing) is
/// unaffected. See `ProxyManager.migrateAwayFromExtremeModeIfNeeded`
/// for the automatic CA/extension cleanup this same launch performs.
struct ReleaseNotesModal: View {
    let version: String
    let onOpenSettings: () -> Void
    let onDismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top) {
                Image(systemName: "sparkles")
                    .foregroundStyle(.purple)
                    .font(.title2)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Simpler, lighter, no certificate.")
                        .font(.title3.bold())
                    Text("New in Bouclier.ai v\(version)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 10) {
                bullet(
                    icon: "checkmark.shield",
                    text: "Extreme mode is gone. The CA-based \"full interception\" mode — installing a trusted certificate and a System Extension — has been removed. If you had it on, this launch automatically uninstalled the CA and deactivated the extension. The certificate-free gateway is now the only mode."
                )
                bullet(
                    icon: "shield.slash",
                    text: "Prompt-injection and attachment-PII scanning are no longer active. That engine only ever ran through extreme mode's interception path, so it left with it."
                )
                bullet(
                    icon: "key.fill",
                    text: "The secret keeper is unaffected and remains Bouclier's primary protection: managed credentials are still scrubbed before reaching the model and restored in the response."
                )
                bullet(
                    icon: "shippingbox",
                    text: "The app is dramatically smaller — it no longer bundles the on-device ML models that scanning used, since nothing calls them anymore."
                )
            }

            Divider()

            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.caption)
                Text("Prototype software. Secret handling is best-effort — false positives and false negatives will occur. Not for production or regulated workloads.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(8)
            .background(Color.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))

            HStack {
                Button("Read terms") {
                    if let url = URL(string: "https://www.bouclier.ai/terms") {
                        NSWorkspace.shared.open(url)
                    }
                }
                .controlSize(.regular)
                Spacer()
                Button("Later") { onDismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Open Settings") {
                    onOpenSettings()
                    onDismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 480)
    }

    private func bullet(icon: String, text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: icon)
                .foregroundStyle(.purple)
                .font(.caption)
                .frame(width: 14)
            Text(text)
                .font(.callout)
                .foregroundStyle(.primary)
        }
    }
}

/// Bridges the modal's "should I show it now?" decision to the bundle
/// version. Returns the version we should show notes for, or nil if
/// the user has already seen this version's notes.
enum ReleaseNotes {
    private static let seenVersionKey = "releaseNotesSeenVersion"

    /// Current short version from the app bundle. Falls back to a
    /// sentinel so a missing Info.plist doesn't break the check.
    static var currentVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
    }

    /// Should we show the release-notes modal on this launch? True iff
    /// this is the first launch on the current version after install
    /// or update.
    static func shouldShow() -> Bool {
        let current = currentVersion
        let seen = UserDefaults.standard.string(forKey: seenVersionKey)
        return seen != current
    }

    /// Mark the current version's release notes as seen so we don't
    /// show them again until the next upgrade.
    static func markSeen() {
        UserDefaults.standard.set(currentVersion, forKey: seenVersionKey)
    }
}
