import SwiftUI

/// One-time "what's new" sheet shown the first time the app launches
/// on a freshly-installed version. Triggered by comparing the bundle
/// `CFBundleShortVersionString` against a UserDefaults watermark; on
/// mismatch the sheet appears once and the watermark advances.
///
/// This release makes the prompt-injection firewall the whole product:
/// the "secret keeper" (managed-credential scrub/restore) has been
/// removed, and the firewall now defaults to monitor mode so it can't
/// break normal agent work on a false positive.
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
                    Text("One job, done well: the injection firewall.")
                        .font(.title3.bold())
                    Text("New in Bouclier.ai v\(version)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 10) {
                bullet(
                    icon: "shield.lefthalf.filled",
                    text: "Bouclier is now a focused prompt-injection firewall. Every request is inspected on-device for injection hidden in untrusted tool output, and forwarded byte-for-byte or refused — never rewritten."
                )
                bullet(
                    icon: "eye",
                    text: "Monitor by default. Out of the box the gateway inspects and logs but forwards everything, so a false positive can't break your agent. Turn on blocking when you want refusals (per install or via MDM)."
                )
                bullet(
                    icon: "key.slash",
                    text: "The secret keeper has been removed. Its scrub/restore path and the agent secret-request flow are gone; the gateway no longer touches credentials. Keep your keys where your tools already read them."
                )
                bullet(
                    icon: "cpu",
                    text: "The on-device ML tier (Meta Prompt Guard 2) runs alongside the 161 detection patterns — fully local, nothing leaves your machine to be classified."
                )
            }

            Divider()

            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .font(.caption)
                Text("Prototype software. Detection is best-effort — false positives and false negatives will occur. Not for production or regulated workloads.")
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
