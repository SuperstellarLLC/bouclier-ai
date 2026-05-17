import SwiftUI

/// One-time "what's new" sheet shown the first time the app launches
/// on a freshly-installed version. Triggered by comparing the bundle
/// CFBundleShortVersionString against a UserDefaults watermark; on
/// mismatch we show the sheet once and update the watermark.
///
/// **Why this exists.** The senior product review flagged that the
/// PII redaction feature ships invisible: off-by-default, buried under
/// a Settings tab, with no discovery moment. Without a release-notes
/// surface, a user upgrades from v0.2.12 to v0.2.13 and is never told
/// the feature exists. This sheet is the discovery surface.
///
/// **Honest copy.** Per the founder's instruction, no superlatives, no
/// "the only", no marketing fluff. State the value directly and flag
/// the prototype caveat in the same breath.
struct ReleaseNotesModal: View {
    let version: String
    let onOpenPrivacySettings: () -> Void
    let onDismiss: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top) {
                Image(systemName: "sparkles")
                    .foregroundStyle(.purple)
                    .font(.title2)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Stop your PII from leaking to LLMs.")
                        .font(.title3.bold())
                    Text("New in Bouclier.ai v\(version)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 10) {
                bullet(
                    icon: "eye.slash.fill",
                    text: "Emails, IBANs, NHS / SIRET / NIR numbers, credit cards, AWS keys, JWTs — replaced with reversible placeholders before the prompt leaves your Mac."
                )
                bullet(
                    icon: "arrow.uturn.backward.circle",
                    text: "The model's response is reversed locally, so you still read normal text."
                )
                bullet(
                    icon: "slider.horizontal.3",
                    text: "Per-domain allow / deny lists let you bypass internal LLM gateways."
                )
                bullet(
                    icon: "pause.circle",
                    text: "One-click pause in the menu bar when a redaction breaks an agent loop."
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
                Button("Open Privacy settings") {
                    onOpenPrivacySettings()
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
