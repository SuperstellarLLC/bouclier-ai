import SwiftUI

/// One-time "what's new" sheet shown the first time the app launches
/// on a freshly-installed version. Triggered by comparing the bundle
/// `CFBundleShortVersionString` against a UserDefaults watermark; on
/// mismatch the sheet appears once and the watermark advances.
///
/// v0.6 changed Bouclier's scope: text prompts are no longer modified
/// (the placeholder shape was tripping upstream abuse detectors and
/// the JSON-blind rewriter risked touching `user` / `metadata` /
/// auth fields). This sheet is what tells a returning user the
/// previous text-PII feature is gone and what stayed.
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
                    Text("Cleaner scope, safer defaults.")
                        .font(.title3.bold())
                    Text("New in Bouclier.ai v\(version)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            VStack(alignment: .leading, spacing: 10) {
                bullet(
                    icon: "text.alignleft",
                    text: "Your text prompts now reach the LLM unchanged. Bouclier no longer rewrites prompt bodies — the placeholder approach was tripping upstream abuse detectors and risked touching auth / analytics fields inside JSON requests."
                )
                bullet(
                    icon: "paperclip",
                    text: "PII protection now focuses on attachments. Images, PDFs, and short audio clips still get scanned on-device; flagged attachments are replaced with a plain-English description so the model can still answer."
                )
                bullet(
                    icon: "shield.checkered",
                    text: "Prompt-injection detection is unchanged — outbound prompts are still scanned and blocked when they match an attack pattern."
                )
                bullet(
                    icon: "key.fill",
                    text: "Auth headers, x-api-key, custom trace IDs, user-agent — all forwarded byte-for-byte. Pinned by a regression test so a future change can't drift."
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
