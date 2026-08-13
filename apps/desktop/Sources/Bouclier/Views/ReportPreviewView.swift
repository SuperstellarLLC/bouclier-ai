import AppKit
import SwiftUI

/// Review-and-confirm sheet for a false-positive report. Shows the operator
/// the *exact* JSON that will be sent (it updates live as they type a note),
/// with an explicit reminder that secrets/PII are auto-scrubbed and nothing
/// leaves the Mac until they click Send. This "see the bytes, then confirm"
/// step is the real privacy guarantee behind the report feature.
struct ReportPreviewView: View {
    let draft: FalsePositiveDraft
    /// Returns true on a successful send. Receives the operator's note.
    let onSend: (String) async -> Bool
    let onClose: () -> Void

    @State private var note = ""
    @State private var status: Status = .idle

    private enum Status: Equatable { case idle, sending, sent, failed }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Report false positive")
                    .font(.headline)
                Text("If this content was blocked by mistake, send it to us so we can tune the detector. It never leaves your Mac until you click Send.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Add context (optional)")
                    .font(.caption).foregroundStyle(.secondary)
                TextField(
                    "e.g. \u{201C}this is a lint diff, not an attack\u{201D}",
                    // Cap at the server's note limit so a large paste can't
                    // jank the live preview or be silently truncated on send.
                    text: Binding(get: { note }, set: { note = String($0.prefix(1000)) }),
                    axis: .vertical
                )
                .textFieldStyle(.roundedBorder)
                .lineLimit(1 ... 3)
                .disabled(status == .sending || status == .sent)
            }

            HStack(spacing: 6) {
                Image(systemName: "eye")
                    .font(.caption).foregroundStyle(.secondary)
                Text("Exactly this will be sent to bouclier.ai — secrets and PII already scrubbed:")
                    .font(.caption).foregroundStyle(.secondary)
            }

            ScrollView {
                Text(FalsePositiveReporter.previewJSON(for: draft, note: note))
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .frame(minHeight: 220, maxHeight: 340)
            .background(Color(nsColor: .textBackgroundColor))
            .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.quaternary))
            .clipShape(RoundedRectangle(cornerRadius: 6))

            statusLine

            HStack {
                Text("No IP address, account, or identifier is attached.")
                    .font(.caption2).foregroundStyle(.tertiary)
                Spacer()
                Button("Cancel", action: onClose)
                    .keyboardShortcut(.cancelAction)
                Button(status == .failed ? "Retry send" : "Send report") { send() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(status == .sending || status == .sent)
            }
        }
        .padding(16)
        .frame(width: 520)
    }

    @ViewBuilder private var statusLine: some View {
        switch status {
        case .idle:
            EmptyView()
        case .sending:
            Label("Sending…", systemImage: "arrow.up.circle")
                .font(.caption).foregroundStyle(.secondary)
        case .sent:
            Label("Thanks — report sent.", systemImage: "checkmark.circle.fill")
                .font(.caption).foregroundStyle(.green)
        case .failed:
            Label("Couldn't reach bouclier.ai. Nothing was sent — try again.", systemImage: "exclamationmark.triangle.fill")
                .font(.caption).foregroundStyle(.orange)
        }
    }

    private func send() {
        status = .sending
        Task {
            let ok = await onSend(note)
            status = ok ? .sent : .failed
            if ok {
                try? await Task.sleep(for: .seconds(1))
                onClose()
            }
        }
    }
}

/// Presents `ReportPreviewView` in a standalone window. AppKit-backed (not a
/// SwiftUI `Window` scene) so it can be raised from *any* context — including
/// a notification action fired while the menu-bar popover is closed — without
/// depending on a live SwiftUI scene to bridge `openWindow`.
@MainActor
final class ReportPresenter {
    private var window: NSWindow?

    func present(_ draft: FalsePositiveDraft, onSend: @escaping (String) async -> Bool) {
        close() // one report window at a time

        let root = ReportPreviewView(
            draft: draft,
            onSend: onSend,
            onClose: { [weak self] in self?.close() }
        )
        let hosting = NSHostingController(rootView: root)
        let win = NSWindow(contentViewController: hosting)
        win.title = "Report false positive"
        win.styleMask = [.titled, .closable]
        win.isReleasedWhenClosed = false
        win.center()
        window = win

        NSApp.activate(ignoringOtherApps: true)
        win.makeKeyAndOrderFront(nil)
    }

    func close() {
        window?.close()
        window = nil
    }
}
