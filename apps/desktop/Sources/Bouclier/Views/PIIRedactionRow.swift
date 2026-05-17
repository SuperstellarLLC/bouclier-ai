import SwiftUI

/// Compact PII redaction control row in the menu bar.
///
/// Three visual states:
/// - **Off** (feature flag disabled): says "Strip PII: off — tap to enable"
///   and links to the Settings → Privacy tab.
/// - **Active**: small purple badge with the pause menu.
/// - **Paused**: amber badge with countdown + Resume button.
///
/// This is the operator's panic surface — the consultant's review
/// called out that an operator who hits a false positive mid-demo
/// currently has to dig through three Settings tabs to disable. The
/// pause button collapses that to one click.
struct PIIRedactionRow: View {
    @ObservedObject var proxyManager: ProxyManager
    @Environment(\.openSettings) private var openSettings

    @AppStorage("piiRedactionEnabled") private var piiRedactionEnabled: Bool = false
    @AppStorage(RedactionPause.pausedUntilKey) private var pausedUntilRaw: Double = 0

    /// Tick the SwiftUI subtree every second while a pause is active
    /// so the remaining-seconds label stays current without forcing
    /// the whole menu to redraw.
    @State private var now: Date = Date()
    private let tick = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        Group {
            if !piiRedactionEnabled {
                disabledRow
            } else if let until = RedactionPause.pausedUntil(now: now) {
                pausedRow(until: until)
            } else {
                activeRow
            }
        }
        .onReceive(tick) { now = $0 }
    }

    // MARK: - States

    private var disabledRow: some View {
        Button(action: openPrivacyTab) {
            HStack(spacing: 6) {
                Image(systemName: "eye.slash")
                    .foregroundStyle(.secondary)
                    .font(.caption)
                Text("Strip PII: off")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer()
                Text("Enable")
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(.purple)
            }
            .padding(8)
            .background(Color.secondary.opacity(0.06))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
        .help("Open Privacy settings to enable PII redaction.")
    }

    private var activeRow: some View {
        Menu {
            ForEach(RedactionPause.presets, id: \.label) { preset in
                Button("Pause for \(preset.label)") {
                    RedactionPause.pause(for: preset.seconds)
                }
            }
            Divider()
            Button("Open Privacy settings…", action: openPrivacyTab)
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "eye.slash.fill")
                    .foregroundStyle(.purple)
                    .font(.caption)
                Text("Stripping PII before send")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer()
                Image(systemName: "pause.circle")
                    .foregroundStyle(.tertiary)
                    .font(.caption)
            }
            .padding(8)
            .background(Color.purple.opacity(0.08))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .menuStyle(.button)
        .menuIndicator(.hidden)
        .help("PII redaction is active. Click to pause if a redaction breaks an agent loop.")
    }

    private func pausedRow(until: Date) -> some View {
        let remaining = RedactionPause.secondsRemaining(now: now)
        return Button(action: { RedactionPause.resume() }) {
            HStack(spacing: 6) {
                Image(systemName: "pause.fill")
                    .foregroundStyle(.orange)
                    .font(.caption)
                Text(remaining > 60
                    ? "PII paused — \(remaining / 60)m \(remaining % 60)s left"
                    : "PII paused — \(remaining)s left")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                Spacer()
                Text("Resume")
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(.orange)
            }
            .padding(8)
            .background(Color.orange.opacity(0.08))
            .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
        .help("Resume PII redaction now.")
        .accessibilityHint("Currently paused until \(until.formatted(date: .omitted, time: .standard))")
    }

    private func openPrivacyTab() {
        NSApp.activate(ignoringOtherApps: true)
        openSettings()
    }
}
