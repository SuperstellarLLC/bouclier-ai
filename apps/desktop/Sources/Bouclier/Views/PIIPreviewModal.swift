import SwiftUI

/// Modal that previews what PII would be redacted before a prompt
/// is forwarded to the LLM.
///
/// PII redaction happens at the TLS proxy layer, so the user's app
/// (Cursor, Claude Desktop, ChatGPT, …) never knows we're substituting
/// tokens. For the first N prompts of each session — controlled by
/// the `piiPreviewBeforeSend` preference — this modal surfaces *what
/// we would redact* without exposing the cleartext to anyone else.
/// Send forwards the request, Cancel aborts it, "Don't ask again"
/// suppresses the modal for the rest of the day.
///
/// The modal does not leave the device, does not log cleartext, and
/// renders its before/after locally from the original prompt and the
/// minted token map. Everything is dropped when the modal closes.
struct PIIPreviewModal: View {
    /// What the user is about to send.
    let entries: [PreviewEntry]
    /// Called when the user confirms the redaction.
    let onSend: () -> Void
    /// Called when the user aborts (we drop the request — the LLM never
    /// sees the prompt).
    let onCancel: () -> Void
    /// Called when the user opts out for the day.
    let onDisablePreview: () -> Void

    struct PreviewEntry: Identifiable, Sendable {
        let id = UUID()
        let entityType: String
        let cleartext: String
        let token: String
    }

    /// The destination host this prompt is going to. Used by the
    /// per-domain "Don't ask again" so the suppression can be scoped
    /// to api.openai.com without silencing previews for other hosts.
    let targetHost: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Image(systemName: "eye.slash.fill")
                    .foregroundStyle(.purple)
                    .font(.title2)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Keeping \(entries.count) item\(entries.count == 1 ? "" : "s") of PII out of this prompt")
                        .font(.title3.bold())
                    if let host = targetHost {
                        Text("Outbound to \(host)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }

            Text("These values will be replaced with placeholders before the prompt leaves your Mac. The model's reply is reversed locally so you read normal text — the cleartext is never seen by the AI provider.")
                .font(.callout)
                .foregroundStyle(.secondary)

            Divider()

            ScrollView {
                VStack(spacing: 8) {
                    ForEach(entries) { entry in
                        PreviewRow(entry: entry)
                    }
                }
                .padding(.vertical, 4)
            }
            .frame(minHeight: 120, maxHeight: 240)

            Divider()

            HStack {
                Button(targetHost.map { "Don't ask again for \($0)" } ?? "Don't ask again") {
                    onDisablePreview()
                }
                .controlSize(.regular)

                Spacer()

                Button("Cancel", role: .cancel) {
                    onCancel()
                }
                .keyboardShortcut(.cancelAction)

                Button("Send with redactions") {
                    onSend()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 540)
    }
}

private struct PreviewRow: View {
    let entry: PIIPreviewModal.PreviewEntry

    var body: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(humanLabel(entry.entityType))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(maskedPreview(entry.cleartext))
                    .font(.system(.callout, design: .monospaced))
            }
            Spacer()
            Image(systemName: "arrow.right")
                .font(.caption)
                .foregroundStyle(.tertiary)
            // Show a human-readable placeholder label, not the HMAC hex.
            // The actual minted token (⟦pii:EMAIL:abc12345⟧) is what gets
            // sent over the wire — but to the user we just say "→ [email
            // placeholder]" so the modal reads like an explanation, not
            // a cryptographic artifact.
            Text(humanPlaceholder(entry.entityType))
                .font(.caption)
                .foregroundStyle(.purple)
                .lineLimit(1)
                .frame(maxWidth: 220, alignment: .leading)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
        .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 6))
    }

    private func humanPlaceholder(_ type: String) -> String {
        switch type {
        case "EMAIL": return "→ [email placeholder]"
        case "IBAN": return "→ [IBAN placeholder]"
        case "CREDIT_CARD": return "→ [card placeholder]"
        case "US_SSN": return "→ [SSN placeholder]"
        case "IPV4", "IPV6": return "→ [IP placeholder]"
        case "AWS_ACCESS_KEY": return "→ [AWS key placeholder]"
        case "JWT": return "→ [JWT placeholder]"
        case "FR_SIRET": return "→ [SIRET placeholder]"
        case "FR_SIREN": return "→ [SIREN placeholder]"
        case "FR_NIR": return "→ [NIR placeholder]"
        case "UK_NHS": return "→ [NHS placeholder]"
        case "UK_NINO": return "→ [NINO placeholder]"
        case "UK_POSTCODE": return "→ [postcode placeholder]"
        case "US_NPI": return "→ [NPI placeholder]"
        default: return "→ [placeholder]"
        }
    }

    /// Show enough of the value that the user can recognize it, but
    /// not the entire string — defense-in-depth against shoulder
    /// surfing and screen recordings.
    private func maskedPreview(_ value: String) -> String {
        if value.count <= 6 { return String(repeating: "•", count: value.count) }
        let head = value.prefix(3)
        let tail = value.suffix(3)
        return "\(head)\(String(repeating: "•", count: min(8, value.count - 6)))\(tail)"
    }

    private func humanLabel(_ type: String) -> String {
        switch type {
        case "EMAIL": return "Email"
        case "IBAN": return "IBAN"
        case "CREDIT_CARD": return "Credit card"
        case "US_SSN": return "US SSN"
        case "IPV4": return "IPv4"
        case "IPV6": return "IPv6"
        case "AWS_ACCESS_KEY": return "AWS access key"
        case "JWT": return "JWT"
        case "FR_SIRET": return "French SIRET"
        case "FR_SIREN": return "French SIREN"
        case "FR_NIR": return "French NIR"
        case "UK_NHS": return "UK NHS number"
        case "UK_NINO": return "UK NINO"
        case "UK_POSTCODE": return "UK postcode"
        case "US_NPI": return "US NPI"
        default: return type
        }
    }
}
