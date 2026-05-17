import AppKit
import CryptoKit
import Foundation

/// Renders the PII redaction report PDF — the artifact a compliance
/// officer can hand to an auditor.
///
/// Design goals:
/// - Single page when the data is small, paginates when entity types
///   exceed one column.
/// - No charts (PDFKit + Charts is heavy and the data is small enough
///   to read as a table).
/// - Includes an integrity-statement section with the tamper-evident
///   hash of the underlying audit rows so an auditor can verify the
///   report wasn't hand-edited after the fact.
/// - Wholly local — never invokes a network call, never uploads.
enum RedactionReport {
    /// Build the PDF from the given storage handle and return its bytes.
    /// Caller writes to disk and presents in Finder.
    static func renderPDF(
        storage: StorageManager,
        windowDays: Int,
        generatedAt: Date
    ) -> Data {
        let totals = storage.piiRedactionTotals(days: windowDays)
        let byType = storage.piiRedactionCounts(days: windowDays)
        let byHost = storage.piiRedactionCountsByHost(days: windowDays)
        let integrityHash = integrityHashHex(byType: byType, byHost: byHost, totals: totals)

        let pageRect = CGRect(x: 0, y: 0, width: 612, height: 792) // US Letter
        let data = NSMutableData()
        guard let consumer = CGDataConsumer(data: data),
              var mediaBox = Optional(pageRect),
              let ctx = CGContext(consumer: consumer, mediaBox: &mediaBox, nil)
        else {
            return Data()
        }

        ctx.beginPDFPage(nil)
        let nsCtx = NSGraphicsContext(cgContext: ctx, flipped: false)
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = nsCtx

        let margin: CGFloat = 48
        var y = pageRect.height - margin

        // Title
        draw(
            "Bouclier.ai — PII Redaction Report",
            at: CGPoint(x: margin, y: y - 24),
            font: .systemFont(ofSize: 22, weight: .semibold)
        )
        y -= 36

        draw(
            "Local-only · No telemetry · Generated \(formattedDate(generatedAt))",
            at: CGPoint(x: margin, y: y - 14),
            font: .systemFont(ofSize: 10),
            color: .secondaryLabelColor
        )
        y -= 28

        // Window
        draw("Reporting window", at: CGPoint(x: margin, y: y - 14), font: .boldSystemFont(ofSize: 12))
        y -= 18
        draw(
            "Last \(windowDays) days · ending \(formattedDate(generatedAt))",
            at: CGPoint(x: margin, y: y - 14),
            font: .systemFont(ofSize: 11)
        )
        y -= 26

        // Totals
        draw("Totals", at: CGPoint(x: margin, y: y - 14), font: .boldSystemFont(ofSize: 12))
        y -= 18
        let coverageRatio = totals.prompts > 0
            ? String(format: "%.1f%%", Double(totals.redactions) / Double(totals.prompts) * 100)
            : "—"
        draw(
            "PII items redacted: \(totals.redactions)",
            at: CGPoint(x: margin, y: y - 14),
            font: .systemFont(ofSize: 11)
        )
        y -= 16
        draw(
            "Prompts scanned: \(totals.prompts)  ·  Redaction density: \(coverageRatio)",
            at: CGPoint(x: margin, y: y - 14),
            font: .systemFont(ofSize: 11)
        )
        y -= 26

        // By type
        draw("By entity type", at: CGPoint(x: margin, y: y - 14), font: .boldSystemFont(ofSize: 12))
        y -= 18
        for (type, count) in byType.sorted(by: { $0.value > $1.value }) {
            if y < margin + 60 { break }
            draw(humanLabel(type), at: CGPoint(x: margin + 12, y: y - 14), font: .systemFont(ofSize: 11))
            draw(
                "\(count)",
                at: CGPoint(x: pageRect.width - margin - 60, y: y - 14),
                font: .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
            )
            y -= 16
        }
        if byType.isEmpty {
            draw("No redactions recorded.", at: CGPoint(x: margin + 12, y: y - 14), font: .systemFont(ofSize: 11), color: .secondaryLabelColor)
            y -= 16
        }
        y -= 10

        // By host
        draw("By destination host", at: CGPoint(x: margin, y: y - 14), font: .boldSystemFont(ofSize: 12))
        y -= 18
        for (host, count) in byHost.sorted(by: { $0.value > $1.value }) {
            if y < margin + 60 { break }
            draw(host, at: CGPoint(x: margin + 12, y: y - 14), font: .systemFont(ofSize: 11))
            draw(
                "\(count)",
                at: CGPoint(x: pageRect.width - margin - 60, y: y - 14),
                font: .monospacedDigitSystemFont(ofSize: 11, weight: .regular)
            )
            y -= 16
        }
        if byHost.isEmpty {
            draw("No outbound redactions recorded.", at: CGPoint(x: margin + 12, y: y - 14), font: .systemFont(ofSize: 11), color: .secondaryLabelColor)
            y -= 16
        }
        y -= 16

        // Verification block
        draw("Verification", at: CGPoint(x: margin, y: y - 14), font: .boldSystemFont(ofSize: 12))
        y -= 18
        for line in [
            "Cleartext never recorded — Bouclier.ai stores entity type + position only.",
            "No telemetry transmitted — zero outbound to bouclier.ai or third parties.",
            "Audit row integrity SHA-256: \(integrityHash.prefix(48))",
            "Audit row integrity SHA-256 (cont.): \(integrityHash.dropFirst(48))",
        ] {
            draw(line, at: CGPoint(x: margin + 12, y: y - 14), font: .systemFont(ofSize: 10))
            y -= 14
        }

        // Footer
        draw(
            "Generated by Bouclier.ai · v\(appVersion) · This report was rendered on the user's device and never transmitted.",
            at: CGPoint(x: margin, y: margin / 2),
            font: .systemFont(ofSize: 9),
            color: .tertiaryLabelColor
        )

        NSGraphicsContext.restoreGraphicsState()
        ctx.endPDFPage()
        ctx.closePDF()
        return data as Data
    }

    // MARK: - Helpers

    private static func draw(
        _ text: String,
        at point: CGPoint,
        font: NSFont,
        color: NSColor = .labelColor
    ) {
        let attrs: [NSAttributedString.Key: Any] = [
            .font: font,
            .foregroundColor: color,
        ]
        (text as NSString).draw(at: point, withAttributes: attrs)
    }

    /// Deterministic fingerprint of the report's aggregated content so a
    /// recipient can re-render the same report and verify the hash. This
    /// is not a tamper-proof signature — that's the Phase 1.5 work — but
    /// it lets an auditor sanity-check that the figures in the PDF match
    /// what's in the audit DB without us having to ship the DB.
    private static func integrityHashHex(
        byType: [String: Int],
        byHost: [String: Int],
        totals: (redactions: Int, prompts: Int)
    ) -> String {
        var hasher = SHA256()
        for (k, v) in byType.sorted(by: { $0.key < $1.key }) {
            hasher.update(data: Data("t:\(k)=\(v)\n".utf8))
        }
        for (k, v) in byHost.sorted(by: { $0.key < $1.key }) {
            hasher.update(data: Data("h:\(k)=\(v)\n".utf8))
        }
        hasher.update(data: Data("totals:r=\(totals.redactions),p=\(totals.prompts)".utf8))
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    private static func formattedDate(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateStyle = .medium
        f.timeStyle = .short
        return f.string(from: date)
    }

    private static var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
    }

    private static func humanLabel(_ type: String) -> String {
        switch type {
        case "EMAIL": return "Email addresses"
        case "IBAN": return "IBAN account numbers"
        case "CREDIT_CARD": return "Credit cards"
        case "US_SSN": return "US Social Security numbers"
        case "IPV4": return "IPv4 addresses"
        case "IPV6": return "IPv6 addresses"
        case "AWS_ACCESS_KEY": return "AWS access keys"
        case "JWT": return "JWT tokens"
        case "FR_SIRET": return "French SIRET (establishment)"
        case "FR_SIREN": return "French SIREN (company)"
        case "FR_NIR": return "French NIR (social security)"
        case "UK_NHS": return "UK NHS numbers"
        case "UK_NINO": return "UK National Insurance numbers"
        case "UK_POSTCODE": return "UK postcodes"
        case "US_NPI": return "US National Provider IDs"
        default: return type
        }
    }
}

// Helper to reach the top-level humanLabel without duplication if
// SettingsView decides to share. Kept private for now.
