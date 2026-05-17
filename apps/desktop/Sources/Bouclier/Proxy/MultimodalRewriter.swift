import Foundation

/// Mutates an outbound multimodal request body so flagged images are
/// replaced with descriptive text placeholders before the body leaves
/// the Mac.
///
/// **Semantics chosen for v0.4.0.** Rather than 4xx-ing the upstream
/// (which would require a synthetic response and an out-of-band
/// "send anyway" retry flow) we strip the offending image leaf
/// in-place and inject a placeholder text content block that tells
/// the model *what* was blocked. The model still answers usefully
/// ("I can't see the image but you mentioned an IBAN — here's how
/// I'd help…") and the user gets a notification with a per-image
/// breakdown.
///
/// Provider-specific shapes:
///
/// * **OpenAI** — replace `{type: "image_url", ...}` with
///   `{type: "text", text: "[Bouclier blocked image — IBAN, email]"}`.
/// * **Anthropic** — replace `{type: "image", source: ...}` with
///   `{type: "text", text: ...}`.
/// * **Gemini** — replace `{inlineData: ...}` with `{text: ...}` (the
///   `parts` array tolerates mixed shapes).
enum MultimodalRewriter {
    /// Rewrite the body. Returns the original bytes when no findings
    /// touch images. Idempotent and **byte-stable on the no-findings
    /// path** — guarded explicitly so a careless refactor can't
    /// reorder the early return and start round-tripping bodies
    /// through JSONSerialization (which would reorder dict keys, alter
    /// number representations, and break upstream cache keys /
    /// signature checks).
    ///
    /// Image-level granularity: each `Finding.contentBlockPath`
    /// addresses exactly one content block; only those blocks are
    /// replaced. Clean images in the same prompt pass through.
    static func stripFlaggedImages(
        from body: Data,
        report: MultimodalPIIInspector.Report
    ) -> Data {
        // Invariant: no findings ⇒ original bytes, no parse, no
        // re-serialize. Locked in by an early return + a debug assert
        // below in case the order ever gets shuffled.
        guard !report.findings.isEmpty else { return body }

        let parsed = try? JSONSerialization.jsonObject(with: body, options: [.fragmentsAllowed])
        // Handle both top-level dict bodies (every well-formed chat
        // completion) and top-level array bodies (some batched
        // request shapes). Without the array branch a malicious
        // batched request could carry a flagged image past the
        // rewriter unchanged.
        if var rootDict = parsed as? [String: Any] {
            rootDict = applyAll(report.findings, to: rootDict)
            guard let rewritten = try? JSONSerialization.data(withJSONObject: rootDict, options: [.fragmentsAllowed]) else {
                return body
            }
            return rewritten
        }
        if var rootArr = parsed as? [Any] {
            rootArr = applyAllArray(report.findings, to: rootArr)
            guard let rewritten = try? JSONSerialization.data(withJSONObject: rootArr, options: [.fragmentsAllowed]) else {
                return body
            }
            return rewritten
        }
        return body
    }

    /// Apply every finding by content-block path. Findings on the
    /// same content block are merged into a single placeholder block.
    private static func applyAll(
        _ findings: [MultimodalPIIInspector.Finding],
        to root: [String: Any]
    ) -> [String: Any] {
        let groups = Dictionary(grouping: findings, by: { $0.contentBlockPath })
        var out = root
        for (path, group) in groups {
            guard let first = group.first else { continue }
            let placeholder = placeholderBlock(for: first.provider, findings: group)
            if let updated = replace(value: placeholder, at: path, in: out) {
                out = updated
            }
        }
        return out
    }

    private static func applyAllArray(
        _ findings: [MultimodalPIIInspector.Finding],
        to root: [Any]
    ) -> [Any] {
        let groups = Dictionary(grouping: findings, by: { $0.contentBlockPath })
        // For an array root we wrap the array in a synthetic dict so
        // we can reuse the same path-walking helpers, then unwrap.
        var wrapped: [String: Any] = ["__root__": root]
        for (path, group) in groups {
            guard let first = group.first else { continue }
            let placeholder = placeholderBlock(for: first.provider, findings: group)
            let prefixed: [MultimodalImageExtractor.Image.PathComponent] = [.key("__root__")] + path
            if let updated = replace(value: placeholder, at: prefixed, in: wrapped) {
                wrapped = updated
            }
        }
        return (wrapped["__root__"] as? [Any]) ?? root
    }

    // MARK: - Placeholder rendering

    private static func placeholderBlock(
        for provider: MultimodalImageExtractor.Image.Provider,
        findings: [MultimodalPIIInspector.Finding]
    ) -> [String: Any] {
        let summary = summarize(findings)
        let message = "[Bouclier blocked an image — \(summary)]"
        switch provider {
        case .openai:
            return ["type": "text", "text": message]
        case .anthropic:
            return ["type": "text", "text": message]
        case .gemini:
            return ["text": message]
        case .unknown:
            return ["type": "text", "text": message]
        }
    }

    private static func summarize(_ findings: [MultimodalPIIInspector.Finding]) -> String {
        var typeCounts: [String: Int] = [:]
        var faces = 0
        for f in findings {
            switch f.category {
            case .textPII(let type):
                typeCounts[type, default: 0] += 1
            case .face:
                faces += 1
            }
        }
        var parts: [String] = []
        for (type, count) in typeCounts.sorted(by: { $0.key < $1.key }) {
            parts.append(count > 1 ? "\(count)× \(humanLabel(type))" : humanLabel(type))
        }
        if faces > 0 {
            parts.append(faces > 1 ? "\(faces) faces" : "1 face")
        }
        return parts.isEmpty ? "PII detected" : parts.joined(separator: ", ")
    }

    private static func humanLabel(_ type: String) -> String {
        switch type {
        case "EMAIL": return "email"
        case "IBAN": return "IBAN"
        case "CREDIT_CARD": return "credit card"
        case "US_SSN": return "SSN"
        case "PHONE": return "phone"
        case "ADDRESS": return "address"
        case "FR_NIR": return "French NIR"
        case "FR_SIRET": return "French SIRET"
        case "FR_SIREN": return "French SIREN"
        case "UK_NHS": return "NHS number"
        case "UK_NINO": return "UK NINO"
        case "PERSON": return "person name"
        case "DATE_OF_BIRTH": return "date of birth"
        default: return type.lowercased().replacingOccurrences(of: "_", with: " ")
        }
    }

    // MARK: - JSON tree replace

    /// Replace the value at `path` inside `root` with `newValue`.
    /// Returns the modified root, or nil if the path doesn't exist.
    /// Empty path is a no-op.
    private static func replace(
        value newValue: Any,
        at path: [MultimodalImageExtractor.Image.PathComponent],
        in root: [String: Any]
    ) -> [String: Any]? {
        guard !path.isEmpty else { return root }
        var copy = root
        // We can't naturally mutate Any-typed nested structures, so
        // walk recursively building up a new tree.
        guard let case0 = path.first else { return root }
        switch case0 {
        case .key(let k):
            guard let child = copy[k] else { return nil }
            if path.count == 1 {
                copy[k] = newValue
                return copy
            }
            let rest = Array(path.dropFirst())
            let updated = updateValue(child, path: rest, newValue: newValue)
            copy[k] = updated
            return copy
        case .index:
            // Top-level isn't an array in our JSON envelopes; treat as missing.
            return nil
        }
    }

    private static func updateValue(
        _ value: Any,
        path: [MultimodalImageExtractor.Image.PathComponent],
        newValue: Any
    ) -> Any {
        guard let case0 = path.first else { return newValue }
        let rest = Array(path.dropFirst())
        switch case0 {
        case .key(let k):
            guard var dict = value as? [String: Any] else { return value }
            if path.count == 1 {
                dict[k] = newValue
                return dict
            }
            guard let child = dict[k] else { return value }
            dict[k] = updateValue(child, path: rest, newValue: newValue)
            return dict
        case .index(let i):
            guard var arr = value as? [Any], i < arr.count else { return value }
            if path.count == 1 {
                arr[i] = newValue
                return arr
            }
            arr[i] = updateValue(arr[i], path: rest, newValue: newValue)
            return arr
        }
    }
}
