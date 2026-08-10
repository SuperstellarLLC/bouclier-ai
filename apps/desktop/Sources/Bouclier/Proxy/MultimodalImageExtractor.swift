import Foundation

/// Locates base64-embedded images inside an outbound multimodal LLM
/// request body and yields each one with enough context for the proxy
/// to inspect it.
///
/// **Why this exists.** OpenAI, Anthropic, and Google Gemini all
/// accept images in `chat/completions`-style endpoints, but each
/// provider chose its own JSON shape:
///
/// * **OpenAI** — `messages[].content[].image_url.url` where the URL
///   is a `data:image/<format>;base64,<payload>` URI.
/// * **Anthropic** — `messages[].content[].source.type == "base64"`
///   with `source.media_type` (`image/png` etc.) and `source.data`
///   carrying the raw base64.
/// * **Gemini** — `contents[].parts[].inlineData.data` + `mimeType`.
///
/// The extractor walks the parsed JSON tree once, surfaces every
/// image it can decode, and remembers each image's location (a
/// JSON-pointer-like path) so we can later substitute redacted bytes
/// back at the same address.
///
/// The walk is deliberately tolerant of unknown shapes: if a key
/// looks plausible (`source.type == "base64"` with a `data` sibling)
/// we extract it, even if the rest of the envelope doesn't match a
/// known provider. That way we keep working when providers ship
/// schema tweaks between releases.
enum MultimodalImageExtractor {
    /// One image found in an outbound payload.
    struct Image: Sendable {
        /// Decoded image bytes (already base64-decoded).
        let data: Data
        /// IANA media type as reported by the JSON envelope. Used to
        /// re-encode any redacted output in the same format; falls
        /// back to PNG when the upstream omits it.
        let mediaType: String
        /// Provider that produced this shape, useful for telemetry
        /// and for choosing the right re-substitution rule.
        let provider: Provider
        /// JSON path to the field that contains the base64 payload,
        /// as a list of object keys / array indices. We store the
        /// keypath verbatim so the writer can mutate the same
        /// position without us re-parsing.
        let path: [PathComponent]
        /// JSON path to the *content block* that wraps the data leaf
        /// — i.e. `path` minus the provider-specific suffix. Stored
        /// explicitly rather than derived via `path.dropLast(N)` so
        /// future providers with deeper nesting don't silently
        /// mutate the wrong subtree when the rewriter runs.
        let contentBlockPath: [PathComponent]

        enum Provider: String, Sendable {
            case openai
            case anthropic
            case gemini
            case unknown
        }

        enum PathComponent: Sendable, Equatable, Hashable {
            case key(String)
            case index(Int)
        }

        /// True if this attachment's media type is a PDF. Centralised
        /// so we don't accidentally drift between three call sites
        /// when Anthropic / Gemini stop normalising the casing of
        /// `media_type` or start appending charset parameters.
        var isPDF: Bool {
            let canonical = mediaType.lowercased()
                .split(separator: ";").first.map(String.init)?
                .trimmingCharacters(in: .whitespaces) ?? ""
            return canonical == "application/pdf"
        }

        /// True if this attachment's media type is any image format.
        var isImage: Bool {
            mediaType.lowercased().hasPrefix("image/")
        }

        /// True if this attachment's media type is audio. Routes
        /// the payload through SFSpeechRecognizer instead of Vision
        /// or PDFKit.
        var isAudio: Bool {
            mediaType.lowercased().hasPrefix("audio/")
        }
    }

    // MARK: - Public entry point

    /// Scan an opaque JSON body. Returns every image we managed to
    /// decode; bodies that aren't JSON or don't contain a recognisable
    /// image field yield an empty array. Never throws — we'd rather
    /// pass through a payload than block a request because of an
    /// unusual envelope.
    static func extract(from body: Data) -> [Image] {
        guard let root = try? JSONSerialization.jsonObject(with: body, options: [.fragmentsAllowed]) else {
            return []
        }
        var found: [Image] = []
        walk(root, path: [], into: &found)
        return found
    }

    /// Maximum decoded size we'll accept from a single field, in
    /// bytes. Models accept up to ~20 MB images and ~32 MB PDFs;
    /// we cap a bit higher than that to absorb base64 overhead
    /// without inviting unbounded buffer growth.
    static let maxBytesPerImage = 32 * 1024 * 1024

    // MARK: - Tree walk

    private static func walk(_ node: Any, path: [Image.PathComponent], into out: inout [Image]) {
        if let dict = node as? [String: Any] {
            // Detect a known image-bearing shape *before* recursing,
            // so we don't double-emit (e.g. anthropic source.data
            // would otherwise also surface as a base64 leaf).
            if let image = matchOpenAIImageURL(dict, at: path) {
                out.append(image)
                return
            }
            if let image = matchAnthropicSource(dict, at: path) {
                out.append(image)
                return
            }
            if let image = matchGeminiInlineData(dict, at: path) {
                out.append(image)
                return
            }
            if let image = matchOpenAIInputAudio(dict, at: path) {
                out.append(image)
                return
            }
            for (k, v) in dict {
                walk(v, path: path + [.key(k)], into: &out)
            }
            return
        }
        if let arr = node as? [Any] {
            for (i, v) in arr.enumerated() {
                walk(v, path: path + [.index(i)], into: &out)
            }
        }
    }

    // MARK: - Provider-specific shape detectors

    private static func matchOpenAIImageURL(_ dict: [String: Any], at path: [Image.PathComponent]) -> Image? {
        guard let imageURL = dict["image_url"] as? [String: Any],
              let url = imageURL["url"] as? String,
              url.hasPrefix("data:")
        else { return nil }
        let payloadPath = path + [.key("image_url"), .key("url")]
        return decodeDataURL(url, path: payloadPath, contentBlockPath: path, provider: .openai)
    }

    private static func matchAnthropicSource(_ dict: [String: Any], at path: [Image.PathComponent]) -> Image? {
        guard let source = dict["source"] as? [String: Any],
              (source["type"] as? String) == "base64",
              let mediaType = source["media_type"] as? String,
              let data = source["data"] as? String
        else { return nil }
        // Anthropic accepts image/* AND application/pdf via the
        // same content-block shape. Both ride through this extractor;
        // downstream scanners route by mediaType. Accept case-
        // insensitively to defend against thin clients that don't
        // normalise the header.
        let canonical = mediaType.lowercased()
            .split(separator: ";").first.map(String.init)?
            .trimmingCharacters(in: .whitespaces) ?? ""
        guard canonical.hasPrefix("image/") || canonical == "application/pdf" else {
            return nil
        }
        guard let decoded = decodeBase64(data) else { return nil }
        let payloadPath = path + [.key("source"), .key("data")]
        return Image(
            data: decoded, mediaType: mediaType, provider: .anthropic,
            path: payloadPath, contentBlockPath: path
        )
    }

    /// OpenAI's audio-input shape used by gpt-4o-audio-preview and
    /// successors:
    /// ```
    /// {"type":"input_audio",
    ///  "input_audio":{"data":"<base64>", "format":"mp3"}}
    /// ```
    /// `format` is one of "wav" or "mp3" per OpenAI's docs; we map it
    /// to a media type so downstream routing matches the Gemini /
    /// Anthropic flow.
    private static func matchOpenAIInputAudio(_ dict: [String: Any], at path: [Image.PathComponent]) -> Image? {
        // Gate on the surrounding `type` field. Without it, any content
        // block that happens to carry an `input_audio` sibling triggers
        // SFSpeechRecognizer (the most expensive scanner in the proxy)
        // and causes the rewriter to clobber an unrelated block. Audio
        // wall-clock cost (~60 s × 4 concurrent) makes audio routing
        // far more sensitive to false matches than image or PDF.
        guard (dict["type"] as? String) == "input_audio",
              let block = dict["input_audio"] as? [String: Any],
              let data = block["data"] as? String
        else { return nil }
        let format = (block["format"] as? String)?.lowercased() ?? "mp3"
        let mediaType: String = {
            switch format {
            case "wav": return "audio/wav"
            case "mp3": return "audio/mpeg"
            case "m4a", "mp4": return "audio/mp4"
            case "flac": return "audio/flac"
            case "ogg", "opus": return "audio/ogg"
            case "webm": return "audio/webm"
            default: return "audio/\(format)"
            }
        }()
        guard let decoded = decodeBase64(data) else { return nil }
        let payloadPath = path + [.key("input_audio"), .key("data")]
        return Image(
            data: decoded, mediaType: mediaType, provider: .openai,
            path: payloadPath, contentBlockPath: path
        )
    }

    private static func matchGeminiInlineData(_ dict: [String: Any], at path: [Image.PathComponent]) -> Image? {
        let inlineKey = dict["inlineData"] != nil ? "inlineData" : (dict["inline_data"] != nil ? "inline_data" : nil)
        guard let inlineKey,
              let inline = dict[inlineKey] as? [String: Any],
              let mediaType = inline["mimeType"] as? String ?? inline["mime_type"] as? String,
              let data = inline["data"] as? String
        else { return nil }
        // Gemini's inlineData carries images, audio, PDFs, and video
        // through the same content shape. We accept image/*, audio/*,
        // and application/pdf — anything else stays untouched.
        let canonical = mediaType.lowercased()
            .split(separator: ";").first.map(String.init)?
            .trimmingCharacters(in: .whitespaces) ?? ""
        guard canonical.hasPrefix("image/") || canonical.hasPrefix("audio/")
            || canonical == "application/pdf" else {
            return nil
        }
        guard let decoded = decodeBase64(data) else { return nil }
        let payloadPath = path + [.key(inlineKey), .key("data")]
        return Image(
            data: decoded, mediaType: mediaType, provider: .gemini,
            path: payloadPath, contentBlockPath: path
        )
    }

    // MARK: - Helpers

    private static func decodeDataURL(
        _ url: String,
        path: [Image.PathComponent],
        contentBlockPath: [Image.PathComponent],
        provider: Image.Provider
    ) -> Image? {
        // data:[<mediatype>][;base64],<data>
        // We accept only the base64-encoded form; URL-encoded images
        // are vanishingly rare in real LLM traffic and we don't want
        // to pay the parser-complexity cost for them today.
        guard url.hasPrefix("data:"),
              let comma = url.firstIndex(of: ",")
        else { return nil }
        let prefix = url[url.index(url.startIndex, offsetBy: "data:".count)..<comma]
        let payload = url[url.index(after: comma)...]
        let parts = prefix.split(separator: ";", maxSplits: 1)
        let mediaType = parts.first.map(String.init) ?? "image/png"
        let isBase64 = parts.count > 1 && parts[1].lowercased().contains("base64")
        guard isBase64 else { return nil }
        guard let decoded = decodeBase64(String(payload)) else { return nil }
        return Image(
            data: decoded, mediaType: mediaType, provider: provider,
            path: path, contentBlockPath: contentBlockPath
        )
    }

    private static func decodeBase64(_ s: String) -> Data? {
        // Strip whitespace defensively — providers often pretty-print.
        let trimmed = s.filter { !$0.isWhitespace }
        guard let data = Data(base64Encoded: trimmed) else { return nil }
        guard data.count <= maxBytesPerImage else { return nil }
        return data
    }
}
