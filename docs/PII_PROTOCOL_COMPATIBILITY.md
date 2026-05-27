# Attachment PII inspection — protocol compatibility matrix

This document captures, per LLM provider and per endpoint, how
Bouclier.ai's attachment-PII inspection behaves. Every row is derived
from the published API docs cited in the corresponding cells.
Deviations from this table are bugs.

**Scope reminder (changed in v0.6).** Bouclier no longer rewrites text
prompt bodies — they reach the upstream byte-for-byte. The only thing
Bouclier may modify on an outbound request is an attachment (image /
PDF / audio) that the on-device scanner has flagged as containing PII;
the attachment's content block is replaced with a plain-English
description. Auth headers, API keys, custom trace IDs, and analytics
fields are forwarded unmodified. The byte-identical guarantee for text
bodies and headers is pinned by `E2EProxyTests`.

Symbols used in the tables below:

| Symbol | Meaning                                                                   |
| ------ | ------------------------------------------------------------------------- |
| ✅     | Attachment inspection runs and the rewriter understands the request shape |
| ⏭     | Endpoint carries no attachments — passes through unchanged                |
| ⚠️     | Inspected but a caveat applies — see notes                                |
| 🚫     | Rejected — the attachment was unscannable and is not silently forwarded   |
| 🧪     | Planned but not yet shipped — see roadmap                                 |

## OpenAI

| Endpoint                                                       | Behaviour | Notes                                                                                                                                                                                                                                    |
| -------------------------------------------------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/chat/completions` (text-only)                        | ⏭        | No attachments — body forwarded byte-for-byte.                                                                                                                                                                                           |
| `POST /v1/chat/completions` with `image_url` content blocks    | ✅        | Vision OCR + face detection on base64 and `data:` URLs. Flagged images replaced with a `type: "text"` placeholder. Unmodified images are byte-stable through the proxy.                                                                  |
| `POST /v1/chat/completions` with `input_audio` content blocks  | ✅        | On-device Apple Speech transcription (60 s cap). Flagged clips replaced with a text description.                                                                                                                                         |
| `POST /v1/chat/completions` (`stream: true`)                   | ⏭        | Streaming responses are forwarded verbatim. Request-side attachment inspection runs the same way regardless of `stream`.                                                                                                                 |
| `POST /v1/embeddings`                                          | ⏭        | No attachments — body forwarded unchanged.                                                                                                                                                                                               |
| `POST /v1/files` (multipart)                                   | ✅        | Multipart file uploads are parsed and each file part is routed by Content-Type to the image, PDF, or audio scanner. Flagged parts are replaced with a `text/plain` placeholder; the rest of the multipart body passes through unchanged. |
| `POST /v1/audio/transcriptions`, `POST /v1/audio/translations` | ✅        | Audio uploads are transcribed on-device via SFSpeechRecognizer before scanning. If the transcript carries PII the upload is stripped.                                                                                                    |
| `POST /v1/audio/speech`                                        | ⏭        | Text-to-speech: prompt forwarded unchanged; response is binary audio and forwarded unchanged.                                                                                                                                            |
| `POST /v1/images/generations`, `/v1/images/edits`              | ⏭        | Generated outputs are binary. Input prompts forwarded byte-for-byte; the response stream is forwarded unchanged.                                                                                                                         |
| `POST /v1/moderations`                                         | ⏭        | Forwarded unchanged.                                                                                                                                                                                                                     |
| `GET /v1/models`, `GET /v1/files/:id`, etc.                    | ⏭        | No request body to inspect.                                                                                                                                                                                                              |

## Anthropic

| Endpoint                                                  | Behaviour | Notes                                                                                                                                                                                             |
| --------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/messages` (text-only)                           | ⏭        | No attachments — body forwarded byte-for-byte.                                                                                                                                                    |
| `POST /v1/messages` with `image` content blocks           | ✅        | Vision OCR + face detection on the base64 source. Flagged blocks become `type: "text"` with a plain-English description.                                                                          |
| `POST /v1/messages` with `document` (PDF) content blocks  | ✅        | PDFKit text-layer extraction with Vision OCR fallback for scanned pages. Encrypted PDFs surface as unscannable and the block is replaced rather than silently forwarded.                          |
| `POST /v1/messages` with `tool_use` / tool results        | ⏭        | Tool blocks carry no media. Forwarded unchanged.                                                                                                                                                  |
| `POST /v1/messages` (`stream: true`)                      | ⏭        | Streaming responses are forwarded verbatim. Request-side inspection runs identically regardless of streaming.                                                                                     |
| `POST /v1/messages` with prompt caching (`cache_control`) | ✅        | Cache prefixes are unaffected because text bodies are no longer rewritten. Only attachment blocks change shape, and the rewriter swaps a stable text description so cache keys remain consistent. |
| `POST /v1/files` (multipart)                              | ✅        | Same multipart pipeline as the OpenAI Files API.                                                                                                                                                  |

## Generic / aggregator endpoints

| Endpoint                                                                                 | Behaviour | Notes                                                                                                                                                                                           |
| ---------------------------------------------------------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cohere `/v2/chat`, Mistral `/v1/chat/completions`, OpenRouter, Together, Groq, Fireworks | ⏭        | OpenAI-compatible shape. Text-only paths forwarded byte-for-byte; if any of these adds attachment blocks in their OpenAI-compatible shape, the OpenAI image/audio handlers apply automatically. |
| Google Gemini `/v1/models/*:generateContent` with `inlineData` blocks                    | ✅        | Image, PDF, and audio blocks via the Gemini-shaped `inlineData` extractor.                                                                                                                      |
| AWS Bedrock `/model/*/invoke`                                                            | ⏭        | Per-model body shapes; text is forwarded byte-for-byte. Attachment support depends on the model's request shape and is shape-detected by the multimodal extractor.                              |
| Azure OpenAI `*/openai/deployments/*/chat/completions`                                   | ✅        | Same as OpenAI.                                                                                                                                                                                 |

## MCP traffic (Model Context Protocol)

| Surface                                   | Behaviour | Notes                                                                                                                                                                                     |
| ----------------------------------------- | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MCP stdio (via `bouclier-ai-mcp-wrapper`) | 🧪        | The TLS proxy doesn't see stdio. Attachment scanning at the wrapper layer is planned. Protocol identifiers (`id`, `cursor`, `_meta`) are never modified by anything Bouclier ships today. |
| MCP over HTTP / SSE                       | ⏭        | Treated as ordinary HTTP+JSON by the existing TLS proxy. Text content is forwarded byte-for-byte; attachment blocks (if any) are routed by the OpenAI / Anthropic shape detectors.        |

## What we never do

- Modify any text prompt body. Bodies traverse the proxy byte-for-byte
  and the upstream receives them exactly as the client sent them. Pinned
  by `E2EProxyTests`.
- Modify any HTTP header. Auth, API keys, custom trace IDs, User-Agent,
  Anthropic-Version, Anthropic-Beta — all forwarded unchanged. Pinned
  by the same test.
- Send any PII or any audit-log row off the device. Attachment inspection
  (Vision OCR, PDFKit, SFSpeechRecognizer) runs fully on-device.
- Persist cleartext anywhere on disk. The `pii_redactions` table stores
  entity type and the first 4 bytes of SHA-256 of the cleartext —
  enough to recognise a repeated value within a session, useless to
  anyone scraping the SQLite file.

## Compliance posture (honest framing)

Defensible to enterprise procurement:

- ✅ **"PII inside attachments never leaves your Mac."** Flagged
  attachments are replaced before the request leaves the device.
- ✅ **"Bouclier does not modify prompt bodies."** Pinned by the E2E
  test — the auth/header passthrough invariant is a strong claim no
  abuse-detection-sensitive proxy normally makes.
- ✅ **"Reduces PII exposure inside uploaded media."** Always true when
  attachment inspection is enabled.

Don't claim:

- ❌ **"HIPAA-compliant" / "Safe Harbor de-identification."** Detection
  covers a subset of the 18 Safe Harbor identifiers and is best-effort.
  Honest framing: "scans common HIPAA identifiers inside attachments;
  covered entities should still operate under a BAA with their LLM
  provider."
- ❌ **"GDPR Art. 4(5) pseudonymisation."** Attachment replacement is
  a destructive rewrite, not pseudonymisation; cleartext isn't
  recoverable from the placeholder description.
- ❌ **"Zero data leakage."** Detection is probabilistic. Say
  "attachment PII leakage minimisation" instead.
- ❌ **"SOC2-ready."** SOC2 is about company controls, not product.
  Don't conflate.

## References

- AI4Privacy `pii-masking-300k`: <https://huggingface.co/datasets/ai4privacy/pii-masking-300k>
- PRvL benchmark: <https://arxiv.org/abs/2508.05545>
- "Unmasking the Reality of PII Masking Models": <https://arxiv.org/abs/2504.12308>
- Piiranha v1: <https://huggingface.co/iiiorg/piiranha-v1-detect-personal-information>
- GLiNER multi-PII: <https://huggingface.co/urchade/gliner_multi_pii-v1>
