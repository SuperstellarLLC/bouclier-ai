# PII redaction — protocol compatibility matrix

This document captures, per LLM provider and per endpoint, how
Bouclier.ai's PII redaction layer behaves. Every row is derived from
the published API docs cited in the corresponding cells. Deviations
from this table are bugs.

Symbols used in the tables below:

| Symbol | Meaning                                                       |
| ------ | ------------------------------------------------------------- |
| ✅     | Redaction runs, response reversal runs, behaviour is correct  |
| ⚠️     | Redaction runs but a caveat applies — see notes               |
| ⏭     | Bypassed (forwarded raw) — redaction would break the protocol |
| 🚫     | Blocked — we refuse the request rather than silently leak     |
| 🧪     | Planned but not yet shipped — see roadmap                     |

## OpenAI

| Endpoint                                                                                  | Outbound | Inbound | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ----------------------------------------------------------------------------------------- | -------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/chat/completions` (non-stream)                                                  | ✅       | ✅      | Body is JSON ≤ 64 MiB → full sandwich works.                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| `POST /v1/chat/completions` (`stream: true`)                                              | ✅       | 🧪      | Streaming SSE reversal isn't wired into `SSEStreamInspector` yet (the sliding-window state machine lives in `PIIStreamReverser`). Outbound redaction runs, the response stream is forwarded raw, and the client sees `⟦pii:…⟧` placeholders until streaming reversal lands.                                                                                                                                                                                                      |
| `POST /v1/chat/completions` with `response_format: { type: "json_schema", strict: true }` | ⚠️       | ⚠️      | Constrained decoding rejects `{` and `}` in non-string positions. Our token format uses Unicode mathematical brackets `⟦…⟧` (U+27E6 / U+27E7), which OpenAI's BPE treats as opaque string content. The placeholder survives constrained decoding **inside string-typed leaves**; it does **not** survive in `type: "number"` or `format: "email"` slots — the request will 400. Document this caveat to users; do not enable redaction for embedding-as-search-fields workflows. |
| `POST /v1/chat/completions` with tool / function calls                                    | ✅       | ⚠️      | Non-streaming JSON path reverses correctly. Streaming `delta.tool_calls[].function.arguments` chunks fall under the SSE streaming gap above.                                                                                                                                                                                                                                                                                                                                     |
| `POST /v1/chat/completions` with images / audio in the body                               | ✅       | ✅      | Multimodal inspection runs: Vision OCR + face detection, PDFKit, and on-device Apple Speech. Flagged attachments are stripped with a text placeholder before the request leaves the Mac.                                                                                                                                                                                                                                                                                         |
| `POST /v1/embeddings`                                                                     | ⏭       | ⏭      | Redacting input destroys the resulting vector — the entire point of an embedding is semantic equivalence to the source. Bypassed with a `bouclier-bypass: embeddings` entry in the audit log.                                                                                                                                                                                                                                                                                    |
| `POST /v1/files` (multipart)                                                              | ✅       | ⏭      | Multipart file uploads (Files API) are parsed and each file part is routed by Content-Type to the image, PDF, or audio scanner. Flagged parts are replaced with a `text/plain` placeholder.                                                                                                                                                                                                                                                                                      |
| `POST /v1/audio/transcriptions`, `POST /v1/audio/translations`                            | ✅       | ⏭      | Audio uploads are transcribed on-device via SFSpeechRecognizer (60 s cap) before scanning. If the transcript carries PII the upload is stripped; the response from OpenAI is not modified.                                                                                                                                                                                                                                                                                       |
| `POST /v1/audio/speech`                                                                   | ⏭       | ⏭      | Text-to-speech: input PII is handled by the existing text path; the response is binary audio and is forwarded unchanged.                                                                                                                                                                                                                                                                                                                                                         |
| `POST /v1/images/generations`, `/v1/images/edits`                                         | ⏭       | ⏭      | Generated outputs are binary. Input prompts go through the text pipeline; the response stream is forwarded unchanged.                                                                                                                                                                                                                                                                                                                                                            |
| `POST /v1/moderations`                                                                    | ⏭       | ⏭      | Counterproductive to redact — moderation explicitly needs the raw text.                                                                                                                                                                                                                                                                                                                                                                                                          |
| `GET /v1/models`, `GET /v1/files/:id`, etc.                                               | ⏭       | ⏭      | No PII in requests.                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

## Anthropic

| Endpoint                                                  | Outbound | Inbound | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| --------------------------------------------------------- | -------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/messages` (non-stream)                          | ✅       | ✅      | Same shape as OpenAI's chat completion.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| `POST /v1/messages` (`stream: true`)                      | ✅       | 🧪      | Same SSE streaming caveat as OpenAI. Anthropic's `content_block_delta` and `input_json_delta` events both fall under the deferred sliding-window reversal.                                                                                                                                                                                                                                                                                                                                                                                    |
| `POST /v1/messages` with prompt caching (`cache_control`) | ⚠️       | ⚠️      | **Cache hits are invalidated by token rotation.** Each session mints fresh HMAC-keyed tokens; any cached prefix that previously contained PII is invalidated when the request runs through redaction. Agents making N sequential calls with cached system prompts pay roughly N× the prompt cost while redaction is on. We mitigate today with deterministic-within-session token recall (same value → same token); a future "PII-anchor" mode that keeps cached prefixes PII-free is on the roadmap. Document the trade-off in product copy. |
| `POST /v1/messages` with extended thinking                | ⚠️       | 🧪      | Reasoning / `thinking` blocks may emit placeholder tokens far apart in the stream. Request-side redaction runs; streaming reversal on the thinking stream lands when the SSE reverser is wired in.                                                                                                                                                                                                                                                                                                                                            |
| `POST /v1/messages` with `tool_use`                       | ✅       | ⚠️      | Same tool-call note as OpenAI.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `POST /v1/messages` with images / documents               | ✅       | ✅      | Image and PDF blocks (`type: "image"`, `type: "document"`) are inspected on-device. Flagged blocks become `type: "text"` placeholders.                                                                                                                                                                                                                                                                                                                                                                                                        |
| `POST /v1/files` (multipart)                              | ✅       | ⏭      | Same multipart pipeline as the OpenAI Files API.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

## Generic / aggregator endpoints

| Endpoint                                                                                 | Outbound | Inbound | Notes                                                                                          |
| ---------------------------------------------------------------------------------------- | -------- | ------- | ---------------------------------------------------------------------------------------------- |
| Cohere `/v2/chat`, Mistral `/v1/chat/completions`, OpenRouter, Together, Groq, Fireworks | ✅       | ✅      | OpenAI-compatible shape; treated identically.                                                  |
| Google Gemini `/v1/models/*:generateContent`                                             | ✅       | ✅      | JSON body, JSON response. Streaming is `text/event-stream` like OpenAI; same streaming caveat. |
| AWS Bedrock `/model/*/invoke`                                                            | ✅       | ✅      | Per-model body shapes; redaction walks JSON string leaves agnostic of shape.                   |
| Azure OpenAI `*/openai/deployments/*/chat/completions`                                   | ✅       | ✅      | Same shape as OpenAI.                                                                          |

## MCP traffic (Model Context Protocol)

| Surface                                   | Outbound | Inbound           | Notes                                                                                                                                                                                                      |
| ----------------------------------------- | -------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MCP stdio (via `bouclier-ai-mcp-wrapper`) | 🧪       | 🧪                | The TLS proxy doesn't see stdio. Redaction at the wrapper layer is planned and needs careful handling of MCP's `id`, `cursor`, `_meta` fields — those are protocol identifiers and must never be redacted. |
| MCP over HTTP / SSE                       | ✅       | ✅ for non-stream | Treated as ordinary HTTP+JSON by the existing TLS proxy; same caveats as the OpenAI table.                                                                                                                 |

## What we never do

- Send any PII or any audit-log row off the device. The redactor and
  reverser run fully on-device; the only network calls in the request
  lifecycle are the user's existing LLM API calls (now carrying
  tokenised content), the Sparkle update check, and, if enterprise-
  configured, the SIEM webhook.
- Persist cleartext anywhere on disk. The `pii_redactions` table
  stores entity type, character offsets, and the first 4 bytes of
  SHA-256 of the cleartext — enough to recognise a repeated value
  within a session, useless to anyone scraping the SQLite file.
- Claim cryptographic protection of the in-memory session map. The
  honest characterisation lives in `PIISession.swift`: the map is
  plaintext in process memory, never written to disk, zeroised on TTL
  expiry, scoped to a single TLS connection.

## Compliance posture (honest framing)

Defensible to enterprise procurement:

- ✅ **"PII never leaves your Mac."** Tokens are emitted by the local
  redactor; the LLM provider sees `⟦pii:EMAIL:…⟧` instead of the
  user's email.
- ✅ **"Reversible per-session pseudonymisation with per-connection key
  isolation."** HMAC-keyed tokens cannot be forged across sessions.
- ✅ **"Reduces PII exposure to upstream LLM providers."** Always true.

Don't claim:

- ❌ **"HIPAA-compliant" / "Safe Harbor de-identification."** The
  redaction tiers cover a subset of the 18 Safe Harbor identifiers.
  Honest framing: "redacts common HIPAA identifiers; covered entities
  should still operate under a BAA with their LLM provider."
- ❌ **"GDPR pseudonymisation per Art. 4(5)."** An in-process map
  satisfies the rule only formally; an auditor will ask about key
  management. Until the audit-log key is Secure-Enclave wrapped,
  pseudonymisation here is operational, not legal.
- ❌ **"Zero data leakage."** Documented protocol gaps remain
  (embeddings, streaming reversal). Say "PII leakage minimisation"
  instead.
- ❌ **"AES-256-GCM encrypted session map."** The encryption-of-
  in-memory-state framing is theatre unless the key itself is wrapped
  in Secure Enclave.
- ❌ **"SOC2-ready."** SOC2 is about company controls, not product.
  Don't conflate.

## References

- AI4Privacy `pii-masking-300k`: <https://huggingface.co/datasets/ai4privacy/pii-masking-300k>
- PRvL benchmark: <https://arxiv.org/abs/2508.05545>
- "Unmasking the Reality of PII Masking Models": <https://arxiv.org/abs/2504.12308>
- Skyflow LLM Privacy Vault: <https://www.skyflow.com/product/llm-privacy-vault>
- Microsoft PII Shield: <https://techcommunity.microsoft.com/blog/azuredevcommunityblog/introducing-pii-shield-a-privacy-proxy-for-every-llm-call/4514726>
- NVIDIA NeMo streaming guardrails: <https://developer.nvidia.com/blog/stream-smarter-and-safer-learn-how-nvidia-nemo-guardrails-enhance-llm-output-streaming/>
- Piiranha v1: <https://huggingface.co/iiiorg/piiranha-v1-detect-personal-information>
- GLiNER multi-PII: <https://huggingface.co/urchade/gliner_multi_pii-v1>
