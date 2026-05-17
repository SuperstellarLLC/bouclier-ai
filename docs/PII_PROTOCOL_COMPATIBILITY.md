# PII redaction — protocol compatibility matrix

This document captures, per LLM provider and per endpoint, exactly how
Bouclier.ai's PII redaction layer behaves. Every row was derived from
the API docs cited in the corresponding cells; deviations from this
table are bugs.

The same conventions apply throughout:

| Symbol | Meaning                                                       |
| ------ | ------------------------------------------------------------- |
| ✅     | Redaction runs, response reversal runs, behavior is correct   |
| ⚠️     | Redaction runs but a caveat applies — see notes               |
| ⏭     | Bypassed (forwarded raw) — redaction would break the protocol |
| 🚫     | Blocked — we refuse the request rather than silently leak     |
| 🧪     | Phase 2 / Phase 3 — not in v0.2.13, planned next release      |

## OpenAI

| Endpoint                                                                                  | Outbound | Inbound | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ----------------------------------------------------------------------------------------- | -------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/chat/completions` (non-stream)                                                  | ✅       | ✅      | Body is JSON ≤ 1 MiB → full sandwich works.                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `POST /v1/chat/completions` (`stream: true`)                                              | ✅       | 🧪      | Phase 3 SSE reversal not yet shipped; the model still receives tokenized input, but the response stream is forwarded raw so the client sees `⟦pii:…⟧` placeholders. Phase 3 adds NeMo-style sliding-window reversal.                                                                                                                                                                                                                                                                         |
| `POST /v1/chat/completions` with `response_format: { type: "json_schema", strict: true }` | ⚠️       | ⚠️      | Constrained decoding rejects `{` and `}` in non-string positions. Our token format uses Unicode mathematical brackets `⟦…⟧` (U+27E6/U+27E7), which OpenAI's BPE treats as opaque string content. The placeholder survives constrained decoding **inside string-typed leaves** of the schema; it does **not** survive in `type: "number"` or `format: "email"` slots — the request will 400. Document this caveat to users; do not enable redaction for embedding-as-search-fields workflows. |
| `POST /v1/chat/completions` with tool/function calls                                      | ✅       | ⚠️      | Arguments arrive as `delta.tool_calls[].function.arguments` chunks. Non-stream JSON path reverses correctly. Streaming arguments fall under the Phase 3 SSE gap above.                                                                                                                                                                                                                                                                                                                       |
| `POST /v1/embeddings`                                                                     | ⏭       | ⏭      | Redacting input destroys the resulting vector — the entire point of an embedding is semantic equivalence to the source. Bypassed with a `bouclier-bypass: embeddings` entry in the audit log.                                                                                                                                                                                                                                                                                                |
| `POST /v1/files`                                                                          | ⏭       | ⏭      | File uploads are `multipart/form-data`; we already skip body scanning for non-JSON content types (`HTTPRequestInspector.scannableMediaPrefixes`). Phase 3 will hook the file-write path for _text_ uploads.                                                                                                                                                                                                                                                                                  |
| `POST /v1/audio/*` (transcriptions, speech)                                               | ⏭       | ⏭      | Binary payloads. Phase 3 adds audio-PII detection via on-device Whisper + Piiranha (post-transcript).                                                                                                                                                                                                                                                                                                                                                                                        |
| `POST /v1/images/*`                                                                       | ⏭       | ⏭      | Binary. PII in images is unaddressed in Phase 1/2; Phase 3 OCR + redact is on the roadmap.                                                                                                                                                                                                                                                                                                                                                                                                   |
| `POST /v1/moderations`                                                                    | ⏭       | ⏭      | Counterproductive to redact — moderation explicitly needs the raw text.                                                                                                                                                                                                                                                                                                                                                                                                                      |
| `GET /v1/models`, `GET /v1/files/:id`, etc.                                               | ⏭       | ⏭      | No PII in requests.                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |

## Anthropic

| Endpoint                                                  | Outbound | Inbound | Notes                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --------------------------------------------------------- | -------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /v1/messages` (non-stream)                          | ✅       | ✅      | Same shape as OpenAI's chat completion.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `POST /v1/messages` (`stream: true`)                      | ✅       | 🧪      | Same Phase 3 caveat as OpenAI SSE. Anthropic's `content_block_delta` and `input_json_delta` events both fall under the deferred sliding-window reversal.                                                                                                                                                                                                                                                                                                                                                                                  |
| `POST /v1/messages` with prompt caching (`cache_control`) | ⚠️       | ⚠️      | **Cache hits are destroyed by token rotation.** Each session mints fresh HMAC-keyed tokens; the cached prefix is invalidated on every request that previously contained PII. For agents making N sequential calls with cached system prompts the cost grows ~Nx. Mitigations under consideration for Phase 3: (a) deterministic-within-session token recall (already implemented — same value → same token), (b) "PII-anchor" mode where the cached prefix is held PII-free so caching survives. Document the trade-off in the docs site. |
| `POST /v1/messages` with extended thinking                | ⚠️       | 🧪      | Reasoning/`thinking` blocks may emit placeholder tokens far apart in the stream. Phase 1 ships request-side redaction; Phase 3 sliding-window reversal will cover thinking-stream reversal.                                                                                                                                                                                                                                                                                                                                               |
| `POST /v1/messages` with `tool_use`                       | ✅       | ⚠️      | Same tool-call note as OpenAI.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `POST /v1/messages` with images / documents               | ⏭       | ⏭      | Same multimodal note.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |

## Generic / aggregator endpoints

| Endpoint                                                                                 | Outbound | Inbound | Notes                                                                                        |
| ---------------------------------------------------------------------------------------- | -------- | ------- | -------------------------------------------------------------------------------------------- |
| Cohere `/v2/chat`, Mistral `/v1/chat/completions`, OpenRouter, Together, Groq, Fireworks | ✅       | ✅      | OpenAI-compatible shape; treated identically.                                                |
| Google Gemini `/v1/models/*:generateContent`                                             | ✅       | ✅      | JSON body, JSON response. Streaming is `text/event-stream` like OpenAI; same Phase 3 caveat. |
| AWS Bedrock `/model/*/invoke`                                                            | ✅       | ✅      | Per-model body shapes; redaction walks JSON string leaves agnostic of shape.                 |
| Azure OpenAI `*/openai/deployments/*/chat/completions`                                   | ✅       | ✅      | Same shape as OpenAI.                                                                        |

## MCP traffic (Model Context Protocol)

| Surface                                   | Outbound | Inbound           | Notes                                                                                                                                                                                                                                                                                    |
| ----------------------------------------- | -------- | ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| MCP stdio (via `bouclier-ai-mcp-wrapper`) | 🧪       | 🧪                | Phase 1's redactor lives in the TLS proxy and so does not see MCP. The MCP wrapper has its own framing (JSON-RPC over stdio); Phase 2 adds redaction there but needs careful handling of MCP's `id`, `cursor`, `_meta` fields which are protocol identifiers and must NEVER be redacted. |
| MCP over HTTP/SSE                         | ✅       | ✅ for non-stream | Treated as ordinary HTTP+JSON traffic by the existing TLS proxy; same caveats as the OpenAI table.                                                                                                                                                                                       |

## What we never do

- Send any PII or any audit-log row off the device. The redactor and reverser run fully on-device; the only network calls in the request lifecycle are the user's existing LLM API calls, which now carry tokenized content.
- Persist cleartext anywhere on disk. The `pii_redactions` table stores entity type, character offsets, and the first 4 bytes of SHA-256 of the cleartext only — that is enough to recognize a repeated value within a session but useless to anyone scraping the SQLite file.
- Claim cryptographic protection of the in-memory session map. The honest characterization is in `PIISession.swift`: the map is plaintext in process memory, never written to disk, zeroized on TTL expiry, scoped to a single TLS connection.

## Compliance posture (honest framing)

What the product team can defensibly say to enterprise procurement after Phase 1/2/3 ship:

- ✅ "PII never leaves your Mac." Tokens are emitted by the local redactor; the LLM provider sees `⟦pii:EMAIL:…⟧` instead of the user's email.
- ✅ "Reversible per-session pseudonymization with per-connection key isolation." Defensible — HMAC-keyed tokens cannot be forged across sessions.
- ✅ "Reduces PII exposure to upstream LLM providers." Always true.

What we **must not** claim:

- ❌ "HIPAA-compliant" / "Safe Harbor de-identification." Phase 1/2 covers ~4–6 of the 18 Safe Harbor identifiers. The honest framing: "redacts common HIPAA identifiers; covered entities should still operate under a BAA with their LLM provider."
- ❌ "GDPR pseudonymization per Art. 4(5)." A 10-minute in-process map satisfies the rule only formally; an auditor will ask about key management. The Secure-Enclave audit log work in Phase 1.5 / v0.2.14 makes this defensible.
- ❌ "Zero data leakage." Phase 1/2 has documented protocol gaps (embeddings, multimodal, files API). Say "PII leakage minimization" instead.
- ❌ "AES-256-GCM encrypted session map." See `PIISession.swift` — the encryption-of-in-memory-state framing is theater unless the key itself is wrapped in Secure Enclave, which is a deferred item.
- ❌ "SOC2-ready." SOC2 is about the company's controls, not the product. Do not conflate.

## Roadmap

- **Phase 1 (v0.2.13)** — Regex + structural validators for: EMAIL, IBAN, CREDIT_CARD, US_SSN, IPV4, IPV6, AWS_ACCESS_KEY, JWT, FR_SIRET, FR_SIREN, FR_NIR, UK_NHS, UK_NINO, UK_POSTCODE, US_NPI. Per-connection session, deterministic tokens, non-streaming JSON response reversal, settings toggle, preview-before-send modal, audit log.
- **Phase 2 (v0.2.14)** — Piiranha mDeBERTa on CoreML / ANE for PERSON, ORG, LOCATION, MEDICAL. Eval harness on AI4Privacy + PRvL. Secure-Enclave audit-log key.
- **Phase 3 (v0.2.15)** — SSE streaming reversal (NeMo Guardrails-style sliding window), GLiNER zero-shot for custom entity types, per-entity policy table, MCP wrapper integration.

References:

- AI4Privacy `pii-masking-300k`: https://huggingface.co/datasets/ai4privacy/pii-masking-300k
- PRvL benchmark: https://arxiv.org/abs/2508.05545
- "Unmasking the Reality of PII Masking Models": https://arxiv.org/abs/2504.12308
- Skyflow LLM Privacy Vault: https://www.skyflow.com/product/llm-privacy-vault
- Microsoft PII Shield: https://techcommunity.microsoft.com/blog/azuredevcommunityblog/introducing-pii-shield-a-privacy-proxy-for-every-llm-call/4514726
- NVIDIA NeMo streaming guardrails: https://developer.nvidia.com/blog/stream-smarter-and-safer-learn-how-nvidia-nemo-guardrails-enhance-llm-output-streaming/
- Piiranha v1: https://huggingface.co/iiiorg/piiranha-v1-detect-personal-information
- GLiNER multi-PII: https://huggingface.co/urchade/gliner_multi_pii-v1
