# Bouclier.ai (Beta)

Stop prompt injections. Stop PII from leaking to LLMs — in text, in images, in PDFs, in audio clips. A local-only macOS app that sits between your apps and AI providers, scrubs prompts (and their attachments) before they leave your Mac, and reverses the model's response so you still read normal text.

> **Experimental, pre-1.0 software.** Bouclier.ai is a prototype intended for evaluation, research, and personal experimentation. Detection is best-effort and probabilistic — false positives and false negatives will occur. **Not** intended for production, regulated workloads, or any environment where a detection failure could cause harm. See [Terms](https://www.bouclier.ai/terms) before installing.

## Architecture

```
apps/
├── desktop/       ← macOS menubar app (Swift) — local proxy engine
└── site/          ← Marketing & docs site (Next.js)

packages/
└── patterns/      ← Shared injection pattern definitions
```

## Getting Started

```bash
# Install dependencies (site + patterns)
pnpm install

# Run the site locally
pnpm dev --filter site

# Build everything
pnpm build

# Run all checks
pnpm check
```

## Desktop App (macOS)

```bash
cd apps/desktop
swift build
swift run Bouclier.ai
```

## How It Works

Bouclier.ai runs as a lightweight macOS menubar app that acts as a local proxy. It intercepts content flowing to AI APIs and MCP servers, scans for prompt injection patterns + PII, and redacts malicious or sensitive content before it reaches the model. As of v0.4, the scanner also opens images, PDFs and short audio clips attached to outbound prompts — Apple Vision for OCR + face detection, PDFKit + Vision for PDFs, and SFSpeechRecognizer (on-device) for audio — and replaces flagged attachments with a short text placeholder so the model still gets the gist without the leak.

Detected injections are replaced with:

```
[Possible prompt injection redacted by Bouclier.ai. See https://www.bouclier.ai/blocked for details]
```

## Attribution

Built with Llama. Bouclier.ai uses Meta Llama Prompt Guard 2 for on-device prompt attack detection.

Third-party notice: `NOTICE.txt`
Llama 4 Community License: `LICENSES/Llama-4-Community-License.txt`
