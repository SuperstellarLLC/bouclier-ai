# Ilvarion

Network middleware that strips prompt injections from content before it reaches LLMs.

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
swift run Ilvarion
```

## How It Works

Ilvarion runs as a lightweight macOS menubar app that acts as a local proxy. It intercepts content flowing to AI APIs and MCP servers, scans for prompt injection patterns, and redacts malicious content before it reaches the model.

Detected injections are replaced with:

```
[Possible prompt injection redacted by Ilvarion. See https://ilvarion.dev/blocked for details]
```
