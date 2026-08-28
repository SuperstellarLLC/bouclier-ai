# Bouclier.ai site

The public product site and its download/report APIs. It is a Next.js app in
the repository's pnpm workspace and consumes the shared detector package.

## Development

```bash
pnpm install               # from the repository root
pnpm --filter site dev
```

Open [http://localhost:3000](http://localhost:3000).

Before submitting a change, run:

```bash
pnpm --filter site lint
pnpm --filter site typecheck
pnpm --filter site test:coverage
SKIP_ENV_VALIDATION=true pnpm --filter site build
pnpm --filter site test:e2e
```

Production configuration and required environment variables are documented in
[`../../docs/DEPLOYMENT.md`](../../docs/DEPLOYMENT.md). The site self-hosts its
fonts; it does not depend on a third-party font request at runtime.

The production Docker build validates that the committed Sparkle appcast names
the same version as the site and records a canonical 64-byte Sparkle Ed25519
signature, positive artifact length, and exact versioned HTTPS DMG URL. Local
`pnpm --filter site build` and Vercel previews skip this release-only gate so
they remain usable while a desktop release is being prepared.
