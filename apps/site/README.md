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

## Docker

The production image also requires the public `DOWNLOAD_REDIRECT_BASE` while it
builds, so it can prove that the website download route and Sparkle appcast use
the same release directory. This URL is public configuration, not a secret.

From the repository root, build a standalone image with:

```bash
docker build \
  --build-arg DOWNLOAD_REDIRECT_BASE=https://0tdi95zyjwsefpzx.public.blob.vercel-storage.com/download \
  -f apps/site/Dockerfile \
  -t bouclier-site .
```

For Compose, put the same value in `apps/site/.env.local`, then use that file
for build interpolation as well as the container runtime:

```bash
docker compose --env-file apps/site/.env.local \
  -f apps/site/docker-compose.yml up --build
```
