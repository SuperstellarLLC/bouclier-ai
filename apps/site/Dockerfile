# ── Run from monorepo root: docker build -f apps/site/Dockerfile . ──

# ── Stage 1: Dependencies ─────────────────────
FROM node:22-alpine AS deps
RUN apk add --no-cache libc6-compat
RUN corepack enable pnpm
WORKDIR /app

COPY pnpm-lock.yaml pnpm-workspace.yaml package.json ./
COPY packages/patterns/package.json ./packages/patterns/
COPY apps/site/package.json ./apps/site/

RUN pnpm install --frozen-lockfile

# ── Stage 2: Build ────────────────────────────
FROM node:22-alpine AS builder
RUN corepack enable pnpm
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/packages/patterns/node_modules ./packages/patterns/node_modules
COPY --from=deps /app/apps/site/node_modules ./apps/site/node_modules
COPY . .

ENV NEXT_TELEMETRY_DISABLED=1
ENV SKIP_ENV_VALIDATION=true
# Docker images are production artifacts even when built outside Vercel. This
# enables the same signed-desktop/appcast alignment gate as VERCEL_ENV does,
# while ordinary local `pnpm build` and Vercel previews remain available for QA.
ENV BOUCLIER_DEPLOYMENT_ENV=production

RUN pnpm --filter @bouclier-ai/patterns build
RUN pnpm --filter site build

# ── Stage 3: Production ──────────────────────
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV BOUCLIER_DEPLOYMENT_ENV=production

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

COPY --from=builder /app/apps/site/public ./apps/site/public
COPY --from=builder --chown=nextjs:nodejs /app/apps/site/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/apps/site/.next/static ./apps/site/.next/static

USER nextjs

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1

CMD ["node", "apps/site/server.js"]
