#!/usr/bin/env bash
set -euo pipefail

# ╔══════════════════════════════════════════════════════════════════╗
# ║  create-app — Enterprise-grade Next.js 16 boilerplate scaffold  ║
# ║                                                                  ║
# ║  Usage: ./create-app.sh <project-name> [--no-install] [--no-git] ║
# ║                                                                  ║
# ║  Creates a production-ready Next.js project with:                ║
# ║  • Security headers (CSP, HSTS, X-Frame-Options, etc.)          ║
# ║  • CI/CD (GitHub Actions: lint, test, e2e, build, security)     ║
# ║  • Testing (Vitest + React Testing Library + Playwright)        ║
# ║  • Docker (multi-stage alpine, non-root, healthcheck)           ║
# ║  • Code quality (ESLint, Prettier, Husky, commitlint)           ║
# ║  • Strict TypeScript, env validation (t3-env + zod)             ║
# ╚══════════════════════════════════════════════════════════════════╝

VERSION="1.0.0"
NODE_MIN="22"

# ── Parse args ────────────────────────────────
if [ $# -lt 1 ] || [[ "$1" == -* ]]; then
  echo "Usage: create-app.sh <project-name> [--no-install] [--no-git]"
  echo ""
  echo "Creates an enterprise-grade Next.js 16 project in ./<project-name>"
  exit 1
fi

NAME="$1"
SKIP_INSTALL=false
SKIP_GIT=false

shift
for arg in "$@"; do
  case "$arg" in
    --no-install) SKIP_INSTALL=true ;;
    --no-git) SKIP_GIT=true ;;
  esac
done

if [ -d "$NAME" ]; then
  echo "Error: directory '$NAME' already exists"
  exit 1
fi

echo ""
echo "  Creating $NAME..."
echo ""

mkdir -p "$NAME"
cd "$NAME"
ROOT=$(pwd)

# ── Helper ────────────────────────────────────
write() { mkdir -p "$(dirname "$1")" && cat > "$1"; }

# ══════════════════════════════════════════════
# Package & Config
# ══════════════════════════════════════════════

write package.json <<ENDL
{
  "name": "${NAME}",
  "version": "0.1.0",
  "private": true,
  "packageManager": "pnpm@9.15.0",
  "engines": { "node": ">=${NODE_MIN}.0.0" },
  "scripts": {
    "dev": "next dev --turbopack",
    "build": "next build",
    "start": "next start",
    "lint": "eslint .",
    "lint:fix": "eslint . --fix",
    "format": "prettier --write .",
    "format:check": "prettier --check .",
    "typecheck": "tsc --noEmit",
    "test": "vitest run",
    "test:watch": "vitest",
    "test:coverage": "vitest run --coverage",
    "test:e2e": "playwright test",
    "test:e2e:ui": "playwright test --ui",
    "analyze": "ANALYZE=true next build",
    "check": "npm run typecheck && npm run lint && npm run format:check && npm run test",
    "prepare": "husky"
  },
  "dependencies": {
    "@t3-oss/env-nextjs": "^0.12.0",
    "next": "^16.2.2",
    "react": "^19.2.0",
    "react-dom": "^19.2.0",
    "zod": "^3.24.0"
  },
  "devDependencies": {
    "@commitlint/cli": "^19.0.0",
    "@commitlint/config-conventional": "^19.0.0",
    "@commitlint/types": "^19.0.0",
    "@next/bundle-analyzer": "^16.2.0",
    "@playwright/test": "^1.50.0",
    "@tailwindcss/postcss": "^4",
    "@testing-library/jest-dom": "^6.6.0",
    "@testing-library/react": "^16.2.0",
    "@types/node": "^22",
    "@types/react": "^19",
    "@types/react-dom": "^19",
    "@vitejs/plugin-react": "^4.4.0",
    "@vitest/coverage-v8": "^3.1.0",
    "eslint": "^9",
    "eslint-config-next": "^16.2.2",
    "eslint-config-prettier": "^10.1.0",
    "husky": "^9.1.0",
    "jsdom": "^26.0.0",
    "lint-staged": "^15.4.0",
    "postcss": "^8",
    "prettier": "^3.5.0",
    "prettier-plugin-tailwindcss": "^0.6.0",
    "tailwindcss": "^4",
    "typescript": "^5.9.0",
    "vitest": "^3.1.0"
  }
}
ENDL

write tsconfig.json <<'ENDL'
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["dom", "dom.iterable", "esnext"],
    "allowJs": true,
    "skipLibCheck": true,
    "strict": true,
    "noEmit": true,
    "esModuleInterop": true,
    "module": "esnext",
    "moduleResolution": "bundler",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "jsx": "react-jsx",
    "incremental": true,
    "noUncheckedIndexedAccess": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "forceConsistentCasingInFileNames": true,
    "plugins": [{ "name": "next" }],
    "paths": { "@/*": ["./src/*"] }
  },
  "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx", ".next/types/**/*.ts", ".next/dev/types/**/*.ts", "**/*.mts"],
  "exclude": ["node_modules", "coverage", "playwright-report"]
}
ENDL

write next.config.ts <<'ENDL'
import type { NextConfig } from "next";
import bundleAnalyzer from "@next/bundle-analyzer";

const withBundleAnalyzer = bundleAnalyzer({
  enabled: process.env.ANALYZE === "true",
});

const securityHeaders = [
  { key: "X-DNS-Prefetch-Control", value: "on" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "SAMEORIGIN" },
  { key: "X-XSS-Protection", value: "1; mode=block" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), browsing-topics=()",
  },
];

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  reactStrictMode: true,
  images: { formats: ["image/avif", "image/webp"] },

  async headers() {
    return [{ source: "/(.*)", headers: securityHeaders }];
  },

  logging: { fetches: { fullUrl: true } },
  typedRoutes: true,
};

export default withBundleAnalyzer(nextConfig);
ENDL

write postcss.config.mjs <<'ENDL'
const config = {
  plugins: {
    "@tailwindcss/postcss": {},
  },
};

export default config;
ENDL

# ══════════════════════════════════════════════
# ESLint, Prettier, Editor
# ══════════════════════════════════════════════

write eslint.config.mjs <<'ENDL'
import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";
import prettier from "eslint-config-prettier";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  prettier,
  {
    rules: {
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/consistent-type-imports": [
        "warn",
        { prefer: "type-imports", fixStyle: "inline-type-imports" },
      ],
      "react/no-danger": "error",
    },
  },
  globalIgnores([".next/**", "out/**", "build/**", "dist/**", "coverage/**", "next-env.d.ts"]),
]);

export default eslintConfig;
ENDL

write .prettierrc <<'ENDL'
{
  "semi": true,
  "singleQuote": false,
  "tabWidth": 2,
  "trailingComma": "all",
  "printWidth": 100,
  "bracketSpacing": true,
  "arrowParens": "always",
  "endOfLine": "lf",
  "plugins": ["prettier-plugin-tailwindcss"]
}
ENDL

write .prettierignore <<'ENDL'
node_modules
.next
out
build
dist
coverage
playwright-report
pnpm-lock.yaml
ENDL

write .editorconfig <<'ENDL'
root = true

[*]
charset = utf-8
end_of_line = lf
indent_size = 2
indent_style = space
insert_final_newline = true
trim_trailing_whitespace = true

[*.md]
trim_trailing_whitespace = false
ENDL

write .vscode/settings.json <<'ENDL'
{
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "esbenp.prettier-vscode",
  "editor.codeActionsOnSave": { "source.fixAll.eslint": "explicit" },
  "typescript.tsdk": "node_modules/typescript/lib",
  "typescript.enablePromptUseWorkspaceTsdk": true,
  "files.eol": "\n"
}
ENDL

write .vscode/extensions.json <<'ENDL'
{
  "recommendations": [
    "esbenp.prettier-vscode",
    "dbaeumer.vscode-eslint",
    "bradlc.vscode-tailwindcss",
    "editorconfig.editorconfig",
    "ms-playwright.playwright"
  ]
}
ENDL

# ══════════════════════════════════════════════
# Git Hooks
# ══════════════════════════════════════════════

write .lintstagedrc.mjs <<'ENDL'
const config = {
  "*.{js,jsx,ts,tsx,mjs,mts}": ["eslint --fix", "prettier --write"],
  "*.{json,css,md,yml,yaml}": ["prettier --write"],
};

export default config;
ENDL

write commitlint.config.ts <<'ENDL'
import type { UserConfig } from "@commitlint/types";

const config: UserConfig = {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "subject-case": [2, "never", ["start-case", "pascal-case", "upper-case"]],
    "header-max-length": [2, "always", 100],
  },
};

export default config;
ENDL

mkdir -p .husky
write .husky/pre-commit <<'ENDL'
npx lint-staged
ENDL
chmod +x .husky/pre-commit

write .husky/commit-msg <<'ENDL'
npx --no -- commitlint --edit "$1"
ENDL
chmod +x .husky/commit-msg

# ══════════════════════════════════════════════
# Environment
# ══════════════════════════════════════════════

write .env.example <<ENDL
# ── ${NAME} ──────────────────────────────────
NODE_ENV=development
NEXT_PUBLIC_APP_URL=http://localhost:3000
# DATABASE_URL=
# AUTH_SECRET=
ENDL

write .nvmrc <<ENDL
${NODE_MIN}
ENDL

write src/env.ts <<'ENDL'
import { createEnv } from "@t3-oss/env-nextjs";
import { z } from "zod";

export const env = createEnv({
  server: {
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  },
  client: {
    NEXT_PUBLIC_APP_URL: z.string().url().default("http://localhost:3000"),
  },
  runtimeEnv: {
    NODE_ENV: process.env.NODE_ENV,
    NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL,
  },
  skipValidation: !!process.env.SKIP_ENV_VALIDATION,
  emptyStringAsUndefined: true,
});
ENDL

# ══════════════════════════════════════════════
# Testing
# ══════════════════════════════════════════════

write vitest.config.ts <<'ENDL'
import react from "@vitejs/plugin-react";
import { resolve } from "path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": resolve(__dirname, "./src") } },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/__tests__/setup.ts"],
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json-summary", "html"],
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/__tests__/**", "src/**/*.d.ts", "src/env.ts"],
      thresholds: { statements: 50, branches: 50, functions: 50, lines: 50 },
    },
  },
});
ENDL

write playwright.config.ts <<'ENDL'
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? "github" : "html",
  timeout: 30_000,
  use: { baseURL: "http://localhost:3000", trace: "on-first-retry", screenshot: "only-on-failure" },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: {
    command: "npm run build && npm run start",
    port: 3000,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: { SKIP_ENV_VALIDATION: "true" },
  },
});
ENDL

write src/__tests__/setup.ts <<'ENDL'
import "@testing-library/jest-dom/vitest";
ENDL

write src/__tests__/home.test.tsx <<ENDL
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import Home from "@/app/page";

describe("Home page", () => {
  it("renders the heading", () => {
    render(<Home />);
    expect(screen.getByRole("heading", { level: 1 })).toBeInTheDocument();
  });
});
ENDL

write e2e/home.spec.ts <<'ENDL'
import { expect, test } from "@playwright/test";

test("should render home page", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
});

test("health check returns ok", async ({ request }) => {
  const res = await request.get("/api/health");
  expect(res.ok()).toBeTruthy();
  const body = await res.json();
  expect(body.status).toBe("healthy");
});

test("security headers present", async ({ page }) => {
  const res = await page.goto("/");
  expect(res?.headers()["x-content-type-options"]).toBe("nosniff");
  expect(res?.headers()["x-frame-options"]).toBe("SAMEORIGIN");
});
ENDL

# ══════════════════════════════════════════════
# Application Source
# ══════════════════════════════════════════════

write src/lib/constants.ts <<ENDL
export const APP_NAME = "${NAME}";
export const APP_DESCRIPTION = "Welcome to ${NAME}";
export const APP_URL = process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000";
ENDL

write src/app/globals.css <<'ENDL'
@import "tailwindcss";

:root {
  --background: #0a0a0a;
  --foreground: #ededed;
}

@theme inline {
  --color-background: var(--background);
  --color-foreground: var(--foreground);
  --font-sans: var(--font-geist-sans);
  --font-mono: var(--font-geist-mono);
}

body {
  background: var(--background);
  color: var(--foreground);
  font-family: var(--font-sans), system-ui, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
}

:focus-visible {
  outline: 2px solid #3b82f6;
  outline-offset: 2px;
}
ENDL

write src/app/layout.tsx <<ENDL
import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";

import { APP_DESCRIPTION, APP_NAME, APP_URL } from "@/lib/constants";

import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"], display: "swap" });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"], display: "swap" });

export const metadata: Metadata = {
  title: { default: APP_NAME, template: \`%s | \${APP_NAME}\` },
  description: APP_DESCRIPTION,
  metadataBase: new URL(APP_URL),
  openGraph: { title: APP_NAME, description: APP_DESCRIPTION, siteName: APP_NAME, locale: "en_US", type: "website" },
  robots: { index: true, follow: true },
};

export const viewport: Viewport = {
  themeColor: "#000000",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={\`\${geistSans.variable} \${geistMono.variable} antialiased\`}>{children}</body>
    </html>
  );
}
ENDL

write src/app/page.tsx <<ENDL
export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-6">
      <h1 className="text-4xl font-bold">${NAME}</h1>
      <p className="mt-4 text-lg text-white/60">Ready for production.</p>
    </main>
  );
}
ENDL

write src/app/not-found.tsx <<'ENDL'
export default function NotFound() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-6">
      <h1 className="text-6xl font-bold">404</h1>
      <p className="mt-4 text-lg text-white/60">Page not found.</p>
    </main>
  );
}
ENDL

write src/app/error.tsx <<'ENDL'
"use client";

import { useEffect } from "react";

export default function Error({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  useEffect(() => { console.error("Unhandled error:", error); }, [error]);

  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-6 text-center">
      <h1 className="text-4xl font-bold">Something went wrong</h1>
      <p className="mt-4 text-lg text-white/60">An unexpected error occurred.</p>
      <button onClick={reset} className="mt-8 rounded-lg bg-white/10 px-6 py-3 text-sm font-medium text-white hover:bg-white/20">
        Try again
      </button>
    </main>
  );
}
ENDL

write src/app/loading.tsx <<'ENDL'
export default function Loading() {
  return (
    <main className="flex min-h-screen items-center justify-center">
      <div className="h-8 w-8 animate-spin rounded-full border-2 border-white/20 border-t-white" />
    </main>
  );
}
ENDL

write src/app/api/health/route.ts <<'ENDL'
import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export function GET() {
  return NextResponse.json(
    { status: "healthy", timestamp: new Date().toISOString(), uptime: process.uptime() },
    { status: 200, headers: { "Cache-Control": "no-store" } },
  );
}
ENDL

write src/app/robots.ts <<'ENDL'
import type { MetadataRoute } from "next";
import { APP_URL } from "@/lib/constants";

export default function robots(): MetadataRoute.Robots {
  return { rules: { userAgent: "*", allow: "/", disallow: ["/api/"] }, sitemap: `${APP_URL}/sitemap.xml` };
}
ENDL

write src/app/sitemap.ts <<'ENDL'
import type { MetadataRoute } from "next";
import { APP_URL } from "@/lib/constants";

export default function sitemap(): MetadataRoute.Sitemap {
  return [{ url: APP_URL, lastModified: new Date(), changeFrequency: "monthly", priority: 1 }];
}
ENDL

write src/middleware.ts <<'ENDL'
import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

const rateLimit = new Map<string, { count: number; resetTime: number }>();
const WINDOW_MS = 60_000;
const MAX_REQUESTS = 100;

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = rateLimit.get(ip);
  if (!entry || now > entry.resetTime) {
    rateLimit.set(ip, { count: 1, resetTime: now + WINDOW_MS });
    return false;
  }
  entry.count++;
  if (rateLimit.size > 10_000) {
    for (const [key, val] of rateLimit) {
      if (now > val.resetTime) rateLimit.delete(key);
    }
  }
  return entry.count > MAX_REQUESTS;
}

function generateNonce(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return btoa(String.fromCharCode(...array));
}

export function middleware(request: NextRequest) {
  const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  if (isRateLimited(ip)) return new NextResponse("Too Many Requests", { status: 429 });

  const nonce = generateNonce();
  const isProd = process.env.NODE_ENV === "production";
  const csp = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' ${isProd ? "" : "'unsafe-eval'"}`.trim(),
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data: blob:`,
    `font-src 'self'`,
    `connect-src 'self'`,
    `frame-ancestors 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `upgrade-insecure-requests`,
  ];

  const response = NextResponse.next({ request: { headers: new Headers(request.headers) } });
  response.headers.set("Content-Security-Policy", csp.join("; "));
  response.headers.set("x-nonce", nonce);
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico|images/).*)"],
};
ENDL

# ══════════════════════════════════════════════
# Docker
# ══════════════════════════════════════════════

write Dockerfile <<'ENDL'
FROM node:22-alpine AS deps
RUN apk add --no-cache libc6-compat
RUN corepack enable pnpm
WORKDIR /app
COPY pnpm-lock.yaml package.json ./
RUN pnpm install --frozen-lockfile

FROM node:22-alpine AS builder
RUN corepack enable pnpm
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1 SKIP_ENV_VALIDATION=true
RUN pnpm run build

FROM node:22-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs
COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
USER nextjs
EXPOSE 3000
ENV PORT=3000 HOSTNAME="0.0.0.0"
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/api/health || exit 1
CMD ["node", "server.js"]
ENDL

write .dockerignore <<'ENDL'
node_modules
.next
.git
.github
.vscode
coverage
playwright-report
test-results
e2e
*.md
.env*
!.env.example
.DS_Store
ENDL

write docker-compose.yml <<'ENDL'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    env_file:
      - .env.local
    environment:
      - NODE_ENV=production
    restart: unless-stopped
ENDL

# ══════════════════════════════════════════════
# GitHub
# ══════════════════════════════════════════════

write .github/workflows/ci.yml <<'ENDL'
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

env:
  NODE_VERSION: "22"
  SKIP_ENV_VALIDATION: "true"

jobs:
  lint:
    name: Lint & Typecheck
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with: { node-version: "${{ env.NODE_VERSION }}", cache: "pnpm" }
      - run: pnpm install --frozen-lockfile
      - run: pnpm typecheck
      - run: pnpm lint
      - run: pnpm format:check

  test:
    name: Unit Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with: { node-version: "${{ env.NODE_VERSION }}", cache: "pnpm" }
      - run: pnpm install --frozen-lockfile
      - run: pnpm test:coverage
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: coverage, path: coverage/, retention-days: 14 }

  e2e:
    name: E2E Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with: { node-version: "${{ env.NODE_VERSION }}", cache: "pnpm" }
      - run: pnpm install --frozen-lockfile
      - run: npx playwright install --with-deps chromium
      - run: pnpm build && pnpm test:e2e
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: playwright-report, path: playwright-report/, retention-days: 14 }

  build:
    name: Build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with: { node-version: "${{ env.NODE_VERSION }}", cache: "pnpm" }
      - run: pnpm install --frozen-lockfile
      - run: pnpm build

  security:
    name: Security Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: pnpm/action-setup@v4
      - uses: actions/setup-node@v4
        with: { node-version: "${{ env.NODE_VERSION }}", cache: "pnpm" }
      - run: pnpm install --frozen-lockfile
      - run: pnpm audit --audit-level=high
ENDL

write .github/dependabot.yml <<'ENDL'
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule: { interval: "weekly", day: "monday" }
    open-pull-requests-limit: 10
    groups:
      dev: { dependency-type: "development", update-types: ["minor", "patch"] }
      prod: { dependency-type: "production", update-types: ["patch"] }
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule: { interval: "weekly", day: "monday" }
ENDL

write .github/pull_request_template.md <<'ENDL'
## Summary
<!-- Brief description -->

## Type
- [ ] Bug fix
- [ ] Feature
- [ ] Refactor
- [ ] CI/CD

## Checklist
- [ ] `pnpm check` passes
- [ ] Tests added/updated
- [ ] No new TypeScript errors
ENDL

# ══════════════════════════════════════════════
# Gitignore
# ══════════════════════════════════════════════

write .gitignore <<'ENDL'
node_modules/
coverage/
playwright-report/
test-results/
.next/
out/
build/
dist/
.DS_Store
*.pem
Thumbs.db
npm-debug.log*
yarn-debug.log*
.pnpm-debug.log*
.env
.env.local
.env.*.local
.vercel
*.tsbuildinfo
next-env.d.ts
.sentryclirc
.idea/
.vscode/*
!.vscode/settings.json
!.vscode/extensions.json
*.swp
*.swo
docker-compose.override.yml
.turbo/
ENDL

# ══════════════════════════════════════════════
# Install & Verify
# ══════════════════════════════════════════════

if [ "$SKIP_INSTALL" = false ]; then
  echo "  Installing dependencies..."
  pnpm install --silent 2>&1 | tail -3

  echo "  Verifying build..."
  SKIP_ENV_VALIDATION=true pnpm build 2>&1 | grep -E "✓|Route|error" || true

  echo "  Running tests..."
  pnpm test 2>&1 | grep -E "Tests|passed|failed" || true
fi

if [ "$SKIP_GIT" = false ]; then
  git init -q
  git add -A
  git commit -q -m "feat: initial project setup"
  echo ""
  echo "  Git initialized with initial commit."
fi

echo ""
echo "  ✓ ${NAME} is ready!"
echo ""
echo "  cd ${NAME}"
echo "  pnpm dev"
echo ""
