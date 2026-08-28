import type { NextConfig } from "next";
import bundleAnalyzer from "@next/bundle-analyzer";
import { readFileSync } from "node:fs";
import path from "node:path";

import { APP_VERSION } from "./src/lib/constants";
import {
  assertProductionReleaseAlignment,
  isProductionDeployment,
  SELF_HOSTED_DEPLOYMENT_ENV_VAR,
} from "./release-alignment";

const vercelEnvironment = process.env.VERCEL_ENV;
const selfHostedEnvironment = process.env[SELF_HOSTED_DEPLOYMENT_ENV_VAR];
const productionDeployment = isProductionDeployment(vercelEnvironment, selfHostedEnvironment);

assertProductionReleaseAlignment({
  vercelEnvironment,
  selfHostedEnvironment,
  desktopVersion: APP_VERSION,
  // Local and Vercel preview builds intentionally remain usable while a
  // release is being prepared. Production builds alone consume and validate
  // the appcast committed beside this config.
  appcastXml: productionDeployment
    ? readFileSync(new URL("./public/appcast.xml", import.meta.url), "utf8")
    : undefined,
});

const withBundleAnalyzer = bundleAnalyzer({
  enabled: process.env.ANALYZE === "true",
});

// The App Router injects inline hydration scripts, so `unsafe-inline` remains
// necessary here. Development also needs eval for React Refresh; production
// deliberately does not. Keep the policy in `headers()` rather than Proxy:
// it is static, needs no request data, and should not add work to every route.
const scriptSrc =
  process.env.NODE_ENV === "development"
    ? `script-src 'self' 'unsafe-inline' 'unsafe-eval'`
    : `script-src 'self' 'unsafe-inline'`;
const contentSecurityPolicy = [
  `default-src 'self'`,
  scriptSrc,
  `style-src 'self' 'unsafe-inline'`,
  `img-src 'self' data: blob:`,
  `font-src 'self'`,
  `connect-src 'self'`,
  `frame-ancestors 'none'`,
  `base-uri 'self'`,
  `form-action 'self'`,
  `object-src 'none'`,
].join("; ");

const securityHeaders = [
  { key: "Content-Security-Policy", value: contentSecurityPolicy },
  { key: "X-DNS-Prefetch-Control", value: "off" },
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  // Disable obsolete browser XSS auditors; CSP is the modern control and the
  // legacy filters can themselves create injection vulnerabilities.
  { key: "X-XSS-Protection", value: "0" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), browsing-topics=()",
  },
];

const nextConfig: NextConfig = {
  // This package inherits repository-level agent instructions. Avoid writing
  // generated AGENTS.md / CLAUDE.md files into the app during `next dev`.
  agentRules: false,

  poweredByHeader: false,

  // The documented Docker image copies Next's traced standalone server.
  // Without this, `.next/standalone` is never produced and the image cannot
  // be built. The package runs with apps/site as its cwd, so tracing two
  // levels up includes workspace dependencies.
  output: "standalone",
  outputFileTracingRoot: path.resolve(process.cwd(), "../.."),

  reactStrictMode: true,

  images: {
    formats: ["image/avif", "image/webp"],
  },

  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },

  logging: {
    fetches: {
      fullUrl: true,
    },
  },

  typedRoutes: true,
};

export default withBundleAnalyzer(nextConfig);
