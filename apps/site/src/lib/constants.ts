export const APP_NAME = "Bouclier.ai";
export const APP_VERSION = "0.3.0";
export const APP_DESCRIPTION =
  "Local prompt injection firewall for macOS. Scans AI API traffic, MCP tool results, and streaming responses. No data leaves your machine.";
export const APP_URL = process.env.NEXT_PUBLIC_APP_URL ?? "https://www.bouclier.ai";

/**
 * User-visible download link. Routes through `/api/download` so the
 * server can record an anonymous timestamp before redirecting to the
 * actual DMG. The redirect target is server-only env
 * (`DOWNLOAD_REDIRECT_BASE`) — clients never see it.
 */
export const DOWNLOAD_URL = `/api/download?v=${APP_VERSION}&c=site`;

// Detection coverage numbers shown on the landing page. Kept in sync
// with packages/patterns benchmark (src/__tests__/benchmark.test.ts).
export const PATTERN_COUNT = 161;
export const CATEGORY_COUNT = 21;
export const BENCHMARK_ATTACKS = 442;
export const BENCHMARK_BENIGN = 240;
export const BENCHMARK_TPR = "91.9%";
export const BENCHMARK_FPR = "2.9%";
