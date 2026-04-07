export const APP_NAME = "Bouclier.ai";
export const APP_VERSION = "0.2.6";
export const APP_DESCRIPTION =
  "Local prompt injection firewall for macOS. Scans AI API traffic, MCP tool results, and streaming responses. No data leaves your machine.";
export const APP_URL = process.env.NEXT_PUBLIC_APP_URL ?? "https://www.bouclier.ai";
export const DOWNLOAD_URL =
  (process.env.NEXT_PUBLIC_DOWNLOAD_URL ?? "") + `/Bouclier-ai-v${APP_VERSION}-macOS.dmg`;

// Detection coverage numbers shown on the landing page. Kept in sync
// with packages/patterns benchmark (src/__tests__/benchmark.test.ts).
export const PATTERN_COUNT = 161;
export const CATEGORY_COUNT = 21;
export const BENCHMARK_ATTACKS = 442;
export const BENCHMARK_BENIGN = 240;
export const BENCHMARK_TPR = "91.9%";
export const BENCHMARK_FPR = "2.9%";
