export const APP_NAME = "Bouclier.ai";
export const APP_VERSION = "0.6.0";
export const APP_DESCRIPTION =
  "Let your AI coding agent use your secrets without ever seeing them. Bouclier runs on your Mac: keeps API keys out of the model, blocks prompt-injection attacks, and strips PII from uploads. No certificate required.";
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
