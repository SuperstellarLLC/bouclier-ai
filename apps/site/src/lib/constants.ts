export const APP_NAME = "Bouclier.ai";
export const APP_VERSION = "0.9.9";
export const APP_DESCRIPTION =
  "A local prompt-injection firewall for AI coding agents. Bouclier runs on your Mac and refuses requests when tool output — a web page, a README, an MCP result — tries to give your model orders. No certificate required.";
export const APP_URL = process.env.NEXT_PUBLIC_APP_URL ?? "https://www.bouclier.ai";

/**
 * Detection-engine size, quoted in user-facing copy.
 *
 * Hardcoded rather than imported so `constants.ts` stays free of the
 * pattern package (it is pulled into every route, including ones that
 * have no business shipping 161 regexes to the client). Drift is
 * prevented by `src/__tests__/constants.test.ts`, which asserts these
 * against the real export.
 */
export const PATTERN_COUNT = 186;
export const CATEGORY_COUNT = 21;

/**
 * User-visible download link. Routes through `/api/download` so the
 * server can record an anonymous timestamp before redirecting to the
 * actual DMG. The redirect target is server-only env
 * (`DOWNLOAD_REDIRECT_BASE`) — clients never see it.
 */
export const DOWNLOAD_URL = `/api/download?v=${APP_VERSION}&c=site`;
