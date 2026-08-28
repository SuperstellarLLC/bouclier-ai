import { versionAtLeast } from "../../release-alignment";

export const APP_NAME = "Bouclier.ai";
export const APP_VERSION = "0.9.10";
export const APP_DESCRIPTION =
  "A local prompt-injection firewall for AI coding agents. Bouclier monitors untrusted tool output on your Mac by default; enable blocking to refuse requests that cross its detection threshold. No certificate required.";
export const APP_URL = process.env.NEXT_PUBLIC_APP_URL ?? "https://www.bouclier.ai";

/**
 * The downloadable 0.9.10 app contains the old MCP pipe wrapper, not the
 * read-only status server implemented in the current source tree. Keep that
 * capability out of deployed marketing until the release script bumps the
 * downloadable version; this prevents a main-branch site deploy from getting
 * ahead of the signed DMG.
 */
export const STATUS_MCP_AVAILABLE = versionAtLeast(APP_VERSION, "0.9.11");
export const ENFORCEMENT_STATUS_AVAILABLE = versionAtLeast(APP_VERSION, "0.9.11");

/**
 * Detection-engine size, quoted in user-facing copy.
 *
 * Hardcoded rather than imported so `constants.ts` stays free of the
 * pattern package (it is pulled into every route, including ones that
 * have no business shipping the full regex set to the client). Drift is
 * prevented by `src/__tests__/constants.test.ts`, which asserts these
 * against the real export.
 */
export const PATTERN_COUNT = 186;
export const CATEGORY_COUNT = 21;

/**
 * User-visible download link. Routes through `/api/download` so the
 * server can record a timestamp/version/channel event with no application
 * identifier before redirecting to the actual DMG. The redirect target is server-only env
 * (`DOWNLOAD_REDIRECT_BASE`) — clients never see it.
 */
export const DOWNLOAD_URL = `/api/download?v=${APP_VERSION}&c=site`;
