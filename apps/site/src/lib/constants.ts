export const APP_NAME = "Bouclier.ai";
export const APP_VERSION = "0.8.0";
export const APP_DESCRIPTION =
  "Let your AI coding agent use your secrets without ever seeing them. Bouclier runs on your Mac and keeps API keys out of the model. No certificate required.";
export const APP_URL = process.env.NEXT_PUBLIC_APP_URL ?? "https://www.bouclier.ai";

/**
 * User-visible download link. Routes through `/api/download` so the
 * server can record an anonymous timestamp before redirecting to the
 * actual DMG. The redirect target is server-only env
 * (`DOWNLOAD_REDIRECT_BASE`) — clients never see it.
 */
export const DOWNLOAD_URL = `/api/download?v=${APP_VERSION}&c=site`;
