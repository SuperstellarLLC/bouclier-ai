import { createEnv } from "@t3-oss/env-nextjs";
import { z } from "zod";

export const env = createEnv({
  /**
   * Server-side environment variables schema.
   * These are not available on the client.
   */
  server: {
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    /**
     * Where the actual DMG lives. The /api/download route redirects here
     * after recording an anonymous timestamp. Falls back to the
     * legacy NEXT_PUBLIC_DOWNLOAD_URL if not set.
     */
    DOWNLOAD_REDIRECT_BASE: z.string().url().optional(),
    /**
     * Upstash Redis REST endpoint for download counts (optional).
     * When unset, the /api/download route logs to console instead and
     * still redirects to the DMG.
     */
    UPSTASH_REDIS_REST_URL: z.string().url().optional(),
    UPSTASH_REDIS_REST_TOKEN: z.string().min(8).optional(),
    /**
     * Bearer token required to read aggregated download stats from
     * /api/download/stats. Without it the stats endpoint 404s, so
     * deploying without the token is a safe default.
     */
    DOWNLOAD_STATS_TOKEN: z.string().min(16).optional(),
    // AUTH_SECRET: z.string().min(32),
  },

  /**
   * Client-side environment variables schema.
   * Prefix with `NEXT_PUBLIC_` to expose to the browser.
   */
  client: {
    NEXT_PUBLIC_APP_URL: z.string().url().default("http://localhost:3000"),
    // NEXT_PUBLIC_POSTHOG_KEY: z.string().optional(),
  },

  /**
   * Runtime values — must match the schema above.
   * Destructure `process.env` so Next.js can statically replace them.
   */
  runtimeEnv: {
    NODE_ENV: process.env.NODE_ENV,
    NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL,
    DOWNLOAD_REDIRECT_BASE: process.env.DOWNLOAD_REDIRECT_BASE,
    UPSTASH_REDIS_REST_URL: process.env.UPSTASH_REDIS_REST_URL,
    UPSTASH_REDIS_REST_TOKEN: process.env.UPSTASH_REDIS_REST_TOKEN,
    DOWNLOAD_STATS_TOKEN: process.env.DOWNLOAD_STATS_TOKEN,
    // NEXT_PUBLIC_POSTHOG_KEY: process.env.NEXT_PUBLIC_POSTHOG_KEY,
  },

  /**
   * Skip validation in Docker builds where env vars aren't available.
   */
  skipValidation: !!process.env.SKIP_ENV_VALIDATION,

  /**
   * Treat empty strings as undefined for optional vars.
   */
  emptyStringAsUndefined: true,
});
