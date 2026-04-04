import { createEnv } from "@t3-oss/env-nextjs";
import { z } from "zod";

export const env = createEnv({
  /**
   * Server-side environment variables schema.
   * These are not available on the client.
   */
  server: {
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    // DATABASE_URL: z.string().url(),
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
    // DATABASE_URL: process.env.DATABASE_URL,
    // AUTH_SECRET: process.env.AUTH_SECRET,
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
