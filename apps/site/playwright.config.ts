import { defineConfig, devices } from "@playwright/test";

const testHost = "127.0.0.1";
const testPort = 4173;

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI
    ? [["github"], ["html", { outputFolder: "playwright-report", open: "never" }]]
    : "html",
  timeout: 30_000,

  use: {
    baseURL: `http://${testHost}:${testPort}`,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
    },
    {
      name: "mobile-chrome",
      use: { ...devices["Pixel 5"] },
    },
    {
      name: "mobile-safari",
      use: { ...devices["iPhone 12"] },
    },
  ],

  webServer: {
    command: "pnpm build && pnpm start",
    port: testPort,
    // Reusing an arbitrary listener can silently run the suite against a
    // different local product. A dedicated port plus a fresh server keeps the
    // browser evidence tied to this checkout in both local and CI runs.
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      HOSTNAME: testHost,
      PORT: String(testPort),
      SKIP_ENV_VALIDATION: "true",
    },
  },
});
