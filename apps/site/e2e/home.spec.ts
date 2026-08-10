import { expect, test } from "@playwright/test";

test.describe("Home page", () => {
  test("should render successfully", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveTitle(/Bouclier.ai/i);
  });

  test("should display main heading", async ({ page }) => {
    await page.goto("/");
    const heading = page.getByRole("heading", { level: 1 });
    await expect(heading).toBeVisible();
  });

  test("should be responsive", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/");
    const heading = page.getByRole("heading", { level: 1 });
    await expect(heading).toBeVisible();
  });
});

test.describe("Injection playground", () => {
  // The provenance split is the product claim. If the toggle stops
  // changing the verdict, the homepage is advertising something the
  // gateway does but the demo no longer demonstrates.
  test("same payload flips between REFUSED and FLAGGED with its origin", async ({ page }) => {
    await page.goto("/#playground");

    const playground = page.locator("#playground");
    const verdict = playground.getByText(/^(REFUSED|FLAGGED|CLEAN)$/);
    const toolOutput = playground.getByRole("radio", { name: /tool output/i });
    const youTyped = playground.getByRole("radio", { name: /you typed it/i });

    // Default preset is a poisoned page arriving as tool output.
    await expect(toolOutput).toBeVisible();
    await expect(verdict).toHaveText("REFUSED");

    // Same text, reattributed to the operator — must not be refused.
    await youTyped.click();
    await expect(verdict).toHaveText("FLAGGED");

    // And back.
    await toolOutput.click();
    await expect(verdict).toHaveText("REFUSED");
  });

  test("an ordinary request is clean", async ({ page }) => {
    await page.goto("/#playground");
    const playground = page.locator("#playground");
    await playground.getByRole("button", { name: /you, ordinary request/i }).click();
    await expect(playground.getByText(/^(REFUSED|FLAGGED|CLEAN)$/)).toHaveText("CLEAN");
  });
});

test.describe("Blocked explainer", () => {
  test("renders the page the 403 points at", async ({ page }) => {
    await page.goto("/blocked");
    await expect(page.getByRole("heading", { name: /your request was refused/i })).toBeVisible();
  });
});

test.describe("404 page", () => {
  test("should show not found for invalid routes", async ({ page }) => {
    await page.goto("/this-page-does-not-exist");
    await expect(page.getByText(/404/i)).toBeVisible();
  });
});

test.describe("Security headers", () => {
  test("should include security headers", async ({ page }) => {
    const response = await page.goto("/");
    const headers = response?.headers();
    expect(headers?.["x-content-type-options"]).toBe("nosniff");
    expect(headers?.["x-frame-options"]).toBe("SAMEORIGIN");
    expect(headers?.["referrer-policy"]).toBe("strict-origin-when-cross-origin");
  });
});

test.describe("Health check", () => {
  test("should return healthy status", async ({ request }) => {
    const response = await request.get("/api/health");
    expect(response.ok()).toBeTruthy();
    const body = await response.json();
    expect(body.status).toBe("healthy");
  });
});
