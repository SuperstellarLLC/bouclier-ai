import { expect, test } from "@playwright/test";

test.describe("Home page", () => {
  test("should render successfully", async ({ page }) => {
    await page.goto("/");
    await expect(page).toHaveTitle(/Ilvarion/i);
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
