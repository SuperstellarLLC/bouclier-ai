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
    await page.setViewportSize({ width: 320, height: 667 });
    await page.goto("/");
    const heading = page.getByRole("heading", { level: 1 });
    await expect(heading).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(320);
  });

  test("does not contact third-party font or analytics hosts", async ({ page, baseURL }) => {
    const thirdPartyRequests: string[] = [];
    const firstPartyOrigin = new URL(baseURL ?? "http://invalid.test").origin;
    page.on("request", (request) => {
      const url = new URL(request.url());
      if (url.origin !== firstPartyOrigin) thirdPartyRequests.push(request.url());
    });

    // `networkidle` is not a reliable page-readiness signal: browser and
    // framework background connections can keep it pending after the UI is
    // fully rendered. Wait for the concrete, hydrated product surface that
    // could initiate fonts or analytics instead.
    await page.goto("/", { waitUntil: "load" });
    await expect(page.getByRole("textbox", { name: "Content to scan" })).toBeVisible();
    expect(thirdPartyRequests).toEqual([]);
  });

  test("mobile navigation includes legal pages and closes with Escape", async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 667 });
    await page.goto("/");

    const trigger = page.getByRole("button", { name: /open menu/i });
    const menuId = await trigger.getAttribute("aria-controls");
    expect(menuId).toBeTruthy();
    await trigger.click();
    const menu = page.locator(`[id="${menuId}"]`);
    await expect(menu.getByRole("link", { name: "Terms", exact: true })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(menu).toBeHidden();
    await expect(trigger).toBeFocused();
  });
});

test.describe("Injection playground", () => {
  // The provenance split is the product claim. If the toggle stops
  // changing the verdict, the homepage is advertising something the
  // gateway does but the demo no longer demonstrates.
  test("monitoring is the default and blocking must be explicitly enabled", async ({ page }) => {
    await page.goto("/#playground");

    const playground = page.locator("#playground");
    const verdict = playground.getByText(/^(REFUSED|WOULD REFUSE|FLAGGED|FORWARDED|CLEAN)$/);
    const toolOutput = playground.getByRole("radio", { name: /tool output/i });
    const youTyped = playground.getByRole("radio", { name: /you typed it/i });
    const monitor = playground.getByRole("radio", { name: /^monitor/i });
    const blocking = playground.getByRole("radio", { name: /^blocking/i });

    // Default preset is poisoned tool output, but the product starts by
    // monitoring: it must truthfully say what would happen without claiming
    // that it already refused the request.
    await expect(toolOutput).toBeVisible();
    await expect(monitor).toBeChecked();
    await expect(verdict).toHaveText("WOULD REFUSE");

    // Only explicit enforcement turns that same finding into a refusal.
    await blocking.check();
    await expect(verdict).toHaveText("REFUSED");

    // Same stand-alone text, reattributed to the operator — normal mode
    // bypasses injection scoring rather than creating a gateway finding.
    await youTyped.check();
    await expect(verdict).toHaveText("FORWARDED");

    // And back, while blocking remains explicit.
    await toolOutput.check();
    await expect(verdict).toHaveText("REFUSED");

    await monitor.check();
    await expect(verdict).toHaveText("WOULD REFUSE");
  });

  test("an ordinary principal-only request is forwarded without scoring", async ({ page }) => {
    await page.goto("/#playground");
    const playground = page.locator("#playground");
    await playground.getByRole("button", { name: /you, ordinary request/i }).click();
    await expect(playground.getByText(/^(REFUSED|FLAGGED|FORWARDED|CLEAN)$/)).toHaveText(
      "FORWARDED",
    );
  });
});

test.describe("Informational pages", () => {
  test("renders the page a 422 refusal points at", async ({ page }) => {
    await page.goto("/blocked");
    await expect(page.getByRole("heading", { name: /your request was refused/i })).toBeVisible();
  });

  for (const path of ["/privacy", "/terms", "/indirect-prompt-injection"]) {
    test(`${path} has a title, one H1, and no narrow-screen overflow`, async ({ page }) => {
      await page.setViewportSize({ width: 320, height: 667 });
      await page.goto(path);
      await expect(page).not.toHaveTitle("");
      await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
      expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBe(320);
    });
  }
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
    // DENY (not SAMEORIGIN) to match the CSP `frame-ancestors 'none'` — the
    // site never frames itself, so all framing is refused.
    expect(headers?.["x-frame-options"]).toBe("DENY");
    expect(headers?.["referrer-policy"]).toBe("strict-origin-when-cross-origin");
    expect(headers?.["x-xss-protection"]).toBe("0");
    expect(headers?.["x-dns-prefetch-control"]).toBe("off");
    expect(headers?.["content-security-policy"]).toContain("font-src 'self'");
    expect(headers?.["content-security-policy"]).not.toContain("fonts.gstatic.com");
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
