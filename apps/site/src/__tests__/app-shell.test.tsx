import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { GET as health } from "@/app/api/health/route";
import ErrorPage from "@/app/error";
import NotFound from "@/app/not-found";
import robots from "@/app/robots";
import { APP_URL } from "@/lib/constants";

describe("robots", () => {
  it("allows the site, blocks the API and points at the sitemap", () => {
    expect(robots()).toEqual({
      rules: { userAgent: "*", allow: "/", disallow: ["/api/"] },
      sitemap: `${APP_URL}/sitemap.xml`,
    });
  });
});

describe("GET /api/health", () => {
  it("reports healthy without caching", async () => {
    const res = health();
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toMatchObject({ status: "healthy" });
  });
});

describe("NotFound", () => {
  it("renders a 404 with a link home", () => {
    render(<NotFound />);
    expect(screen.getByRole("heading", { name: "404" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Back to Bouclier.ai" })).toHaveAttribute("href", "/");
  });
});

describe("Error boundary", () => {
  afterEach(() => vi.restoreAllMocks());

  it("logs the error and lets the user retry", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    const reset = vi.fn();
    const error = new Error("boom");

    render(<ErrorPage error={error} reset={reset} />);

    expect(screen.getByRole("alert")).toHaveTextContent("Something went wrong");
    expect(consoleError).toHaveBeenCalledWith("Unhandled error:", error);
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(reset).toHaveBeenCalledOnce();
  });
});
