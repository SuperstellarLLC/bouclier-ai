import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import sitemap from "@/app/sitemap";
import { APP_URL } from "@/lib/constants";

describe("site metadata and privacy posture", () => {
  it("includes every indexable page in the sitemap with stable modification dates", () => {
    const entries = sitemap();
    expect(entries.map((entry) => entry.url)).toEqual([
      APP_URL,
      `${APP_URL}/indirect-prompt-injection`,
      `${APP_URL}/blocked`,
      `${APP_URL}/privacy`,
      `${APP_URL}/terms`,
    ]);
    expect(entries.every((entry) => entry.lastModified === "2026-08-29")).toBe(true);
  });

  it("does not make browsers contact a third-party font host", () => {
    const css = readFileSync(resolve(process.cwd(), "src/app/globals.css"), "utf8");
    expect(css).not.toContain("fonts.gstatic.com");
    expect(css).not.toContain("@font-face");
  });

  it("does not repeat the stale 161-pattern claim in long-form or social copy", () => {
    for (const path of [
      "src/app/indirect-prompt-injection/page.tsx",
      "src/app/opengraph-image.tsx",
    ]) {
      expect(readFileSync(resolve(process.cwd(), path), "utf8")).not.toMatch(/\b161\b/);
    }
  });

  it("does not claim that every routed request is inspected", () => {
    const articleSource = readFileSync(
      resolve(process.cwd(), "src/app/indirect-prompt-injection/page.tsx"),
      "utf8",
    );
    expect(articleSource).not.toMatch(/inspects every request/i);
  });

  it("frames beta status as non-reliance guidance, not a field-of-use restriction", () => {
    for (const path of ["src/app/layout.tsx", "src/app/mobile-nav.tsx"]) {
      const source = readFileSync(resolve(process.cwd(), path), "utf8");
      expect(source).toMatch(/Experimental, pre-1\.0/i);
      expect(source).not.toMatch(/not for production/i);
    }
  });

  it("links to the live NotInject dataset and not the unrelated Serge site", () => {
    const homeSource = readFileSync(resolve(process.cwd(), "src/app/page.tsx"), "utf8");
    const articleSource = readFileSync(
      resolve(process.cwd(), "src/app/indirect-prompt-injection/page.tsx"),
      "utf8",
    );

    expect(homeSource).toContain("https://huggingface.co/datasets/leolee99/NotInject");
    expect(homeSource).not.toContain("github.com/leolee99/NotInject");
    expect(articleSource).not.toContain("serge.ai");
  });

  it("scopes byte-faithful claims to model-visible body bytes", () => {
    for (const path of [
      "src/app/page.tsx",
      "src/app/playground.tsx",
      "src/app/blocked/page.tsx",
      "src/app/privacy/page.tsx",
      "src/app/terms/page.tsx",
    ]) {
      const source = readFileSync(resolve(process.cwd(), path), "utf8");
      expect(source).not.toMatch(/request(?: is)? (?:forwarded )?byte-for-byte/i);
      expect(source).not.toMatch(/request headers are forwarded byte-for-byte/i);
      expect(source).not.toMatch(/every header reaches the upstream unmodified/i);
    }
  });
});
