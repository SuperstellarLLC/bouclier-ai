import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { patterns } from "@bouclier-ai/patterns";
import { APP_VERSION, CATEGORY_COUNT, PATTERN_COUNT } from "@/lib/constants";

/**
 * The homepage and /blocked both quote these figures. They are hardcoded
 * in constants.ts so the pattern package doesn't get pulled into every
 * route's bundle — which means they can silently go stale. This is the
 * thing that stops that.
 */
describe("advertised detection-engine size", () => {
  it("PATTERN_COUNT matches the shipped pattern set", () => {
    expect(PATTERN_COUNT).toBe(patterns.length);
  });

  it("CATEGORY_COUNT matches the distinct categories in the set", () => {
    const categories = new Set(patterns.map((p) => p.category));
    expect(CATEGORY_COUNT).toBe(categories.size);
  });

  it("every pattern the site advertises is enabled", () => {
    const disabled = patterns.filter((p) => !p.enabled).map((p) => p.id);
    expect(disabled).toEqual([]);
  });
});

/**
 * The hero badge, the benchmark caption, and the download URL all quote
 * APP_VERSION, but nothing forced it to move with a release — the page
 * test only checks that the page renders the constant, which is
 * self-referential and can't catch staleness. The root CHANGELOG's top
 * entry is the release source of truth (publish-update.sh extracts it
 * verbatim for the Sparkle appcast), so pin the site to it.
 */
describe("advertised app version", () => {
  it("APP_VERSION matches the latest CHANGELOG release", () => {
    // cwd is apps/site when vitest runs (jsdom rewrites import.meta.url
    // to a non-file scheme, so the module URL can't anchor the path).
    const changelog = readFileSync(resolve(process.cwd(), "../../CHANGELOG.md"), "utf8");
    const latest = changelog.match(/^## \[(\d+\.\d+\.\d+)\]/m)?.[1];
    expect(latest).toBeDefined();
    expect(APP_VERSION).toBe(latest);
  });
});
