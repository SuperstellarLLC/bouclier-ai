import { describe, expect, it } from "vitest";
import { patterns } from "@bouclier-ai/patterns";
import { CATEGORY_COUNT, PATTERN_COUNT } from "@/lib/constants";

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
