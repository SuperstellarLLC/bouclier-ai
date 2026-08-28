import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { patterns } from "@bouclier-ai/patterns";
import {
  APP_DESCRIPTION,
  APP_VERSION,
  CATEGORY_COUNT,
  ENFORCEMENT_STATUS_AVAILABLE,
  PATTERN_COUNT,
  STATUS_MCP_AVAILABLE,
} from "@/lib/constants";
import { versionAtLeast } from "../../release-alignment";

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

  it("describes monitor-by-default rather than implying automatic blocking", () => {
    expect(APP_DESCRIPTION).toMatch(/monitors?.+by default/i);
    expect(APP_DESCRIPTION).toMatch(/enable blocking/i);
  });

  it("does not advertise the status MCP ahead of its signed desktop release", () => {
    const released = versionAtLeast(APP_VERSION, "0.9.11");
    expect(STATUS_MCP_AVAILABLE).toBe(released);
    expect(ENFORCEMENT_STATUS_AVAILABLE).toBe(released);
    expect(versionAtLeast("0.9.11", "0.9.11")).toBe(true);
    expect(versionAtLeast("0.10.0", "0.9.11")).toBe(true);
    expect(versionAtLeast("0.9.10", "0.9.11")).toBe(false);
  });
});

/**
 * The hero badge and download URL quote APP_VERSION. Benchmark evidence is
 * deliberately pinned to its measured revision in benchmark-provenance.ts,
 * while the root CHANGELOG's top release remains the source of truth for the
 * currently downloadable app version.
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
