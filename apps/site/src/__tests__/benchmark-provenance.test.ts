import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { BENCHMARK_PROVENANCE } from "@/lib/benchmark-provenance";
import { APP_VERSION } from "@/lib/constants";

describe("published benchmark provenance", () => {
  it("pins the original measurement instead of following the current app version", () => {
    expect(BENCHMARK_PROVENANCE).toEqual({
      measuredRelease: "0.9.3",
      measuredOnISO: "2026-08-10",
      measuredOnLabel: "10 Aug 2026",
      sourceRevision: "9808b73ef55c35e74ed35641132f885a4d08b0d3",
      sourceUrl:
        "https://github.com/SuperstellarLLC/bouclier-ai/tree/9808b73ef55c35e74ed35641132f885a4d08b0d3/apps/desktop/benchmark",
      pipeline: {
        patternCount: 161,
        dampenerCount: 8,
        classifier: "Prompt Guard 2",
        classifierActive: true,
        untrustedBlockThreshold: 0.6,
      },
      benignCorpus: {
        total: 512,
        blockedPercent: 0.6,
        notInjectBlockedPercent: 1.8,
      },
      instructionOverrideCorpus: {
        name: "Lakera/gandalf_ignore_instructions",
        total: 777,
        detectedPercent: 98.3,
      },
    });
    expect(BENCHMARK_PROVENANCE.measuredRelease).not.toBe(APP_VERSION);
  });

  it("is frozen deeply enough that display code cannot mutate the evidence", () => {
    expect(Object.isFrozen(BENCHMARK_PROVENANCE)).toBe(true);
    expect(Object.isFrozen(BENCHMARK_PROVENANCE.pipeline)).toBe(true);
    expect(Object.isFrozen(BENCHMARK_PROVENANCE.benignCorpus)).toBe(true);
    expect(Object.isFrozen(BENCHMARK_PROVENANCE.instructionOverrideCorpus)).toBe(true);
  });

  it("does not import mutable release metadata", () => {
    const source = readFileSync(resolve(process.cwd(), "src/lib/benchmark-provenance.ts"), "utf8");
    expect(source).not.toMatch(/^import\b/m);
    expect(source).not.toContain("APP_VERSION");
  });
});
