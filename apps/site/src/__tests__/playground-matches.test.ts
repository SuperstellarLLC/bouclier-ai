import { describe, expect, it } from "vitest";
import type { ScanMatch } from "@bouclier-ai/patterns";

import { computeRegexSignal, dedupeMatches } from "@/app/playground";

const first: ScanMatch = {
  patternId: "override-repeat",
  patternName: "Repeated override",
  category: "instruction-override",
  severity: "medium",
  offset: 0,
  length: 12,
  matched: "ignore rules",
};

describe("playground match scoring", () => {
  it("keeps distinct non-overlapping hits from the same pattern", () => {
    const repeated = { ...first, offset: 24 };
    const matches = dedupeMatches([first, { ...first }, repeated]);

    expect(matches.map((match) => match.offset)).toEqual([0, 24]);
    expect(computeRegexSignal(matches)).toBeCloseTo(0.7);
    expect(computeRegexSignal([first])).toBeCloseTo(0.35);
  });
});
