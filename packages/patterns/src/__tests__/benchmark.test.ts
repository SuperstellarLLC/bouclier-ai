import { describe, expect, it } from "vitest";
import { patterns } from "../patterns.js";
import { scan } from "../scanner.js";
import { benignCorpus } from "./benign-corpus.js";

/**
 * Detection-quality benchmark.
 *
 * Attack corpus: every curated example string attached to each Pattern
 *   (~440 samples across all 21 categories).
 * Benign corpus: hand-curated in benign-corpus.ts (~230 samples across
 *   product support, code discussion, security papers, creative writing,
 *   non-English text, translation requests, and fenced code discussions).
 *
 * We require:
 *   - True-positive rate  (attack detected)           ≥ 0.90
 *   - False-positive rate (benign blocked)            ≤ 0.05
 *   - Benign warn rate    (benign warned-but-allowed) ≤ 0.12
 *
 * The thresholds are calibration targets, not stretch goals. If the
 * benchmark regresses past these bounds the test fails and we revisit
 * either the offending pattern or the scoring weights.
 */

interface Metrics {
  total: number;
  detected: number;
  blocked: number;
  warned: number;
  tpr: number;
  blockRate: number;
  warnRate: number;
}

function evaluate(samples: string[]): Metrics {
  let detected = 0;
  let blocked = 0;
  let warned = 0;
  for (const s of samples) {
    const r = scan(s);
    if (r.detected) detected++;
    if (r.score.shouldBlock) blocked++;
    if (r.score.shouldWarn) warned++;
  }
  return {
    total: samples.length,
    detected,
    blocked,
    warned,
    tpr: detected / samples.length,
    blockRate: blocked / samples.length,
    warnRate: warned / samples.length,
  };
}

describe("detection benchmark", () => {
  const attacks = patterns.flatMap((p) => p.examples);

  it("corpus sizes meet SF-team targets (300+ attacks, 200+ benign)", () => {
    expect(attacks.length).toBeGreaterThanOrEqual(300);
    expect(benignCorpus.length).toBeGreaterThanOrEqual(200);
  });

  it("true-positive rate on attack corpus ≥ 0.90", () => {
    const m = evaluate(attacks);
    // eslint-disable-next-line no-console
    console.log(
      `[benchmark] attacks n=${m.total} detected=${m.detected} blocked=${m.blocked} warned=${m.warned} tpr=${m.tpr.toFixed(3)}`,
    );
    expect(m.tpr).toBeGreaterThanOrEqual(0.9);
  });

  it("false-positive block rate on benign corpus ≤ 0.05", () => {
    const m = evaluate(benignCorpus);
    // eslint-disable-next-line no-console
    console.log(
      `[benchmark] benign  n=${m.total} detected=${m.detected} blocked=${m.blocked} warned=${m.warned} blockRate=${m.blockRate.toFixed(3)} warnRate=${m.warnRate.toFixed(3)}`,
    );
    expect(m.blockRate).toBeLessThanOrEqual(0.05);
  });

  it("false-positive warn rate on benign corpus ≤ 0.12", () => {
    const m = evaluate(benignCorpus);
    expect(m.warnRate).toBeLessThanOrEqual(0.12);
  });
});
