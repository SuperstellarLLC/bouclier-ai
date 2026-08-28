/**
 * Immutable evidence for the benchmark currently published on the homepage.
 *
 * This is intentionally independent from current release metadata and the live
 * pattern count. A release must never relabel old measurements. Update this
 * record only after rerunning the external harness for a named release, then
 * update its exact-value test in the same reviewed change.
 */
export const BENCHMARK_PROVENANCE = Object.freeze({
  measuredRelease: "0.9.3",
  measuredOnISO: "2026-08-10",
  measuredOnLabel: "10 Aug 2026",
  sourceRevision: "9808b73ef55c35e74ed35641132f885a4d08b0d3",
  sourceUrl:
    "https://github.com/SuperstellarLLC/bouclier-ai/tree/9808b73ef55c35e74ed35641132f885a4d08b0d3/apps/desktop/benchmark",
  pipeline: Object.freeze({
    patternCount: 161,
    dampenerCount: 8,
    classifier: "Prompt Guard 2",
    classifierActive: true,
    untrustedBlockThreshold: 0.6,
  }),
  benignCorpus: Object.freeze({
    total: 512,
    blockedPercent: 0.6,
    notInjectBlockedPercent: 1.8,
  }),
  instructionOverrideCorpus: Object.freeze({
    name: "Lakera/gandalf_ignore_instructions",
    total: 777,
    detectedPercent: 98.3,
  }),
});
