/**
 * Immutable display record for the benchmark currently published on the homepage.
 *
 * This is intentionally independent from current release metadata and the live
 * pattern count. A release must never relabel old measurements. Update this
 * record only after rerunning the external harness for a named release, then
 * update its exact-value test in the same reviewed change.
 *
 * The source revision pins the harness, not the third-party dataset bytes. The
 * original run did not preserve dataset revisions, input hashes, or a raw result
 * artifact, so this record describes the published result but cannot guarantee
 * an exact rerun.
 */
export const BENCHMARK_PROVENANCE = Object.freeze({
  measuredRelease: "0.9.3",
  measuredOnISO: "2026-08-10",
  measuredOnLabel: "10 Aug 2026",
  sourceRevision: "9808b73ef55c35e74ed35641132f885a4d08b0d3",
  sourceUrl:
    "https://github.com/SuperstellarLLC/bouclier-ai/tree/9808b73ef55c35e74ed35641132f885a4d08b0d3/apps/desktop/benchmark",
  reproducibility: Object.freeze({
    exactRerunGuaranteed: false,
    note: "The source revision pins the harness, but the corpora were fetched from live Hugging Face dataset endpoints without preserved dataset revisions, input hashes, or a raw result artifact. An exact rerun is therefore not guaranteed if those third-party datasets change.",
  }),
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
