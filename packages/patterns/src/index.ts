export { patterns } from "./patterns.js";
export { normalize, deobfuscateLeet } from "./normalize.js";
export { computeScore } from "./scorer.js";
export { scan, REDACTION_MESSAGE } from "./scanner.js";
export type { ScanOptions } from "./scanner.js";
export { SEVERITY_WEIGHTS } from "./types.js";
export type {
  Category,
  Pattern,
  PatternSet,
  ScanMatch,
  ScanResult,
  Severity,
  ThreatScore,
} from "./types.js";
