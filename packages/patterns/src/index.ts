export { dampeners, DAMPENER_PROXIMITY } from "./dampeners.js";
export { patterns } from "./patterns.js";
export { normalize, deobfuscateLeet } from "./normalize.js";
export { computeScore, findDampenerRanges } from "./scorer.js";
export { scan, REDACTION_MESSAGE } from "./scanner.js";
export type { ScanOptions } from "./scanner.js";
export { SEVERITY_WEIGHTS } from "./types.js";
export type {
  Category,
  Dampener,
  Pattern,
  PatternSet,
  ScanMatch,
  ScanResult,
  Severity,
  ThreatScore,
} from "./types.js";
