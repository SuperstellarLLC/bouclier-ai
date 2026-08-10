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

export {
  PII_DETECTORS,
  applyRedactions,
  ibanMod97,
  isPlausibleIPv4,
  isPlausibleIPv6,
  isPlausibleJWT,
  isPlausibleNHS,
  isPlausibleNINO,
  isPlausibleNIR,
  isPlausibleNPI,
  isPlausibleSIREN,
  isPlausibleSIRET,
  isPlausibleSSN,
  isPlausibleUKPostcode,
  luhn,
  scanPII,
} from "./pii/index.js";
export type { PIIDetection, PIIDetector, PIIEntityType, PIIScanOptions } from "./pii/index.js";
