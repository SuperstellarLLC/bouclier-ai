/** Severity of a detected prompt injection */
export type Severity = "low" | "medium" | "high" | "critical";

/** Category of prompt injection technique */
export type Category =
  | "role-hijack"
  | "instruction-override"
  | "context-manipulation"
  | "encoding-bypass"
  | "delimiter-attack"
  | "payload-splitting"
  | "indirect-injection"
  | "data-exfiltration"
  | "obfuscation"
  | "prompt-leaking"
  | "recursive-injection"
  | "tool-poisoning"
  | "credential-leak"
  | "memory-manipulation"
  | "function-hijack"
  | "model-specific"
  | "multilingual"
  | "code-injection"
  | "sandbox-escape"
  | "chain-of-thought-manipulation"
  | "alignment-bypass";

/** Dampener that reduces severity for benign contexts (academic, tutorials, etc.) */
export interface Dampener {
  id: string;
  label: string;
  regex: string;
  flags: string;
  /** Multiplier applied to matched pattern severity when dampener is present. 0-1 range. */
  dampen: number;
}

/** Severity weights for threat scoring */
export const SEVERITY_WEIGHTS: Record<Severity, number> = {
  low: 0.15,
  medium: 0.35,
  high: 0.6,
  critical: 1.0,
};

/** A single prompt injection detection pattern */
export interface Pattern {
  /** Unique identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** Description of what this pattern detects */
  description: string;
  /** Injection technique category */
  category: Category;
  /** Threat severity */
  severity: Severity;
  /** Regex pattern string (compatible with both JS and Swift NSRegularExpression) */
  regex: string;
  /** Regex flags (e.g., "i" for case-insensitive) */
  flags: string;
  /** Example strings this pattern should match */
  examples: string[];
  /** Whether this pattern is enabled by default */
  enabled: boolean;
}

/** The full pattern set with metadata */
export interface PatternSet {
  version: string;
  updatedAt: string;
  patterns: Pattern[];
}

/** Threat score computed by the heuristic scoring engine */
export interface ThreatScore {
  /** Overall threat score 0.0 – 1.0 */
  total: number;
  /** Whether content should be blocked (total >= blockThreshold) */
  shouldBlock: boolean;
  /** Whether content is suspicious but not blocked (total >= warnThreshold) */
  shouldWarn: boolean;
  /** Number of distinct categories matched */
  categoryCount: number;
  /** Highest severity among matches */
  highestSeverity: Severity | null;
}

/** Result of scanning content */
export interface ScanResult {
  /** Whether any injection was detected */
  detected: boolean;
  /** Matched patterns */
  matches: ScanMatch[];
  /** The sanitized content with injections redacted */
  sanitized: string;
  /** Heuristic threat score */
  score: ThreatScore;
}

/** A single match found during scanning */
export interface ScanMatch {
  patternId: string;
  patternName: string;
  category: Category;
  severity: Severity;
  /** Character offset of the match start */
  offset: number;
  /** Length of the matched content */
  length: number;
  /** The matched content */
  matched: string;
}
