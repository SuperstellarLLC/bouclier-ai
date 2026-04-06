import type { Dampener } from "./types.js";

/**
 * False-positive dampeners — reduce severity when pattern hits occur inside
 * benign contexts (academic writing, tutorials, translation requests, etc.).
 *
 * The scoring layer applies a dampener's multiplier to any matched pattern
 * whose offset is within DAMPENER_PROXIMITY characters of the dampener hit.
 *
 * Sources: HackAPrompt false-positive analysis, OWASP LLM safety-research corpus.
 */
export const DAMPENER_PROXIMITY = 200;

export const dampeners: Dampener[] = [
  {
    id: "fp-001",
    label: "academic-discussion",
    regex:
      "\\b(?:paper|arxiv|et\\s+al\\.?|researchers?|study|authors?|cited|published|journal|conference|proceedings)\\b",
    flags: "i",
    dampen: 0.5,
  },
  {
    id: "fp-002",
    label: "security-tutorial",
    regex:
      "\\b(?:tutorial|example|demo|PoC|proof[-\\s]of[-\\s]concept|reproduce|how\\s+to\\s+(?:detect|prevent|mitigate|test))\\b",
    flags: "i",
    dampen: 0.4,
  },
  {
    id: "fp-003",
    label: "translation-request",
    regex:
      "\\b(?:how\\s+do\\s+you\\s+say|translate|what\\s+does.{0,20}mean\\s+in|in\\s+(?:french|spanish|german|chinese|japanese|arabic|russian|italian|portuguese))\\b",
    flags: "i",
    dampen: 0.3,
  },
  {
    id: "fp-004",
    label: "fenced-code-context",
    regex: "```[a-z]*\\n[\\s\\S]*?```",
    flags: "",
    dampen: 0.5,
  },
  {
    id: "fp-005",
    label: "password-reset",
    regex: "\\b(?:reset|forgot|change|recover|update)\\s+(?:my\\s+|the\\s+)?password\\b",
    flags: "i",
    dampen: 0.2,
  },
  {
    id: "fp-006",
    label: "news-hedge",
    regex:
      "\\b(?:according\\s+to|reportedly|allegedly|researchers?\\s+(?:say|found|discovered)|reported\\s+that)\\b",
    flags: "i",
    dampen: 0.5,
  },
  {
    id: "fp-007",
    label: "developer-mode-benign",
    regex:
      "(?:chrome|android|ios|vs\\s?code|visual\\s+studio|firefox|windows)\\s+developer\\s+mode",
    flags: "i",
    dampen: 0.1,
  },
  {
    id: "fp-008",
    label: "owasp-mitre-reference",
    regex: "\\b(?:owasp|mitre|atlas|cve-\\d{4}-\\d+|cwe-\\d+|llm0\\d)\\b",
    flags: "i",
    dampen: 0.4,
  },
];
