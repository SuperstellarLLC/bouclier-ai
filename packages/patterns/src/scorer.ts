import { DAMPENER_PROXIMITY } from "./dampeners.js";
import type { Category, Dampener, ScanMatch, Severity, ThreatScore } from "./types.js";
import { SEVERITY_WEIGHTS } from "./types.js";

/**
 * Default thresholds — tuned on the built-in benchmark (442 attacks,
 * 240 benign). At these values a single critical-severity hit on a
 * short input blocks, while typical academic / code / support text
 * stays below the warn line. See src/__tests__/benchmark.test.ts.
 */
const BLOCK_THRESHOLD = 0.6;
const WARN_THRESHOLD = 0.25;

/**
 * Compute a per-match severity multiplier from dampener hits. A match gets
 * the lowest (most aggressive) dampener multiplier among all dampener
 * ranges that contain — or are within DAMPENER_PROXIMITY of — the match.
 */
function computeDampening(
  match: ScanMatch,
  dampenerRanges: Array<{ start: number; end: number; dampen: number }>,
): number {
  let multiplier = 1;
  const matchStart = match.offset;
  const matchEnd = match.offset + match.length;
  for (const r of dampenerRanges) {
    const gap = Math.max(0, Math.max(r.start - matchEnd, matchStart - r.end));
    if (gap <= DAMPENER_PROXIMITY && r.dampen < multiplier) {
      multiplier = r.dampen;
    }
  }
  return multiplier;
}

/**
 * Scan content for dampener hits and return their ranges.
 */
const dampenerRegexCache = new Map<string, RegExp>();

export function findDampenerRanges(
  content: string,
  dampeners: Dampener[],
): Array<{ start: number; end: number; dampen: number }> {
  const ranges: Array<{ start: number; end: number; dampen: number }> = [];
  for (const d of dampeners) {
    let regex = dampenerRegexCache.get(d.id);
    if (!regex) {
      regex = new RegExp(d.regex, `g${d.flags}`);
      dampenerRegexCache.set(d.id, regex);
    }
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(content)) !== null) {
      ranges.push({ start: m.index, end: m.index + m[0].length, dampen: d.dampen });
      if (m.index === regex.lastIndex) regex.lastIndex++;
    }
  }
  return ranges;
}

/**
 * Compute a heuristic threat score from scan matches.
 *
 * Factors:
 * 1. Severity-weighted match score
 * 2. Category diversity (more categories = higher confidence of real attack)
 * 3. Match density relative to content length
 * 4. Position clustering (matches close together = more suspicious)
 */
export function computeScore(
  matches: ScanMatch[],
  contentLength: number,
  blockThreshold = BLOCK_THRESHOLD,
  warnThreshold = WARN_THRESHOLD,
  dampenerRanges: Array<{ start: number; end: number; dampen: number }> = [],
): ThreatScore {
  if (matches.length === 0) {
    return {
      total: 0,
      shouldBlock: false,
      shouldWarn: false,
      categoryCount: 0,
      highestSeverity: null,
    };
  }

  // Factor 1: Severity-weighted sum (capped at 1.0) with dampening
  const severityScore = Math.min(
    1.0,
    matches.reduce((sum, m) => {
      const multiplier = dampenerRanges.length > 0 ? computeDampening(m, dampenerRanges) : 1;
      return sum + SEVERITY_WEIGHTS[m.severity] * multiplier;
    }, 0),
  );

  // Factor 2: Category diversity (unique categories / total possible)
  const categories = new Set<Category>(matches.map((m) => m.category));
  const categoryScore = Math.min(1.0, categories.size / 3); // 3+ categories = max

  // Factor 3: Match density (total matched chars / content length)
  const matchedChars = matches.reduce((sum, m) => sum + m.length, 0);
  const densityRatio = contentLength > 0 ? matchedChars / contentLength : 0;
  const densityScore = Math.min(1.0, densityRatio * 10); // 10%+ matched = max

  // Factor 4: Position clustering
  const clusterScore = computeClusterScore(matches, contentLength);

  // Weighted combination. Severity is the dominant signal — a single
  // critical match on a short input should be enough to warrant blocking.
  // Category diversity and density provide secondary evidence; clustering
  // is the weakest signal because short inputs have too few matches for
  // it to be meaningful.
  const total = Math.min(
    1.0,
    severityScore * 0.6 + categoryScore * 0.2 + densityScore * 0.15 + clusterScore * 0.05,
  );

  // Determine highest severity
  const severityOrder: Severity[] = ["low", "medium", "high", "critical"];
  const highestSeverity = matches.reduce<Severity>((highest, m) => {
    return severityOrder.indexOf(m.severity) > severityOrder.indexOf(highest)
      ? m.severity
      : highest;
  }, matches[0]!.severity);

  return {
    total: Math.round(total * 1000) / 1000, // 3 decimal precision
    shouldBlock: total >= blockThreshold,
    shouldWarn: total >= warnThreshold && total < blockThreshold,
    categoryCount: categories.size,
    highestSeverity,
  };
}

/**
 * Compute a clustering score — matches close together are more suspicious.
 */
function computeClusterScore(matches: ScanMatch[], contentLength: number): number {
  if (matches.length < 2 || contentLength === 0) return 0;

  // Calculate average gap between consecutive matches
  let totalGap = 0;
  for (let i = 1; i < matches.length; i++) {
    const gap = matches[i]!.offset - (matches[i - 1]!.offset + matches[i - 1]!.length);
    totalGap += Math.max(0, gap);
  }
  const avgGap = totalGap / (matches.length - 1);

  // Small gaps relative to content = high clustering
  const relativeGap = avgGap / contentLength;
  return Math.max(0, 1.0 - relativeGap * 5);
}
