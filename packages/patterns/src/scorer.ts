import type { Category, ScanMatch, Severity, ThreatScore } from "./types.js";
import { SEVERITY_WEIGHTS } from "./types.js";

/** Default thresholds */
const BLOCK_THRESHOLD = 0.7;
const WARN_THRESHOLD = 0.3;

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

  // Factor 1: Severity-weighted sum (capped at 1.0)
  const severityScore = Math.min(
    1.0,
    matches.reduce((sum, m) => sum + SEVERITY_WEIGHTS[m.severity], 0),
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

  // Weighted combination
  const total = Math.min(
    1.0,
    severityScore * 0.45 + categoryScore * 0.25 + densityScore * 0.15 + clusterScore * 0.15,
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
