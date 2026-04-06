import { dampeners as defaultDampeners } from "./dampeners.js";
import { deobfuscateLeet, normalize } from "./normalize.js";
import { patterns as defaultPatterns } from "./patterns.js";
import { computeScore, findDampenerRanges } from "./scorer.js";
import type { Dampener, Pattern, ScanMatch, ScanResult } from "./types.js";

const REDACTION_MESSAGE =
  "[Possible prompt injection redacted by Bouclier.ai. See https://bouclier.ai/blocked for details]";

/**
 * Compile a Pattern into a RegExp.
 * Caches compiled regexes for performance.
 */
const regexCache = new Map<string, RegExp>();

function compilePattern(pattern: Pattern): RegExp {
  const cached = regexCache.get(pattern.id);
  if (cached) return cached;

  const regex = new RegExp(pattern.regex, `g${pattern.flags}`);
  regexCache.set(pattern.id, regex);
  return regex;
}

export interface ScanOptions {
  /** Custom pattern set (defaults to built-in patterns) */
  patterns?: Pattern[];
  /** Custom dampener set (defaults to built-in dampeners). Pass [] to disable. */
  dampeners?: Dampener[];
  /** Threat score threshold for blocking (default: 0.6) */
  blockThreshold?: number;
  /** Threat score threshold for warning (default: 0.25) */
  warnThreshold?: number;
  /** Enable leetspeak deobfuscation pass (default: true) */
  deobfuscateLeetspeak?: boolean;
}

/**
 * Scan content for prompt injections.
 *
 * Pipeline:
 * 1. Normalize content (NFKC, homoglyphs, zero-width stripping)
 * 2. Optionally deobfuscate leetspeak
 * 3. Run regex patterns against normalized content
 * 4. Map match offsets back to original content
 * 5. Compute heuristic threat score
 * 6. Build sanitized output
 */
export function scan(content: string, options?: ScanOptions): ScanResult {
  const {
    patterns: customPatterns,
    dampeners: customDampeners,
    blockThreshold,
    warnThreshold,
    deobfuscateLeetspeak: deobfuscate = true,
  } = options ?? {};

  const emptyScore = {
    total: 0,
    shouldBlock: false,
    shouldWarn: false,
    categoryCount: 0,
    highestSeverity: null,
  };

  if (!content) {
    return { detected: false, matches: [], sanitized: content, score: emptyScore };
  }

  const activePatterns = (customPatterns ?? defaultPatterns).filter((p) => p.enabled);

  // Step 1-2: Normalize — scan both original and normalized variants
  const normalized = normalize(content);
  const variants = [content]; // Always include original (catches zero-width chars etc.)
  if (normalized !== content) {
    variants.push(normalized);
  }
  if (deobfuscate) {
    const leetNormalized = deobfuscateLeet(normalized);
    if (leetNormalized !== normalized && leetNormalized !== content) {
      variants.push(leetNormalized);
    }
  }

  // Step 3: Run patterns against all variants
  // Track matches from original content separately for accurate redaction offsets
  const allMatches: ScanMatch[] = [];
  const originalMatches: ScanMatch[] = [];

  for (let vi = 0; vi < variants.length; vi++) {
    const variant = variants[vi]!;
    const isOriginal = vi === 0;

    for (const pattern of activePatterns) {
      const regex = compilePattern(pattern);
      regex.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = regex.exec(variant)) !== null) {
        const scanMatch: ScanMatch = {
          patternId: pattern.id,
          patternName: pattern.name,
          category: pattern.category,
          severity: pattern.severity,
          offset: match.index,
          length: match[0].length,
          matched: match[0],
        };
        allMatches.push(scanMatch);
        if (isOriginal) {
          originalMatches.push(scanMatch);
        }
      }
    }
  }

  // Deduplicate all matches by pattern+offset for scoring
  const seenKeys = new Set<string>();
  const uniqueMatches = allMatches.filter((m) => {
    const key = `${m.patternId}:${m.offset}`;
    if (seenKeys.has(key)) return false;
    seenKeys.add(key);
    return true;
  });
  uniqueMatches.sort((a, b) => a.offset - b.offset);

  // Step 4: Compute threat score from all unique matches, dampened by context.
  const activeDampeners = customDampeners ?? defaultDampeners;
  const dampenerRanges =
    activeDampeners.length > 0 && uniqueMatches.length > 0
      ? findDampenerRanges(content, activeDampeners)
      : [];
  const score = computeScore(
    uniqueMatches,
    content.length,
    blockThreshold,
    warnThreshold,
    dampenerRanges,
  );

  // Step 5: Build sanitized content using only original-content matches (safe offsets)
  let sanitized = content;
  originalMatches.sort((a, b) => a.offset - b.offset);
  if (originalMatches.length > 0) {
    const nonOverlapping = deduplicateOverlaps(originalMatches);
    for (let i = nonOverlapping.length - 1; i >= 0; i--) {
      const m = nonOverlapping[i]!;
      sanitized =
        sanitized.slice(0, m.offset) + REDACTION_MESSAGE + sanitized.slice(m.offset + m.length);
    }
  }

  // Use all unique matches for the result (detection + scoring) but report them
  const matches = uniqueMatches;

  return {
    detected: matches.length > 0,
    matches,
    sanitized,
    score,
  };
}

/**
 * Remove overlapping matches, keeping the higher-severity or earlier match.
 */
function deduplicateOverlaps(matches: ScanMatch[]): ScanMatch[] {
  const result: ScanMatch[] = [];
  let lastEnd = -1;

  for (const match of matches) {
    if (match.offset >= lastEnd) {
      result.push(match);
      lastEnd = match.offset + match.length;
    }
  }

  return result;
}

export { REDACTION_MESSAGE };
