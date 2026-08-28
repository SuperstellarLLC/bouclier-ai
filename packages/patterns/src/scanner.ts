import { dampeners as defaultDampeners } from "./dampeners.js";
import {
  deobfuscateLeetWithSourceMap,
  normalize,
  normalizeWithSourceMap,
  type MappedContent,
} from "./normalize.js";
import { patterns as defaultPatterns } from "./patterns.js";
import { computeScore, findDampenerRanges } from "./scorer.js";
import type { Dampener, Pattern, ScanMatch, ScanResult } from "./types.js";

const REDACTION_MESSAGE =
  "[Possible prompt injection redacted by Bouclier.ai. See https://www.bouclier.ai/blocked for details]";

/**
 * Compile a Pattern into a RegExp.
 * Caches compiled regexes for performance.
 */
const regexCache = new Map<string, RegExp>();

function compilePattern(pattern: Pattern): RegExp {
  const flags = [...new Set(`g${pattern.flags}`)].join("");
  const cacheKey = `${pattern.regex}\0${flags}`;
  const cached = regexCache.get(cacheKey);
  if (cached) return cached;

  const regex = new RegExp(pattern.regex, flags);
  regexCache.set(cacheKey, regex);
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
  const original = identitySourceMap(content);
  const normalizedText = normalize(content);
  const normalized = normalizedText === content ? original : normalizeWithSourceMap(content);
  const variants: MappedContent[] = [original]; // Always include original (catches zero-width chars etc.)
  if (normalizedText !== content) {
    variants.push(normalized);
  }
  if (deobfuscate) {
    const leetNormalized = deobfuscateLeetWithSourceMap(normalized);
    if (leetNormalized.text !== normalized.text && leetNormalized.text !== content) {
      variants.push(leetNormalized);
    }
  }

  // Step 3: Run patterns against all variants
  const allMatches: ScanMatch[] = [];

  for (const variant of variants) {
    for (const pattern of activePatterns) {
      const regex = compilePattern(pattern);
      regex.lastIndex = 0;

      let match: RegExpExecArray | null;
      while ((match = regex.exec(variant.text)) !== null) {
        // A zero-width custom pattern contains no content to report or redact.
        // Advance explicitly so it can never wedge the scanner in an infinite loop.
        if (match[0].length === 0) {
          regex.lastIndex = advanceStringIndex(variant.text, regex.lastIndex, regex.unicode);
          continue;
        }
        const sourceRange = mapSourceRange(variant, match.index, match[0].length);
        const scanMatch: ScanMatch = {
          patternId: pattern.id,
          patternName: pattern.name,
          category: pattern.category,
          severity: pattern.severity,
          offset: sourceRange.start,
          length: sourceRange.end - sourceRange.start,
          matched: content.slice(sourceRange.start, sourceRange.end),
        };
        allMatches.push(scanMatch);
      }
    }
  }

  // Deduplicate all matches by pattern+offset for scoring
  const seenKeys = new Set<string>();
  const uniqueMatches = allMatches.filter((m) => {
    const key = `${m.patternId}:${m.offset}:${m.length}`;
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

  // Step 5: Every variant now carries safe original offsets, so normalized-only
  // detections are redacted too. Merge overlap unions to avoid leaking the tail
  // of a longer match when a shorter pattern starts at the same position.
  let sanitized = content;
  if (uniqueMatches.length > 0) {
    const redactionRanges = mergeOverlaps(uniqueMatches);
    for (let i = redactionRanges.length - 1; i >= 0; i--) {
      const m = redactionRanges[i]!;
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

/** Merge overlapping match spans into complete redaction ranges. */
function mergeOverlaps(matches: ScanMatch[]): Array<{ offset: number; length: number }> {
  const result: Array<{ offset: number; length: number }> = [];
  for (const match of matches) {
    const previous = result.at(-1);
    const matchEnd = match.offset + match.length;
    if (!previous || match.offset >= previous.offset + previous.length) {
      result.push({ offset: match.offset, length: match.length });
    } else {
      previous.length = Math.max(previous.offset + previous.length, matchEnd) - previous.offset;
    }
  }
  return result;
}

function identitySourceMap(content: string): MappedContent {
  return {
    text: content,
    sourceStarts: Array.from({ length: content.length }, (_, i) => i),
    sourceEnds: Array.from({ length: content.length }, (_, i) => i + 1),
  };
}

function mapSourceRange(
  content: MappedContent,
  normalizedOffset: number,
  normalizedLength: number,
): { start: number; end: number } {
  const end = normalizedOffset + normalizedLength;
  let sourceStart = content.sourceStarts[normalizedOffset]!;
  let sourceEnd = content.sourceEnds[normalizedOffset]!;
  for (let i = normalizedOffset + 1; i < end; i++) {
    sourceStart = Math.min(sourceStart, content.sourceStarts[i]!);
    sourceEnd = Math.max(sourceEnd, content.sourceEnds[i]!);
  }
  return {
    start: sourceStart,
    end: sourceEnd,
  };
}

function advanceStringIndex(content: string, index: number, unicode: boolean): number {
  if (!unicode || index >= content.length) return index + 1;
  const first = content.charCodeAt(index);
  if (first < 0xd800 || first > 0xdbff || index + 1 >= content.length) return index + 1;
  const second = content.charCodeAt(index + 1);
  return second >= 0xdc00 && second <= 0xdfff ? index + 2 : index + 1;
}

export { REDACTION_MESSAGE };
