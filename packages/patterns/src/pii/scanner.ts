import { PII_DETECTORS } from "./detectors.js";
import type { PIIDetection, PIIDetector } from "./types.js";

export interface PIIScanOptions {
  /** Override the default detector list (mostly useful for tests / custom recognizers). */
  detectors?: PIIDetector[];
}

/**
 * Scan content for PII entities. Returns non-overlapping detections in input order.
 *
 * Resolution when two detectors match overlapping spans: the detector listed
 * first in `PII_DETECTORS` wins (the list is ordered most-specific first).
 * Within a single detector, longer spans win over shorter ones starting at
 * the same offset.
 */
export function scanPII(content: string, options?: PIIScanOptions): PIIDetection[] {
  if (!content) return [];
  const detectors = options?.detectors ?? PII_DETECTORS;

  const raw: { d: PIIDetection; rank: number }[] = [];
  for (let i = 0; i < detectors.length; i++) {
    const det = detectors[i]!;
    const re = new RegExp(
      det.regex.source,
      det.regex.flags.includes("g") ? det.regex.flags : det.regex.flags + "g",
    );
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) {
      const value = m[0];
      if (value.length === 0) {
        re.lastIndex++;
        continue;
      }
      if (det.validate && !det.validate(value)) continue;
      const detection = { type: det.type, start: m.index, end: m.index + value.length, value };
      if (det.contextOk && !det.contextOk(content, detection)) continue;
      raw.push({ d: detection, rank: i });
    }
  }

  // Sort by start, then by detector rank (lower wins), then by longer span first.
  raw.sort((a, b) => {
    if (a.d.start !== b.d.start) return a.d.start - b.d.start;
    if (a.rank !== b.rank) return a.rank - b.rank;
    return a.d.end !== b.d.end ? b.d.end - a.d.end : 0;
  });

  const out: PIIDetection[] = [];
  let lastEnd = -1;
  for (const { d } of raw) {
    if (d.start >= lastEnd) {
      out.push(d);
      lastEnd = d.end;
    }
  }
  return out;
}

/**
 * Apply a list of detections to the input, replacing each span with the
 * placeholder returned by `mintToken(detection)`. Detections must come from
 * `scanPII` (non-overlapping, sorted).
 *
 * Returns the redacted string. The session-map side of the round-trip is
 * the caller's responsibility — this function is intentionally stateless
 * so it composes cleanly with the Swift PIISession actor.
 */
export function applyRedactions(
  content: string,
  detections: PIIDetection[],
  mintToken: (d: PIIDetection) => string,
): string {
  if (detections.length === 0) return content;
  let out = "";
  let cursor = 0;
  for (const d of detections) {
    out += content.slice(cursor, d.start);
    out += mintToken(d);
    cursor = d.end;
  }
  out += content.slice(cursor);
  return out;
}
