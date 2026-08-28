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

  // Resolve overlaps by detector priority first, regardless of which candidate
  // starts a few characters earlier. This is the contract of PII_DETECTORS:
  // a broad, lower-priority candidate must never swallow a more specific
  // provider token merely because its regex began first.
  raw.sort((a, b) => {
    if (a.rank !== b.rank) return a.rank - b.rank;
    if (a.d.start !== b.d.start) return a.d.start - b.d.start;
    return b.d.end - a.d.end;
  });

  const selected: PIIDetection[] = [];
  for (const { d } of raw) {
    if (!selected.some((existing) => d.start < existing.end && existing.start < d.end)) {
      selected.push(d);
    }
  }
  return selected.sort((a, b) => a.start - b.start || a.end - b.end);
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
    if (
      !Number.isInteger(d.start) ||
      !Number.isInteger(d.end) ||
      d.start < cursor ||
      d.end <= d.start ||
      d.end > content.length ||
      content.slice(d.start, d.end) !== d.value
    ) {
      throw new RangeError("detections must be ordered, non-overlapping spans from the input");
    }
    out += content.slice(cursor, d.start);
    out += mintToken(d);
    cursor = d.end;
  }
  out += content.slice(cursor);
  return out;
}
