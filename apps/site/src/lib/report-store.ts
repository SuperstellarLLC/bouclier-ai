/**
 * False-positive report store.
 *
 * When an operator hits "Report false positive" in the menu-bar app, the
 * app POSTs a *redacted* block sample to `/api/report`. This module is the
 * only place that persists it. It is a deliberate sibling of
 * `download-tracker.ts` and inherits the same discipline:
 *
 * - Record only what the operator chose to send: the redaction happens on
 *   their Mac, and they see the exact bytes in a confirm dialog before it
 *   leaves. This module trusts that and stores the payload as-received.
 * - DO NOT record IP address, user-agent, referrer, geo, or anything else
 *   that identifies the reporter. The app's brand promise is "no
 *   telemetry"; a false-positive report is a *user-initiated* share of one
 *   flagged span, not passive tracking.
 * - Be graceful when storage isn't configured — fall back to a
 *   `console.log` line so a deployment without Upstash still 200s the
 *   report instead of erroring.
 *
 * Storage: Upstash Redis REST (same store as downloads). Rolling event log
 * via LPUSH + LTRIM; a lifetime counter and per-day buckets for a
 * glanceable "are reports coming in" signal. If you swap stores later,
 * only this module changes.
 */

import { env } from "@/env";

/** Rolling report-log size — older reports drop off the back. */
const MAX_REPORTS = 2_000;

/** Server-side hard caps, defence-in-depth behind the app's own capping. */
export const LIMITS = {
  excerpt: 4096,
  topWindow: 4096,
  note: 1000,
  locator: 512,
  host: 253,
  appVersion: 32,
  patternName: 128,
  maxPatternNames: 16,
} as const;

/**
 * A redacted false-positive report as accepted by `/api/report`. Mirrors
 * the desktop `BlockSample` (minus anything identifying). `ts` is stamped
 * server-side at receive time — the client's clock is never trusted.
 */
export interface FalsePositiveReport {
  /** ISO 8601 UTC, stamped on receive. Not client-supplied. */
  ts: string;
  /** App version that produced the block (e.g. "0.9.8"). */
  appVersion: string;
  /** Upstream host the request targeted (api.anthropic.com, …). */
  targetHost: string;
  /** JSON path of the offending span (structural, not content). */
  locator: string;
  patternNames: string[];
  fusedScore: number;
  mlScore: number | null;
  entropyAnomaly: number;
  benignMultiplier: number;
  matchCount: number;
  /** Redacted excerpt of the offending span (secrets/PII scrubbed app-side). */
  spanExcerpt: string;
  /** Redacted highest-scoring ML window, when ML drove the block. */
  topWindow: string | null;
  topWindowScore: number | null;
  /** Salted, machine-local span fingerprint — not reversible to content. */
  fingerprint: string;
  /** Optional free-text note the reporter added. */
  note: string | null;
}

/** Shape of what the client is allowed to send (everything but `ts`). */
export type FalsePositiveReportInput = Omit<FalsePositiveReport, "ts">;

function clamp(value: unknown, max: number): string {
  return typeof value === "string" ? value.slice(0, max) : "";
}

function finiteOrZero(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function finiteOrNull(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * Validate + normalize an untrusted request body into a report, or return
 * null if it doesn't look like one. Strings are hard-capped and numbers
 * coerced, so a malformed or oversized field can't bloat the store or
 * smuggle a non-string through — the route has already size-capped the
 * raw body, this caps each field.
 */
export function normalizeReport(raw: unknown): FalsePositiveReportInput | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;

  // Require the fields that make a report actionable: where it came from,
  // what matched, and the offending excerpt. Everything else is optional.
  if (typeof r.spanExcerpt !== "string" || r.spanExcerpt.length === 0) return null;
  if (typeof r.targetHost !== "string" || r.targetHost.length === 0) return null;

  const patternNames = Array.isArray(r.patternNames)
    ? r.patternNames
        .filter((n): n is string => typeof n === "string")
        .slice(0, LIMITS.maxPatternNames)
        .map((n) => n.slice(0, LIMITS.patternName))
    : [];

  return {
    appVersion: clamp(r.appVersion, LIMITS.appVersion),
    targetHost: clamp(r.targetHost, LIMITS.host),
    locator: clamp(r.locator, LIMITS.locator),
    patternNames,
    fusedScore: finiteOrZero(r.fusedScore),
    mlScore: finiteOrNull(r.mlScore),
    entropyAnomaly: finiteOrZero(r.entropyAnomaly),
    benignMultiplier: finiteOrZero(r.benignMultiplier),
    matchCount: finiteOrZero(r.matchCount),
    spanExcerpt: clamp(r.spanExcerpt, LIMITS.excerpt),
    topWindow: typeof r.topWindow === "string" ? r.topWindow.slice(0, LIMITS.topWindow) : null,
    topWindowScore: finiteOrNull(r.topWindowScore),
    fingerprint: clamp(r.fingerprint, 128),
    note: typeof r.note === "string" && r.note.length > 0 ? r.note.slice(0, LIMITS.note) : null,
  };
}

/** Persist one report. Safe to call even when storage isn't configured. */
export async function recordReport(input: FalsePositiveReportInput): Promise<void> {
  const report: FalsePositiveReport = { ts: new Date().toISOString(), ...input };

  if (!env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN) {
    // Console fallback so a deployment without Upstash still captures the
    // report in Vercel function logs instead of dropping it.
    console.log(JSON.stringify({ kind: "false_positive_report", ...report }));
    return;
  }

  const day = report.ts.slice(0, 10); // YYYY-MM-DD
  const pipeline = [
    ["INCR", "reports:total"],
    ["HINCRBY", "reports:daily", day, "1"],
    ["LPUSH", "reports:events", JSON.stringify(report)],
    ["LTRIM", "reports:events", "0", String(MAX_REPORTS - 1)],
  ];

  try {
    const res = await fetch(`${env.UPSTASH_REDIS_REST_URL}/pipeline`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.UPSTASH_REDIS_REST_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(pipeline),
      cache: "no-store",
    });
    if (!res.ok) {
      console.warn(`[report-store] Upstash write failed: ${res.status} ${res.statusText}`);
    }
  } catch (err) {
    // Recording must never make the endpoint 500 on the reporter.
    console.warn(`[report-store] Upstash unreachable: ${(err as Error).message}`);
  }
}
