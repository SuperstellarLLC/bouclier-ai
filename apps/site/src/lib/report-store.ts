/**
 * False-positive report store — Postgres (Neon / Vercel Postgres).
 *
 * When an operator taps "Report false positive" in the menu-bar app, the app
 * POSTs a *redacted* block sample to `/api/report`. This module is the only
 * place that persists it. Design notes:
 *
 * - **Durable + queryable.** Reports are the raw material for tuning detection,
 *   so they belong in a database you can query (by pattern, date, fingerprint),
 *   not an evictable Redis list. A row is never dropped by a later write, so a
 *   flood can't push genuine reports out (the eviction the audit flagged).
 * - **IP-free global write cap.** The only abuse control here is a single global
 *   ceiling on inserts-per-minute, enforced *atomically inside the INSERT* — no
 *   client IP, identity, or per-key state. It bounds cost and DB growth; the
 *   proof-of-work stamp on the route makes reaching the cap expensive.
 * - **No IP / UA / identifier is ever stored** — only the redacted fields the
 *   app sends. Redaction happens on the operator's Mac and is shown to them
 *   before send; this module trusts that and just validates + caps + persists.
 * - **Graceful when unconfigured.** No `DATABASE_URL` → each report is logged to
 *   the console instead of persisted, so a fresh deployment still 200s.
 */

import { neon, type NeonQueryFunction } from "@neondatabase/serverless";

import { env } from "@/env";

/** Global ceiling on accepted reports per rolling minute (across everyone). */
const GLOBAL_WRITES_PER_MIN = 300;

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
 * A redacted false-positive report as accepted by `/api/report`. Mirrors the
 * desktop `BlockSample` (minus anything identifying). `ts` is only used by the
 * console fallback; the DB stamps `created_at` server-side.
 */
export interface FalsePositiveReport {
  ts: string;
  appVersion: string;
  targetHost: string;
  locator: string;
  patternNames: string[];
  fusedScore: number;
  mlScore: number | null;
  entropyAnomaly: number;
  benignMultiplier: number;
  matchCount: number;
  spanExcerpt: string;
  topWindow: string | null;
  topWindowScore: number | null;
  fingerprint: string;
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
 * Validate + normalize an untrusted request body into a report, or return null
 * if it doesn't look like one. Strings are hard-capped and numbers coerced, so
 * a malformed or oversized field can't bloat a row or smuggle a non-string
 * through — the route has already size-capped the raw body, this caps each
 * field. Pure (no DB), so it's unit-testable on its own.
 */
export function normalizeReport(raw: unknown): FalsePositiveReportInput | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;

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

let _sql: NeonQueryFunction<false, false> | null = null;
function getSql(): NeonQueryFunction<false, false> | null {
  if (!env.DATABASE_URL) return null;
  if (!_sql) _sql = neon(env.DATABASE_URL);
  return _sql;
}

// Create the table + indexes once per process (idempotent). Reset on failure so
// a transient error doesn't wedge every later write behind a rejected promise.
let schemaReady: Promise<void> | null = null;
function ensureSchema(sql: NeonQueryFunction<false, false>): Promise<void> {
  if (!schemaReady) {
    schemaReady = (async () => {
      await sql`CREATE TABLE IF NOT EXISTS false_positive_reports (
        id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        created_at        timestamptz NOT NULL DEFAULT now(),
        app_version       text NOT NULL,
        target_host       text NOT NULL,
        locator           text NOT NULL,
        pattern_names     jsonb NOT NULL DEFAULT '[]'::jsonb,
        fused_score       double precision NOT NULL,
        ml_score          double precision,
        entropy_anomaly   double precision NOT NULL,
        benign_multiplier double precision NOT NULL,
        match_count       integer NOT NULL,
        span_excerpt      text NOT NULL,
        top_window        text,
        top_window_score  double precision,
        fingerprint       text NOT NULL,
        note              text
      )`;
      await sql`CREATE INDEX IF NOT EXISTS fpr_created_at_idx ON false_positive_reports (created_at DESC)`;
      await sql`CREATE INDEX IF NOT EXISTS fpr_fingerprint_idx ON false_positive_reports (fingerprint)`;
    })().catch((err) => {
      schemaReady = null;
      throw err;
    });
  }
  return schemaReady;
}

/**
 * Persist one report. Safe to call even when storage isn't configured. The
 * global per-minute ceiling is enforced *inside* the INSERT (insert only if the
 * last-minute count is under the cap) so it's atomic and needs no IP or
 * per-client state; over the cap, the row is simply not written.
 */
export async function recordReport(input: FalsePositiveReportInput): Promise<void> {
  const sql = getSql();
  if (!sql) {
    // Console fallback so a deployment without a database still captures the
    // report in the function logs instead of dropping it.
    console.log(
      JSON.stringify({ kind: "false_positive_report", ts: new Date().toISOString(), ...input }),
    );
    return;
  }

  try {
    await ensureSchema(sql);
    const rows = await sql`
      INSERT INTO false_positive_reports
        (app_version, target_host, locator, pattern_names, fused_score, ml_score,
         entropy_anomaly, benign_multiplier, match_count, span_excerpt, top_window,
         top_window_score, fingerprint, note)
      SELECT ${input.appVersion}, ${input.targetHost}, ${input.locator},
             ${JSON.stringify(input.patternNames)}::jsonb, ${input.fusedScore}, ${input.mlScore},
             ${input.entropyAnomaly}, ${input.benignMultiplier}, ${input.matchCount},
             ${input.spanExcerpt}, ${input.topWindow}, ${input.topWindowScore},
             ${input.fingerprint}, ${input.note}
      WHERE (SELECT count(*) FROM false_positive_reports
             WHERE created_at > now() - interval '1 minute') < ${GLOBAL_WRITES_PER_MIN}
      RETURNING id`;
    if (rows.length === 0) {
      console.warn("[report-store] global write cap reached; report dropped");
    }
  } catch (err) {
    // Persisting must never make the endpoint 500 on the reporter.
    console.warn(`[report-store] persist failed: ${(err as Error).message}`);
  }
}
