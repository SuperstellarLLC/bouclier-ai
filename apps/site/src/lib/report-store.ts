/**
 * False-positive report store — Postgres (Neon / Vercel Postgres).
 *
 * When an operator taps "Report false positive" in the menu-bar app, the app
 * POSTs a *redacted* block sample to `/api/report`. This module is the only
 * place that persists it. Design notes:
 *
 * - **Durable + queryable.** Reports are the raw material for tuning detection,
 *   so they belong in a database you can query (by pattern, date, fingerprint),
 *   not an evictable Redis list. Within the retention window, a later write
 *   cannot evict an earlier report, so a flood can't push genuine reports out.
 * - **Finite retention policy.** Accepted reports become deletion-eligible
 *   after 90 days. Every write first deletes expired rows through the indexed
 *   `created_at` column; deployments that need a strict wall-clock guarantee
 *   run the idempotent daily cleanup documented in `docs/DEPLOYMENT.md`.
 * - **IP-free global write cap.** The only abuse control here is a single global
 *   ceiling per one-minute quota window, enforced by an atomic Postgres UPSERT —
 *   no client IP, identity, or per-client state. It bounds cost and DB growth;
 *   the proof-of-work stamp on the route makes reaching the cap expensive.
 * - **No IP / UA / identifier is ever stored** — only the redacted fields the
 *   app sends. Redaction happens on the operator's Mac and is shown to them
 *   before send; this module trusts that and just validates + caps + persists.
 * - **Honest failure when unconfigured.** No `DATABASE_URL` means the endpoint
 *   returns 503. Report contents are never sprayed into function logs and the
 *   client is never told that a report was accepted when it was not persisted.
 */

import { neon, type NeonQueryFunction } from "@neondatabase/serverless";

import { env } from "@/env";

/** Global ceiling on accepted reports per one-minute quota window. */
const GLOBAL_WRITES_PER_MIN = 300;

/** False-positive reports are tuning data, not a permanent content archive. */
export const REPORT_RETENTION_DAYS = 90;

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
  fingerprint: 64,
  matchCount: 10_000,
} as const;

/** A redacted false-positive report accepted by `/api/report`. */
export interface FalsePositiveReportInput {
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

function clamp(value: unknown, max: number): string {
  if (typeof value !== "string") return "";
  const truncated = value.slice(0, max);
  // Never return half of a UTF-16 surrogate pair at the truncation boundary.
  return /[\uD800-\uDBFF]$/.test(truncated) ? truncated.slice(0, -1) : truncated;
}

function containsPostgresNul(value: unknown): boolean {
  return typeof value === "string" && value.includes("\u0000");
}

function isFiniteInRange(value: unknown, min: number, max: number): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= min && value <= max;
}

function optionalScore(value: unknown): number | null | undefined {
  if (value === null || value === undefined) return null;
  return isFiniteInRange(value, 0, 1) ? value : undefined;
}

/**
 * Validate + normalize an untrusted request body into a report, or return null
 * if it doesn't look like one. Strings are hard-capped and numeric signals are
 * range-checked, so malformed input cannot poison tuning data or fail later at
 * the database boundary. The route has already size-capped the raw body; this
 * caps each field. Pure (no DB), so it is unit-testable on its own.
 */
export function normalizeReport(raw: unknown): FalsePositiveReportInput | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;

  if (
    typeof r.spanExcerpt !== "string" ||
    r.spanExcerpt.trim().length === 0 ||
    containsPostgresNul(r.spanExcerpt)
  ) {
    return null;
  }
  if (
    typeof r.appVersion !== "string" ||
    r.appVersion.trim().length === 0 ||
    /[\u0000-\u001F\u007F]/.test(r.appVersion)
  ) {
    return null;
  }
  if (
    typeof r.locator !== "string" ||
    r.locator.trim().length === 0 ||
    /[\u0000-\u001F\u007F]/.test(r.locator)
  ) {
    return null;
  }
  if (
    typeof r.targetHost !== "string" ||
    r.targetHost.trim().length === 0 ||
    /[\s\u0000-\u001F\u007F/@?#]/.test(r.targetHost.trim())
  ) {
    return null;
  }
  // The desktop app sends a salted SHA-256 hex digest. PoW is bound only to
  // this value, so accepting an empty or delimiter-bearing fingerprint would
  // make the anti-replay identity ambiguous and the work reusable.
  if (
    typeof r.fingerprint !== "string" ||
    r.fingerprint.length !== LIMITS.fingerprint ||
    !/^[a-f0-9]+$/.test(r.fingerprint)
  ) {
    return null;
  }

  if (!isFiniteInRange(r.fusedScore, 0, 1)) return null;
  if (!isFiniteInRange(r.entropyAnomaly, 0, 1)) return null;
  if (!isFiniteInRange(r.benignMultiplier, 0, 1)) return null;
  if (
    typeof r.matchCount !== "number" ||
    !Number.isInteger(r.matchCount) ||
    r.matchCount < 0 ||
    r.matchCount > LIMITS.matchCount
  ) {
    return null;
  }
  const mlScore = optionalScore(r.mlScore);
  const topWindowScore = optionalScore(r.topWindowScore);
  if (mlScore === undefined || topWindowScore === undefined) return null;
  if (r.topWindow !== null && r.topWindow !== undefined && typeof r.topWindow !== "string") {
    return null;
  }
  if (r.note !== null && r.note !== undefined && typeof r.note !== "string") return null;
  // PostgreSQL `text` cannot store U+0000. Reject it at validation time so a
  // syntactically valid report cannot turn into a misleading, retry-forever
  // 503 at the persistence boundary.
  if (containsPostgresNul(r.topWindow) || containsPostgresNul(r.note)) return null;

  if (!Array.isArray(r.patternNames) || r.patternNames.some((n) => typeof n !== "string")) {
    return null;
  }
  const normalizedPatternNames = r.patternNames.map((n) => n.trim());
  if (normalizedPatternNames.some((n) => n.length === 0 || /[\u0000-\u001F\u007F]/.test(n))) {
    return null;
  }
  const patternNames = normalizedPatternNames
    .slice(0, LIMITS.maxPatternNames)
    .map((n) => clamp(n, LIMITS.patternName));

  return {
    appVersion: clamp(r.appVersion.trim(), LIMITS.appVersion),
    targetHost: clamp(r.targetHost.trim(), LIMITS.host),
    locator: clamp(r.locator.trim(), LIMITS.locator),
    patternNames,
    fusedScore: r.fusedScore,
    mlScore,
    entropyAnomaly: r.entropyAnomaly,
    benignMultiplier: r.benignMultiplier,
    matchCount: r.matchCount,
    spanExcerpt: clamp(r.spanExcerpt, LIMITS.excerpt),
    topWindow: typeof r.topWindow === "string" ? clamp(r.topWindow, LIMITS.topWindow) : null,
    topWindowScore,
    fingerprint: r.fingerprint,
    note:
      typeof r.note === "string" && r.note.trim().length > 0
        ? clamp(r.note.trim(), LIMITS.note)
        : null,
  };
}

let _sql: NeonQueryFunction<false, false> | null = null;
let lastStorageWarningAt = 0;

function warnStorageUnavailable(message: string): void {
  const now = Date.now();
  if (now - lastStorageWarningAt < 60_000) return;
  lastStorageWarningAt = now;
  console.warn(message);
}

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
      await sql`CREATE TABLE IF NOT EXISTS false_positive_report_limits (
        scope          text PRIMARY KEY,
        window_started timestamptz NOT NULL,
        write_count    integer NOT NULL CHECK (write_count >= 0)
      )`;
    })().catch((err) => {
      schemaReady = null;
      throw err;
    });
  }
  return schemaReady;
}

/**
 * Persist one report and say what happened. The quota UPSERT locks one global
 * row and increments it atomically; the report INSERT can run only when that
 * UPSERT returns a quota token. This avoids the read-count-then-insert race
 * where concurrent requests could all observe the same below-limit count.
 */
export type RecordReportResult = "recorded" | "rate-limited" | "storage-unavailable";

export async function recordReport(input: FalsePositiveReportInput): Promise<RecordReportResult> {
  const sql = getSql();
  if (!sql) {
    warnStorageUnavailable("[report-store] DATABASE_URL is not configured; report not stored");
    return "storage-unavailable";
  }

  try {
    await ensureSchema(sql);
    const rows = await sql`
      WITH expired AS (
        DELETE FROM false_positive_reports
        WHERE created_at < now() - (${REPORT_RETENTION_DAYS}::integer * interval '1 day')
        RETURNING id
      ), quota AS (
        INSERT INTO false_positive_report_limits (scope, window_started, write_count)
        VALUES ('global', now(), 1)
        ON CONFLICT (scope) DO UPDATE SET
          window_started = CASE
            WHEN false_positive_report_limits.window_started <= now() - interval '1 minute'
              THEN now()
            ELSE false_positive_report_limits.window_started
          END,
          write_count = CASE
            WHEN false_positive_report_limits.window_started <= now() - interval '1 minute'
              THEN 1
            ELSE false_positive_report_limits.write_count + 1
          END
        WHERE false_positive_report_limits.window_started <= now() - interval '1 minute'
           OR false_positive_report_limits.write_count < ${GLOBAL_WRITES_PER_MIN}
        RETURNING 1
      )
      INSERT INTO false_positive_reports
        (app_version, target_host, locator, pattern_names, fused_score, ml_score,
         entropy_anomaly, benign_multiplier, match_count, span_excerpt, top_window,
         top_window_score, fingerprint, note)
      SELECT ${input.appVersion}, ${input.targetHost}, ${input.locator},
             ${JSON.stringify(input.patternNames)}::jsonb, ${input.fusedScore}, ${input.mlScore},
             ${input.entropyAnomaly}, ${input.benignMultiplier}, ${input.matchCount},
             ${input.spanExcerpt}, ${input.topWindow}, ${input.topWindowScore},
             ${input.fingerprint}, ${input.note}
      FROM quota
      RETURNING id`;
    if (rows.length === 0) {
      return "rate-limited";
    }
    return "recorded";
  } catch {
    // Driver errors can include query parameters; never let report content
    // escape into provider logs through an exception string.
    warnStorageUnavailable("[report-store] persist failed");
    return "storage-unavailable";
  }
}
