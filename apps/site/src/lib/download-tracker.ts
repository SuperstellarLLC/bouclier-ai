/**
 * Anonymous download tracker.
 *
 * Goals (matched by tests + privacy policy):
 * - Record the timestamp + version + channel of each DMG download so we
 *   can see adoption over time.
 * - DO NOT record IP addresses, user-agent strings, country, referrer,
 *   or anything else that identifies the person clicking the link. The
 *   brand promise on the app is "no telemetry"; on the site, the only
 *   thing recorded is the *event* of a download.
 * - Be graceful when storage isn't configured — skip tracking so a fresh
 *   deployment still serves the DMG. Never emit one attacker-amplifiable log
 *   line per public request.
 *
 * Storage choice: Upstash Redis REST API.
 * - Atomic INCR for counters; LPUSH for a rolling event log; HINCRBY
 *   for per-day buckets.
 * - REST API means no SDK dependency — `fetch` is enough.
 * - Two env vars (URL + token); Upstash free tier covers easily ≫ a
 *   small beta's traffic.
 *
 * If you swap stores later, only this module needs to change.
 */

import { env } from "@/env";
import { APP_VERSION } from "@/lib/constants";
import { normalizeSafeHttpsBaseUrl } from "@/lib/safe-base-url";

const MAX_EVENTS = 5_000; // rolling log size — older events drop off the back
const STORAGE_TIMEOUT_MS = 5_000;
const TRACKED_CHANNELS = ["site", "github", "homebrew", "direct", "other"] as const;
const ALLOWED_CHANNELS = new Set<string>(TRACKED_CHANNELS);
let lastStorageWarningAt = 0;

function warnStorage(message: string): void {
  const now = Date.now();
  if (now - lastStorageWarningAt < 60_000) return;
  lastStorageWarningAt = now;
  console.warn(message);
}

export interface DownloadEvent {
  /** ISO 8601 UTC timestamp at server-receive time. */
  ts: string;
  /** App version requested (e.g. "0.3.0"). */
  version: string;
  /**
   * High-level surface that initiated the download — distinguishes a
   * marketing-site click from a Homebrew install. NEVER user-identifying.
   */
  channel: string;
}

/** Record one download. Safe to call even when storage isn't configured. */
export async function recordDownload(event: DownloadEvent): Promise<void> {
  const safeChannel = ALLOWED_CHANNELS.has(event.channel) ? event.channel : "other";
  const normalized: DownloadEvent = { ...event, channel: safeChannel };

  if (!env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN) {
    return;
  }

  const redisBase = normalizeSafeHttpsBaseUrl(env.UPSTASH_REDIS_REST_URL);
  if (!redisBase) {
    warnStorage("[download-tracker] invalid Upstash URL; event not stored");
    return;
  }

  const day = normalized.ts.slice(0, 10); // YYYY-MM-DD
  // Pipeline three writes into one round-trip via the Upstash REST pipeline.
  // INCR downloads:total                — lifetime counter
  // HINCRBY downloads:daily {day} 1     — per-day histogram
  // LPUSH downloads:events {event}      — rolling event log (LTRIM to MAX_EVENTS)
  const pipeline = [
    ["INCR", "downloads:total"],
    ["HINCRBY", "downloads:daily", day, "1"],
    ["HINCRBY", `downloads:version:${normalized.version}`, day, "1"],
    ["HINCRBY", `downloads:channel:${normalized.channel}`, day, "1"],
    ["LPUSH", "downloads:events", JSON.stringify(normalized)],
    ["LTRIM", "downloads:events", "0", String(MAX_EVENTS - 1)],
  ];

  try {
    const res = await fetch(`${redisBase}/pipeline`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.UPSTASH_REDIS_REST_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(pipeline),
      cache: "no-store",
      signal: AbortSignal.timeout(STORAGE_TIMEOUT_MS),
    });
    if (!res.ok) {
      warnStorage(`[download-tracker] Upstash write failed (${res.status})`);
    }
  } catch {
    // Recording must never block the redirect.
    warnStorage("[download-tracker] Upstash unreachable");
  }
}

export interface DownloadStats {
  total: number;
  daily: Record<string, number>;
  /** Daily counts for the currently published version. */
  byVersion: Record<string, Record<string, number>>;
  /** Daily counts for each bounded, non-identifying channel bucket. */
  byChannel: Record<string, Record<string, number>>;
  recentEvents: DownloadEvent[];
}

/** Read aggregated stats. Returns nulls when Upstash isn't configured. */
export async function readDownloadStats(): Promise<DownloadStats | null> {
  if (!env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN) return null;
  const redisBase = normalizeSafeHttpsBaseUrl(env.UPSTASH_REDIS_REST_URL);
  if (!redisBase) return null;

  const pipeline = [
    ["GET", "downloads:total"],
    ["HGETALL", "downloads:daily"],
    ["LRANGE", "downloads:events", "0", "199"],
    ["HGETALL", `downloads:version:${APP_VERSION}`],
    ...TRACKED_CHANNELS.map((channel) => ["HGETALL", `downloads:channel:${channel}`]),
  ];
  try {
    const res = await fetch(`${redisBase}/pipeline`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.UPSTASH_REDIS_REST_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(pipeline),
      cache: "no-store",
      signal: AbortSignal.timeout(STORAGE_TIMEOUT_MS),
    });
    if (!res.ok) return null;
    const data = (await res.json()) as unknown;
    if (!Array.isArray(data)) return null;

    const rawTotal = Number((data[0] as { result?: unknown } | undefined)?.result ?? 0);
    const total = Number.isSafeInteger(rawTotal) && rawTotal >= 0 ? rawTotal : 0;
    const daily = parseHGetAll((data[1] as { result?: unknown } | undefined)?.result);
    const recent = parseEventList((data[2] as { result?: unknown } | undefined)?.result);
    const byVersion = {
      [APP_VERSION]: parseHGetAll((data[3] as { result?: unknown } | undefined)?.result),
    };
    const byChannel = Object.fromEntries(
      TRACKED_CHANNELS.map((channel, index) => [
        channel,
        parseHGetAll((data[4 + index] as { result?: unknown } | undefined)?.result),
      ]),
    );

    return {
      total,
      daily,
      byVersion,
      byChannel,
      recentEvents: recent,
    };
  } catch {
    return null;
  }
}

function parseHGetAll(raw: unknown): Record<string, number> {
  if (Array.isArray(raw)) {
    const out: Record<string, number> = {};
    for (let i = 0; i < raw.length; i += 2) {
      const key = String(raw[i]);
      const value = Number(raw[i + 1]);
      if (key && Number.isSafeInteger(value) && value >= 0) out[key] = value;
    }
    return out;
  }
  if (raw && typeof raw === "object") {
    const out: Record<string, number> = {};
    for (const [key, rawValue] of Object.entries(raw as Record<string, unknown>)) {
      const value = Number(rawValue);
      if (key && Number.isSafeInteger(value) && value >= 0) out[key] = value;
    }
    return out;
  }
  return {};
}

function parseEventList(raw: unknown): DownloadEvent[] {
  if (!Array.isArray(raw)) return [];
  const out: DownloadEvent[] = [];
  for (const line of raw) {
    try {
      const parsed = JSON.parse(String(line));
      if (
        parsed &&
        typeof parsed.ts === "string" &&
        typeof parsed.version === "string" &&
        typeof parsed.channel === "string"
      ) {
        out.push({ ts: parsed.ts, version: parsed.version, channel: parsed.channel });
      }
    } catch {
      // Skip malformed entries — robust against legacy formats.
    }
  }
  return out;
}
