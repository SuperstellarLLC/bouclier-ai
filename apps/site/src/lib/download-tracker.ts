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
 * - Be graceful when storage isn't configured — fall back to a
 *   `console.log` line so a fresh Vercel deployment without Upstash
 *   still serves the DMG.
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

const MAX_EVENTS = 5_000; // rolling log size — older events drop off the back
const ALLOWED_CHANNELS = new Set(["site", "github", "homebrew", "direct", "other"]);

export interface DownloadEvent {
  /** ISO 8601 UTC timestamp at server-receive time. */
  ts: string;
  /** App version requested (e.g. "0.2.12"). */
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
    // Console fallback so a fresh deployment without Upstash still has
    // something to grep for in Vercel function logs.
    console.log(JSON.stringify({ kind: "download", ...normalized }));
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
      console.warn(`[download-tracker] Upstash write failed: ${res.status} ${res.statusText}`);
    }
  } catch (err) {
    // Recording must never block the redirect.
    console.warn(`[download-tracker] Upstash unreachable: ${(err as Error).message}`);
  }
}

export interface DownloadStats {
  total: number;
  daily: Record<string, number>;
  byVersion: Record<string, Record<string, number>>;
  byChannel: Record<string, Record<string, number>>;
  recentEvents: DownloadEvent[];
}

/** Read aggregated stats. Returns nulls when Upstash isn't configured. */
export async function readDownloadStats(): Promise<DownloadStats | null> {
  if (!env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN) return null;

  const pipeline = [
    ["GET", "downloads:total"],
    ["HGETALL", "downloads:daily"],
    ["LRANGE", "downloads:events", "0", "199"],
  ];
  const res = await fetch(`${env.UPSTASH_REDIS_REST_URL}/pipeline`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.UPSTASH_REDIS_REST_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(pipeline),
    cache: "no-store",
  });
  if (!res.ok) return null;
  const data = (await res.json()) as { result: unknown }[];

  const total = Number(data[0]?.result ?? 0);
  const daily = parseHGetAll(data[1]?.result);
  const recent = parseEventList(data[2]?.result);

  return {
    total,
    daily,
    byVersion: {}, // queryable separately if a UI ever wants the breakdown
    byChannel: {},
    recentEvents: recent,
  };
}

function parseHGetAll(raw: unknown): Record<string, number> {
  if (Array.isArray(raw)) {
    const out: Record<string, number> = {};
    for (let i = 0; i < raw.length; i += 2) {
      const key = String(raw[i]);
      const value = Number(raw[i + 1]);
      if (key && !Number.isNaN(value)) out[key] = value;
    }
    return out;
  }
  if (raw && typeof raw === "object") {
    return Object.fromEntries(
      Object.entries(raw as Record<string, unknown>).map(([k, v]) => [k, Number(v)]),
    );
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
        out.push(parsed);
      }
    } catch {
      // Skip malformed entries — robust against legacy formats.
    }
  }
  return out;
}
