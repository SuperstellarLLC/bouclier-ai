import { env } from "@/env";
import { normalizeSafeHttpsBaseUrl } from "@/lib/safe-base-url";

/**
 * Single-use enforcement for a proof-of-work stamp.
 *
 * `verifyReportPow` (pow.ts) is stateless: a solved stamp stays valid for its
 * whole freshness window (`POW_WINDOW_MS`), so without this a single solve
 * could be replayed up to the global write cap. This claims the stamp's
 * identity (`timestamp:fingerprint:nonce`) in Upstash with `SET … NX EX`, so
 * the first request that presents a given solve wins and every replay of it is
 * rejected until it expires (and it's expired past the window anyway).
 *
 * TTL is set above the PoW window so a claim can't lapse while the stamp is
 * still otherwise valid; the key auto-expires, so storage stays bounded.
 *
 * Degrades open: if Upstash isn't configured or errors, returns `"unavailable"`
 * and the caller proceeds — the atomic global write cap still bounds abuse, so
 * a missing replay-cache weakens the per-solve cost but never blocks reporting.
 */

// Must exceed POW_WINDOW_MS + permitted future skew (150 s) so a seen stamp
// cannot be reused while it is still within its freshness window.
const CLAIM_TTL_SECONDS = 180;
const CLAIM_TIMEOUT_MS = 3_000;

export type PowClaim = "claimed" | "replay" | "unavailable";

export async function claimPowStamp(
  timestamp: number,
  fingerprint: string,
  nonce: string,
): Promise<PowClaim> {
  if (!env.UPSTASH_REDIS_REST_URL || !env.UPSTASH_REDIS_REST_TOKEN) {
    return "unavailable";
  }
  const redisBase = normalizeSafeHttpsBaseUrl(env.UPSTASH_REDIS_REST_URL);
  if (!redisBase) return "unavailable";
  // Fully identifies one solved stamp; `:` is safe — none of the parts contain it.
  const key = `pow:${timestamp}:${fingerprint}:${nonce}`;
  try {
    // SET key 1 NX EX 180 → "OK" on the first claim, null once it already exists.
    const res = await fetch(redisBase, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.UPSTASH_REDIS_REST_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(["SET", key, "1", "NX", "EX", String(CLAIM_TTL_SECONDS)]),
      cache: "no-store",
      signal: AbortSignal.timeout(CLAIM_TIMEOUT_MS),
    });
    if (!res.ok) return "unavailable";
    const body = (await res.json()) as { result?: unknown };
    if (body.result === "OK") return "claimed";
    if (body.result === null) return "replay";
    return "unavailable";
  } catch {
    return "unavailable";
  }
}
