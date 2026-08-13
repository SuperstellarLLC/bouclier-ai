/**
 * Hashcash-style proof of work for the public /api/report endpoint.
 *
 * Each submission must carry a nonce such that SHA-256(material‖nonce) has at
 * least `bits` leading zero bits, where `material` binds a recent timestamp to
 * the report's fingerprint. This makes flooding cost real CPU per report
 * without any client IP, identity, or shipped secret — so it is safe in an
 * open-source client (PoW security does not depend on the algorithm being
 * secret). The server verifies with a single hash.
 *
 * It is a cost multiplier, not a wall: a determined attacker can still grind,
 * and a solved stamp can be reused within the freshness window. Both are
 * bounded — by the difficulty and by the store's global per-minute write cap.
 */

import { createHash } from "node:crypto";

/** Freshness window: a stamp's timestamp must be within this of the server clock. */
export const POW_WINDOW_MS = 2 * 60_000;

/** Default difficulty (leading zero bits) when REPORT_POW_BITS is unset:
 * ~2^20 ≈ 1M hashes, sub-second on the reporter's Mac, real cost to flood. */
export const DEFAULT_POW_BITS = 20;

/** The value the nonce is mined against — recent time bound to the report. */
export function powMaterial(timestamp: number, fingerprint: string): string {
  return `${timestamp}:${fingerprint}`;
}

/** Count leading zero bits of a SHA-256 digest. */
function leadingZeroBits(digest: Buffer): number {
  let count = 0;
  for (const byte of digest) {
    if (byte === 0) {
      count += 8;
      continue;
    }
    count += Math.clz32(byte) - 24; // clz32 of a byte value → leading zeros within the byte
    break;
  }
  return count;
}

/** True iff SHA-256(material‖nonce) has ≥ `bits` leading zero bits. */
export function verifyPow(material: string, nonce: string, bits: number): boolean {
  if (bits <= 0) return true;
  const digest = createHash("sha256").update(material).update(nonce).digest();
  return leadingZeroBits(digest) >= bits;
}

/** Reference solver — also used by tests. Returns the first nonce that satisfies. */
export function solvePow(material: string, bits: number): string {
  for (let n = 0; ; n++) {
    const nonce = n.toString(36);
    if (verifyPow(material, nonce, bits)) return nonce;
  }
}

/**
 * Validate a report's PoW stamp: the timestamp must be fresh and the nonce must
 * satisfy the difficulty for `${timestamp}:${fingerprint}`. `bits <= 0` disables
 * the check (returns ok).
 */
export function verifyReportPow(params: {
  timestamp: unknown;
  nonce: unknown;
  fingerprint: string;
  bits: number;
  now: number;
}): { ok: boolean; reason?: string } {
  const { timestamp, nonce, fingerprint, bits, now } = params;
  if (bits <= 0) return { ok: true };
  if (typeof timestamp !== "number" || !Number.isFinite(timestamp)) {
    return { ok: false, reason: "missing or invalid pow.timestamp" };
  }
  if (typeof nonce !== "string" || nonce.length === 0 || nonce.length > 64) {
    return { ok: false, reason: "missing or invalid pow.nonce" };
  }
  if (Math.abs(now - timestamp) > POW_WINDOW_MS) {
    return { ok: false, reason: "pow.timestamp outside the freshness window" };
  }
  if (!verifyPow(powMaterial(timestamp, fingerprint), nonce, bits)) {
    return { ok: false, reason: "pow does not meet the required difficulty" };
  }
  return { ok: true };
}
