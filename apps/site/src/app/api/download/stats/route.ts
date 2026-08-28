/**
 * Read-only aggregated download stats.
 *
 * Returns 404 unless `DOWNLOAD_STATS_TOKEN` is set in env AND the
 * request carries a matching `Authorization: Bearer …` header. The
 * default-deny posture means deploying without the env var is safe —
 * the endpoint never accidentally exposes counts to the public.
 *
 * Usage (operator):
 *   curl -H "Authorization: Bearer $DOWNLOAD_STATS_TOKEN" \\
 *        https://www.bouclier.ai/api/download/stats
 */

import { createHash, timingSafeEqual as cryptoTimingSafeEqual } from "node:crypto";

import { type NextRequest, NextResponse } from "next/server";

import { env } from "@/env";
import { readDownloadStats } from "@/lib/download-tracker";

export const dynamic = "force-dynamic";
const NO_STORE = { "Cache-Control": "no-store" } as const;

export async function GET(req: NextRequest) {
  if (!env.DOWNLOAD_STATS_TOKEN) {
    return new NextResponse(null, { status: 404, headers: NO_STORE });
  }
  const header = req.headers.get("authorization") ?? "";
  const match = header.match(/^Bearer ([^\s]+)$/i);
  const provided = match?.[1] ?? null;
  if (!provided || !timingSafeEqual(provided, env.DOWNLOAD_STATS_TOKEN)) {
    return new NextResponse(null, { status: 404, headers: NO_STORE });
  }
  const stats = await readDownloadStats();
  if (!stats) {
    return NextResponse.json(
      { error: "download tracker storage unavailable" },
      { status: 503, headers: NO_STORE },
    );
  }
  return NextResponse.json(stats, {
    headers: NO_STORE,
  });
}

/** Constant-time token comparison so an attacker can't time-side-channel guess. */
function timingSafeEqual(a: string, b: string): boolean {
  const aDigest = createHash("sha256").update(a).digest();
  const bDigest = createHash("sha256").update(b).digest();
  return cryptoTimingSafeEqual(aDigest, bDigest);
}
