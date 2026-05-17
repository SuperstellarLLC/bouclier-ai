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

import { NextRequest, NextResponse } from "next/server";

import { env } from "@/env";
import { readDownloadStats } from "@/lib/download-tracker";

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  if (!env.DOWNLOAD_STATS_TOKEN) {
    return new NextResponse(null, { status: 404 });
  }
  const header = req.headers.get("authorization") ?? "";
  const provided = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!provided || !timingSafeEqual(provided, env.DOWNLOAD_STATS_TOKEN)) {
    return new NextResponse(null, { status: 404 });
  }
  const stats = await readDownloadStats();
  if (!stats) {
    return NextResponse.json({ error: "download tracker storage not configured" }, { status: 503 });
  }
  return NextResponse.json(stats, {
    headers: { "Cache-Control": "no-store" },
  });
}

/** Constant-time token comparison so an attacker can't time-side-channel guess. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
