/**
 * Download redirect + anonymous timestamp tracker.
 *
 * Flow:
 *   GET /api/download?v=0.3.0&c=site
 *     1. Validate `v` against a strict version regex (we never echo
 *        arbitrary user input back as a redirect target).
 *     2. Record `{ts, version, channel}` to Upstash if configured,
 *        else log to stdout.
 *     3. 302 redirect to DOWNLOAD_REDIRECT_BASE/Bouclier-ai-v<version>-macOS.dmg
 *
 * What we DO NOT record:
 *   - IP address (we never read req.headers["x-forwarded-for"] or
 *     similar).
 *   - User agent.
 *   - Referrer (we don't read req.headers["referer"]).
 *   - Geo / country.
 *   - Cookies.
 *
 * The brand promise — "no analytics, no telemetry" — applies to the
 * app. The site logs the *event* of a download to know whether anyone
 * is using the product. This is disclosed in /privacy.
 */

import { NextRequest, NextResponse } from "next/server";

import { env } from "@/env";
import { recordDownload } from "@/lib/download-tracker";

// Tight version regex: digits dot digits dot digits, optional pre-release
// suffix like "-rc1". Anything else 400s — we never let the client paint
// the redirect URL.
const VERSION_RE = /^\d+\.\d+\.\d+(?:-[a-z0-9]+)?$/i;
const CHANNEL_RE = /^[a-z]{1,16}$/i;

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const version = url.searchParams.get("v") ?? "";
  const channel = url.searchParams.get("c") ?? "site";

  if (!VERSION_RE.test(version)) {
    return NextResponse.json({ error: "invalid version" }, { status: 400 });
  }
  if (!CHANNEL_RE.test(channel)) {
    return NextResponse.json({ error: "invalid channel" }, { status: 400 });
  }

  // Fire-and-forget the record. We deliberately don't `await` so the
  // redirect happens immediately even if Upstash is slow; record errors
  // never block a download.
  void recordDownload({
    ts: new Date().toISOString(),
    version,
    channel,
  });

  const base = env.DOWNLOAD_REDIRECT_BASE ?? process.env.NEXT_PUBLIC_DOWNLOAD_URL ?? "";

  if (!base) {
    return NextResponse.json({ error: "download base not configured" }, { status: 503 });
  }

  const target = `${base.replace(/\/$/, "")}/Bouclier-ai-v${version}-macOS.dmg`;
  return NextResponse.redirect(target, { status: 302 });
}
