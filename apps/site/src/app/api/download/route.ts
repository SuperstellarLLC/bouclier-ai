/**
 * Download redirect + anonymous timestamp tracker.
 *
 * Flow:
 *   GET /api/download?v=0.9.10&c=site
 *     1. Require the currently published app version (we never echo
 *        arbitrary user input back as a redirect target or stats key).
 *     2. Record `{ts, version, channel}` to Upstash if configured,
 *        otherwise skip tracking.
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

import { after, type NextRequest, NextResponse } from "next/server";

import { env } from "@/env";
import { APP_VERSION } from "@/lib/constants";
import { recordDownload } from "@/lib/download-tracker";
import { normalizeSafeHttpsBaseUrl } from "@/lib/safe-base-url";

// Tight version regex: digits dot digits dot digits, optional pre-release
// suffix like "-rc1". Anything else 400s — we never let the client paint
// the redirect URL.
const VERSION_RE = /^\d+\.\d+\.\d+(?:-[a-z0-9]+)?$/i;
const CHANNEL_RE = /^[a-z]{1,16}$/i;
const NO_STORE = { "Cache-Control": "no-store" } as const;

export const dynamic = "force-dynamic";

export async function GET(req: NextRequest) {
  const url = new URL(req.url);
  const version = url.searchParams.get("v") ?? "";
  const rawChannel = url.searchParams.get("c") ?? "site";

  if (!VERSION_RE.test(version)) {
    return NextResponse.json({ error: "invalid version" }, { status: 400, headers: NO_STORE });
  }
  if (version !== APP_VERSION) {
    return NextResponse.json({ error: "version unavailable" }, { status: 404, headers: NO_STORE });
  }
  if (!CHANNEL_RE.test(rawChannel)) {
    return NextResponse.json({ error: "invalid channel" }, { status: 400, headers: NO_STORE });
  }
  const channel = rawChannel.toLowerCase();

  const base = env.DOWNLOAD_REDIRECT_BASE ?? "";

  if (!base) {
    return NextResponse.json(
      { error: "download base not configured" },
      { status: 503, headers: NO_STORE },
    );
  }

  let target: URL;
  try {
    const safeBase = normalizeSafeHttpsBaseUrl(base);
    if (!safeBase) throw new Error("unsafe download base");
    const baseUrl = new URL(safeBase);
    baseUrl.pathname = `${baseUrl.pathname.replace(/\/$/, "")}/Bouclier-ai-v${version}-macOS.dmg`;
    target = baseUrl;
  } catch {
    return NextResponse.json(
      { error: "download base misconfigured" },
      { status: 503, headers: NO_STORE },
    );
  }

  // `after` is backed by the platform's waitUntil primitive, so the redirect
  // stays immediate while a serverless invocation remains alive long enough
  // for the anonymous counter write to finish.
  const event = { ts: new Date().toISOString(), version, channel };
  after(() => recordDownload(event));

  return NextResponse.redirect(target, { status: 302, headers: NO_STORE });
}
