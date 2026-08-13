/**
 * False-positive report intake.
 *
 * The menu-bar app POSTs a *redacted* block sample here when an operator
 * taps "Report false positive". The excerpt is scrubbed of secrets/PII on
 * the Mac and the operator sees the exact payload in a confirm dialog
 * before it is sent — this endpoint trusts that and just validates,
 * size-caps, and stores.
 *
 * What we DO NOT store with a report: no IP, user-agent, referrer, geo, or
 * cookie is written into the report or the store — the persisted payload is
 * only the fields the app sends. (The shared rate-limit middleware transiently
 * reads x-forwarded-for to throttle abuse; that IP lives in an in-memory
 * window and is never logged, persisted, or attached to a report.)
 *
 * Abuse posture: unauthenticated by necessity (the app ships no secret),
 * so the gate is a hard body-size cap + strict shape validation + POST
 * only. No IP-based rate limiter — that would mean handling IPs, which the
 * brand promise forbids. If spam ever materializes, a hashed-IP ephemeral
 * counter is the next step, decided deliberately.
 */

import { type NextRequest, NextResponse } from "next/server";

import { normalizeReport, recordReport } from "@/lib/report-store";

export const dynamic = "force-dynamic";

/** Hard cap on the raw request body. The app caps the excerpt at 4 KB; a
 * full report is well under this. Anything larger is rejected outright. */
const MAX_BODY_BYTES = 32 * 1024;

const NO_STORE = { "Cache-Control": "no-store" } as const;

export async function POST(req: NextRequest) {
  const contentType = req.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    return NextResponse.json(
      { ok: false, error: "content-type must be application/json" },
      { status: 415, headers: NO_STORE },
    );
  }

  // Reject oversize before reading the whole body when the client is honest
  // about Content-Length; still guard on the actual byte length after.
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
    return NextResponse.json(
      { ok: false, error: "payload too large" },
      { status: 413, headers: NO_STORE },
    );
  }

  const rawText = await req.text();
  if (Buffer.byteLength(rawText, "utf8") > MAX_BODY_BYTES) {
    return NextResponse.json(
      { ok: false, error: "payload too large" },
      { status: 413, headers: NO_STORE },
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return NextResponse.json(
      { ok: false, error: "invalid JSON" },
      { status: 400, headers: NO_STORE },
    );
  }

  const report = normalizeReport(parsed);
  if (!report) {
    return NextResponse.json(
      { ok: false, error: "missing required fields (spanExcerpt, targetHost)" },
      { status: 400, headers: NO_STORE },
    );
  }

  await recordReport(report);
  return NextResponse.json({ ok: true }, { status: 200, headers: NO_STORE });
}

/** Anything but POST is not allowed — no listing, no reading reports back. */
export function GET() {
  return NextResponse.json(
    { ok: false, error: "method not allowed" },
    { status: 405, headers: { ...NO_STORE, Allow: "POST" } },
  );
}
