/**
 * False-positive report intake.
 *
 * The menu-bar app POSTs a *redacted* block sample here when an operator taps
 * "Report false positive". The excerpt is scrubbed of secrets/PII on the Mac
 * and the operator sees the exact payload before it is sent — this endpoint
 * validates, size-caps, gates on proof-of-work, and persists to Postgres.
 *
 * Abuse posture (open-source, so no shipped secret can help): the endpoint is
 * unauthenticated by necessity, so the gates are (1) a hard body size cap read
 * with stream-and-abort — never trusting client-declared Content-Length, (2) a
 * hashcash proof-of-work stamp that costs the caller real CPU per report
 * without any IP or identity, and (3) an atomic global per-minute write cap in
 * the store. Per-IP rate limiting is intentionally NOT done in app code — that
 * belongs at the edge (Vercel Firewall), where an IP is transport, not data we
 * collect. Nothing here reads or stores an IP, user-agent, or identifier.
 */

import { type NextRequest, NextResponse } from "next/server";

import { env } from "@/env";
import { DEFAULT_POW_BITS, verifyReportPow } from "@/lib/pow";
import { claimPowStamp } from "@/lib/pow-nonce-store";
import { normalizeReport, recordReport } from "@/lib/report-store";

export const dynamic = "force-dynamic";

/** Hard cap on the raw request body. The app caps the excerpt at 4 KB; a full
 * report (with the PoW stamp) is well under this. Anything larger is aborted. */
const MAX_BODY_BYTES = 32 * 1024;

const NO_STORE = { "Cache-Control": "no-store" } as const;

/**
 * Read the request body up to `maxBytes`, aborting the stream as soon as it is
 * exceeded — so an oversized (or Content-Length-less chunked) body is never
 * fully buffered. Returns null when the cap is exceeded.
 */
async function readCappedBody(req: NextRequest, maxBytes: number): Promise<string | null> {
  const body = req.body;
  if (!body) return "";
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

export async function POST(req: NextRequest) {
  const contentType = req.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) {
    return NextResponse.json(
      { ok: false, error: "content-type must be application/json" },
      { status: 415, headers: NO_STORE },
    );
  }

  const rawText = await readCappedBody(req, MAX_BODY_BYTES);
  if (rawText === null) {
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

  // Proof-of-work: the stamp is bound to a fresh timestamp + this report's
  // fingerprint. Costs the caller CPU per report; costs us one hash to check.
  const pow = (parsed as { pow?: { timestamp?: unknown; nonce?: unknown } }).pow ?? {};
  const powCheck = verifyReportPow({
    timestamp: pow.timestamp,
    nonce: pow.nonce,
    fingerprint: report.fingerprint,
    bits: env.REPORT_POW_BITS ?? DEFAULT_POW_BITS,
    now: Date.now(),
  });
  if (!powCheck.ok) {
    return NextResponse.json(
      { ok: false, error: `proof of work required: ${powCheck.reason}` },
      { status: 403, headers: NO_STORE },
    );
  }

  // Single-use: a valid stamp is stateless and stays fresh for its whole
  // window, so reject a replay of one we've already seen. Degrades open when
  // Upstash is unconfigured — the global write cap still bounds abuse.
  const claim = await claimPowStamp(Number(pow.timestamp), report.fingerprint, String(pow.nonce));
  if (claim === "replay") {
    return NextResponse.json(
      { ok: false, error: "proof of work already used" },
      { status: 403, headers: NO_STORE },
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
