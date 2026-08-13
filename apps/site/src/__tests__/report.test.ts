// @vitest-environment node
// Route handlers run server-side; the default jsdom env makes t3-env treat
// `env.UPSTASH_*` (server-only) access as a client leak and throw.
import { NextRequest } from "next/server";
import { describe, expect, it } from "vitest";

import { GET, POST } from "@/app/api/report/route";
import { env } from "@/env";
import { DEFAULT_POW_BITS, powMaterial, solvePow } from "@/lib/pow";
import { LIMITS, normalizeReport } from "@/lib/report-store";

const validInput = {
  appVersion: "0.9.8",
  targetHost: "api.anthropic.com",
  locator: "messages[2].content[0].tool_result",
  patternNames: ["system-prompt-extraction"],
  fusedScore: 0.91,
  mlScore: 0.99,
  entropyAnomaly: 0.1,
  benignMultiplier: 1.0,
  matchCount: 1,
  spanExcerpt: "…offending span excerpt…",
  topWindow: "…top window…",
  topWindowScore: 0.99,
  fingerprint: "abc123",
  note: "this is a lint diff, not an attack",
};

function postRequest(body: string, contentType = "application/json"): NextRequest {
  return new NextRequest("http://localhost/api/report", {
    method: "POST",
    headers: { "content-type": contentType },
    body,
  });
}

// The route requires a valid proof-of-work stamp; tests run at low difficulty
// (vitest env REPORT_POW_BITS=8), so mining one is instant.
const POW_BITS = env.REPORT_POW_BITS ?? DEFAULT_POW_BITS;
function withPow<T extends { fingerprint: string }>(input: T) {
  const timestamp = Date.now();
  const nonce = solvePow(powMaterial(timestamp, input.fingerprint), POW_BITS);
  return { ...input, pow: { timestamp, nonce } };
}

describe("normalizeReport", () => {
  it("rejects non-objects and reports missing required fields", () => {
    expect(normalizeReport(null)).toBeNull();
    expect(normalizeReport("nope")).toBeNull();
    expect(normalizeReport({ ...validInput, spanExcerpt: "" })).toBeNull();
    expect(normalizeReport({ ...validInput, spanExcerpt: undefined })).toBeNull();
    expect(normalizeReport({ ...validInput, targetHost: "" })).toBeNull();
  });

  it("accepts a valid report and does not fabricate a timestamp", () => {
    const r = normalizeReport(validInput);
    expect(r).not.toBeNull();
    expect(r?.spanExcerpt).toBe(validInput.spanExcerpt);
    expect(r?.patternNames).toEqual(["system-prompt-extraction"]);
    // `ts` is stamped server-side in recordReport, never in the normalizer.
    expect((r as Record<string, unknown>).ts).toBeUndefined();
  });

  it("hard-caps oversized strings and pattern lists", () => {
    const r = normalizeReport({
      ...validInput,
      spanExcerpt: "x".repeat(LIMITS.excerpt + 5000),
      patternNames: Array.from({ length: 50 }, (_, i) => "p".repeat(200) + i),
    });
    expect(r?.spanExcerpt.length).toBe(LIMITS.excerpt);
    expect(r?.patternNames.length).toBe(LIMITS.maxPatternNames);
    expect(r?.patternNames[0]?.length).toBe(LIMITS.patternName);
  });

  it("coerces non-finite / wrong-typed numbers and empty optionals", () => {
    const r = normalizeReport({
      ...validInput,
      fusedScore: "high",
      mlScore: Number.NaN,
      matchCount: undefined,
      topWindow: 42,
      note: "",
    });
    expect(r?.fusedScore).toBe(0);
    expect(r?.mlScore).toBeNull();
    expect(r?.matchCount).toBe(0);
    expect(r?.topWindow).toBeNull();
    expect(r?.note).toBeNull();
  });
});

describe("POST /api/report", () => {
  it("415s a non-JSON content type", async () => {
    const res = await POST(postRequest(JSON.stringify(validInput), "text/plain"));
    expect(res.status).toBe(415);
  });

  it("413s an oversized body", async () => {
    const huge = JSON.stringify({ ...validInput, spanExcerpt: "x".repeat(40 * 1024) });
    const res = await POST(postRequest(huge));
    expect(res.status).toBe(413);
  });

  it("400s invalid JSON", async () => {
    const res = await POST(postRequest("{not json"));
    expect(res.status).toBe(400);
  });

  it("400s a body missing required fields", async () => {
    const res = await POST(postRequest(JSON.stringify({ targetHost: "h" })));
    expect(res.status).toBe(400);
  });

  it("200s a valid report with a valid proof-of-work", async () => {
    const res = await POST(postRequest(JSON.stringify(withPow(validInput))));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("403s a valid report with no proof-of-work", async () => {
    const res = await POST(postRequest(JSON.stringify(validInput)));
    expect(res.status).toBe(403);
  });

  it("403s a proof-of-work whose timestamp is stale (outside the freshness window)", async () => {
    const stale = Date.now() - 10 * 60_000;
    const nonce = solvePow(powMaterial(stale, validInput.fingerprint), POW_BITS);
    const res = await POST(
      postRequest(JSON.stringify({ ...validInput, pow: { timestamp: stale, nonce } })),
    );
    expect(res.status).toBe(403);
  });
});

describe("GET /api/report", () => {
  it("405s — reports are write-only, never readable back", async () => {
    const res = GET();
    expect(res.status).toBe(405);
  });
});
