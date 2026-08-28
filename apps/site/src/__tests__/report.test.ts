// @vitest-environment node
// Route handlers run server-side; the default jsdom env makes t3-env treat
// `env.UPSTASH_*` (server-only) access as a client leak and throw.
import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const routeMocks = vi.hoisted(() => ({
  recordReport: vi.fn(),
  claimPowStamp: vi.fn(),
  env: { REPORT_POW_BITS: 8 } as { REPORT_POW_BITS?: number },
}));
vi.mock("@/env", () => ({ env: routeMocks.env }));
vi.mock("@/lib/pow-nonce-store", () => ({ claimPowStamp: routeMocks.claimPowStamp }));
vi.mock("@/lib/report-store", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("@/lib/report-store");
  return { ...actual, recordReport: routeMocks.recordReport };
});

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
  fingerprint: "a".repeat(64),
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
    expect(normalizeReport({ ...validInput, targetHost: "not a host" })).toBeNull();
    expect(normalizeReport({ ...validInput, targetHost: "https://example.com" })).toBeNull();
    expect(normalizeReport({ ...validInput, fingerprint: "" })).toBeNull();
    expect(normalizeReport({ ...validInput, fingerprint: "abc123" })).toBeNull();
  });

  it("accepts a valid report and does not fabricate a timestamp", () => {
    const r = normalizeReport(validInput);
    expect(r).not.toBeNull();
    expect(r?.spanExcerpt).toBe(validInput.spanExcerpt);
    expect(r?.patternNames).toEqual(["system-prompt-extraction"]);
    // `ts` is stamped server-side in recordReport, never in the normalizer.
    expect(r).not.toHaveProperty("ts");
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

  it("rejects non-finite, wrong-typed, out-of-range, and fractional numeric fields", () => {
    expect(normalizeReport({ ...validInput, fusedScore: "high" })).toBeNull();
    expect(normalizeReport({ ...validInput, mlScore: Number.NaN })).toBeNull();
    expect(normalizeReport({ ...validInput, entropyAnomaly: 1.1 })).toBeNull();
    expect(normalizeReport({ ...validInput, benignMultiplier: -0.1 })).toBeNull();
    expect(normalizeReport({ ...validInput, matchCount: 1.5 })).toBeNull();
    expect(normalizeReport({ ...validInput, topWindow: 42 })).toBeNull();
    expect(normalizeReport({ ...validInput, note: 42 })).toBeNull();
    expect(normalizeReport({ ...validInput, patternNames: ["ok", 42] })).toBeNull();
  });

  it("rejects NUL in every persisted free-text field before PostgreSQL", () => {
    expect(normalizeReport({ ...validInput, spanExcerpt: "before\u0000after" })).toBeNull();
    expect(normalizeReport({ ...validInput, topWindow: "before\u0000after" })).toBeNull();
    expect(normalizeReport({ ...validInput, note: "before\u0000after" })).toBeNull();
  });

  it("trims metadata and empty notes without altering the report excerpt", () => {
    const r = normalizeReport({
      ...validInput,
      appVersion: " 0.9.8 ",
      targetHost: " api.anthropic.com ",
      locator: " body.messages[0] ",
      note: "   ",
    });
    expect(r).toMatchObject({
      appVersion: "0.9.8",
      targetHost: "api.anthropic.com",
      locator: "body.messages[0]",
      note: null,
      spanExcerpt: validInput.spanExcerpt,
    });
  });
});

describe("POST /api/report", () => {
  beforeEach(() => {
    routeMocks.env.REPORT_POW_BITS = 8;
    routeMocks.recordReport.mockReset();
    routeMocks.recordReport.mockResolvedValue("recorded");
    routeMocks.claimPowStamp.mockReset();
    routeMocks.claimPowStamp.mockResolvedValue("unavailable");
  });

  it("415s a non-JSON content type", async () => {
    const res = await POST(postRequest(JSON.stringify(validInput), "text/plain"));
    expect(res.status).toBe(415);
  });

  it("does not accept a content type that merely contains application/json", async () => {
    const res = await POST(postRequest(JSON.stringify(validInput), "text/application/json"));
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

  it("429s honestly when the atomic store quota is exhausted", async () => {
    routeMocks.recordReport.mockResolvedValueOnce("rate-limited");
    const res = await POST(postRequest(JSON.stringify(withPow(validInput))));
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60");
  });

  it("503s instead of claiming success when report storage is unavailable", async () => {
    routeMocks.recordReport.mockResolvedValueOnce("storage-unavailable");
    const res = await POST(postRequest(JSON.stringify(withPow(validInput))));
    expect(res.status).toBe(503);
    expect(await res.json()).toMatchObject({ ok: false });
  });

  it("skips replay-cache claims when proof of work is explicitly disabled", async () => {
    routeMocks.env.REPORT_POW_BITS = 0;
    const res = await POST(postRequest(JSON.stringify(validInput)));
    expect(res.status).toBe(200);
    expect(routeMocks.claimPowStamp).not.toHaveBeenCalled();
    expect(routeMocks.recordReport).toHaveBeenCalledOnce();
  });
});

describe("GET /api/report", () => {
  it("405s — reports are write-only, never readable back", async () => {
    const res = GET();
    expect(res.status).toBe(405);
  });
});
