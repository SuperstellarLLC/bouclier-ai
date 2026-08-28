// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock env (only for this file) so the store treats Upstash as configured; the
// report-route tests keep the real env (Upstash unset → "unavailable").
const mocks = vi.hoisted(() => ({
  env: {
    UPSTASH_REDIS_REST_URL: "https://upstash.test///",
    UPSTASH_REDIS_REST_TOKEN: "test-token-123456",
  },
}));

vi.mock("@/env", () => ({
  env: mocks.env,
}));

import { claimPowStamp } from "@/lib/pow-nonce-store";

const FINGERPRINT = "a".repeat(64);

function fetchReturning(body: unknown, status = 200) {
  return vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
    Promise.resolve(new Response(JSON.stringify(body), { status })),
  );
}

describe("claimPowStamp — single-use proof-of-work", () => {
  beforeEach(() => {
    mocks.env.UPSTASH_REDIS_REST_URL = "https://upstash.test///";
  });

  afterEach(() => vi.restoreAllMocks());

  it("'claimed' when Upstash SET NX succeeds (first time this stamp is seen)", async () => {
    const fetchMock = fetchReturning({ result: "OK" });
    vi.stubGlobal("fetch", fetchMock);
    expect(await claimPowStamp(1, FINGERPRINT, "42")).toBe("claimed");
    expect(fetchMock.mock.calls[0]![0]).toBe("https://upstash.test");
  });

  it("'replay' when the stamp was already claimed (NX returns null)", async () => {
    vi.stubGlobal("fetch", fetchReturning({ result: null }));
    expect(await claimPowStamp(1, FINGERPRINT, "42")).toBe("replay");
  });

  it("degrades open to 'unavailable' on an Upstash error response", async () => {
    vi.stubGlobal("fetch", fetchReturning("nope", 500));
    expect(await claimPowStamp(1, FINGERPRINT, "42")).toBe("unavailable");
  });

  it("treats a malformed success response as unavailable, not as a replay", async () => {
    vi.stubGlobal("fetch", fetchReturning({ result: "unexpected" }));
    expect(await claimPowStamp(1, FINGERPRINT, "42")).toBe("unavailable");
  });

  it("degrades open to 'unavailable' when fetch throws", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    expect(await claimPowStamp(1, FINGERPRINT, "42")).toBe("unavailable");
  });

  it("never sends the Redis bearer token to an unsafe configured URL", async () => {
    mocks.env.UPSTASH_REDIS_REST_URL = "https://user:secret@upstash.test?redirect=attacker";
    const fetchMock = fetchReturning({ result: "OK" });
    vi.stubGlobal("fetch", fetchMock);

    expect(await claimPowStamp(1, FINGERPRINT, "42")).toBe("unavailable");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("claims a key bound to timestamp:fingerprint:nonce via SET … NX EX", async () => {
    const f = fetchReturning({ result: "OK" });
    vi.stubGlobal("fetch", f);
    await claimPowStamp(1700000000000, FINGERPRINT, "99");
    const [, init] = f.mock.calls[0] as unknown as [string, RequestInit];
    const body = JSON.parse(init.body as string) as string[];
    expect(body[0]).toBe("SET");
    expect(body[1]).toBe(`pow:1700000000000:${FINGERPRINT}:99`);
    expect(body).toContain("NX");
    expect(body).toContain("EX");
  });
});
