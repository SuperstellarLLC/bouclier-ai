// @vitest-environment node
import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  env: { DOWNLOAD_STATS_TOKEN: "operator-token-123456" } as {
    DOWNLOAD_STATS_TOKEN?: string;
  },
  readDownloadStats: vi.fn(),
}));

vi.mock("@/env", () => ({ env: mocks.env }));
vi.mock("@/lib/download-tracker", () => ({ readDownloadStats: mocks.readDownloadStats }));

import { GET } from "@/app/api/download/stats/route";

function request(authorization?: string): NextRequest {
  return new NextRequest("http://localhost/api/download/stats", {
    headers: authorization ? { authorization } : undefined,
  });
}

describe("GET /api/download/stats", () => {
  beforeEach(() => {
    mocks.env.DOWNLOAD_STATS_TOKEN = "operator-token-123456";
    mocks.readDownloadStats.mockReset();
    mocks.readDownloadStats.mockResolvedValue({
      total: 1,
      daily: { "2026-08-28": 1 },
      byVersion: {},
      byChannel: {},
      recentEvents: [],
    });
  });

  it("stays hidden and no-store when disabled or unauthorized", async () => {
    expect((await GET(request())).status).toBe(404);
    const wrong = await GET(request("Bearer wrong-token"));
    expect(wrong.status).toBe(404);
    expect(wrong.headers.get("cache-control")).toBe("no-store");

    mocks.env.DOWNLOAD_STATS_TOKEN = undefined;
    expect((await GET(request("Bearer operator-token-123456"))).status).toBe(404);
    expect(mocks.readDownloadStats).not.toHaveBeenCalled();
  });

  it("accepts the case-insensitive Bearer scheme and returns no-store stats", async () => {
    const res = await GET(request("bearer operator-token-123456"));
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.json()).toMatchObject({ total: 1 });
  });

  it("returns 503 when the backing tracker is unavailable", async () => {
    mocks.readDownloadStats.mockResolvedValueOnce(null);
    const res = await GET(request("Bearer operator-token-123456"));
    expect(res.status).toBe(503);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });
});
