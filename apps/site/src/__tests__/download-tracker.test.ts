// @vitest-environment node
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/env", () => ({
  env: {
    UPSTASH_REDIS_REST_URL: "https://redis.example/",
    UPSTASH_REDIS_REST_TOKEN: "test-token-123456",
  },
}));

import { APP_VERSION } from "@/lib/constants";
import { readDownloadStats, recordDownload } from "@/lib/download-tracker";

describe("download tracker", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("normalizes unknown channels and writes without a double-slash endpoint", async () => {
    const fetchMock = vi.fn(
      async (_input: string | URL | Request, _init?: RequestInit) =>
        new Response("[]", { status: 200 }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await recordDownload({ ts: "2026-08-28T12:00:00.000Z", version: APP_VERSION, channel: "utm" });

    expect(fetchMock.mock.calls[0]![0]).toBe("https://redis.example/pipeline");
    const body = JSON.parse(fetchMock.mock.calls[0]![1]!.body as string) as string[][];
    expect(body).toContainEqual(["HINCRBY", "downloads:channel:other", "2026-08-28", "1"]);
    expect(body.find((command) => command[0] === "LPUSH")?.[2]).toContain('"channel":"other"');
  });

  it("returns validated totals plus real current-version and channel breakdowns", async () => {
    const results = [
      { result: "5" },
      { result: ["2026-08-28", "5", "bad", "NaN"] },
      {
        result: [
          JSON.stringify({
            ts: "2026-08-28T12:00:00.000Z",
            version: APP_VERSION,
            channel: "site",
            ignored: "field",
          }),
          "not-json",
        ],
      },
      { result: ["2026-08-28", "5"] },
      { result: ["2026-08-28", "3"] },
      { result: ["2026-08-28", "1"] },
      { result: [] },
      { result: [] },
      { result: ["2026-08-28", "1"] },
    ];
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json(results)),
    );

    const stats = await readDownloadStats();
    expect(stats).toMatchObject({
      total: 5,
      daily: { "2026-08-28": 5 },
      byVersion: { [APP_VERSION]: { "2026-08-28": 5 } },
      byChannel: {
        site: { "2026-08-28": 3 },
        github: { "2026-08-28": 1 },
        other: { "2026-08-28": 1 },
      },
      recentEvents: [{ ts: "2026-08-28T12:00:00.000Z", version: APP_VERSION, channel: "site" }],
    });
  });

  it("returns null instead of throwing on malformed or unreachable storage", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        throw new Error("network down");
      }),
    );
    expect(await readDownloadStats()).toBeNull();
  });
});
