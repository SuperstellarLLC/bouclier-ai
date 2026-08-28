// @vitest-environment node
import { NextRequest } from "next/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  after: vi.fn(),
  recordDownload: vi.fn(),
  env: { DOWNLOAD_REDIRECT_BASE: "https://downloads.example/releases" } as {
    DOWNLOAD_REDIRECT_BASE?: string;
  },
}));

vi.mock("next/server", async () => {
  const actual = await vi.importActual<Record<string, unknown>>("next/server");
  return { ...actual, after: mocks.after };
});
vi.mock("@/env", () => ({ env: mocks.env }));
vi.mock("@/lib/download-tracker", () => ({ recordDownload: mocks.recordDownload }));

import { GET } from "@/app/api/download/route";
import { APP_VERSION } from "@/lib/constants";

describe("GET /api/download", () => {
  beforeEach(() => {
    mocks.after.mockReset();
    mocks.recordDownload.mockReset();
    mocks.recordDownload.mockResolvedValue(undefined);
    mocks.env.DOWNLOAD_REDIRECT_BASE = "https://downloads.example/releases";
  });

  it("validates input before scheduling or redirecting", async () => {
    const res = await GET(new NextRequest("http://localhost/api/download?v=../etc&c=site"));
    expect(res.status).toBe(400);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(mocks.after).not.toHaveBeenCalled();
  });

  it("does not let arbitrary semver values pollute release paths or download stats", async () => {
    const res = await GET(new NextRequest("http://localhost/api/download?v=9.9.9&c=site"));
    expect(res.status).toBe(404);
    expect(mocks.after).not.toHaveBeenCalled();
  });

  it("redirects immediately and retains the tracker task with Next after()", async () => {
    const res = await GET(new NextRequest(`http://localhost/api/download?v=${APP_VERSION}&c=SITE`));
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(
      `https://downloads.example/releases/Bouclier-ai-v${APP_VERSION}-macOS.dmg`,
    );
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(mocks.recordDownload).not.toHaveBeenCalled();
    expect(mocks.after).toHaveBeenCalledOnce();

    await mocks.after.mock.calls[0]![0]();
    expect(mocks.recordDownload).toHaveBeenCalledWith(
      expect.objectContaining({ version: APP_VERSION, channel: "site" }),
    );
  });

  it("503s without counting when the download base is missing", async () => {
    mocks.env.DOWNLOAD_REDIRECT_BASE = undefined;
    const res = await GET(new NextRequest(`http://localhost/api/download?v=${APP_VERSION}&c=site`));
    expect(res.status).toBe(503);
    expect(mocks.after).not.toHaveBeenCalled();
  });

  it("rejects an insecure or credential-bearing download base", async () => {
    mocks.env.DOWNLOAD_REDIRECT_BASE = "http://user:pass@downloads.example/releases";
    const res = await GET(new NextRequest(`http://localhost/api/download?v=${APP_VERSION}&c=site`));
    expect(res.status).toBe(503);
    expect(mocks.after).not.toHaveBeenCalled();
  });
});
