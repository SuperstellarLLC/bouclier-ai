// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  env: { DATABASE_URL: "postgresql://user:pass@db.example/test" } as {
    DATABASE_URL?: string;
  },
  sql: vi.fn(),
  neon: vi.fn(),
}));

vi.mock("@/env", () => ({ env: mocks.env }));
vi.mock("@neondatabase/serverless", () => ({ neon: mocks.neon }));

const report = {
  appVersion: "0.9.10",
  targetHost: "api.anthropic.com",
  locator: "messages[0]",
  patternNames: ["system-prompt-extraction"],
  fusedScore: 0.9,
  mlScore: 0.8,
  entropyAnomaly: 0.1,
  benignMultiplier: 1,
  matchCount: 1,
  spanExcerpt: "private report excerpt",
  topWindow: null,
  topWindowScore: null,
  fingerprint: "a".repeat(64),
  note: null,
};

describe("recordReport", () => {
  beforeEach(() => {
    vi.resetModules();
    vi.restoreAllMocks();
    mocks.env.DATABASE_URL = "postgresql://user:pass@db.example/test";
    mocks.sql.mockReset();
    mocks.neon.mockReset();
    mocks.neon.mockReturnValue(mocks.sql);
  });

  it("claims quota by atomic UPSERT in the same statement as the report INSERT", async () => {
    let quotaSql = "";
    mocks.sql.mockImplementation(async (strings: TemplateStringsArray) => {
      const text = strings.join("?");
      if (text.includes("INSERT INTO false_positive_report_limits")) {
        quotaSql = text;
        return [{ id: 1 }];
      }
      return [];
    });

    const { recordReport } = await import("@/lib/report-store");
    expect(await recordReport(report)).toBe("recorded");
    expect(quotaSql).toContain("ON CONFLICT (scope) DO UPDATE");
    expect(quotaSql).toContain("FROM quota");
    expect(quotaSql).not.toContain("SELECT count(*)");
  });

  it("prunes reports older than 90 days through the created-at index", async () => {
    const statements: Array<{ text: string; values: unknown[] }> = [];
    mocks.sql.mockImplementation(async (strings: TemplateStringsArray, ...values: unknown[]) => {
      const text = strings.join("?");
      statements.push({ text, values });
      return text.includes("INSERT INTO false_positive_report_limits") ? [{ id: 1 }] : [];
    });

    const { REPORT_RETENTION_DAYS, recordReport } = await import("@/lib/report-store");
    expect(REPORT_RETENTION_DAYS).toBe(90);
    expect(await recordReport(report)).toBe("recorded");

    expect(
      statements.some(({ text }) =>
        text.includes("fpr_created_at_idx ON false_positive_reports (created_at DESC)"),
      ),
    ).toBe(true);
    const write = statements.find(({ text }) => text.includes("WITH expired AS"));
    expect(write?.text).toContain("DELETE FROM false_positive_reports");
    expect(write?.text).toContain("created_at < now() - (?::integer * interval '1 day')");
    expect(write?.values).toContain(REPORT_RETENTION_DAYS);
    expect(write!.text.indexOf("DELETE FROM false_positive_reports")).toBeLessThan(
      write!.text.indexOf("INSERT INTO false_positive_report_limits"),
    );
  });

  it("returns rate-limited when the quota UPSERT yields no token", async () => {
    mocks.sql.mockResolvedValue([]);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const { recordReport } = await import("@/lib/report-store");
    expect(await recordReport(report)).toBe("rate-limited");
  });

  it("fails honestly without storage and never writes report content to logs", async () => {
    mocks.env.DATABASE_URL = undefined;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const { recordReport } = await import("@/lib/report-store");
    expect(await recordReport(report)).toBe("storage-unavailable");
    expect(warn).toHaveBeenCalledOnce();
    expect(JSON.stringify(warn.mock.calls)).not.toContain(report.spanExcerpt);
  });

  it("does not echo driver errors that may contain query parameters", async () => {
    mocks.sql.mockImplementation(async (strings: TemplateStringsArray) => {
      if (strings.join("?").includes("INSERT INTO false_positive_report_limits")) {
        throw new Error(`driver failed near ${report.spanExcerpt}`);
      }
      return [];
    });
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const { recordReport } = await import("@/lib/report-store");
    expect(await recordReport(report)).toBe("storage-unavailable");
    expect(JSON.stringify(warn.mock.calls)).not.toContain(report.spanExcerpt);
  });
});
