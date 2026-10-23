import { afterEach, describe, expect, it, vi } from "vitest";

async function loadLogger(env: { LOG_LEVEL?: string; NODE_ENV?: string }) {
  vi.resetModules();
  vi.stubEnv("LOG_LEVEL", env.LOG_LEVEL);
  vi.stubEnv("NODE_ENV", env.NODE_ENV);
  return (await import("@/lib/logger")).logger;
}

describe("logger", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.restoreAllMocks();
  });

  it("routes each level to the matching console method in readable dev format", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const error = vi.spyOn(console, "error").mockImplementation(() => {});
    const logger = await loadLogger({ LOG_LEVEL: "debug", NODE_ENV: "development" });

    logger.debug("d");
    logger.info("i", { a: 1 });
    logger.warn("w");
    logger.error("e");

    expect(log).toHaveBeenCalledTimes(2);
    expect(log.mock.calls[0]?.[0]).toMatch(/\] DEBUG: d$/);
    expect(log.mock.calls[1]?.[0]).toMatch(/\] INFO: i \{"a":1\}$/);
    expect(warn.mock.calls[0]?.[0]).toMatch(/\] WARN: w$/);
    expect(error.mock.calls[0]?.[0]).toMatch(/\] ERROR: e$/);
  });

  it("emits structured JSON in production and drops messages below the level", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const logger = await loadLogger({ NODE_ENV: "production" });

    logger.debug("hidden");
    logger.info("shown", { k: "v" });

    expect(log).toHaveBeenCalledTimes(1);
    expect(JSON.parse(log.mock.calls[0]?.[0] as string)).toMatchObject({
      level: "info",
      message: "shown",
      meta: { k: "v" },
    });
  });
});
