// @vitest-environment node
import { describe, expect, it } from "vitest";

import { normalizeSafeHttpsBaseUrl } from "@/lib/safe-base-url";

describe("normalizeSafeHttpsBaseUrl", () => {
  it("accepts HTTPS endpoints and removes every trailing slash", () => {
    expect(normalizeSafeHttpsBaseUrl("https://redis.example/path///")).toBe(
      "https://redis.example/path",
    );
  });

  it.each([
    "http://redis.example",
    "https://user:secret@redis.example",
    "https://redis.example?token=leak",
    "https://redis.example#fragment",
    "https://redis.example?",
    "https://redis.example#",
  ])("rejects unsafe credential destinations: %s", (value) => {
    expect(normalizeSafeHttpsBaseUrl(value)).toBeNull();
  });
});
