// @vitest-environment node
import { describe, expect, it } from "vitest";

import {
  DEFAULT_POW_BITS,
  POW_FUTURE_SKEW_MS,
  POW_WINDOW_MS,
  powMaterial,
  solvePow,
  verifyPow,
  verifyReportPow,
} from "@/lib/pow";

const FINGERPRINT = "a".repeat(64);

describe("proof of work", () => {
  it("a mined nonce satisfies the difficulty it was mined for", () => {
    for (const bits of [4, 8, 12]) {
      const material = powMaterial(1000, FINGERPRINT);
      const nonce = solvePow(material, bits);
      expect(verifyPow(material, nonce, bits)).toBe(true);
    }
  });

  it("a nonce mined for low difficulty fails a much higher one", () => {
    const material = powMaterial(1000, FINGERPRINT);
    const nonce = solvePow(material, 4);
    // 1/2^24 false-positive probability — effectively deterministic.
    expect(verifyPow(material, nonce, 24)).toBe(false);
  });

  it("bits <= 0 disables the check", () => {
    expect(verifyPow("anything", "x", 0)).toBe(true);
  });

  it("matches the cross-language parity vector", () => {
    // SHA256("parity:anchor" ‖ "884") has EXACTLY 12 leading zero bits. The
    // Swift client's ReportProofOfWorkTests asserts the identical vector, so
    // the client provably mines what this server verifies.
    expect(verifyPow("parity:anchor", "884", 12)).toBe(true);
    expect(verifyPow("parity:anchor", "884", 13)).toBe(false);
  });

  it("powMaterial binds the stamp to a fresh timestamp AND the fingerprint", () => {
    // Different fingerprint or timestamp -> different material -> a solved
    // stamp cannot be reused for another report or replayed later.
    expect(powMaterial(1000, "a".repeat(64))).not.toBe(powMaterial(1000, "b".repeat(64)));
    expect(powMaterial(1000, FINGERPRINT)).not.toBe(powMaterial(2000, FINGERPRINT));
  });

  describe("verifyReportPow", () => {
    const now = 1_000_000_000_000;

    it("accepts a fresh, valid stamp", () => {
      const nonce = solvePow(powMaterial(now, FINGERPRINT), 8);
      expect(
        verifyReportPow({ timestamp: now, nonce, fingerprint: FINGERPRINT, bits: 8, now }).ok,
      ).toBe(true);
    });

    it("rejects missing / wrong-typed timestamp or nonce", () => {
      expect(
        verifyReportPow({ timestamp: "x", nonce: "n", fingerprint: FINGERPRINT, bits: 8, now }).ok,
      ).toBe(false);
      expect(
        verifyReportPow({ timestamp: now, nonce: 123, fingerprint: FINGERPRINT, bits: 8, now }).ok,
      ).toBe(false);
      expect(
        verifyReportPow({ timestamp: now, nonce: "", fingerprint: FINGERPRINT, bits: 8, now }).ok,
      ).toBe(false);
      expect(
        verifyReportPow({
          timestamp: now + 0.5,
          nonce: "n",
          fingerprint: FINGERPRINT,
          bits: 8,
          now,
        }).ok,
      ).toBe(false);
    });

    it("rejects a stale timestamp", () => {
      const stale = now - POW_WINDOW_MS - 1;
      const nonce = solvePow(powMaterial(stale, FINGERPRINT), 8);
      expect(
        verifyReportPow({ timestamp: stale, nonce, fingerprint: FINGERPRINT, bits: 8, now }).ok,
      ).toBe(false);
    });

    it("allows small clock skew but rejects a far-future timestamp", () => {
      const withinSkew = now + POW_FUTURE_SKEW_MS;
      const validNonce = solvePow(powMaterial(withinSkew, FINGERPRINT), 8);
      expect(
        verifyReportPow({
          timestamp: withinSkew,
          nonce: validNonce,
          fingerprint: FINGERPRINT,
          bits: 8,
          now,
        }).ok,
      ).toBe(true);

      const future = now + POW_FUTURE_SKEW_MS + 1;
      const futureNonce = solvePow(powMaterial(future, FINGERPRINT), 8);
      expect(
        verifyReportPow({
          timestamp: future,
          nonce: futureNonce,
          fingerprint: FINGERPRINT,
          bits: 8,
          now,
        }).ok,
      ).toBe(false);
    });

    it("bits <= 0 disables it", () => {
      expect(
        verifyReportPow({ timestamp: 0, nonce: "", fingerprint: FINGERPRINT, bits: 0, now: 0 }).ok,
      ).toBe(true);
    });
  });

  it("DEFAULT_POW_BITS is a sane production difficulty", () => {
    expect(DEFAULT_POW_BITS).toBeGreaterThanOrEqual(16);
  });
});
