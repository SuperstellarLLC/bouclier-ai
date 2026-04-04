import { describe, expect, it } from "vitest";
import { normalize, deobfuscateLeet } from "../normalize.js";

describe("normalize", () => {
  it("strips zero-width characters", () => {
    const result = normalize("hello\u200B\u200Cworld");
    expect(result).toBe("helloworld");
  });

  it("replaces Cyrillic homoglyphs with Latin equivalents", () => {
    // "аеорс" in Cyrillic looks like "aeopc" in Latin
    const result = normalize("\u0430\u0435\u043E\u0440\u0441");
    expect(result).toBe("aeopc");
  });

  it("collapses split single-character words", () => {
    const result = normalize("i g n o r e");
    expect(result).toBe("ignore");
  });

  it("does not collapse normal words", () => {
    const result = normalize("I am a person");
    expect(result).toBe("I am a person");
  });

  it("handles fullwidth characters via NFKC", () => {
    // Fullwidth "ｈｅｌｌｏ"
    const result = normalize("\uFF48\uFF45\uFF4C\uFF4C\uFF4F");
    expect(result).toBe("hello");
  });
});

describe("deobfuscateLeet", () => {
  it("converts leetspeak between alpha characters", () => {
    const result = deobfuscateLeet("1gn0r3");
    expect(result).toBe("ignore");
  });

  it("does not convert standalone numbers", () => {
    const result = deobfuscateLeet("I have 100 items");
    expect(result).toBe("I have 100 items");
  });

  it("converts @ to a when adjacent to alpha", () => {
    const result = deobfuscateLeet("s@fety");
    expect(result).toBe("safety");
  });
});
