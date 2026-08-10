/**
 * Unicode normalization and deobfuscation layer.
 * Runs before regex scanning to catch evasion techniques.
 */

/** Common leetspeak substitution map */
const LEET_MAP: Record<string, string> = {
  "0": "o",
  "1": "i",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "8": "b",
  "@": "a",
  $: "s",
};

/** Homoglyph map — visually similar characters from other scripts */
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic → Latin
  "\u0430": "a", // а
  "\u0435": "e", // е
  "\u043E": "o", // о
  "\u0440": "p", // р
  "\u0441": "c", // с
  "\u0443": "y", // у
  "\u0445": "x", // х
  "\u0410": "A", // А
  "\u0415": "E", // Е
  "\u041E": "O", // О
  "\u0420": "P", // Р
  "\u0421": "C", // С
  "\u0422": "T", // Т
  "\u041D": "H", // Н
  "\u0412": "B", // В
  "\u041C": "M", // М
  // Greek → Latin
  "\u03B1": "a", // α
  "\u03B5": "e", // ε
  "\u03BF": "o", // ο
  "\u03C1": "p", // ρ
  "\u0391": "A", // Α
  "\u0395": "E", // Ε
  "\u039F": "O", // Ο
  "\u03A1": "P", // Ρ
  // Fullwidth → ASCII
  "\uFF41": "a",
  "\uFF42": "b",
  "\uFF43": "c",
  "\uFF44": "d",
  "\uFF45": "e",
  "\uFF49": "i",
  "\uFF4F": "o",
  "\uFF50": "p",
  "\uFF53": "s",
  "\uFF54": "t",
};

/**
 * Normalize content for injection scanning.
 * Returns a normalized copy — the original content is preserved for redaction.
 */
export function normalize(content: string): string {
  let result = content;

  // Step 1: Unicode NFKC normalization (normalizes fullwidth, compatibility chars)
  result = result.normalize("NFKC");

  // Step 2: Replace homoglyphs with Latin equivalents
  result = replaceHomoglyphs(result);

  // Step 3: Strip zero-width characters (but note: indirect-002 pattern detects these separately)
  result = stripZeroWidth(result);

  // Step 4: Normalize excessive whitespace within words (catches "i g n o r e")
  // Only collapse single-space gaps between single characters
  result = collapseSplitWords(result);

  return result;
}

/**
 * Apply leetspeak deobfuscation.
 * Only applies when a digit/symbol is surrounded by alpha characters,
 * to avoid false positives on normal numbers.
 */
export function deobfuscateLeet(content: string): string {
  const chars = [...content];
  const result: string[] = [];

  for (let i = 0; i < chars.length; i++) {
    const char = chars[i]!;
    const replacement = LEET_MAP[char];

    if (replacement) {
      // Only replace if surrounded by alpha characters
      const prev = i > 0 ? chars[i - 1]! : "";
      const next = i < chars.length - 1 ? chars[i + 1]! : "";
      const prevIsAlpha = /[a-zA-Z]/.test(prev);
      const nextIsAlpha = /[a-zA-Z]/.test(next);

      if (prevIsAlpha || nextIsAlpha) {
        result.push(replacement);
      } else {
        result.push(char);
      }
    } else {
      result.push(char);
    }
  }

  return result.join("");
}

function replaceHomoglyphs(content: string): string {
  const chars = [...content];
  return chars.map((c) => HOMOGLYPH_MAP[c] ?? c).join("");
}

function stripZeroWidth(content: string): string {
  return content.replace(/[\u200B\u200C\u200D\uFEFF\u2060\u00AD]/g, "");
}

function collapseSplitWords(content: string): string {
  // Match sequences of single characters separated by spaces: "i g n o r e"
  // Only trigger when at least 4 characters are split this way
  return content.replace(
    /\b([a-zA-Z])\s([a-zA-Z])\s([a-zA-Z])\s([a-zA-Z])(?:\s([a-zA-Z]))*/g,
    (match) => {
      return match.replace(/\s/g, "");
    },
  );
}
