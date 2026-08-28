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

const GRAPHEME_SEGMENTER = new Intl.Segmenter(undefined, { granularity: "grapheme" });

/**
 * Normalized text plus a UTF-16 source span for every UTF-16 code unit.
 * RegExp offsets are UTF-16 offsets, so keeping the map at the same
 * granularity lets the scanner safely project normalized matches back onto
 * the exact source span it must report and redact.
 */
export interface MappedContent {
  text: string;
  sourceStarts: number[];
  sourceEnds: number[];
}

/**
 * Normalize content for injection scanning.
 * Returns a normalized copy — the original content is preserved for redaction.
 */
export function normalize(content: string): string {
  let result = content.normalize("NFKC");
  result = [...result].map((char) => HOMOGLYPH_MAP[char] ?? char).join("");
  result = result.replace(/[\u200B\u200C\u200D\uFEFF\u2060\u00AD]/g, "");
  return result.replace(
    /\b([a-zA-Z])\s([a-zA-Z])\s([a-zA-Z])\s([a-zA-Z])(?:\s([a-zA-Z]))*/g,
    (match) => match.replace(/\s/g, ""),
  );
}

/**
 * Normalize content while retaining the original span of every output unit.
 *
 * NFKC is applied per grapheme cluster. Unicode normalization cannot compose
 * across grapheme boundaries, so this remains equivalent to whole-string
 * normalization while giving expansions (for example, a ligature becoming
 * two ASCII letters) one well-defined source span.
 */
export function normalizeWithSourceMap(content: string): MappedContent {
  let mapped = normalizeNfkc(content);
  mapped = replaceHomoglyphs(mapped);
  mapped = stripZeroWidth(mapped);
  mapped = collapseSplitWords(mapped);
  return mapped;
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

/** Apply leetspeak deobfuscation without losing the original source map. */
export function deobfuscateLeetWithSourceMap(content: MappedContent): MappedContent {
  const chars = [...content.text];
  let codeUnitOffset = 0;
  const out: MappedContent = { text: "", sourceStarts: [], sourceEnds: [] };

  for (let i = 0; i < chars.length; i++) {
    const char = chars[i]!;
    const replacement = LEET_MAP[char];
    const prev = i > 0 ? chars[i - 1]! : "";
    const next = i < chars.length - 1 ? chars[i + 1]! : "";
    const shouldReplace =
      replacement !== undefined && (/[a-zA-Z]/.test(prev) || /[a-zA-Z]/.test(next));
    appendReplacement(
      out,
      content,
      codeUnitOffset,
      codeUnitOffset + char.length,
      shouldReplace ? replacement : char,
    );
    codeUnitOffset += char.length;
  }

  return out;
}

function normalizeNfkc(content: string): MappedContent {
  const out: MappedContent = { text: "", sourceStarts: [], sourceEnds: [] };

  for (const part of GRAPHEME_SEGMENTER.segment(content)) {
    const start = part.index;
    const end = start + part.segment.length;
    const normalized = part.segment.normalize("NFKC");
    out.text += normalized;
    for (let i = 0; i < normalized.length; i++) {
      out.sourceStarts.push(start);
      out.sourceEnds.push(end);
    }
  }

  return out;
}

function replaceHomoglyphs(content: MappedContent): MappedContent {
  const out: MappedContent = { text: "", sourceStarts: [], sourceEnds: [] };
  let codeUnitOffset = 0;
  for (const char of content.text) {
    appendReplacement(
      out,
      content,
      codeUnitOffset,
      codeUnitOffset + char.length,
      HOMOGLYPH_MAP[char] ?? char,
    );
    codeUnitOffset += char.length;
  }
  return out;
}

function stripZeroWidth(content: MappedContent): MappedContent {
  return filterMapped(content, (char) => !/[\u200B\u200C\u200D\uFEFF\u2060\u00AD]/.test(char));
}

function collapseSplitWords(content: MappedContent): MappedContent {
  // Match sequences of single characters separated by spaces: "i g n o r e"
  // Only trigger when at least 4 characters are split this way
  const splitWord = /\b([a-zA-Z])\s([a-zA-Z])\s([a-zA-Z])\s([a-zA-Z])(?:\s([a-zA-Z]))*/g;
  const out: MappedContent = { text: "", sourceStarts: [], sourceEnds: [] };
  let cursor = 0;
  let match: RegExpExecArray | null;
  while ((match = splitWord.exec(content.text)) !== null) {
    appendSlice(out, content, cursor, match.index);
    const end = match.index + match[0].length;
    for (let i = match.index; i < end; i++) {
      if (!/\s/.test(content.text[i]!)) appendSlice(out, content, i, i + 1);
    }
    cursor = end;
  }
  appendSlice(out, content, cursor, content.text.length);
  return out;
}

function filterMapped(content: MappedContent, keep: (char: string) => boolean): MappedContent {
  const out: MappedContent = { text: "", sourceStarts: [], sourceEnds: [] };
  let codeUnitOffset = 0;
  for (const char of content.text) {
    if (keep(char)) {
      appendSlice(out, content, codeUnitOffset, codeUnitOffset + char.length);
    }
    codeUnitOffset += char.length;
  }
  return out;
}

function appendSlice(out: MappedContent, source: MappedContent, start: number, end: number): void {
  out.text += source.text.slice(start, end);
  for (let i = start; i < end; i++) {
    out.sourceStarts.push(source.sourceStarts[i]!);
    out.sourceEnds.push(source.sourceEnds[i]!);
  }
}

function appendReplacement(
  out: MappedContent,
  source: MappedContent,
  start: number,
  end: number,
  replacement: string,
): void {
  let sourceStart = source.sourceStarts[start]!;
  let sourceEnd = source.sourceEnds[start]!;
  for (let i = start + 1; i < end; i++) {
    sourceStart = Math.min(sourceStart, source.sourceStarts[i]!);
    sourceEnd = Math.max(sourceEnd, source.sourceEnds[i]!);
  }
  out.text += replacement;
  for (let i = 0; i < replacement.length; i++) {
    out.sourceStarts.push(sourceStart);
    out.sourceEnds.push(sourceEnd);
  }
}
