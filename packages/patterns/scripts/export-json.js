/**
 * Exports patterns as a JSON file for consumption by the Swift app.
 * Run after `tsc` compiles the TypeScript source.
 */
import { readFileSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const distDir = join(__dirname, "..", "dist");

// Dynamic import of the compiled JS
const { patterns: rawPatterns } = await import(join(distDir, "patterns.js"));

// The Swift engine compiles these with NSRegularExpression (ICU), which
// is not JS RegExp. Where a pattern carries an `icuRegex` override, that
// is what ships — the JS form stays in the TS module for the scanner and
// the site playground. `icuRegex` itself is dropped from the payload so
// the Swift decoder sees exactly the fields it declares.
const patterns = rawPatterns.map(({ icuRegex, ...p }) => ({
  ...p,
  regex: icuRegex ?? p.regex,
}));

const overridden = rawPatterns.filter((p) => p.icuRegex).length;

const patternSet = {
  version: JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf-8")).version,
  updatedAt: new Date().toISOString(),
  patterns,
};

// Trailing newline so the copy that lands in the app's Resources is
// already Prettier-clean — otherwise `pnpm format:check` fails on a
// freshly synced artifact and every sync shows up as a diff.
const outPath = join(distDir, "patterns.json");
writeFileSync(outPath, JSON.stringify(patternSet, null, 2) + "\n");
console.log(
  `Exported ${patterns.length} patterns to ${outPath}` +
    (overridden ? ` (${overridden} with an ICU regex override)` : ""),
);
