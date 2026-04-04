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
const { patterns } = await import(join(distDir, "patterns.js"));

const patternSet = {
  version: JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf-8")).version,
  updatedAt: new Date().toISOString(),
  patterns,
};

const outPath = join(distDir, "patterns.json");
writeFileSync(outPath, JSON.stringify(patternSet, null, 2));
console.log(`Exported ${patterns.length} patterns to ${outPath}`);
