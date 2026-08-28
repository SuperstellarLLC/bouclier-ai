import { readFile } from "node:fs/promises";

const generatedPath = new URL("../packages/patterns/dist/patterns.json", import.meta.url);
const bundledPath = new URL(
  "../apps/desktop/Sources/Bouclier/Resources/patterns.json",
  import.meta.url,
);

async function readPatternSet(path) {
  const parsed = JSON.parse(await readFile(path, "utf8"));
  // `updatedAt` records when export-json.js ran, so two otherwise identical
  // artifacts legitimately differ here. Every field that affects runtime
  // detection remains part of the comparison.
  delete parsed.updatedAt;
  return parsed;
}

const [generated, bundled] = await Promise.all([
  readPatternSet(generatedPath),
  readPatternSet(bundledPath),
]);

if (JSON.stringify(generated) !== JSON.stringify(bundled)) {
  console.error(
    "The desktop patterns.json is stale. Run apps/desktop/scripts/sync-patterns.sh after building @bouclier-ai/patterns, then commit the updated resource.",
  );
  process.exitCode = 1;
} else {
  console.log(
    `Desktop pattern bundle is in sync (${generated.patterns.length} patterns, ${generated.dampeners.length} dampeners).`,
  );
}
