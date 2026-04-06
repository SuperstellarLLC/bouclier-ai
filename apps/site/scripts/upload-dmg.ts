import { put } from "@vercel/blob";
import { readFileSync } from "fs";

const dmgPath = process.argv[2];
if (!dmgPath) {
  console.error("Usage: npx tsx scripts/upload-dmg.ts <path-to-dmg>");
  process.exit(1);
}

const file = readFileSync(dmgPath);

// Always upload as "latest" so the download URL never changes
const filename = "Bouclier-latest-macOS.dmg";

console.log(`Uploading ${dmgPath} as ${filename}...`);

const blob = await put(filename, file, {
  access: "public",
  addRandomSuffix: false,
});

console.log(`\nUploaded: ${blob.url}`);
