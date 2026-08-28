import { cpSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const siteRoot = process.cwd();
const standaloneSite = join(siteRoot, ".next", "standalone", "apps", "site");

if (!existsSync(join(standaloneSite, "server.js"))) {
  throw new Error("Next.js standalone server was not produced");
}

const standaloneNext = join(standaloneSite, ".next");
mkdirSync(standaloneNext, { recursive: true });
cpSync(join(siteRoot, ".next", "static"), join(standaloneNext, "static"), {
  recursive: true,
  force: true,
});

const publicDir = join(siteRoot, "public");
if (existsSync(publicDir)) {
  cpSync(publicDir, join(standaloneSite, "public"), {
    recursive: true,
    force: true,
  });
}
