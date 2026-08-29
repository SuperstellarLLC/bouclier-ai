import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  assertProductionReleaseAlignment,
  isProductionDeployment,
  SELF_HOSTED_DEPLOYMENT_ENV_VAR,
  SITE_COPY_MIN_DESKTOP_VERSION,
  versionAtLeast,
} from "../../release-alignment";

const releaseVersion = SITE_COPY_MIN_DESKTOP_VERSION;
const validSignature = Buffer.alloc(64, 0xa5).toString("base64");

function appcast({
  version = releaseVersion,
  shortVersion = version,
  signature = validSignature,
  length = "272202400",
  url = `https://downloads.example/releases/Bouclier-ai-v${version}-macOS.dmg`,
  secondItem = "",
}: {
  version?: string;
  shortVersion?: string;
  signature?: string;
  length?: string;
  url?: string;
  secondItem?: string;
} = {}): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<rss xmlns:sparkle="http://www.andymatuschak.org/xml-namespaces/sparkle">
  <channel>
    <item>
      <sparkle:version>${version}</sparkle:version>
      <sparkle:shortVersionString>${shortVersion}</sparkle:shortVersionString>
      <enclosure url="${url}" sparkle:edSignature="${signature}" length="${length}" />
    </item>
    ${secondItem}
  </channel>
</rss>`;
}

function assertAlignment({
  vercelEnvironment,
  selfHostedEnvironment,
  desktopVersion = releaseVersion,
  appcastXml = appcast(),
  downloadRedirectBase = "https://downloads.example/releases",
}: {
  vercelEnvironment?: string;
  selfHostedEnvironment?: string;
  desktopVersion?: string;
  appcastXml?: string;
  downloadRedirectBase?: string;
} = {}): void {
  assertProductionReleaseAlignment({
    vercelEnvironment,
    selfHostedEnvironment,
    desktopVersion,
    appcastXml,
    downloadRedirectBase,
  });
}

describe("production release alignment", () => {
  it("keeps local and Vercel preview builds available for release QA", () => {
    expect(() =>
      assertAlignment({
        desktopVersion: "0.9.10",
        appcastXml: undefined,
        downloadRedirectBase: undefined,
      }),
    ).not.toThrow();
    expect(() =>
      assertAlignment({
        vercelEnvironment: "preview",
        desktopVersion: "0.9.10",
        appcastXml: undefined,
        downloadRedirectBase: "http://user:secret@downloads.example/releases?token=secret",
      }),
    ).not.toThrow();
  });

  it("recognizes both Vercel and Docker/self-hosted production builds", () => {
    expect(SELF_HOSTED_DEPLOYMENT_ENV_VAR).toBe("BOUCLIER_DEPLOYMENT_ENV");
    expect(isProductionDeployment("production", undefined)).toBe(true);
    expect(isProductionDeployment(undefined, "production")).toBe(true);
    expect(isProductionDeployment("preview", undefined)).toBe(false);

    expect(() => assertAlignment({ vercelEnvironment: "production" })).not.toThrow();
    expect(() => assertAlignment({ selfHostedEnvironment: "production" })).not.toThrow();
  });

  it("activates the self-hosted gate before the Docker site build", () => {
    const dockerfile = readFileSync(resolve(process.cwd(), "Dockerfile"), "utf8");
    const compose = readFileSync(resolve(process.cwd(), "docker-compose.yml"), "utf8");
    const readme = readFileSync(resolve(process.cwd(), "README.md"), "utf8");
    const gate = "ENV BOUCLIER_DEPLOYMENT_ENV=production";
    const build = "RUN pnpm --filter site build";
    const publicBaseArgument = "ARG DOWNLOAD_REDIRECT_BASE";
    const publicBaseEnvironment = "ENV DOWNLOAD_REDIRECT_BASE=$DOWNLOAD_REDIRECT_BASE";
    const productionDownloadBase =
      "https://0tdi95zyjwsefpzx.public.blob.vercel-storage.com/download";
    const requiredComposeValue =
      "${DOWNLOAD_REDIRECT_BASE:?set DOWNLOAD_REDIRECT_BASE in apps/site/.env.local}";

    expect(dockerfile.indexOf(gate)).toBeGreaterThan(-1);
    expect(dockerfile.indexOf(gate)).toBeLessThan(dockerfile.indexOf(build));
    expect(dockerfile.indexOf(publicBaseArgument)).toBeGreaterThan(-1);
    expect(dockerfile.indexOf(publicBaseArgument)).toBeLessThan(dockerfile.indexOf(build));
    expect(dockerfile.indexOf(publicBaseEnvironment)).toBeGreaterThan(-1);
    expect(dockerfile.indexOf(publicBaseEnvironment)).toBeLessThan(dockerfile.indexOf(build));
    expect(
      compose.match(new RegExp(requiredComposeValue.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g")),
    ).toHaveLength(2);
    expect(dockerfile).toContain(`--build-arg DOWNLOAD_REDIRECT_BASE=${productionDownloadBase}`);
    expect(readme).toContain(`--build-arg DOWNLOAD_REDIRECT_BASE=${productionDownloadBase}`);
    expect(readme).toContain("--env-file apps/site/.env.local");
  });

  it("requires a desktop version new enough for the production copy", () => {
    expect(() =>
      assertAlignment({ vercelEnvironment: "production", desktopVersion: "0.9.10" }),
    ).toThrow(/copy requires desktop 0\.9\.11\+/);
    expect(versionAtLeast("0.9.11", "0.9.11")).toBe(true);
    expect(versionAtLeast("0.10.0", "0.9.11")).toBe(true);
    expect(versionAtLeast("0.9.11-preview", "0.9.11")).toBe(false);
  });

  it("requires one safe production download base and accepts a trailing slash", () => {
    expect(() =>
      assertProductionReleaseAlignment({
        vercelEnvironment: "production",
        selfHostedEnvironment: undefined,
        desktopVersion: releaseVersion,
        appcastXml: appcast(),
        downloadRedirectBase: undefined,
      }),
    ).toThrow(/DOWNLOAD_REDIRECT_BASE is required/);

    for (const downloadRedirectBase of [
      "http://downloads.example/releases",
      "https://user:secret@downloads.example/releases",
      "https://downloads.example/releases?token=secret",
      "https://downloads.example/releases#latest",
      "not a URL",
    ]) {
      expect(() =>
        assertAlignment({ vercelEnvironment: "production", downloadRedirectBase }),
      ).toThrow(/must be a safe HTTPS base URL/);
    }

    expect(() =>
      assertAlignment({
        vercelEnvironment: "production",
        downloadRedirectBase: "https://downloads.example/releases/",
      }),
    ).not.toThrow();
  });

  it.each([
    ["a different host", "https://mirror.example/releases"],
    ["a different port", "https://downloads.example:8443/releases"],
    ["a parent path", "https://downloads.example"],
    ["a sibling path", "https://downloads.example/download"],
    ["a nested path", "https://downloads.example/releases/stable"],
  ])("rejects an appcast enclosure whose base uses %s", (_label, downloadRedirectBase) => {
    expect(() =>
      assertAlignment({ vercelEnvironment: "production", downloadRedirectBase }),
    ).toThrow(/enclosure directory must exactly match DOWNLOAD_REDIRECT_BASE/);
  });

  it("validates the first appcast item rather than a matching later item", () => {
    const matchingLaterItem = `<item>
      <sparkle:version>${releaseVersion}</sparkle:version>
      <sparkle:shortVersionString>${releaseVersion}</sparkle:shortVersionString>
      <enclosure
        url="https://downloads.example/Bouclier-ai-v${releaseVersion}-macOS.dmg"
        sparkle:edSignature="${validSignature}"
        length="123"
      />
    </item>`;

    expect(() =>
      assertAlignment({
        vercelEnvironment: "production",
        appcastXml: appcast({ version: "0.9.10", secondItem: matchingLaterItem }),
      }),
    ).toThrow(/first appcast item is 0\.9\.10\/0\.9\.10/);
  });

  it.each([
    ["an empty appcast", "", /appcast\.xml is missing or empty/],
    ["a missing item", "<rss><channel /></rss>", /no release item/],
    ["a missing signature", appcast({ signature: "" }), /no Sparkle EdDSA signature/],
    [
      "a placeholder signature",
      appcast({ signature: "signed-release" }),
      /canonical base64 for exactly 64 Ed25519 signature bytes/,
    ],
    [
      "a 63-byte signature",
      appcast({ signature: Buffer.alloc(63, 0xa5).toString("base64") }),
      /canonical base64 for exactly 64 Ed25519 signature bytes/,
    ],
    [
      "a 65-byte signature",
      appcast({ signature: Buffer.alloc(65, 0xa5).toString("base64") }),
      /canonical base64 for exactly 64 Ed25519 signature bytes/,
    ],
    [
      "noncanonical missing padding",
      appcast({ signature: validSignature.slice(0, -2) }),
      /canonical base64 for exactly 64 Ed25519 signature bytes/,
    ],
    ["a zero length", appcast({ length: "0" }), /not a positive integer/],
    ["a nonnumeric length", appcast({ length: "large" }), /not a positive integer/],
  ])("rejects %s", (_label, appcastXml, error) => {
    expect(() => assertAlignment({ selfHostedEnvironment: "production", appcastXml })).toThrow(
      error,
    );
  });

  it.each([
    ["plain HTTP", `http://downloads.example/Bouclier-ai-v${releaseVersion}-macOS.dmg`],
    ["the wrong version", "https://downloads.example/Bouclier-ai-v0.9.10-macOS.dmg"],
    [
      "a filename suffix",
      `https://downloads.example/Bouclier-ai-v${releaseVersion}-macOS.dmg.backup`,
    ],
    ["a query", `https://downloads.example/Bouclier-ai-v${releaseVersion}-macOS.dmg?latest=1`],
    ["a fragment", `https://downloads.example/Bouclier-ai-v${releaseVersion}-macOS.dmg#download`],
    [
      "embedded credentials",
      `https://user:secret@downloads.example/Bouclier-ai-v${releaseVersion}-macOS.dmg`,
    ],
  ])("rejects an enclosure URL using %s", (_label, url) => {
    expect(() =>
      assertAlignment({ vercelEnvironment: "production", appcastXml: appcast({ url }) }),
    ).toThrow(/exact Bouclier-ai-v0\.9\.11-macOS\.dmg artifact/);
  });
});
