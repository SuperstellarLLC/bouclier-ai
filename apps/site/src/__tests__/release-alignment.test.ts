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
}: {
  vercelEnvironment?: string;
  selfHostedEnvironment?: string;
  desktopVersion?: string;
  appcastXml?: string;
} = {}): void {
  assertProductionReleaseAlignment({
    vercelEnvironment,
    selfHostedEnvironment,
    desktopVersion,
    appcastXml,
  });
}

describe("production release alignment", () => {
  it("keeps local and Vercel preview builds available for release QA", () => {
    expect(() =>
      assertAlignment({ desktopVersion: "0.9.10", appcastXml: undefined }),
    ).not.toThrow();
    expect(() =>
      assertAlignment({
        vercelEnvironment: "preview",
        desktopVersion: "0.9.10",
        appcastXml: undefined,
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
    const gate = "ENV BOUCLIER_DEPLOYMENT_ENV=production";
    const build = "RUN pnpm --filter site build";

    expect(dockerfile.indexOf(gate)).toBeGreaterThan(-1);
    expect(dockerfile.indexOf(gate)).toBeLessThan(dockerfile.indexOf(build));
  });

  it("requires a desktop version new enough for the production copy", () => {
    expect(() =>
      assertAlignment({ vercelEnvironment: "production", desktopVersion: "0.9.10" }),
    ).toThrow(/copy requires desktop 0\.9\.11\+/);
    expect(versionAtLeast("0.9.11", "0.9.11")).toBe(true);
    expect(versionAtLeast("0.10.0", "0.9.11")).toBe(true);
    expect(versionAtLeast("0.9.11-preview", "0.9.11")).toBe(false);
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
