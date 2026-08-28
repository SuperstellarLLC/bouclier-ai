/**
 * The current site source documents desktop behavior introduced after the
 * signed 0.9.10 DMG. Preview/local builds remain available for QA, but a
 * production deployment must not replace the honest 0.9.10 site until the
 * matching signed desktop release is represented by the committed appcast.
 */
export const SITE_COPY_MIN_DESKTOP_VERSION = "0.9.11";

export const SELF_HOSTED_DEPLOYMENT_ENV_VAR = "BOUCLIER_DEPLOYMENT_ENV";

export interface ProductionReleaseAlignmentInput {
  vercelEnvironment: string | undefined;
  selfHostedEnvironment: string | undefined;
  desktopVersion: string;
  appcastXml: string | undefined;
}

function parseVersion(value: string): readonly [number, number, number] | undefined {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(value);
  if (!match) return undefined;

  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

export function versionAtLeast(current: string, minimum: string): boolean {
  const left = parseVersion(current);
  const right = parseVersion(minimum);
  if (!left || !right) return false;

  for (let index = 0; index < left.length; index += 1) {
    const delta = left[index]! - right[index]!;
    if (delta !== 0) return delta > 0;
  }
  return true;
}

export function isProductionDeployment(
  vercelEnvironment: string | undefined,
  selfHostedEnvironment: string | undefined,
): boolean {
  return vercelEnvironment === "production" || selfHostedEnvironment === "production";
}

function elementText(xml: string, elementName: string): string | undefined {
  const escapedName = elementName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`<${escapedName}(?:\\s[^>]*)?>([^<]*)<\\/${escapedName}\\s*>`, "i")
    .exec(xml)?.[1]
    ?.trim();
}

function attributeValue(attributes: string, attributeName: string): string | undefined {
  const escapedName = attributeName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?:^|\\s)${escapedName}\\s*=\\s*(["'])(.*?)\\1`, "i")
    .exec(attributes)?.[2]
    ?.trim();
}

function canonicalBase64ByteLength(value: string): number | undefined {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    return undefined;
  }

  try {
    const decoded = atob(value);
    return btoa(decoded) === value ? decoded.length : undefined;
  } catch {
    return undefined;
  }
}

function refuse(reason: string): never {
  throw new Error(`Refusing production site deploy: ${reason}`);
}

function assertMatchingAppcast(desktopVersion: string, appcastXml: string | undefined): void {
  if (!appcastXml?.trim()) {
    refuse("the committed public/appcast.xml is missing or empty.");
  }

  const firstItem = /<item\b[^>]*>([\s\S]*?)<\/item\s*>/i.exec(appcastXml)?.[1];
  if (!firstItem) {
    refuse("the committed appcast has no release item.");
  }

  const sparkleVersion = elementText(firstItem, "sparkle:version");
  const shortVersion = elementText(firstItem, "sparkle:shortVersionString");
  if (sparkleVersion !== desktopVersion || shortVersion !== desktopVersion) {
    refuse(
      `the first appcast item is ${sparkleVersion ?? "missing version"}/${shortVersion ?? "missing short version"}, not desktop ${desktopVersion}.`,
    );
  }

  const enclosureAttributes = /<enclosure\b([^>]*)\/?\s*>/i.exec(firstItem)?.[1];
  if (!enclosureAttributes) {
    refuse("the first appcast item has no enclosure.");
  }

  const signature = attributeValue(enclosureAttributes, "sparkle:edSignature");
  if (!signature) {
    refuse("the first appcast enclosure has no Sparkle EdDSA signature.");
  }
  if (canonicalBase64ByteLength(signature) !== 64) {
    refuse(
      "the first appcast enclosure signature must be canonical base64 for exactly 64 Ed25519 signature bytes.",
    );
  }

  const length = attributeValue(enclosureAttributes, "length");
  if (!length || !/^[1-9]\d*$/.test(length)) {
    refuse("the first appcast enclosure length is missing or not a positive integer.");
  }

  const enclosureUrl = attributeValue(enclosureAttributes, "url");
  if (!enclosureUrl) {
    refuse("the first appcast enclosure has no download URL.");
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(enclosureUrl);
  } catch {
    refuse("the first appcast enclosure URL is invalid.");
  }

  const expectedFilename = `Bouclier-ai-v${desktopVersion}-macOS.dmg`;
  const exactVersionedArtifact =
    parsedUrl.protocol === "https:" &&
    parsedUrl.username === "" &&
    parsedUrl.password === "" &&
    parsedUrl.search === "" &&
    parsedUrl.hash === "" &&
    parsedUrl.pathname.endsWith(`/${expectedFilename}`);
  if (!exactVersionedArtifact) {
    refuse(
      `the first appcast enclosure must be an HTTPS URL for the exact ${expectedFilename} artifact, without credentials, query, or fragment.`,
    );
  }
}

export function assertProductionReleaseAlignment({
  vercelEnvironment,
  selfHostedEnvironment,
  desktopVersion,
  appcastXml,
}: ProductionReleaseAlignmentInput): void {
  if (!isProductionDeployment(vercelEnvironment, selfHostedEnvironment)) return;

  if (!versionAtLeast(desktopVersion, SITE_COPY_MIN_DESKTOP_VERSION)) {
    refuse(
      `copy requires desktop ${SITE_COPY_MIN_DESKTOP_VERSION}+ but APP_VERSION is ${desktopVersion}. Publish the matching signed DMG/appcast first.`,
    );
  }

  assertMatchingAppcast(desktopVersion, appcastXml);
}
