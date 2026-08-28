/**
 * Shannon entropy in bits-per-character. Used to distinguish high-entropy
 * secret-like strings ("ZmGq7tH8K…") from low-entropy English-like strings
 * ("usernameusernameuser"). A threshold around 3.5–4.0 cleanly separates
 * real tokens from repetitive or text-like strings of the same length.
 */
export function hasShannonEntropy(value: string, minBitsPerChar: number): boolean {
  if (value.length === 0) return false;
  const counts = new Map<string, number>();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  const n = value.length;
  for (const c of counts.values()) {
    const p = c / n;
    entropy -= p * Math.log2(p);
  }
  return entropy >= minBitsPerChar;
}

/**
 * Length-agnostic Luhn check on a pure-digit string. Used by every
 * Luhn-based validator (card, SIREN, SIRET, NPI-with-prefix).
 */
function luhnCore(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

function hasVariedDigits(digits: string): boolean {
  return !/^(\d)\1+$/.test(digits);
}

/** Luhn checksum used by most card networks (Visa/MC/Amex/Discover). */
export function luhn(digits: string): boolean {
  const clean = digits.replace(/[\s-]/g, "");
  if (!/^\d{12,19}$/.test(clean)) return false;
  // Checksums accept all-zero/repeated-digit placeholders mathematically,
  // but those are documentation fixtures, not plausible account numbers.
  if (!hasVariedDigits(clean)) return false;
  return luhnCore(clean);
}

/** IBAN mod-97 check per ISO 13616. Length is country-specific (15–34). */
export function ibanMod97(iban: string): boolean {
  const clean = iban.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(clean)) return false;
  const rearranged = clean.slice(4) + clean.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const value = code >= 65 ? code - 55 : code - 48;
    remainder = (remainder * (value > 9 ? 100 : 10) + value) % 97;
  }
  return remainder === 1;
}

/** Reject obviously non-routable US SSNs per SSA invalid-number rules. */
export function isPlausibleSSN(ssn: string): boolean {
  const m = ssn.match(/^(\d{3})-?(\d{2})-?(\d{4})$/);
  if (!m) return false;
  const [, area, group, serial] = m;
  if (area === "000" || area === "666" || area!.startsWith("9")) return false;
  if (group === "00") return false;
  if (serial === "0000") return false;
  return true;
}

/**
 * Validate an IPv6 textual representation. Accepts full and `::`-compressed
 * forms; rejects all-zero / all-FFFF sentinels and date-like decimal-only
 * shapes (e.g., build-log timestamps `2024:08:31:12:34:56:78:99` parse as
 * structurally valid hex IPv6 but never appear as real addresses in the wild).
 *
 * Disambiguation rule: real IPv6 in production traffic almost always contains
 * either a `::` compression OR at least one a-f hex letter. Pure-decimal
 * 8-group IPv6 is theoretically legal but vanishingly rare; the
 * false-positive cost on dates is much higher than the false-negative cost
 * on those edge cases.
 */
export function isPlausibleIPv6(ip: string): boolean {
  const doubleColons = ip.split("::").length - 1;
  if (doubleColons > 1) return false;

  let groups: string[];
  if (doubleColons === 1) {
    const [head, tail] = ip.split("::");
    const headGroups = head!.length > 0 ? head!.split(":") : [];
    const tailGroups = tail!.length > 0 ? tail!.split(":") : [];
    const fillCount = 8 - headGroups.length - tailGroups.length;
    if (fillCount < 1) return false;
    groups = [...headGroups, ...Array(fillCount).fill("0"), ...tailGroups];
  } else {
    groups = ip.split(":");
  }

  if (groups.length !== 8) return false;

  let allZero = true;
  let allFFFF = true;
  let hasHexLetter = false;
  for (const g of groups) {
    if (g.length === 0 || g.length > 4) return false;
    if (!/^[0-9A-Fa-f]+$/.test(g)) return false;
    const n = parseInt(g, 16);
    if (Number.isNaN(n) || n < 0 || n > 0xffff) return false;
    if (n !== 0) allZero = false;
    if (n !== 0xffff) allFFFF = false;
    if (/[A-Fa-f]/.test(g)) hasHexLetter = true;
  }
  if (allZero || allFFFF) return false;

  // Disambiguate from decimal-only date/timestamp shapes: require either
  // `::` compression or at least one hex letter somewhere in the input.
  if (doubleColons === 0 && !hasHexLetter) return false;

  return true;
}

/** Reject IPv4 octets >255 and 0.0.0.0 / 255.255.255.255 sentinels (common false-positives in code). */
export function isPlausibleIPv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  const nums: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    if (n < 0 || n > 255) return false;
    nums.push(n);
  }
  if (nums.every((n) => n === 0)) return false;
  if (nums.every((n) => n === 255)) return false;
  return true;
}

/**
 * French SIREN: 9 digits, standard Luhn. Identifies an enterprise.
 */
export function isPlausibleSIREN(siren: string): boolean {
  const clean = siren.replace(/\s+/g, "");
  if (!/^\d{9}$/.test(clean)) return false;
  if (!hasVariedDigits(clean)) return false;
  return luhnCore(clean);
}

/**
 * French SIRET: 14 digits, standard Luhn (with one special case for La
 * Poste establishments which use a custom mod-5 rule we accept lazily).
 * SIRET shape overlaps with credit-card shape — detectors are ordered
 * so SIRET wins precedence.
 */
export function isPlausibleSIRET(siret: string): boolean {
  const clean = siret.replace(/\s+/g, "");
  if (!/^\d{14}$/.test(clean)) return false;
  if (!hasVariedDigits(clean)) return false;
  if (clean.startsWith("356000000")) {
    let sum = 0;
    for (const ch of clean) sum += ch.charCodeAt(0) - 48;
    return sum % 5 === 0;
  }
  return luhnCore(clean);
}

/**
 * French NIR (Numéro d'Inscription au Répertoire / SSN): 13 digits +
 * 2-digit key. Key = 97 - (first-13-digits mod 97). Some Corsican
 * registrations use 'A'/'B' in position 7 — accept those by mapping
 * A→1 (value subtracted by 1M) and B→2 (value subtracted by 2M).
 */
export function isPlausibleNIR(nir: string): boolean {
  const clean = nir.replace(/\s+/g, "").toUpperCase();
  if (!/^[12]\d{2}(0[1-9]|1[012]|20|[3-9]\d|[0-9][AB])\d[AB0-9]\d{6}\d{2}$/.test(clean)) {
    return false;
  }
  let body = clean.slice(0, 13);
  let adjust = 0;
  if (body.includes("A")) {
    body = body.replace(/A/g, "0");
    adjust = 1_000_000;
  } else if (body.includes("B")) {
    body = body.replace(/B/g, "0");
    adjust = 2_000_000;
  }
  const key = parseInt(clean.slice(13), 10);
  const num = parseInt(body, 10) - adjust;
  return 97 - (num % 97) === key;
}

/**
 * UK NHS number: 10 digits, mod-11 weighted (weights 10..2 for digits
 * 1-9, check = (11 - sum mod 11) mod 11; reject if check == 10).
 */
export function isPlausibleNHS(nhs: string): boolean {
  const clean = nhs.replace(/[\s-]/g, "");
  if (!/^\d{10}$/.test(clean)) return false;
  if (!hasVariedDigits(clean)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += (clean.charCodeAt(i) - 48) * (10 - i);
  const remainder = sum % 11;
  const check = (11 - remainder) % 11;
  if (check === 10) return false;
  return check === clean.charCodeAt(9) - 48;
}

/**
 * UK NINO: `[A-Z]{2}\d{6}[A-D]` with disallowed prefix letters per HMRC
 * rules (D, F, I, Q, U, V in either position; O in the second).
 */
export function isPlausibleNINO(nino: string): boolean {
  const clean = nino.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{6}[A-D]$/.test(clean)) return false;
  const banned1 = new Set(["D", "F", "I", "Q", "U", "V"]);
  const banned2 = new Set(["D", "F", "I", "O", "Q", "U", "V"]);
  if (banned1.has(clean[0]!)) return false;
  if (banned2.has(clean[1]!)) return false;
  // BG, GB, NK, KN, TN, NT, ZZ are administratively reserved.
  const reservedPairs = new Set(["BG", "GB", "NK", "KN", "TN", "NT", "ZZ"]);
  if (reservedPairs.has(clean.slice(0, 2))) return false;
  return true;
}

/**
 * UK postcode (BS7666-aligned format). Recall-first regex (no checksum
 * is defined for postcodes themselves; structural validity is enough).
 */
export function isPlausibleUKPostcode(pc: string): boolean {
  return /^(GIR ?0AA|[A-PR-UWYZ](?:[0-9]{1,2}|[A-HK-Y][0-9]|[A-HK-Y][0-9](?:[0-9]|[ABEHMNPRV-Y])|[0-9][A-HJKPS-UW]) ?[0-9][ABD-HJLNP-UW-Z]{2})$/i.test(
    pc.trim(),
  );
}

/**
 * US National Provider Identifier: 10 digits, Luhn computed on the
 * 80840-prefixed 15-digit string.
 */
export function isPlausibleNPI(npi: string): boolean {
  const clean = npi.replace(/\s+/g, "");
  if (!/^\d{10}$/.test(clean)) return false;
  if (!hasVariedDigits(clean)) return false;
  return luhnCore("80840" + clean);
}

/** JWT is three base64url segments separated by `.`; header must decode to JSON with an `alg` field. */
export function isPlausibleJWT(token: string): boolean {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  if (parts.some((p) => p.length === 0)) return false;
  try {
    const header = parts[0]!.replace(/-/g, "+").replace(/_/g, "/");
    const padded = header + "=".repeat((4 - (header.length % 4)) % 4);
    const decoded = atob(padded);
    const parsed = JSON.parse(decoded);
    return typeof parsed === "object" && parsed !== null && typeof parsed.alg === "string";
  } catch {
    return false;
  }
}
