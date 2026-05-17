import { SECRET_DETECTORS_GENERIC, SECRET_DETECTORS_HIGH_PRECISION } from "./secrets.js";
import type { PIIDetection, PIIDetector } from "./types.js";
import {
  ibanMod97,
  isPlausibleIPv4,
  isPlausibleIPv6,
  isPlausibleJWT,
  isPlausibleNHS,
  isPlausibleNINO,
  isPlausibleNIR,
  isPlausibleNPI,
  isPlausibleSIREN,
  isPlausibleSIRET,
  isPlausibleSSN,
  isPlausibleUKPostcode,
  luhn,
} from "./validators.js";

/** Email per a pragmatic RFC 5322 subset; the goal is recall + no obvious junk, not full compliance. */
const EMAIL = /\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b/g;

/**
 * PHONE is intentionally NOT covered by regex in this tier.
 * Reviewed 2026-05-17: regex-based phone detection produces too many false
 * positives against ISO timestamps ("2024-08-31 12"), EU dates
 * ("25.06.2025 14"), and arbitrary digit groups ("1234 5678 90") to be
 * shippable to enterprise clients. PHONE detection is deferred to the
 * ML tier (Piiranha mDeBERTa, Phase 2), which uses surrounding context
 * to disambiguate.
 */

/** IBAN: 2 letters + 2 digits + 11–30 alphanumerics. Validator runs mod-97. */
const IBAN = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b/g;

/**
 * 13–19 digit credit-card-shaped span. Separator is never at the tail
 * (closing `\d` is mandatory) so the matched span never swallows trailing
 * whitespace. Validator runs Luhn.
 */
const CREDIT_CARD = /\b\d(?:[ -]?\d){12,18}\b/g;

/**
 * Context tokens that suppress a credit-card match. Luhn passes ~10% of
 * random 16-digit strings, so without context we'd redact transaction
 * IDs, hashes, correlation IDs, and order numbers. If any of these tokens
 * appears in the ~32 chars preceding the match, drop it.
 */
const CC_SUPPRESS_CONTEXT =
  /(?:sha(?:1|256|512)?|md5|hash|nonce|txn[_-]?id|tx[_-]?id|correlation[_-]?id|trace[_-]?id|order[_-]?id|request[_-]?id|session[_-]?id|user[_-]?id)\s*[:=]?\s*$/i;

/** Suppress CC matches whose preceding context names a non-card identifier. */
function ccContextOk(content: string, match: PIIDetection): boolean {
  const lookbackStart = Math.max(0, match.start - 48);
  const lookback = content.slice(lookbackStart, match.start);
  return !CC_SUPPRESS_CONTEXT.test(lookback);
}

/** US SSN: 3-2-4 with optional dashes. Validator rejects SSA-invalid prefixes. */
const US_SSN = /\b\d{3}-?\d{2}-?\d{4}\b/g;

/** IPv4 dotted quad. Validator rejects octets >255 and sentinel addresses. */
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

/** IPv6 (full + compressed forms). Conservative — matches the canonical shapes only. */
const IPV6 =
  /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}:(?:[A-Fa-f0-9]{1,4}:){0,6}[A-Fa-f0-9]{0,4}\b/g;

/** AWS access key: 16-char base32-ish prefixed by AKIA/ASIA/AIDA. Unambiguous, no validator needed. */
const AWS_ACCESS_KEY = /\b(?:AKIA|ASIA|AIDA|AGPA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/g;

/** JWT: three base64url segments separated by dots. Validator parses the header. */
const JWT = /\b[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;

/** French SIRET: 14 digits, optionally space-separated as 3-3-3-5. Luhn validated. */
const FR_SIRET = /\b\d{3}[ ]?\d{3}[ ]?\d{3}[ ]?\d{5}\b/g;

/** French SIREN: 9 digits, optionally space-separated 3-3-3. */
const FR_SIREN = /\b\d{3}[ ]?\d{3}[ ]?\d{3}\b/g;

/** French NIR (SSN): 15-char with optional spaces. */
const FR_NIR = /\b[12][ ]?\d{2}[ ]?\d{2}[ ]?[0-9AB]\d[ ]?\d{3}[ ]?\d{3}[ ]?\d{2}\b/g;

/** UK NHS number: three groups 3-3-4 with space or hyphen separators. */
const UK_NHS = /\b\d{3}[ -]\d{3}[ -]\d{4}\b/g;

/** UK NINO: AA 12 34 56 A with optional spaces between segments. */
const UK_NINO = /\b[A-Z]{2}[ ]?\d{2}[ ]?\d{2}[ ]?\d{2}[ ]?[A-D]\b/g;

/** UK postcode. Recall-first; validator enforces structural validity. */
const UK_POSTCODE = /\b[A-PR-UWYZ][A-Z0-9]{1,3}[ ]?\d[A-Z]{2}\b/gi;

/** US NPI: 10 digits, Luhn-on-80840-prefix validated. */
const US_NPI = /\b\d{10}\b/g;

/**
 * Detector list. Order matters when spans overlap: higher-precision detectors
 * come first so the scanner's overlap-resolution keeps them.
 */
export const PII_DETECTORS: PIIDetector[] = [
  // ── Tier 1 — high-precision secrets (prefix-anchored, near-zero FP).
  // A string like ghp_AAAA…AAAA gets tagged GITHUB_PAT, never weaker.
  ...SECRET_DETECTORS_HIGH_PRECISION,

  // ── Tier 2 — structured data with strong validators. JWT must
  // precede the generic fallback so its full 3-segment span wins over
  // a bare GENERIC_API_KEY match on the first segment alone.
  { type: "JWT", regex: JWT, validate: isPlausibleJWT },
  { type: "AWS_ACCESS_KEY", regex: AWS_ACCESS_KEY },
  { type: "EMAIL", regex: EMAIL },
  { type: "IBAN", regex: IBAN, validate: ibanMod97 },

  // NIR before CC/SIREN/SIRET because its shape is most specific (15 chars
  // with a leading [12]).
  { type: "FR_NIR", regex: FR_NIR, validate: isPlausibleNIR },

  // SIRET (14 digits) must precede CREDIT_CARD (13-19 digits) so a
  // Luhn-passing SIRET isn't mis-tagged as a card.
  { type: "FR_SIRET", regex: FR_SIRET, validate: isPlausibleSIRET },
  { type: "CREDIT_CARD", regex: CREDIT_CARD, validate: luhn, contextOk: ccContextOk },

  // NHS (10 digits weighted mod-11) and NPI (10 digits Luhn-on-prefix)
  // are both 10-digit shapes — order by validator strictness; NHS first
  // since its check digit is more constraining.
  { type: "UK_NHS", regex: UK_NHS, validate: isPlausibleNHS },
  { type: "US_NPI", regex: US_NPI, validate: isPlausibleNPI },

  // SIREN (9 digits, Luhn) — last among Luhn-style codes so it doesn't
  // win over a SIRET prefix.
  { type: "FR_SIREN", regex: FR_SIREN, validate: isPlausibleSIREN },

  { type: "US_SSN", regex: US_SSN, validate: isPlausibleSSN },
  { type: "UK_NINO", regex: UK_NINO, validate: isPlausibleNINO },
  { type: "UK_POSTCODE", regex: UK_POSTCODE, validate: isPlausibleUKPostcode },

  { type: "IPV6", regex: IPV6, validate: isPlausibleIPv6 },
  { type: "IPV4", regex: IPV4, validate: isPlausibleIPv4 },

  // ── Tier 3 — generic, context-gated secret fallbacks. Last so any
  // structurally precise detector has already had its chance to match.
  ...SECRET_DETECTORS_GENERIC,
];
