/** PII entity type. Stable identifiers — used as the type slug in placeholders like `{EMAIL_1}`. */
export type PIIEntityType =
  | "EMAIL"
  | "IBAN"
  | "CREDIT_CARD"
  | "US_SSN"
  | "IPV4"
  | "IPV6"
  | "AWS_ACCESS_KEY"
  | "JWT"
  // EU
  | "FR_SIRET"
  | "FR_SIREN"
  | "FR_NIR"
  // UK
  | "UK_NHS"
  | "UK_NINO"
  | "UK_POSTCODE"
  // US healthcare
  | "US_NPI";

/** A single detected PII span. Offsets are into the original (un-normalized) input. */
export interface PIIDetection {
  type: PIIEntityType;
  start: number;
  end: number;
  value: string;
}

/** A PII detector: a regex plus an optional structural validator and context check. */
export interface PIIDetector {
  type: PIIEntityType;
  regex: RegExp;
  /** Return true to keep the match, false to drop it as a false positive. */
  validate?: (match: string) => boolean;
  /**
   * Return true to keep the match given its surrounding context. Used to
   * suppress matches that are structurally valid but contextually wrong
   * (e.g., a Luhn-passing hash labeled `sha256:`).
   */
  contextOk?: (content: string, match: PIIDetection) => boolean;
}
