/**
 * Secret-key detectors (Gitleaks-derived, MIT-licensed regex shapes).
 *
 * Each detector is a high-precision regex anchored on a publicly
 * documented provider prefix (`sk-`, `ghp_`, `xoxb-`, …) so the
 * false-positive rate stays near zero. Validators are intentionally
 * sparse — the prefix anchor is already most of the precision; what
 * remains is length + charset, which the regex enforces.
 *
 * Attribution: Patterns are derived from Gitleaks
 * (https://github.com/gitleaks/gitleaks, MIT) and from each provider's
 * public documentation. NOTICE.txt carries the upstream attribution.
 */

import type { PIIDetector } from "./types.js";
import { hasShannonEntropy } from "./validators.js";

// ── LLM providers ─────────────────────────────────────────────────────

// Order matters here: more-specific `sk-…` variants (ANTHROPIC,
// OPENROUTER, DEEPSEEK) must precede the broader OPENAI shape so the
// scanner's same-start overlap resolver picks the right one. OPENAI
// itself carries a negative lookahead as a second line of defence in
// case someone reorders the list later.
const ANTHROPIC = /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{86,}\b/g;
const OPENROUTER = /\bsk-or-(?:v\d+-)?[A-Za-z0-9]{40,}\b/g;
const DEEPSEEK = /\bsk-[A-Fa-f0-9]{32}\b/g;
const OPENAI = /\bsk-(?!ant-|or-|live_|test_)(?:proj-|admin-|svcacct-)?[A-Za-z0-9_-]{32,}\b/g;
const XAI = /\bxai-[A-Za-z0-9]{80}\b/g;
const GOOGLE_API_KEY = /\bAIza[A-Za-z0-9_-]{35}\b/g;
const MISTRAL = /\b[A-Za-z0-9]{32}\b/g; // generic; validator filters with context
const GROQ = /\bgsk_[A-Za-z0-9]{52}\b/g;
const FIREWORKS = /\bfw_[A-Za-z0-9]{24,}\b/g;
const COHERE = /\bco_[A-Za-z0-9]{40}\b/g;
const PERPLEXITY = /\bpplx-[A-Za-z0-9]{48,}\b/g;
const TOGETHER = /\btogether_[A-Za-z0-9]{40,}\b/g;

// ── Source control ───────────────────────────────────────────────────

const GITHUB_PAT = /\bghp_[A-Za-z0-9]{36}\b/g;
const GITHUB_OAUTH = /\bgho_[A-Za-z0-9]{36}\b/g;
const GITHUB_APP = /\b(?:ghu|ghs|ghr)_[A-Za-z0-9]{36}\b/g;
const GITHUB_FG_PAT = /\bgithub_pat_[A-Za-z0-9_]{82}\b/g;
const GITLAB_PAT = /\bglpat-[A-Za-z0-9_-]{20}\b/g;
const BITBUCKET_APP_PW = /\bATBB[A-Za-z0-9]{32}[A-Fa-f0-9]{8}\b/g;

// ── Communication ────────────────────────────────────────────────────

const SLACK_TOKEN = /\bxox[abprs]-(?:\d+-){2,}[A-Za-z0-9-]+\b/g;
const SLACK_WEBHOOK =
  /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24,}\b/g;
const DISCORD_WEBHOOK =
  /\bhttps:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,}\b/g;
const DISCORD_BOT_TOKEN = /\b[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b/g;
const TELEGRAM_BOT_TOKEN = /\b\d{8,10}:[A-Za-z0-9_-]{35}\b/g;

// ── Payments ─────────────────────────────────────────────────────────

const STRIPE_KEY = /\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{24,99}\b/g;
const SQUARE_TOKEN = /\bsq0(?:atp|csp|idp)-[A-Za-z0-9_-]{22,43}\b/g;
const PAYPAL_BRAINTREE = /\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}\b/g;
const SHOPIFY_TOKEN = /\b(?:shpat|shpca|shpss|shppa)_[a-fA-F0-9]{32}\b/g;

// ── Email & comms SaaS ───────────────────────────────────────────────

const SENDGRID_KEY = /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g;
const MAILGUN_KEY = /\bkey-[a-f0-9]{32}\b/g;
const MAILCHIMP_KEY = /\b[a-f0-9]{32}-us\d{1,2}\b/g;
const POSTMARK_TOKEN = /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g; // UUID — context-validated
const TWILIO_API_KEY = /\bSK[a-f0-9]{32}\b/g;
const TWILIO_ACCOUNT_SID = /\bAC[a-f0-9]{32}\b/g;

// ── Cloud infra ──────────────────────────────────────────────────────

const GCP_OAUTH_CLIENT = /\b\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com\b/g;
const GCP_SA_KEY_HEAD =
  /"type"\s*:\s*"service_account"[\s\S]{0,500}"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/g;
const AZURE_STORAGE_KEY =
  /\bDefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{60,}\b/g;
const CLOUDFLARE_TOKEN = /\bcf-[A-Za-z0-9_-]{40}\b/g;
const DIGITALOCEAN_TOKEN = /\bdop_v1_[a-f0-9]{64}\b/g;
const HEROKU_KEY = /\bHRKU-[A-Za-z0-9_-]{36,}\b/g;
const FLY_API_TOKEN = /\bfly_[A-Za-z0-9_-]{40,}\b/g;
const AWS_SECRET_KEY_CTX = /\b[A-Za-z0-9+/]{40}\b/g; // gated by context only

// ── Observability ────────────────────────────────────────────────────

const SENTRY_DSN = /\bhttps:\/\/[a-f0-9]{32}@(?:o\d+\.)?ingest(?:\.[a-z]+)?\.sentry\.io\/\d+\b/g;
const DATADOG_API_KEY_CTX = /\b[a-f0-9]{32}\b/g; // gated by context
const NEW_RELIC_KEY = /\bNRAK-[A-Z0-9]{27}\b/g;
// PagerDuty / Algolia patterns are too generic (20-char alphanum / 32-hex)
// to ship without much tighter context anchoring than we have today.
// Deliberately out of scope until we can land a shared "labelled value
// near 'key:' / 'token:'" extractor.

// ── Packaging ────────────────────────────────────────────────────────

const NPM_TOKEN = /\bnpm_[A-Za-z0-9]{36}\b/g;
const PYPI_TOKEN = /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g;

// ── Productivity / workspace ─────────────────────────────────────────

const NOTION_TOKEN = /\bsecret_[A-Za-z0-9]{43}\b/g;
const LINEAR_KEY = /\blin_api_[A-Za-z0-9]{40}\b/g;
const ASANA_PAT = /\b\d{1,4}\/\d{16,}:[a-f0-9]{32}\b/g;
const ATLASSIAN_TOKEN = /\bATATT[A-Za-z0-9_-]{180,}\b/g;
const HUBSPOT_KEY =
  /\bpat-(?:na1|eu1|na2)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/g;

// ── PEM / SSH private keys (multi-line; use `s` semantics via [\s\S]) ─

const PEM_PRIVATE_KEY =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |PRIVATE )?PRIVATE KEY-----[\s\S]{20,8000}?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |PRIVATE )?PRIVATE KEY-----/g;
const SSH_PRIVATE_KEY =
  /-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]{20,8000}?-----END OPENSSH PRIVATE KEY-----/g;

// ── DB connection strings ────────────────────────────────────────────

const POSTGRES_URL = /\bpostgres(?:ql)?:\/\/[^\s:@/]+:[^\s@/]+@[^\s/]+(?::\d+)?\/[^\s?]+\b/g;
const MYSQL_URL = /\bmysql:\/\/[^\s:@/]+:[^\s@/]+@[^\s/]+(?::\d+)?\/[^\s?]+\b/g;
const MONGODB_URL = /\bmongodb(?:\+srv)?:\/\/[^\s:@/]+:[^\s@/]+@[^\s/]+\b/g;
const REDIS_URL = /\bredis:\/\/(?:[^\s:@/]*:)?[^\s@/]+@[^\s/]+(?::\d+)?\b/g;

// ── Generic, context-gated ───────────────────────────────────────────

const BEARER_TOKEN = /\b(?:Bearer|Token)\s+[A-Za-z0-9_\-.=:]{20,}\b/g;
/**
 * Generic API-key pattern that requires both (a) a key-naming context
 * word in the preceding ~32 chars (`api_key`, `apikey`, `secret`,
 * `token`, `password`, `auth`, `bearer`) AND (b) Shannon entropy ≥ 4.0
 * on the captured value. Catches credentials that don't match any
 * provider-specific shape but still look like high-entropy bearer
 * material in a key-value context. Last in detector order so
 * provider-specific shapes always win.
 *
 * `=` is intentionally excluded from the character class so the regex
 * doesn't greedily consume the `key=` prefix together with the value
 * itself — that would leave the engine stranded with no candidate
 * start positions for the actual token.
 */
const GENERIC_HIGH_ENTROPY = /[A-Za-z0-9+/_-]{32,}/g;

// ── Context guards ───────────────────────────────────────────────────

const KEY_CONTEXT_LOOKBACK =
  /(?:api[_\-\s]?key|apikey|secret|access[_\-\s]?key|access[_\-\s]?token|token|password|passwd|pwd|auth|bearer|client[_\-\s]?secret)[\s:=]{1,4}["']?$/i;

const AWS_SECRET_CTX = /(?:aws[_\-]?secret(?:[_\-]?access)?[_\-]?key|aws_secret)[\s:=]{1,4}["']?$/i;

const DATADOG_CTX = /(?:dd[_\-]?api[_\-]?key|datadog[_\-]?api[_\-]?key)[\s:=]{1,4}["']?$/i;

function contextLookback(content: string, start: number, max = 48): string {
  const lookbackStart = Math.max(0, start - max);
  return content.slice(lookbackStart, start);
}

const requireContext = (re: RegExp) => (content: string, match: { start: number }) =>
  re.test(contextLookback(content, match.start));

const requireEntropy = (min: number) => (value: string) => hasShannonEntropy(value, min);

const validateMistral = (value: string) =>
  /^[A-Za-z0-9]{32}$/.test(value) && hasShannonEntropy(value, 4.0);

// Generic-key validator: entropy threshold + must look like a token.
const genericKeyValueOk = (value: string) =>
  value.length >= 32 && hasShannonEntropy(value, 4.0) && /[A-Za-z]/.test(value) && /\d/.test(value);

// ── Detector list ────────────────────────────────────────────────────

/**
 * High-precision secret detectors anchored on documented provider
 * prefixes. Splice these FIRST in the master detector order — they're
 * the most specific and should never lose to a structured-data
 * detector like JWT or CC.
 */
export const SECRET_DETECTORS_HIGH_PRECISION: PIIDetector[] = [
  // LLM providers — most-specific `sk-…` variants FIRST so OPENAI's
  // broader shape doesn't eat them at the same start offset.
  { type: "ANTHROPIC_KEY", regex: ANTHROPIC },
  { type: "OPENROUTER_KEY", regex: OPENROUTER },
  { type: "DEEPSEEK_KEY", regex: DEEPSEEK },
  { type: "OPENAI_KEY", regex: OPENAI },
  { type: "XAI_KEY", regex: XAI },
  { type: "GOOGLE_API_KEY", regex: GOOGLE_API_KEY },
  { type: "GROQ_KEY", regex: GROQ },
  { type: "FIREWORKS_KEY", regex: FIREWORKS },
  { type: "COHERE_KEY", regex: COHERE },
  { type: "PERPLEXITY_KEY", regex: PERPLEXITY },
  { type: "TOGETHER_KEY", regex: TOGETHER },
  {
    type: "MISTRAL_KEY",
    regex: MISTRAL,
    validate: validateMistral,
    contextOk: requireContext(KEY_CONTEXT_LOOKBACK),
  },

  // Source control.
  { type: "GITHUB_FINE_GRAINED_PAT", regex: GITHUB_FG_PAT },
  { type: "GITHUB_PAT", regex: GITHUB_PAT },
  { type: "GITHUB_OAUTH", regex: GITHUB_OAUTH },
  { type: "GITHUB_APP", regex: GITHUB_APP },
  { type: "GITLAB_PAT", regex: GITLAB_PAT },
  { type: "BITBUCKET_APP_PASSWORD", regex: BITBUCKET_APP_PW },

  // Communication.
  { type: "SLACK_TOKEN", regex: SLACK_TOKEN },
  { type: "SLACK_WEBHOOK", regex: SLACK_WEBHOOK },
  { type: "DISCORD_WEBHOOK", regex: DISCORD_WEBHOOK },
  { type: "DISCORD_BOT_TOKEN", regex: DISCORD_BOT_TOKEN },
  { type: "TELEGRAM_BOT_TOKEN", regex: TELEGRAM_BOT_TOKEN },

  // Payments.
  { type: "STRIPE_KEY", regex: STRIPE_KEY },
  { type: "SQUARE_TOKEN", regex: SQUARE_TOKEN },
  { type: "PAYPAL_BRAINTREE", regex: PAYPAL_BRAINTREE },
  { type: "SHOPIFY_TOKEN", regex: SHOPIFY_TOKEN },

  // Email & SaaS.
  { type: "SENDGRID_KEY", regex: SENDGRID_KEY },
  { type: "MAILGUN_KEY", regex: MAILGUN_KEY },
  { type: "MAILCHIMP_KEY", regex: MAILCHIMP_KEY },
  { type: "TWILIO_API_KEY", regex: TWILIO_API_KEY },
  { type: "TWILIO_ACCOUNT_SID", regex: TWILIO_ACCOUNT_SID },
  // Postmark is plain UUID — only gate via context, and only after
  // UUID-shaped competitors that ARE provider-specific have had a
  // chance to match.
  {
    type: "POSTMARK_TOKEN",
    regex: POSTMARK_TOKEN,
    contextOk: requireContext(/(?:postmark|server[_\-]?token)[\s:=]{1,4}["']?$/i),
  },

  // Cloud infra.
  { type: "GCP_OAUTH_CLIENT", regex: GCP_OAUTH_CLIENT },
  { type: "GCP_SERVICE_ACCOUNT_KEY", regex: GCP_SA_KEY_HEAD },
  { type: "AZURE_STORAGE_KEY", regex: AZURE_STORAGE_KEY },
  { type: "CLOUDFLARE_TOKEN", regex: CLOUDFLARE_TOKEN },
  { type: "DIGITALOCEAN_TOKEN", regex: DIGITALOCEAN_TOKEN },
  { type: "HEROKU_KEY", regex: HEROKU_KEY },
  { type: "FLY_API_TOKEN", regex: FLY_API_TOKEN },
  {
    type: "AWS_SECRET_KEY",
    regex: AWS_SECRET_KEY_CTX,
    validate: requireEntropy(4.0),
    contextOk: requireContext(AWS_SECRET_CTX),
  },

  // Observability.
  { type: "SENTRY_DSN", regex: SENTRY_DSN },
  { type: "NEW_RELIC_KEY", regex: NEW_RELIC_KEY },
  {
    type: "DATADOG_API_KEY",
    regex: DATADOG_API_KEY_CTX,
    contextOk: requireContext(DATADOG_CTX),
  },

  // Packaging.
  { type: "NPM_TOKEN", regex: NPM_TOKEN },
  { type: "PYPI_TOKEN", regex: PYPI_TOKEN },

  // Productivity.
  { type: "NOTION_TOKEN", regex: NOTION_TOKEN },
  { type: "LINEAR_KEY", regex: LINEAR_KEY },
  { type: "ASANA_PAT", regex: ASANA_PAT },
  { type: "ATLASSIAN_TOKEN", regex: ATLASSIAN_TOKEN },
  { type: "HUBSPOT_KEY", regex: HUBSPOT_KEY },

  // PEM / SSH (multi-line) — high precision, no validator needed.
  { type: "SSH_PRIVATE_KEY", regex: SSH_PRIVATE_KEY },
  { type: "PEM_PRIVATE_KEY", regex: PEM_PRIVATE_KEY },

  // DB connection strings.
  { type: "POSTGRES_URL", regex: POSTGRES_URL },
  { type: "MYSQL_URL", regex: MYSQL_URL },
  { type: "MONGODB_URL", regex: MONGODB_URL },
  { type: "REDIS_URL", regex: REDIS_URL },
];

/**
 * Generic, last-resort secret detectors. Splice these AFTER all
 * structured-data detectors (JWT, CC, IBAN, …) so a JWT-shaped
 * string never gets miscategorised as a generic high-entropy key.
 * Both require key-naming context AND entropy.
 */
export const SECRET_DETECTORS_GENERIC: PIIDetector[] = [
  { type: "BEARER_TOKEN", regex: BEARER_TOKEN, validate: requireEntropy(3.5) },
  {
    type: "GENERIC_API_KEY",
    regex: GENERIC_HIGH_ENTROPY,
    validate: genericKeyValueOk,
    contextOk: requireContext(KEY_CONTEXT_LOOKBACK),
  },
];

/** Combined list — convenient for callers that don't care about tier order. */
export const SECRET_DETECTORS: PIIDetector[] = [
  ...SECRET_DETECTORS_HIGH_PRECISION,
  ...SECRET_DETECTORS_GENERIC,
];
