/** PII entity type. Stable identifiers — used as the type slug in placeholders like `{EMAIL_1}`. */
export type PIIEntityType =
  | "EMAIL"
  | "IBAN"
  | "CREDIT_CARD"
  | "US_SSN"
  | "IPV4"
  | "IPV6"
  | "AWS_ACCESS_KEY"
  | "AWS_SECRET_KEY"
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
  | "US_NPI"
  // LLM providers
  | "OPENAI_KEY"
  | "ANTHROPIC_KEY"
  | "XAI_KEY"
  | "GOOGLE_API_KEY"
  | "OPENROUTER_KEY"
  | "MISTRAL_KEY"
  | "GROQ_KEY"
  | "FIREWORKS_KEY"
  | "COHERE_KEY"
  | "PERPLEXITY_KEY"
  | "DEEPSEEK_KEY"
  | "TOGETHER_KEY"
  // Source control
  | "GITHUB_PAT"
  | "GITHUB_OAUTH"
  | "GITHUB_APP"
  | "GITHUB_FINE_GRAINED_PAT"
  | "GITLAB_PAT"
  | "BITBUCKET_APP_PASSWORD"
  // Communication
  | "SLACK_TOKEN"
  | "SLACK_WEBHOOK"
  | "DISCORD_WEBHOOK"
  | "DISCORD_BOT_TOKEN"
  | "TELEGRAM_BOT_TOKEN"
  // Payments
  | "STRIPE_KEY"
  | "SQUARE_TOKEN"
  | "PAYPAL_BRAINTREE"
  | "SHOPIFY_TOKEN"
  // Email & SaaS
  | "SENDGRID_KEY"
  | "MAILGUN_KEY"
  | "MAILCHIMP_KEY"
  | "POSTMARK_TOKEN"
  | "TWILIO_API_KEY"
  | "TWILIO_ACCOUNT_SID"
  // Cloud infra
  | "GCP_API_KEY"
  | "GCP_OAUTH_CLIENT"
  | "GCP_SERVICE_ACCOUNT_KEY"
  | "AZURE_STORAGE_KEY"
  | "CLOUDFLARE_TOKEN"
  | "DIGITALOCEAN_TOKEN"
  | "HEROKU_KEY"
  | "FLY_API_TOKEN"
  // Observability
  | "DATADOG_API_KEY"
  | "SENTRY_DSN"
  | "PAGERDUTY_KEY"
  | "NEW_RELIC_KEY"
  // Packaging
  | "NPM_TOKEN"
  | "PYPI_TOKEN"
  // Productivity / workspace
  | "NOTION_TOKEN"
  | "LINEAR_KEY"
  | "ASANA_PAT"
  | "ATLASSIAN_TOKEN"
  | "HUBSPOT_KEY"
  | "ALGOLIA_KEY"
  // Secrets at rest
  | "PEM_PRIVATE_KEY"
  | "SSH_PRIVATE_KEY"
  // Database connection strings (carry embedded passwords)
  | "POSTGRES_URL"
  | "MYSQL_URL"
  | "MONGODB_URL"
  | "REDIS_URL"
  // Generic high-entropy bearer / authorization
  | "BEARER_TOKEN"
  | "GENERIC_API_KEY"
  // Native (NSDataDetector on macOS, regex elsewhere)
  | "PHONE"
  | "ADDRESS"
  | "DATE_OF_BIRTH"
  // ML-only labels (Piiranha mDeBERTa-v3 token classification, Phase 2)
  | "PERSON"
  | "USERNAME"
  | "ID_NUM"
  | "DRIVER_LICENSE"
  | "MEDICAL_LICENSE"
  | "BANK_ACCOUNT"
  | "TAX_NUM";

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
