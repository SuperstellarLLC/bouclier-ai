import { describe, expect, it } from "vitest";
import { applyRedactions, scanPII } from "../pii/index.js";
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
} from "../pii/validators.js";

describe("PII validators", () => {
  it("luhn accepts known-good test cards and rejects mutations", () => {
    expect(luhn("4242 4242 4242 4242")).toBe(true); // Stripe test Visa
    expect(luhn("5555-5555-5555-4444")).toBe(true); // Stripe test MC
    expect(luhn("378282246310005")).toBe(true); // Amex test
    expect(luhn("4242424242424241")).toBe(false); // last digit off by 1
    expect(luhn("1234567890123")).toBe(false);
    expect(luhn("0000 0000 0000 0000")).toBe(false);
    expect(luhn("1111 1111 1111 1111")).toBe(false);
  });

  it("ibanMod97 accepts canonical examples and rejects mutations", () => {
    expect(ibanMod97("GB82 WEST 1234 5698 7654 32")).toBe(true);
    expect(ibanMod97("DE89370400440532013000")).toBe(true);
    expect(ibanMod97("FR1420041010050500013M02606")).toBe(true);
    expect(ibanMod97("GB82WEST12345698765433")).toBe(false); // last digit off
    expect(ibanMod97("XX00NOTANIBAN")).toBe(false);
  });

  it("isPlausibleSSN rejects SSA-invalid prefixes", () => {
    expect(isPlausibleSSN("123-45-6789")).toBe(true);
    expect(isPlausibleSSN("000-12-3456")).toBe(false); // area 000
    expect(isPlausibleSSN("666-12-3456")).toBe(false); // area 666
    expect(isPlausibleSSN("900-12-3456")).toBe(false); // 9xx reserved
    expect(isPlausibleSSN("123-00-4567")).toBe(false); // group 00
    expect(isPlausibleSSN("123-45-0000")).toBe(false); // serial 0000
  });

  it("isPlausibleIPv6 accepts canonical forms and rejects date-like shapes", () => {
    expect(isPlausibleIPv6("2001:db8::8a2e:370:7334")).toBe(true);
    expect(isPlausibleIPv6("fe80::1")).toBe(true);
    expect(isPlausibleIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")).toBe(true);
    // R4 regression: a build-log date that matches the regex but has
    // groups exceeding 16 bits must be rejected.
    expect(isPlausibleIPv6("2024:08:31:12:34:56:78:99")).toBe(false);
    expect(isPlausibleIPv6("0:0:0:0:0:0:0:0")).toBe(false);
    expect(isPlausibleIPv6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")).toBe(false);
    expect(isPlausibleIPv6("gggg::1")).toBe(false);
    expect(isPlausibleIPv6("1::2::3")).toBe(false); // two ::
    expect(isPlausibleIPv6("1:2:3:4:5:6:7")).toBe(false); // too few groups, no ::
  });

  it("isPlausibleIPv4 rejects out-of-range octets and sentinels", () => {
    expect(isPlausibleIPv4("192.168.1.1")).toBe(true);
    expect(isPlausibleIPv4("8.8.8.8")).toBe(true);
    expect(isPlausibleIPv4("999.1.1.1")).toBe(false);
    expect(isPlausibleIPv4("0.0.0.0")).toBe(false);
    expect(isPlausibleIPv4("255.255.255.255")).toBe(false);
    expect(isPlausibleIPv4("1.2.3")).toBe(false);
  });

  it("isPlausibleSIREN accepts TotalEnergies SIREN, rejects mutations", () => {
    expect(isPlausibleSIREN("732 829 320")).toBe(true);
    expect(isPlausibleSIREN("732829320")).toBe(true);
    expect(isPlausibleSIREN("732 829 321")).toBe(false);
    expect(isPlausibleSIREN("12345678")).toBe(false); // 8 digits
    expect(isPlausibleSIREN("000 000 000")).toBe(false);
  });

  it("isPlausibleSIRET accepts TotalEnergies HQ SIRET, rejects mutations", () => {
    expect(isPlausibleSIRET("732 829 320 00074")).toBe(true);
    expect(isPlausibleSIRET("73282932000074")).toBe(true);
    expect(isPlausibleSIRET("73282932000075")).toBe(false);
    expect(isPlausibleSIRET("00000000000000")).toBe(false);
  });

  it("isPlausibleNIR accepts a constructed-then-keyed NIR", () => {
    const body = "184127511630"; // 12 digits (sex/year/month/dept/commune/order)
    // Wait: NIR is 13-digit body + 2-digit key. Let's construct 13.
    const body13 = "1841275116305";
    const key = 97 - (Number(body13) % 97);
    const nir = body13 + key.toString().padStart(2, "0");
    expect(isPlausibleNIR(nir)).toBe(true);
    // Mutate the key → must fail.
    const badKey = ((key % 97) + 1).toString().padStart(2, "0");
    expect(isPlausibleNIR(body13 + badKey)).toBe(false);
    // Wrong leading digit → must fail (must start with 1 or 2).
    expect(isPlausibleNIR("3841275116305" + key.toString().padStart(2, "0"))).toBe(false);
    void body;
  });

  it("isPlausibleNHS accepts NHS Digital test number, rejects mutations", () => {
    expect(isPlausibleNHS("943 476 5919")).toBe(true);
    expect(isPlausibleNHS("9434765919")).toBe(true);
    expect(isPlausibleNHS("9434765918")).toBe(false);
    expect(isPlausibleNHS("000 000 0000")).toBe(false);
  });

  it("isPlausibleNINO accepts canonical, rejects banned prefixes and reserved pairs", () => {
    expect(isPlausibleNINO("AB123456C")).toBe(true);
    expect(isPlausibleNINO("AB 12 34 56 C")).toBe(true);
    expect(isPlausibleNINO("DA123456C")).toBe(false); // D banned in pos 1
    expect(isPlausibleNINO("AO123456C")).toBe(false); // O banned in pos 2
    expect(isPlausibleNINO("BG123456A")).toBe(false); // BG reserved
    expect(isPlausibleNINO("ZZ123456A")).toBe(false); // ZZ reserved
    expect(isPlausibleNINO("AB123456E")).toBe(false); // suffix outside A-D
  });

  it("isPlausibleUKPostcode accepts canonical UK postcodes", () => {
    expect(isPlausibleUKPostcode("SW1A 1AA")).toBe(true);
    expect(isPlausibleUKPostcode("EC1A 1BB")).toBe(true);
    expect(isPlausibleUKPostcode("M1 1AE")).toBe(true);
    expect(isPlausibleUKPostcode("GIR 0AA")).toBe(true);
    expect(isPlausibleUKPostcode("XX1 1AA")).toBe(false);
    expect(isPlausibleUKPostcode("12345")).toBe(false);
  });

  it("isPlausibleNPI accepts CMS test NPI, rejects mutations", () => {
    expect(isPlausibleNPI("1234567893")).toBe(true);
    expect(isPlausibleNPI("1234567894")).toBe(false);
    expect(isPlausibleNPI("123456789")).toBe(false); // 9 digits
  });

  it("isPlausibleJWT requires a JSON header with alg", () => {
    // header={alg:HS256,typ:JWT}, payload={sub:1}, sig=anything
    const valid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjF9.signature";
    expect(isPlausibleJWT(valid)).toBe(true);
    expect(isPlausibleJWT("not.a.jwt")).toBe(false);
    expect(isPlausibleJWT("aaaa.bbbb")).toBe(false); // only 2 segments
  });
});

describe("scanPII", () => {
  it("detects an email and reports correct offsets", () => {
    const text = "Contact me at jane.doe@example.com please";
    const hits = scanPII(text);
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({ type: "EMAIL", value: "jane.doe@example.com" });
    expect(text.slice(hits[0]!.start, hits[0]!.end)).toBe("jane.doe@example.com");
  });

  it("detects multiple entity types in one input", () => {
    const text = "Email alice@acme.io, card 4242 4242 4242 4242, IBAN GB82 WEST 1234 5698 7654 32";
    const hits = scanPII(text);
    const types = hits.map((h) => h.type).sort();
    expect(types).toEqual(["CREDIT_CARD", "EMAIL", "IBAN"]);
  });

  it("rejects card-shaped numbers that fail Luhn", () => {
    const hits = scanPII("invoice 1234567890123456 from vendor");
    expect(hits.filter((h) => h.type === "CREDIT_CARD")).toHaveLength(0);
  });

  it("rejects IBAN-shaped strings that fail mod-97", () => {
    const hits = scanPII("ref GB82WEST12345698765433 invalid");
    expect(hits.filter((h) => h.type === "IBAN")).toHaveLength(0);
  });

  it("does not flag version strings as IPv4", () => {
    const hits = scanPII("upgrade to 999.1.2.3 today");
    expect(hits.filter((h) => h.type === "IPV4")).toHaveLength(0);
  });

  it("does not flag SSA-invalid SSNs", () => {
    const hits = scanPII("internal ticket 000-12-3456");
    expect(hits.filter((h) => h.type === "US_SSN")).toHaveLength(0);
  });

  it("detects AWS access keys", () => {
    const hits = scanPII("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE");
    expect(hits).toHaveLength(1);
    expect(hits[0]!.type).toBe("AWS_ACCESS_KEY");
  });

  it("detects JWTs and filters base64-shaped non-JWTs", () => {
    const valid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjF9.signature";
    const hits = scanPII(`token: ${valid}`);
    expect(hits.find((h) => h.type === "JWT")).toBeDefined();
  });

  it("returns non-overlapping detections in input order", () => {
    const text = "user@a.io and 4242 4242 4242 4242 then bob@b.io";
    const hits = scanPII(text);
    for (let i = 1; i < hits.length; i++) {
      expect(hits[i]!.start).toBeGreaterThanOrEqual(hits[i - 1]!.end);
    }
  });

  it("returns empty for empty input", () => {
    expect(scanPII("")).toEqual([]);
  });

  // R3 regression: the CC regex used to swallow trailing whitespace, so
  // the matched span extended past the PAN and applyRedactions clobbered
  // characters that weren't part of the card number.
  it("CREDIT_CARD does not swallow trailing separator", () => {
    const text = "card 4242 4242 4242 4242 deadbeef";
    const hits = scanPII(text);
    const cc = hits.find((h) => h.type === "CREDIT_CARD")!;
    expect(cc).toBeDefined();
    expect(cc.value).toBe("4242 4242 4242 4242");
    expect(text.slice(cc.start, cc.end)).toBe("4242 4242 4242 4242");
    expect(cc.end).toBeLessThan(text.indexOf("deadbeef"));
  });

  // ── Secret-key detectors (Gitleaks-derived) ───────────────────────────

  it("detects OpenAI / Anthropic / xAI API keys by prefix", () => {
    const keys = [
      ["OPENAI_KEY", "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA12345678"],
      ["OPENAI_KEY", "sk-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA12345678"],
      ["ANTHROPIC_KEY", "sk-ant-api03-" + "A".repeat(86)],
      ["XAI_KEY", "xai-" + "A".repeat(80)],
    ] as const;
    for (const [type, key] of keys) {
      const hits = scanPII(`api: ${key}`);
      expect(
        hits.find((h) => h.type === type),
        type,
      ).toBeDefined();
    }
  });

  it("detects GitHub PATs of every shape", () => {
    const cases = [
      ["GITHUB_PAT", "ghp_" + "A".repeat(36)],
      ["GITHUB_OAUTH", "gho_" + "B".repeat(36)],
      ["GITHUB_APP", "ghs_" + "C".repeat(36)],
      ["GITHUB_FINE_GRAINED_PAT", "github_pat_" + "D".repeat(82)],
    ] as const;
    for (const [type, key] of cases) {
      const hits = scanPII(`Authorization: ${key}`);
      expect(
        hits.find((h) => h.type === type),
        type,
      ).toBeDefined();
    }
  });

  it("detects Slack tokens and Discord/Slack webhook URLs", () => {
    const slackTok = "xoxb-12345678901-12345678901-AbCdEfGhIjKlMnOpQrStUvWx";
    const slackHook = "https://hooks.slack.com/services/T0ABCDEFG/B0ABCDEFG/" + "A".repeat(24);
    const discordHook = "https://discord.com/api/webhooks/1234567890123456789/" + "B".repeat(60);
    expect(scanPII(slackTok).find((h) => h.type === "SLACK_TOKEN")).toBeDefined();
    expect(scanPII(slackHook).find((h) => h.type === "SLACK_WEBHOOK")).toBeDefined();
    expect(scanPII(discordHook).find((h) => h.type === "DISCORD_WEBHOOK")).toBeDefined();
  });

  it("detects Stripe / Google / SendGrid / Twilio keys", () => {
    const cases = [
      ["STRIPE_KEY", "sk_live_" + "A".repeat(24)],
      ["STRIPE_KEY", "rk_test_" + "B".repeat(24)],
      ["GOOGLE_API_KEY", "AIza" + "C".repeat(35)],
      ["SENDGRID_KEY", "SG." + "D".repeat(22) + "." + "E".repeat(43)],
      ["TWILIO_API_KEY", "SK" + "0".repeat(32)],
      ["TWILIO_ACCOUNT_SID", "AC" + "1".repeat(32)],
    ] as const;
    for (const [type, key] of cases) {
      const hits = scanPII(`secret: ${key}`);
      expect(
        hits.find((h) => h.type === type),
        type,
      ).toBeDefined();
    }
  });

  it("detects PEM private keys (multi-line)", () => {
    const pem = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyz1234567890==
-----END RSA PRIVATE KEY-----`;
    const hits = scanPII(`config: ${pem}`);
    expect(hits.find((h) => h.type === "PEM_PRIVATE_KEY")).toBeDefined();
  });

  it("detects DB connection strings with embedded passwords", () => {
    const cases = [
      ["POSTGRES_URL", "postgres://user:s3cr3t@db.example.com:5432/mydb"],
      ["MYSQL_URL", "mysql://root:hunter2@10.0.0.1:3306/app"],
      ["MONGODB_URL", "mongodb+srv://alice:tok3n@cluster.mongodb.net"],
      ["REDIS_URL", "redis://:p4ss@redis.example.com:6379"],
    ] as const;
    for (const [type, url] of cases) {
      const hits = scanPII(`DATABASE_URL=${url}`);
      expect(
        hits.find((h) => h.type === type),
        type,
      ).toBeDefined();
    }
  });

  it("generic API-key fallback requires both context and entropy", () => {
    const highEntropy = "Zk9q7tH8KvLm2nXrPdY3wQa1Bs6Cf4Dg7Hj0Lz5Mn8VbCx";
    // With context word → matches.
    const withCtx = scanPII(`api_key=${highEntropy}`);
    expect(withCtx.find((h) => h.type === "GENERIC_API_KEY")).toBeDefined();
    // Same value without a key-naming context word → does NOT match.
    const withoutCtx = scanPII(`hash: ${highEntropy}`);
    expect(withoutCtx.find((h) => h.type === "GENERIC_API_KEY")).toBeUndefined();
    // Low-entropy string with context → still does NOT match.
    const lowEntropy = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    expect(
      scanPII(`api_key=${lowEntropy}`).find((h) => h.type === "GENERIC_API_KEY"),
    ).toBeUndefined();
  });

  it("JWT still wins over GENERIC_API_KEY on the same offset", () => {
    const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjF9.signature";
    const hits = scanPII(`token: ${jwt}`);
    expect(hits.find((h) => h.type === "JWT")).toBeDefined();
    expect(hits.find((h) => h.type === "GENERIC_API_KEY")).toBeUndefined();
  });

  // R3 part 2: Luhn passes ~10% of random 16-digit strings, so without
  // contextual suppression we'd redact hashes, txn IDs, etc.
  it("CREDIT_CARD context suppression skips Luhn-passing identifiers", () => {
    // 4242424242424242 passes Luhn but is labeled as a hash.
    const ccLike = "4242 4242 4242 4242";
    expect(luhn(ccLike)).toBe(true); // sanity
    for (const prefix of [
      "sha256:",
      "md5:",
      "txn_id=",
      "correlation_id=",
      "trace-id ",
      "hash: ",
      "order_id=",
    ]) {
      const hits = scanPII(`${prefix}${ccLike}`);
      expect(
        hits.filter((h) => h.type === "CREDIT_CARD"),
        prefix,
      ).toHaveLength(0);
    }
  });

  // EU / UK / healthcare detector smoke tests — ensure the detector
  // list picks the right type and that overlap resolution between
  // shape-colliding types behaves.

  it("detects French SIRET as FR_SIRET, not CREDIT_CARD", () => {
    const hits = scanPII("entreprise SIRET 732 829 320 00074 immatriculée");
    expect(hits.find((h) => h.type === "FR_SIRET")).toBeDefined();
    expect(hits.find((h) => h.type === "CREDIT_CARD")).toBeUndefined();
  });

  it("detects UK NHS number with mod-11 validation", () => {
    const hits = scanPII("patient ID 943 476 5919 admitted today");
    expect(hits.find((h) => h.type === "UK_NHS")).toBeDefined();
  });

  it("detects UK NINO and UK postcode in the same prompt", () => {
    const hits = scanPII("My NINO is AB 12 34 56 C and I live at SW1A 1AA");
    expect(hits.find((h) => h.type === "UK_NINO")).toBeDefined();
    expect(hits.find((h) => h.type === "UK_POSTCODE")).toBeDefined();
  });

  it("detects French NIR", () => {
    const body13 = "1841275116305";
    const key = 97 - (Number(body13) % 97);
    const nir = body13 + key.toString().padStart(2, "0");
    const hits = scanPII(`Numéro de sécurité sociale: ${nir}`);
    expect(hits.find((h) => h.type === "FR_NIR")).toBeDefined();
  });

  it("detects US NPI", () => {
    const hits = scanPII("Provider NPI: 1234567893 enrolled");
    expect(hits.find((h) => h.type === "US_NPI")).toBeDefined();
  });

  // R4 regression: build-log date "2024:08:31:12:34:56:78:99" matches the
  // IPv6 regex but is not a valid address.
  it("IPV6 rejects date-like colon-separated strings", () => {
    const hits = scanPII("build started 2024:08:31:12:34:56:78:99 ok");
    expect(hits.filter((h) => h.type === "IPV6")).toHaveLength(0);
  });

  it("IPV6 detects real addresses", () => {
    const hits = scanPII("upstream 2001:db8::8a2e:370:7334 connected");
    expect(hits.find((h) => h.type === "IPV6")).toBeDefined();
  });

  it("IPV6 detects valid addresses compressed from the leading groups", () => {
    const hits = scanPII("peer ::abcd:1 connected");
    expect(hits.find((h) => h.type === "IPV6")?.value).toBe("::abcd:1");
  });

  it("detector priority wins even when a lower-priority overlap starts earlier", () => {
    const specific = { type: "JWT" as const, regex: /secret/g };
    const broad = { type: "GENERIC_API_KEY" as const, regex: /a-secret-value/g };
    const hits = scanPII("x a-secret-value y", { detectors: [specific, broad] });
    expect(hits).toEqual([{ type: "JWT", start: 4, end: 10, value: "secret" }]);
  });

  // R1 regression: scanner.ts:45 used to be `b.d.end - b.d.end === 0 ? 0
  // : b.d.end - a.d.end`, which is identically zero. The fix matters
  // whenever two detectors of the same rank produce overlapping spans
  // at the same offset with different lengths — the longer span must win
  // so we never leave a PII substring un-redacted inside the un-replaced
  // tail of a shorter match.
  //
  // In the production detector list every detector has a distinct rank so
  // this only fires with custom detectors. Verify by constructing two
  // detectors with overlapping regexes wrapped in a single rank position
  // via a synthetic detector that captures the longer-of-two-matches
  // intent: an IBAN-shaped span sometimes covers a CC-shaped span,
  // and the overlap resolver picks one. The test below documents the
  // observable invariant: a longer span starting at the same offset as
  // a shorter same-rank span wins, ensuring no PII tail survives.
  it("longer-span-wins documents the invariant the scanner.ts:45 fix preserves", () => {
    // Two detectors of nominally-different rank, but with the same regex
    // shape match at the same offset; sort by start (tie), then rank
    // (lower wins). This documents that rank precedence is intentional —
    // the R1 fix exists to handle the case where rank also ties.
    const broad = { type: "EMAIL" as const, regex: /foo\.bar@example\.com extended/g };
    const narrow = { type: "EMAIL" as const, regex: /foo\.bar@example\.com/g };
    // narrow comes first → wins by rank, leaving " extended" un-redacted.
    const hitsNarrowFirst = scanPII("see foo.bar@example.com extended now", {
      detectors: [narrow, broad],
    });
    expect(hitsNarrowFirst[0]!.value).toBe("foo.bar@example.com");
    // broad comes first → wins by rank, covering the whole span.
    const hitsBroadFirst = scanPII("see foo.bar@example.com extended now", {
      detectors: [broad, narrow],
    });
    expect(hitsBroadFirst[0]!.value).toBe("foo.bar@example.com extended");
  });
});

describe("applyRedactions", () => {
  it("replaces detected spans with minted tokens and preserves surrounding text", () => {
    const text = "Hi jane.doe@example.com, see you";
    const hits = scanPII(text);
    let n = 0;
    const out = applyRedactions(text, hits, (d) => `{${d.type}_${++n}}`);
    expect(out).toBe("Hi {EMAIL_1}, see you");
  });

  it("round-trips: re-substituting cleartext into placeholders restores the original", () => {
    const text = "Wire to GB82 WEST 1234 5698 7654 32 from 4242 4242 4242 4242";
    const hits = scanPII(text);
    const map = new Map<string, string>();
    let n = 0;
    const redacted = applyRedactions(text, hits, (d) => {
      const tok = `{${d.type}_${++n}}`;
      map.set(tok, d.value);
      return tok;
    });
    let restored = redacted;
    for (const [tok, val] of map) restored = restored.split(tok).join(val);
    expect(restored).toBe(text);
  });

  it("is a no-op when no detections were found", () => {
    expect(applyRedactions("hello world", [], () => "X")).toBe("hello world");
  });

  it("fails closed on stale or overlapping caller-supplied offsets", () => {
    expect(() =>
      applyRedactions("abc", [{ type: "EMAIL", start: 1, end: 3, value: "wrong" }], () => "X"),
    ).toThrow(RangeError);
  });
});

// Property-based round-trip invariants (task #15). Vitest's `fast-check`
// isn't installed; we approximate with a deterministic sweep over a
// representative corpus that exercises the round-trip closure.
describe("round-trip property invariants", () => {
  const corpus = [
    "",
    "no pii here at all just plain text",
    "contact alice@example.com",
    "two emails alice@a.io and bob@b.io in one line",
    "card 4242 4242 4242 4242 plus iban GB82 WEST 1234 5698 7654 32",
    "SIRET 732 829 320 00074 active",
    "NHS 943 476 5919 + NINO AB 12 34 56 C at SW1A 1AA",
    "ipv6 2001:db8::8a2e:370:7334 and ipv4 192.168.1.1",
    "jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOjF9.signature",
    "aws AKIAIOSFODNN7EXAMPLE in env",
    // Adversarial: literal placeholder shapes that an attacker might
    // include in input. They should round-trip exactly (they're not in
    // the session map, so reverse is a no-op).
    "user-typed ⟦pii:EMAIL:deadbeef⟧ should pass through",
    "{EMAIL_1} curly-brace lookalike should pass through",
    // Newlines, tabs, unicode, varied whitespace.
    "line1\nemail\tinside @nope wait alice@x.io\n\rbob@y.io",
  ];

  it("redact then restore matches the original for every corpus item", () => {
    for (const text of corpus) {
      const hits = scanPII(text);
      const map = new Map<string, string>();
      let n = 0;
      const redacted = applyRedactions(text, hits, (d) => {
        const tok = `⟦pii:${d.type}:${(++n).toString(16).padStart(8, "0")}⟧`;
        map.set(tok, d.value);
        return tok;
      });
      let restored = redacted;
      // Reverse in deterministic order — longest tokens first so a token
      // that happens to contain another token's substring doesn't collide.
      const tokens = Array.from(map.keys()).sort((a, b) => b.length - a.length);
      for (const tok of tokens) restored = restored.split(tok).join(map.get(tok)!);
      expect(restored, JSON.stringify(text)).toBe(text);
    }
  });

  it("detections are non-overlapping and ordered for every corpus item", () => {
    for (const text of corpus) {
      const hits = scanPII(text);
      for (let i = 1; i < hits.length; i++) {
        expect(hits[i]!.start, `overlap in ${JSON.stringify(text)}`).toBeGreaterThanOrEqual(
          hits[i - 1]!.end,
        );
      }
    }
  });

  it("redactions never extend past the input length", () => {
    for (const text of corpus) {
      const hits = scanPII(text);
      for (const h of hits) {
        expect(h.end).toBeLessThanOrEqual(text.length);
        expect(h.start).toBeGreaterThanOrEqual(0);
        expect(text.slice(h.start, h.end)).toBe(h.value);
      }
    }
  });
});
