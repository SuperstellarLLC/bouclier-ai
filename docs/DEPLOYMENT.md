# Deployment & operations

Operational notes for the marketing site (`apps/site`). The desktop app ships as
a signed DMG and needs no server configuration.

## False-positive report intake (`POST /api/report`)

The menu-bar app posts **redacted** false-positive samples here so detection can
be tuned. Every abuse control is **IP-free by design** — the app reads and
stores no client IP, user-agent, or identifier:

| Concern                   | Control                                                                                                                                                                                                                                                                                         |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Durability / queryability | **Postgres** (`DATABASE_URL`). Reports go into `false_positive_reports` (schema created automatically on first write) — durable and queryable, so a flood can't evict genuine reports. Unset/unreachable → 503; report content is not logged or silently dropped.                               |
| Retention                 | Reports become eligible for deletion after **90 days**. The next valid database intake deletes expired rows using the `fpr_created_at_idx` index before attempting its insert. Schedule the cleanup query below when strict wall-clock deletion is required during periods with no new reports. |
| Per-report cost           | A hashcash **proof-of-work** stamp mined by the client (`REPORT_POW_BITS` leading zero bits, default 20). Flooding costs real CPU per report, with no client identity.                                                                                                                          |
| Global volume / cost      | An atomic **one-minute quota row** (currently 300/window) claimed by UPSERT in the same statement as the report INSERT. Concurrent requests cannot race a read-count check; exhausted submissions receive 429.                                                                                  |
| Data integrity            | Required metadata is type/range checked, the PoW-bound fingerprint must be a 64-character lowercase SHA-256 hex digest, and rejected/storage-failed submissions never receive a false success response.                                                                                         |
| Body size                 | Stream-and-abort at 32 KB; never trusts the client-declared `Content-Length`.                                                                                                                                                                                                                   |
| Per-IP rate limiting      | **Not in app code.** Enable a rate-limit rule on `/api/report` in **Vercel Firewall** — abuse mitigation belongs at the edge, where an IP is transport, not data we collect.                                                                                                                    |

### Retention cleanup during inactive periods

Valid report intake opportunistically removes every row older than 90 days; idle
intake therefore does not provide a strict wall-clock deletion guarantee. A
deployment that requires one should schedule this idempotent query at least daily,
using its Postgres provider's scheduler or an external job:

```sql
DELETE FROM false_positive_reports
WHERE created_at < now() - interval '90 days';
```

The automatically-created `fpr_created_at_idx` index supports the range predicate.

## Environment variables

- `DOWNLOAD_REDIRECT_BASE` — HTTPS release-directory URL used by `/api/download` (no credentials, query, or fragment). Without it, downloads return 503.
- `DATABASE_URL` — Postgres connection string (Neon / Vercel Postgres, HTTP driver) for report persistence. Required for report intake; without it, `/api/report` returns 503.
- `REPORT_POW_BITS` — proof-of-work difficulty. Default `20`; `0` disables. Raising it is a **break-glass lever** during an attack — note that shipped app builds mine at `20`, so a value above that makes older clients fail to report until they update.
- `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` — anonymous download-count store and single-use PoW replay cache. The URL must use HTTPS and cannot contain credentials, a query, or a fragment. Downloads still redirect when unset; report volume remains bounded by the Postgres quota, but replay resistance is weaker.
- `DOWNLOAD_STATS_TOKEN` — bearer token gating `GET /api/download/stats`; the endpoint 404s when unset (default-deny).

## Production release alignment

Production site builds are coupled to the signed desktop release recorded in
`apps/site/public/appcast.xml`. A Vercel production build, or a self-hosted build
with `BOUCLIER_DEPLOYMENT_ENV=production`, stops unless the appcast's first item:

- matches `APP_VERSION` in both Sparkle version fields;
- has a canonical base64 Sparkle Ed25519 signature that decodes to exactly 64
  bytes, plus a positive artifact length; and
- points over HTTPS to the exact `Bouclier-ai-vVERSION-macOS.dmg` filename,
  without credentials, a query, or a fragment; and
- uses the exact normalized origin, port, and directory path configured in
  `DOWNLOAD_REDIRECT_BASE`, so the site button and Sparkle cannot drift to
  different artifacts.

The production Dockerfile sets `BOUCLIER_DEPLOYMENT_ENV=production` during its
build stage, so it cannot bypass this check. Pass the public download directory
with `--build-arg DOWNLOAD_REDIRECT_BASE=...`; the supplied Compose file obtains
the same value from `apps/site/.env.local` for both the build and runtime.
Ordinary local builds and Vercel preview deployments deliberately skip the
gate, allowing release-candidate QA before the signed DMG and appcast are ready.

## Self-hosting (Docker, no Vercel edge)

There is no edge WAF in front of a self-hosted container, so abuse control is the
proof-of-work stamp plus the global write cap. If you want per-IP rate limiting,
front the container with your own reverse proxy / WAF — the app itself never
reads a client IP, so this is purely an infrastructure choice.
