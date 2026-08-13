# Deployment & operations

Operational notes for the marketing site (`apps/site`). The desktop app ships as
a signed DMG and needs no server configuration.

## False-positive report intake (`POST /api/report`)

The menu-bar app posts **redacted** false-positive samples here so detection can
be tuned. Every abuse control is **IP-free by design** — the app reads and
stores no client IP, user-agent, or identifier:

| Concern                   | Control                                                                                                                                                                                                                                                            |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Durability / queryability | **Postgres** (`DATABASE_URL`). Reports go into `false_positive_reports` (schema created automatically on first write) — durable and queryable, so a flood can't evict genuine reports. Unset → each report is logged to the function console instead of persisted. |
| Per-report cost           | A hashcash **proof-of-work** stamp mined by the client (`REPORT_POW_BITS` leading zero bits, default 20). Flooding costs real CPU per report, with no client identity.                                                                                             |
| Global volume / cost      | An atomic **per-minute write cap** enforced inside the INSERT (currently 300/min) — bounds DB growth and cost.                                                                                                                                                     |
| Body size                 | Stream-and-abort at 32 KB; never trusts the client-declared `Content-Length`.                                                                                                                                                                                      |
| Per-IP rate limiting      | **Not in app code.** Enable a rate-limit rule on `/api/report` in **Vercel Firewall** — abuse mitigation belongs at the edge, where an IP is transport, not data we collect.                                                                                       |

## Environment variables (all optional; safe defaults)

- `DATABASE_URL` — Postgres connection string (Neon / Vercel Postgres, HTTP driver) for report persistence.
- `REPORT_POW_BITS` — proof-of-work difficulty. Default `20`; `0` disables. Raising it is a **break-glass lever** during an attack — note that shipped app builds mine at `20`, so a value above that makes older clients fail to report until they update.
- `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` — download-count store (separate from reports; downloads still redirect when unset).
- `DOWNLOAD_STATS_TOKEN` — bearer token gating `GET /api/download/stats`; the endpoint 404s when unset (default-deny).

## Self-hosting (Docker, no Vercel edge)

There is no edge WAF in front of a self-hosted container, so abuse control is the
proof-of-work stamp plus the global write cap. If you want per-IP rate limiting,
front the container with your own reverse proxy / WAF — the app itself never
reads a client IP, so this is purely an infrastructure choice.
