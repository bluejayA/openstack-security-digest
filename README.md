# OpenStack Security Digest

Fetches the [Stackers Network](https://stackers.network) weekly OpenStack
mailing-list digest (`feed.xml`), **filters the security content**, classifies
each advisory **by operational impact**, and:

- serves it as a **REST API**,
- renders it on a **dashboard** (impact-grouped advisories + weekly timeline),
- **pushes notable advisories to Slack** when a new digest is published.

![Dashboard](docs/dashboard.png)

## Architecture

```
  stackers.network/feed.xml
            │
            ▼
   ┌─────────────────────────────────────────────────────────┐
   │ Go backend (server/)                                      │
   │  Fetcher → RSS Parser → Security Extractor → Classifier   │
   │  ├─ Scheduler  : poll feed, detect new digest, push Slack │
   │  ├─ Slack      : Incoming Webhook + Block Kit             │
   │  ├─ SQLite     : settings / seen digests / deliveries     │
   │  └─ REST API   : /api/security, /api/settings, …          │
   └─────────────────────────────────────────────────────────┘
            │ JSON (CORS)
            ▼
   ┌─────────────────────────────────────────────────────────┐
   │ Next.js + Tailwind v4 + shadcn/ui (web/)                  │
   │  Dashboard (impact groups, timeline, delivery status)     │
   │  Settings  (webhook, threshold, poll interval, scope)     │
   └─────────────────────────────────────────────────────────┘
```

## Impact classification (rule-based)

Each advisory's summary is scored against keyword tiers, then adjusted:

| Category   | Example signals                                                        |
|------------|------------------------------------------------------------------------|
| **Critical** | `escalate to cloud admin`, RCE, authentication bypass                |
| **High**     | `authorization/policy bypass`, privilege escalation, credential leak |
| **Medium**   | DoS, infinite loop, information disclosure                           |
| **Low**      | operator notes (OSSN), minor / locally-scoped issues                 |

Modifiers: broad blast radius (`all 2026.x deployments`, `permanently`) upgrades
a tier; a narrowly-scoped issue (`project reader`, `same-project`) downgrades a
High to Medium; a bundle of ≥3 CVEs bumps one tier. All deterministic, no LLM.

> Example: `OSSA-2026-015` (Keystone, cloud-admin escalation, 5 CVEs) → **Critical**,
> `OSSA-2026-014` (Swift s3api DoS, permanent) → **High**,
> `OSSA-2026-016` (Neutron tagging bypass, project-reader scope) → **Medium**.

## Running locally

### Backend (Go ≥ 1.26)

```bash
cd server
go test ./...        # run the test suite
go run ./cmd/server  # starts on :8080
```

Environment variables (all optional):

| Var               | Default                          | Purpose                       |
|-------------------|----------------------------------|-------------------------------|
| `ADDR`            | `:8080`                          | listen address                |
| `DB_PATH`         | `./data/digest.db`               | SQLite file                   |
| `FEED_URL`        | `https://stackers.network/feed.xml` | feed source (override for tests) |
| `FEED_CACHE_TTL`  | `10m`                            | in-memory feed cache TTL      |

### Frontend (Node ≥ 20)

```bash
cd web
npm install
npm run dev          # http://localhost:3000  (expects the API on :8080)
```

`web/.env.local` sets `NEXT_PUBLIC_API_BASE` (default `http://localhost:8080`).

## API

| Method | Path                       | Description                                    |
|--------|----------------------------|------------------------------------------------|
| GET    | `/api/security?weeks=N`    | advisories from the N most recent digests      |
| GET    | `/api/security?from=&to=`  | advisories in a date range (`YYYY-MM-DD`)      |
| GET    | `/api/settings`            | current settings                               |
| PUT    | `/api/settings`            | update settings                                |
| POST   | `/api/settings/test`       | send a test message to the configured webhook  |
| GET    | `/api/deliveries`          | recent Slack delivery history                  |
| GET    | `/healthz`                 | health check                                   |

`/api/security` response groups advisories by impact:

```jsonc
{
  "count": 3,
  "totals": { "Critical": 1, "High": 1, "Medium": 1 },
  "groups": {
    "Critical": [ { "id": "OSSA-2026-015", "component": "Keystone",
                    "cves": ["CVE-2026-42999", ...], "impact": "Critical",
                    "digestDate": "2026-05-30", ... } ]
  },
  "digests": [ { "date": "2026-05-30", "count": 3, "topRank": 4 } ]
}
```

## Slack notifications

1. Create a Slack **Incoming Webhook** and paste the URL into **Settings**.
2. Pick a **threshold** (e.g. *High and above*) and enable **Auto-push**.
3. The scheduler polls the feed; when a new digest appears it pushes advisories
   at or above the threshold as a colored Block Kit message. The first poll on a
   fresh database is a silent baseline (no backfill spam); deliveries are
   de-duplicated so an advisory is never sent twice.

## Layout

```
server/                      Go service
  cmd/server/                main / wiring
  internal/feed/             fetch + RSS parse
  internal/security/         extract security section + impact classifier
  internal/store/            SQLite (settings, seen digests, deliveries)
  internal/slack/            Block Kit + webhook delivery
  internal/scheduler/        poll → detect new → notify
  internal/api/              REST handlers
  testdata/feed.xml          real feed fixture (offline tests)
web/                         Next.js dashboard + settings
```
