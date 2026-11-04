# Greywatch Staging Deployment — Caddy HTTPS Reverse Proxy

First deployment milestone: prepare a staging VPS deployment using **Caddy as the
HTTPS reverse proxy** with **FastAPI/uvicorn bound to `127.0.0.1:8000` only**.
uvicorn is never exposed on a public interface.

This document is operational guidance for staging. It does **not** provision cloud
resources, change DNS, or deploy to a live host. Do not proceed to a real host
without explicit authorization.

## Contents

1. [Architecture](#architecture)
2. [Authentication architecture](#authentication-architecture)
3. [Security assumptions](#security-assumptions)
4. [DNS records](#dns-records)
5. [Firewall ports](#firewall-ports)
6. [Service user and file permissions](#service-user-and-file-permissions)
7. [Environment variables](#environment-variables)
8. [Files created in this milestone](#files-created-in-this-milestone)
9. [Build and deploy the frontend](#build-and-deploy-the-frontend)
10. [Database backup, restore, and disaster recovery](#database-backup-restore-and-disaster-recovery)
11. [Event retention and database maintenance](#event-retention-and-database-maintenance)
12. [Rollback steps](#rollback-steps)
13. [Staging verification checklist](#staging-verification-checklist)
14. [Unresolved blockers and manual steps](#unresolved-blockers-and-manual-steps)

---

## Architecture

```
Internet ──[HTTPS 443]── Caddy (reverse proxy, TLS termination)
                              │ HTTP 127.0.0.1:8000 (loopback only)
                              ▼
                    uvicorn backend.app.main:app
                              │ GREYWATCH_DB=/var/lib/greywatch/greywatch.db
                              ▼
                         SQLite (WAL) + collector_state
                              ▲
                    (optional) journalctl / Suricata eve.json
                              (local file access, same host)

Frontend static build served by Caddy from /var/www/greywatch/dist.
Shared API token injected server-side by Caddy; the browser never sees it.
Agent API keys are forwarded untouched; Caddy never substitutes the shared token.
```

## Authentication architecture

Greywatch uses a **layered** authentication model for the beta:

1. **Dashboard shell (human user):** Caddy `basicauth` on `https://{DOMAIN}/`
   and on every `/api/*` route except the dedicated agent ingest routes. The
   browser must present valid basicauth credentials before the SPA
   (HTML/JS) is served. Without credentials, the dashboard shell returns 401.

2. **API credentials:** Caddy injects `GREYWATCH_API_TOKEN` in the
   `X-Greywatch-Token` header **server-side** when proxying dashboard API
   requests to the backend on `127.0.0.1:8000`. The browser **never sees**
   the API token. The backend accepts this proxy header, a direct
   `Authorization: Bearer <token>`, or `X-API-Key: <token>` for legacy
   shared-token access, and validates it on every non-public endpoint
   (constant-time `hmac.compare_digest`). Missing/invalid → 401.

3. **Agent API keys (`gw_...`):** ingestion-only integrations authenticate
   with their own revocable key. The `Caddyfile` has dedicated routes for
   `POST /api/v1/events/ingest` when the request carries
   `X-API-Key: gw_...` or `Authorization: Bearer gw_...`. Those routes
   intentionally bypass dashboard `basic_auth` (a machine agent has no human
   dashboard password), do **not** inject the shared token, and strip any
   inbound `X-Greywatch-Token`. The backend authenticates the key itself and
   restricts it to the ingest endpoint.

Agent credentials are exclusive: if either `Authorization` or `X-API-Key`
contains a `gw_...` value, only agent authentication is attempted. An invalid,
expired, or revoked key returns 401 and is **never** downgraded to shared-token
authentication, even when a valid shared token is also present. A valid agent
key used on any non-ingest path (including `/api/v1/admin/*`) returns 403.
Admin routes remain behind dashboard `basic_auth` plus the injected shared
token; the agent ingress routes match only the exact ingest path and key shape.

Why server-side token injection:
- A token delivered to browser JavaScript (`window.__GREYWATCH_API_TOKEN__`)
  is exposed to the authenticated browser user. It can be read from DevTools,
  network logs, or any same-origin script. For a shared beta token, this
  means every dashboard user can extract and reuse it.
- By having Caddy inject the token server-side, the token stays out of the
  browser entirely. Caddy holds it in its environment; the browser sends no
  API credential. Caddy adds `X-Greywatch-Token` on the upstream request.
- `Authorization` is deliberately **not** overwritten: doing so would replace
  an agent key with the shared token and turn a revoked/expired key into
  legacy access.

Request flows:
```
Browser ──(basicauth)──► Caddy ──(adds X-Greywatch-Token)──► uvicorn 127.0.0.1:8000
                              (dashboard/API routes)         (backend validates token)

Agent ──(X-API-Key: gw_... or Bearer gw_...)──► Caddy ──(no basicauth, no token)──► uvicorn
                                                (agent ingest route)                (backend validates key)
```

`/docs` and `/openapi.json` are **not proxied** by Caddy and return 404.
They are also not in the backend's public paths, so even if reached they
require token auth. The staging `Caddyfile` intentionally contains no
`handle /docs` or `handle /openapi.json` blocks: an unmatched path is what
makes Caddy return 404 without a basicauth gate, so adding those blocks would
expose the API schema on the public listener.

---

## Security assumptions

- The operator controls the VPS, DNS for `{REPLACE_ME_WITH_DOMAIN}`, and the
  TLS certificate (or uses Let's Encrypt once DNS resolves).
- `GREYWATCH_API_TOKEN` is the single shared secret used by the staging
  dashboard/API path (generated with `scripts/generate_staging_token.sh`). It
  must be set in **both** Caddy's environment (for server-side injection) and
  the backend's environment (for validation). Agent API keys (`gw_...`) are
  also available for ingestion-only integrations and support revocation and
  rotation through the admin API, but they do not replace the shared dashboard
  token. See [`ADMIN_API.md`](ADMIN_API.md) for the operator reference.
  Compromise of the shared token compromises all API access (accepted
  beta risk). The shared token must **not** start with `gw_`: that prefix is
  reserved for agent API keys, and a `gw_...` shared token would be treated as
  an agent credential and rejected.
- Agent API keys are presented directly to Caddy on the dedicated ingest
  route. Caddy does not require dashboard `basic_auth` on that route and does
  not inject the shared token; the backend alone decides whether the key is
  valid. This is intentional: the key is the machine credential. The route
  matches only `POST /api/v1/events/ingest` with `X-API-Key: gw_*` or
  `Authorization: Bearer gw_*`, so it cannot be used to reach admin or read
  endpoints.
- The frontend never holds a build-time secret: `VITE_*` values are compiled
  into the public bundle and must never contain a token. No runtime token is
  injected into the browser.
- Secrets live only in `/etc/greywatch/greywatch.env` (mode 0600, root) and
  Caddy's environment (mode 0600, root). Neither is served over HTTP.
- Logs and HTTP responses never contain the token (verified by
  `backend/tests/test_auth_hardening.py`).

---

## DNS records

| Record | Name | Type | Value | Purpose |
|--------|------|------|-------|---------|
| Dashboard + API | `greywatch.example.com` (replace) | A / AAAA | VPS public IP | Public HTTPS endpoint |
| (optional) API-only | `api.greywatch.example.com` | CNAME | `greywatch.example.com` | Dedicated API hostname |

Action: create the A/AAAA record for `{REPLACE_ME_WITH_DOMAIN}` pointing at the
VPS before enabling `auto_https`/Let's Encrypt. Do not change DNS without
authorization.

---

## Firewall ports

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 443  | TCP      | 0.0.0.0/0, ::/0 | Public HTTPS (Caddy) |
| 80   | TCP      | 0.0.0.0/0, ::/0 | HTTP → HTTPS redirect (Caddy) |
| 22   | TCP      | admin subnet only | SSH (administration) |
| 8000 | TCP      | 127.0.0.1 only | uvicorn (loopback; **not** public) |
| 2019 | TCP      | 127.0.0.1 only | Caddy admin API (loopback; **not** public) |

Do not open 8000 or 2019 to the public internet. uvicorn binds to
`127.0.0.1:8000` only (see `scripts/greywatch-api.service` and the Caddyfile
`reverse_proxy 127.0.0.1:8000`).

---

## Service user and file permissions

Create a dedicated unprivileged user:

```bash
sudo useradd --system --create-home --shell /usr/bin/nologin greywatch
```

| Path | Owner | Mode | Purpose |
|------|-------|------|---------|
| `/opt/greywatch` | `greywatch:greywatch` | `0750` | Repository checkout |
| `/var/lib/greywatch/greywatch.db` | `greywatch:greywatch` | `0600` | SQLite database (WAL) |
| `/etc/greywatch/greywatch.env` | `root:root` | `0600` | Backend env incl. `GREYWATCH_API_TOKEN` |
| `/etc/caddy/Caddyfile` | `root:root` | `0644` | Caddy config (references token via env) |
| `/etc/caddy/certs/*.{crt,key}` | `root:root` | cert `0644`, key `0600` | TLS certificates |
| `/var/www/greywatch/dist` | `root:root` / `www-data:www-data` | `0755` dirs / `0644` files | Built frontend |

The `greywatch` user needs read access to `/etc/greywatch/greywatch.env` (via
systemd `EnvironmentFile`, read by root before dropping privileges) and write
access to `/var/lib/greywatch/`.

Caddy needs read access to `GREYWATCH_API_TOKEN` from its own environment
(systemd `EnvironmentFile` or caddy service env), mode 0600.

---

## Environment variables

Defined in `/etc/greywatch/greywatch.env` (mode 0600, generated by
`scripts/generate_staging_token.sh`) and consumed by systemd via
`EnvironmentFile=/etc/greywatch/greywatch.env`.

| Variable | Staging value | Meaning |
|----------|---------------|---------|
| `GREYWATCH_DB` | `/var/lib/greywatch/greywatch.db` | Isolated SQLite path |
| `GREYWATCH_API_TOKEN` | generated (0600 file) | Required for remote/token mode. **Also set in Caddy's environment.** |
| `GREYWATCH_API_LOOPBACK_ONLY` | `1` | Remote peers require token |
| `GREYWATCH_RATE_LIMIT_ENABLED` | `1` | Global limiter on (all non-public routes) |
| `GREYWATCH_RATE_LIMIT_INGESTION` | `60` | req/min for `/api/v1/events/ingest` |
| `GREYWATCH_RATE_LIMIT_READS` | `120` | req/min for reads and other uncategorized routes |
| `GREYWATCH_RATE_LIMIT_COLLECTOR` | `30` | req/min for journal/Suricata collect endpoints |
| `GREYWATCH_RATE_LIMIT_ALERT_CLOSE` | `30` | req/min for alert close and incident acknowledge/resolve |
| `GREYWATCH_RATE_LIMIT_BURST_MULTIPLIER` | `2` | burst = limit × multiplier |
| `GREYWATCH_AGENT_RATE_LIMIT_ENABLED` | `1` | Per-agent limiter on (agent API-key ingestion only) |
| `GREYWATCH_AGENT_RATE_INGESTION` | `60` | req/min per agent for ingestion |
| `GREYWATCH_AGENT_RATE_READS` | `120` | Configured only; not currently enforced |
| `GREYWATCH_AGENT_RATE_COLLECTOR` | `10` | Configured only; not currently enforced |
| `GREYWATCH_AGENT_RATE_ALERT_CLOSE` | `30` | Configured only; not currently enforced |
| `GREYWATCH_AGENT_RATE_BURST` | `1.5` | Per-agent burst = `int(limit × multiplier)` |
| `GREYWATCH_PREAUTH_RATE_LIMIT_ENABLED` | `1` | Pre-auth agent-key limiter on (outermost, before auth/audit) |
| `GREYWATCH_PREAUTH_RATE_LIMIT` | `120` | Agent-key attempts/min per client identity |
| `GREYWATCH_PREAUTH_RATE_BURST_MULTIPLIER` | `2` | Pre-auth burst = `limit × multiplier` |
| `GREYWATCH_PREAUTH_RATE_MAX_ENTRIES` | `10000` | Maximum distinct identities retained (LRU eviction) |
| `GREYWATCH_TRUSTED_PROXIES` | `127.0.0.1/32,::1/128` | Peers whose forwarding headers may identify the client |
| `GREYWATCH_MAX_REQUEST_BYTES` | `1048576` | 1 MiB body limit |
| `GREYWATCH_JOURNAL_ENABLED` | `0` | Optional collector, off by default |
| `GREYWATCH_SURICATA_ENABLED` | `0` | Optional collector, off by default |
| `GREYWATCH_CORRELATION_WINDOW_MINUTES` | `30` | SSH brute-force→success window |
| `GREYWATCH_EVENT_RETENTION_DAYS` | *(unset = disabled)* | Positive integer: events older than N days are eligible for pruning. `0`, negative, or non-numeric values disable retention. |
| `GREYWATCH_RETENTION_BATCH_SIZE` | `1000` | Events deleted per transaction during retention execution. |
| `GREYWATCH_BACKUP_DIR` | `/var/backups/greywatch` | Directory for verified migration backups. **Required in production** (when `GREYWATCH_REQUIRE_BACKUP` is not explicitly disabled). |
| `GREYWATCH_REQUIRE_BACKUP` | *(unset = required)* | Backup preflight policy. **Unset means required** (fail-safe production default). Set to `0`, `false`, `no`, or `off` for an intentional development opt-out. Any other value is a configuration error. |
| `GREYWATCH_MAX_BACKUP_AGE_HOURS` | `24` | Maximum age of the newest backup before migration is refused. Must be a positive integer. |

`GREYWATCH_API_TOKEN` is mandatory for remote access. It must be identical in
the backend env file and Caddy's environment, and it must not begin with `gw_`
(reserved for agent API keys). `GREYWATCH_API_LOOPBACK_ONLY` is left at the
default `1`; the proxy architecture requires **token mode** (set via the
token), not a change to the loopback setting.

Per-agent rate limiting currently applies only to agent API-key requests to
`POST /api/v1/events/ingest`; the `READS`, `COLLECTOR`, and `ALERT_CLOSE`
per-agent values are configured but not enforced. See
[`docs/RATE_LIMITING.md`](RATE_LIMITING.md) for global vs per-agent scope,
bucket behavior, and multi-worker caveats.

The pre-auth limiter runs before agent authentication and audit writes, so it
also covers invalid, revoked, expired, and unknown `gw_*` keys. Caddy sets
`X-Greywatch-Client-IP {http.request.remote.host}` and overwrites
`X-Forwarded-For` with the same host on every proxy route. The backend trusts
those headers only from `GREYWATCH_TRUSTED_PROXIES` (loopback by default). If
Caddy runs on a non-loopback address, add its exact address/CIDR; never trust a
range containing untrusted clients.

---

## Files created in this milestone

| File | Purpose |
|------|---------|
| `Caddyfile` | Staging HTTPS reverse proxy → `127.0.0.1:8000`. Injects the shared token in `X-Greywatch-Token` for dashboard/API routes; dedicated agent-ingest routes bypass dashboard basicauth without injecting the token. Basicauth on dashboard shell. |
| `backend/.env.example` | Backend env template (placeholders only) |
| `scripts/generate_staging_token.sh` | Generates token for backend env (0600, root). No browser-visible JS. |
| `scripts/greywatch-api.service` | Example systemd unit (loopback uvicorn) |
| `docs/DEPLOYMENT.md` | This document |

`backend/.env` and `/etc/greywatch/greywatch.env` (with real secrets) are
**not** committed; `.env` is gitignored.

---

## Build and deploy the frontend

The dashboard is a static Vite build served by Caddy from `/var/www/greywatch/dist`.

On the staging host:

```bash
# On the build host (or in CI):
cd frontend
npm ci
npm run build          # produces frontend/dist/

# Copy the built assets to the VPS:
scp -r frontend/dist/* greywatch@<vps>:/var/www/greywatch/dist/
sudo chown -R root:root /var/www/greywatch/dist
sudo chmod 0755 /var/www/greywatch/dist
sudo find /var/www/greywatch/dist -type f -exec chmod 0644 {} +
```

No script tag needs to be added to `index.html`. The browser sends no
API credential; Caddy injects the shared token in `X-Greywatch-Token`
server-side when proxying `/api/*` to the backend.

---

## Database backup, restore, and disaster recovery

The SQLite database is the system of record. Back it up before upgrades,
configuration changes, or any manual intervention.

### Local development vs production

- **Local development** uses `data/greywatch.db` (gitignored) and needs no
  backup automation. The tool is safe to run against it by pointing
  `GREYWATCH_DB` at the local file; it never touches production paths unless
  those paths are explicitly configured.
- **Production/staging** uses `/var/lib/greywatch/greywatch.db` (set via
  `GREYWATCH_DB`). The paths in this section are production defaults; every
  command honors the `GREYWATCH_*` variables from
  `/etc/greywatch/greywatch.env`.

The tool is `scripts/gw_db_backup.sh`, a thin wrapper over
`scripts/gw_db_backup.py`, which uses SQLite's **online backup API**
(`sqlite3.Connection.backup`). A live database file is never copied directly.

### Backup configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `GREYWATCH_DB` | `/var/lib/greywatch/greywatch.db` | Database to back up |
| `GREYWATCH_BACKUP_DIR` | `/var/backups/greywatch` | Backup destination (set to `0700`) |
| `GREYWATCH_BACKUP_RETENTION_DAYS` | `30` | Backups older than this are pruned |
| `GREYWATCH_DB_OWNER` | (unset) | `user[:group]` to chown a restored database |
| `GREYWATCH_PYTHON` | `python3` | Interpreter providing the stdlib `sqlite3` module |

Backups are written `0600` into `GREYWATCH_BACKUP_DIR`. The backup run also
prunes files older than the retention window; only files named `greywatch.db.*`
are considered, so unrelated files are never deleted.

### Backup execution

```bash
sudo ./scripts/gw_db_backup.sh backup
```

Each backup is verified with `PRAGMA integrity_check` and
`PRAGMA foreign_key_check` before success is reported. An incomplete backup is
removed and the command exits non-zero. Verify an existing backup any time:

```bash
sudo ./scripts/gw_db_backup.sh verify /var/backups/greywatch/greywatch.db.<timestamp>
```

Schedule backups with a systemd timer or cron (run as the `greywatch` user
where possible, otherwise as root — see WAL notes):

```cron
0 * * * * root GREYWATCH_DB=/var/lib/greywatch/greywatch.db GREYWATCH_BACKUP_DIR=/var/backups/greywatch /opt/greywatch/scripts/gw_db_backup.sh backup >>/var/log/greywatch-backup.log 2>&1
```

### Migration backup preflight (v0.2+)

Greywatch v0.2 enforces a verified backup before **any** schema migration —
whether triggered by application startup or the manual `gw_migrate migrate`
CLI. This is the production-safe default: the database is never modified unless
a valid backup exists.

**Policy variables:**

| Variable | Production default | Behavior |
|----------|-------------------|----------|
| `GREYWATCH_REQUIRE_BACKUP` | **unset (required)** | Unset = require a verified backup. Explicit `0/false/no/off` = development opt-out. Any other value = configuration error. |
| `GREYWATCH_BACKUP_DIR` | `/var/backups/greywatch` | Directory containing `greywatch.db.*` backups. Required when backup is required. |
| `GREYWATCH_MAX_BACKUP_AGE_HOURS` | `24` | Newest backup must be this fresh or newer. Positive integer only. |

**Preflight steps (run before any write):**
1. Resolve policy from environment.
2. If development opt-out (`GREYWATCH_REQUIRE_BACKUP=0`), skip preflight.
3. Validate `GREYWATCH_BACKUP_DIR` exists and is a directory.
4. Select the newest `greywatch.db.*` backup by mtime.
5. Reject if that backup is the live database (same file, hardlink, or symlink).
6. Reject if backup age exceeds `GREYWATCH_MAX_BACKUP_AGE_HOURS`.
7. Verify backup with `PRAGMA integrity_check` + `foreign_key_check`.
8. On any failure: abort before opening a write connection; database is untouched.

**To create a backup immediately before migration:**

```bash
# Run as the service user (greywatch) or root
sudo -u greywatch GREYWATCH_DB=/var/lib/greywatch/greywatch.db \
  GREYWATCH_BACKUP_DIR=/var/backups/greywatch \
  /opt/greywatch/scripts/gw_db_backup.sh backup
```

**To verify a backup before relying on it:**

```bash
sudo -u greywatch /opt/greywatch/scripts/gw_db_backup.sh verify \
  /var/backups/greywatch/greywatch.db.20260101T120000Z
```

**Development mode (intentional opt-out):**

```bash
# Only for throwaway databases. Never use in production.
GREYWATCH_REQUIRE_BACKUP=0 GREYWATCH_DB=/tmp/test.db \
  python3 -m backend.app.main
```

### Audit-chain verification

The audit log is hash-chained in insertion order (`id ASC`). Verify it
read-only at any time after deploying v0.2:

```bash
sudo -u greywatch python3 ./scripts/gw_migrate audit-verify \
    /var/lib/greywatch/greywatch.db
```

- Exit code `0`: `OK: audit chain at ... is valid (N records)`.
- Exit code `1`: the chain is invalid or could not be read; the command lists
  the failing record ids and expected/stored hashes on stderr.
- Verification never repairs, rewrites, or migrates the database. WAL
  databases are copied to a private temporary directory before being opened,
  so no `-wal`/`-shm` sidecars are created beside the live file.
- Migration v4 (`audit_chain_order`) rebuilds any chain left in the old
  timestamp order. It refuses to rebuild when existing record content does not
  match either known historical hash shape, so unrelated tampering is reported
  instead of being silently concealed.

### Schema verification by migration version

The migration ledger alone is never treated as proof that the schema exists.
On startup, `gw_migrate status`/`verify`, and after every migration, Greywatch
compares the live schema against the cumulative schema required by the
validated ledger version:

| Ledger version | Required objects |
|----------------|------------------|
| v1 `baseline` | `events`, `alerts`, `incidents`, `incident_events`, `collector_state` with all baseline columns and indexes. |
| v2 `agents_and_api_keys` | v1 plus `agents`, `api_keys`, `audit_log`; nullable `events.agent_id` (`REFERENCES agents(id) ON DELETE SET NULL`); indexes `idx_events_agent_id`, `idx_agents_status`, `idx_agents_last_seen`, `idx_api_keys_agent_id`, `idx_api_keys_key_prefix`, `idx_api_keys_status`, `idx_audit_log_timestamp`, `idx_audit_log_agent_id`, `idx_audit_log_event_type`. |
| v3 `audit_log_integrity` | v2 plus `audit_log.prev_hash`, `audit_log.chain_hash`, `idx_audit_log_chain`. |
| v4 `audit_chain_order` | Same schema as v3 (data-only rebuild). |

A missing table, critical column, required index, or foreign key makes the
database `inconsistent`, even when every ledger row says the migration was
applied. The report names the exact object, for example:

```text
State: inconsistent
Detail: ledger claims applied version 4 but the schema does not match the expected v4 schema: missing table(s): agents; events missing column(s): agent_id; events missing index(es): idx_events_agent_id
```

Startup fails closed on that state rather than serving from a damaged schema.
Verification is read-only and never recreates or repairs objects. Inspect the
file without writes:

```bash
sudo -u greywatch ./scripts/gw_migrate status /var/lib/greywatch/greywatch.db
sudo -u greywatch sqlite3 'file:/var/lib/greywatch/greywatch.db?mode=ro' \
    "PRAGMA table_info(events); PRAGMA index_list(agents);"
```

Do not run manual `ALTER`/`DROP`/`CREATE`, edit `schema_migrations`, or delete
ledger rows. Restore a verified backup instead, as described below. See
[docs/MIGRATION_RUNNER.md](MIGRATION_RUNNER.md#schema-requirements-by-migration-version)
for the full per-version contract and migration recovery procedures.

### WAL considerations

Greywatch runs SQLite in WAL mode. The online backup API reads a consistent
snapshot, so backups are safe while the service is running. The tool converts
each backup to a self-contained file and tracks `-wal`/`-shm` sidecars: if a
read-only source open creates sidecars that did not exist before, they are
removed afterwards, so a root-run backup never leaves root-owned sidecars next
to a service-owned database.

### Restore prerequisites and downtime

**Restore requires downtime.** It replaces the database file and is **not
atomic across the database and its `-wal`/`-shm` sidecars**. The tool never
stops or starts `greywatch-api`; the operator must:

1. Stop the service: `sudo systemctl stop greywatch-api`.
2. Ensure no other process holds the database open.
3. Keep the service stopped until restore and verification complete.

### Safe restore

```bash
sudo systemctl stop greywatch-api
sudo ./scripts/gw_db_backup.sh restore \
    /var/backups/greywatch/greywatch.db.<timestamp> --yes
sudo -u greywatch sqlite3 /var/lib/greywatch/greywatch.db \
    "PRAGMA integrity_check; PRAGMA foreign_key_check;"
sudo -u greywatch ./scripts/gw_migrate status /var/lib/greywatch/greywatch.db
sudo systemctl start greywatch-api
```

The `status` check is read-only. A pre-migration backup normally reports
`fresh`, `ledger_only`, or `pending`; the service migrates it forward on
startup. A report of `current` is also fine. If `status` reports `inconsistent`,
do not start the service: verify and restore an earlier backup instead. The
version-aware check validates the restored file against its own ledger version,
so a valid older backup is not rejected merely for lacking later tables.

`restore` requires `--yes` and:

- verifies the backup **before** touching the destination;
- makes a recoverable online copy of the current database
  (`<db>.pre-restore.<timestamp>` in the database directory);
- stages and verifies the replacement in the destination directory, then
  renames it into place atomically (`os.replace`);
- moves any stale `-wal`/`-shm` aside to
  `<db>.wal.pre-restore.<timestamp>` / `<db>.shm.pre-restore.<timestamp>`;
- sets the restored file to `0600` and chowns it only when the configured
  owner resolves (an unknown user is reported and existing ownership is
  preserved).

If any step fails, the original database and sidecars are restored where
possible and the command exits non-zero.

### If restoration fails

1. Read the error. The original database should still be in place (the tool
   rolls back when it can and never overwrites the destination before the
   backup is verified).
2. Look for the pre-restore copy:
   `/var/lib/greywatch/greywatch.db.pre-restore.<timestamp>`.
3. Verify whichever database you intend to keep, then set ownership/mode:
   `sudo chown greywatch:greywatch <db> && sudo chmod 0600 <db>`.
4. Start the service and check `/health` and a known alert/incident.

### Database ownership and permissions

| Path | Owner | Mode |
|------|-------|------|
| `/var/lib/greywatch/greywatch.db` | `greywatch:greywatch` | `0600` |
| `/var/lib/greywatch/greywatch.db.pre-restore.*` | `greywatch:greywatch` | `0600` |
| `/var/backups/greywatch` | `root:root` (or `greywatch`) | `0700` |
| `/var/backups/greywatch/greywatch.db.*` | backup user | `0600` |

---

## Event retention and database maintenance

### What is pruned

Greywatch's SQLite database grows indefinitely as events are collected.
The retention tool (`backend/app/retention.py`) safely removes events older
than `GREYWATCH_EVENT_RETENTION_DAYS` days, subject to strict preservation
rules (see [README](../README.md#database-lifecycle-management) for full
details).

**Preserved events (never deleted):**

1. Events referenced by any incident via `incident_events` (open,
   acknowledged, or resolved).
2. Events matching the evidence query of any open alert:
   - `SSH_BRUTE_FORCE`: `ssh_login_failed` events from the alert's `source_ip`
     within `[last_triggered_at - 5 min, last_triggered_at]`.
   - `SURICATA_ALERT`: `suricata_alert` events matching the alert's
     signature/network 5-tuple within `[created_at, last_triggered_at]`.
   - Unknown rule: all events within the alert's lifetime window
     `[created_at, last_triggered_at]`.

**Never deleted:** alert rows, incident rows, incident_events rows,
collector_state rows. Only the `events` table is pruned.

### Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `GREYWATCH_EVENT_RETENTION_DAYS` | *(unset = disabled)* | Positive integer. Events older than N days are eligible. `0`, negative, or non-numeric values disable retention. |
| `GREYWATCH_RETENTION_BATCH_SIZE` | `1000` | Events deleted per transaction. Smaller = less lock contention. |

### Running retention

1. **Preview** (always do this first):
   ```bash
   sudo ./scripts/gw_retention.sh dry-run
   # or: python -m backend.app.retention --dry-run
   ```

2. **Execute** (requires `GREYWATCH_EVENT_RETENTION_DAYS` to be set):
   ```bash
   sudo ./scripts/gw_retention.sh execute
   # or: python -m backend.app.retention --execute
   ```
   Can run while the service is up (WAL mode allows concurrent readers;
   ingestion may briefly wait for the write lock, bounded by `--batch-size`).

3. **Compact** (optional, requires downtime):
   ```bash
   sudo ./scripts/gw_retention.sh vacuum
   ```
   See [SQLite VACUUM](#sqlite-vacuum-during-downtime) below.

### Foreign-key safety

Retention enables `PRAGMA foreign_keys = ON` on its working connection.  If
a bug in the protection logic ever attempted to delete an event still
referenced by `incident_events`, the operation would fail with a
constraint error and roll back — the database is never left with orphaned
rows.  After deletion, `PRAGMA foreign_key_check` is run and reported in
the summary.

### SQLite VACUUM (during downtime)

Deleting rows makes SQLite pages reusable for new inserts, but the **file
size does not shrink**.  `VACUUM` rewrites the database to reclaim free
pages, but it requires an **exclusive lock** — no other process can hold
the file.

**Procedure (requires stopping the service):**

```bash
sudo systemctl stop greywatch-api
sudo ./scripts/gw_db_backup.sh backup        # back up before maintenance
sudo ./scripts/gw_retention.sh vacuum
sudo systemctl start greywatch-api
verify
```

**Why not automatic?** `VACUUM` blocks all readers and writers.  Running it
during ingestion or collection would corrupt in-flight transactions.  It is
never invoked at startup or on the API hot path.

**Limitations:**
- Greywatch uses `auto_vacuum = NONE` (the SQLite default), so only full
  `VACUUM` works — `PRAGMA incremental_vacuum` is not available.
- After `VACUUM`, the WAL file is reset; the next checkpoint starts fresh.

### Scheduling maintenance

A typical retention cadence for a production deployment:

```cron
# Daily retention preview (dry-run; review before execute)
0 2 * * * root GREYWATCH_DB=/var/lib/greywatch/greywatch.db /opt/greywatch/scripts/gw_retention.sh dry-run >>/var/log/greywatch-retention.log 2>&1

# Weekly execution (Sunday 3 AM)
0 3 * * 0 root GREYWATCH_DB=/var/lib/greywatch/greywatch.db GREYWATCH_EVENT_RETENTION_DAYS=90 /opt/greywatch/scripts/gw_retention.sh execute >>/var/log/greywatch-retention.log 2>&1

# Monthly VACUUM (first Sunday, 4 AM — requires the service to be stopped)
0 4 1-7 * * 0 [ $(date +\%u) -eq 7 ] && root systemctl stop greywatch-api && /opt/greywatch/scripts/gw_retention.sh vacuum && systemctl start greywatch-api
```

Always run a **dry-run** before the first **execute** to confirm the
eligible/protected counts match expectations.

---

## Rollback steps

Use this when a change (code or config) must be undone.

1. Stop services:
   ```bash
   sudo systemctl stop greywatch-api caddy
   ```
2. Restore the SQLite database from the most recent verified backup using the
   backup tool (do **not** copy over a database that SQLite may still be
   using):
   ```bash
   sudo ./scripts/gw_db_backup.sh restore \
       /var/backups/greywatch/greywatch.db.<timestamp> --yes
   ```
   The tool verifies the backup, keeps a pre-restore copy, and reports the
   recovery path.
3. Verify integrity:
   ```bash
   sudo -u greywatch sqlite3 /var/lib/greywatch/greywatch.db \
       "PRAGMA integrity_check; PRAGMA foreign_key_check;"
   ```
   Expect `ok` and no rows from `foreign_key_check`.
4. Restart services:
   ```bash
   sudo systemctl start caddy greywatch-api
   ```
5. Verify `/health` returns 200 and a known alert/incident is readable over HTTPS.

If a config change caused the issue, revert the corresponding env var or
Caddyfile placeholder and restart.

---

## Staging verification checklist

Run each item on the staging host (or from an external client against the public
URL) and record pass/fail.

### A. HTTPS and certificate
- [ ] `curl -I https://{REPLACE_ME_WITH_DOMAIN}/` returns `200` or `308` (TLS terminates).
- [ ] Certificate is valid for `{REPLACE_ME_WITH_DOMAIN}` (no browser warnings with the intended cert).
- [ ] `curl -I http://{REPLACE_ME_WITH_DOMAIN}/` returns `308` to HTTPS.

### B. Invalid credentials (dashboard + API)
- [ ] Dashboard (`https://.../`) without basicauth credentials returns `401`.
- [ ] `curl https://.../api/v1/alerts` without dashboard basicauth credentials returns `401` from Caddy.
- [ ] Direct-to-backend (on the staging host) `curl http://127.0.0.1:8000/api/v1/alerts` without a token returns `401`; do not expose port 8000 publicly.
- [ ] Direct-to-backend `curl http://127.0.0.1:8000/api/v1/alerts -H "Authorization: Bearer wrong"` returns `401`, and the response body does **not** contain the token.
- [ ] With valid dashboard basicauth, `curl https://.../api/v1/alerts -u "$DASHBOARD_USER"` returns `200` (Caddy injects `X-Greywatch-Token`).

### C. Protected API routes (dashboard: basicauth + injected token)
- [ ] `GET /api/v1/events` — returns data when accessed via Caddy with dashboard basicauth.
- [ ] `GET /api/v1/alerts/{id}` — returns data via Caddy.
- [ ] `GET /api/v1/incidents` — returns data via Caddy.
- [ ] `GET /api/v1/journal/status` — returns data via Caddy.
- [ ] `GET /api/v1/suricata/status` — returns data via Caddy.
- [ ] `POST /api/v1/events/ingest` — returns 200 via Caddy with valid lines.
- [ ] `POST /api/v1/alerts/{id}/close` — returns 200 via Caddy.

### D. Agent API keys (dedicated Caddy ingest route)
- [ ] `POST /api/v1/events/ingest` with `X-API-Key: gw_...` returns `200` **without** dashboard basicauth.
- [ ] The same request also carrying `Authorization: Bearer $GREYWATCH_API_TOKEN` still returns `200` and is attributed to the agent, not the shared token.
- [ ] An invalid, revoked, or expired agent key plus a valid shared token returns `401` (never silently downgraded).
- [ ] A valid agent key on `GET /api/v1/admin/agents` returns `401` from Caddy without dashboard basicauth, or `403` if dashboard basicauth is also supplied; it never returns `200`.
- [ ] Agent-key traffic is limited per agent and returns `429` with `Retry-After` when `GREYWATCH_AGENT_RATE_INGESTION` is exceeded.

### E. Rate limits
- [ ] Exceeding `GREYWATCH_RATE_LIMIT_INGESTION` returns `429` with a `Retry-After` header.
- [ ] Exceeding `GREYWATCH_PREAUTH_RATE_LIMIT` with repeated invalid agent keys
  returns `429` with a numeric `Retry-After` and
  `{"detail":"Agent authentication rate limit exceeded"}`, and adds no new
  `auth_failure` rows to `audit_log`.
- [ ] Exceeding `GREYWATCH_AGENT_RATE_INGESTION` with an agent API key returns
  `429` with a `Retry-After` header and `{"detail":"Agent rate limit exceeded"}`.
- [ ] `GET /` and `GET /health` remain reachable (public, not rate-limited).
- [ ] A 401 (auth failure) does not consume a global or per-agent rate-limit
  token (verified by `test_rate_limit.py::test_auth_failure_does_not_consume_rate_token`
  and `test_agent_rate_limit.py::test_failed_agent_auth_does_not_consume_agent_quota`).
- [ ] A direct client rotating `X-Forwarded-For` or `X-Greywatch-Client-IP`
  cannot reset its pre-auth bucket; a valid agent still authenticates behind
  Caddy.

### Rate limit limitation: process-local buckets (multi-instance deployments)

**Important:** The pre-auth, global, and per-agent limiters use in-process
token buckets. This means:

- Each uvicorn worker process maintains its **own independent** rate-limit state.
- Running multiple workers (e.g., `uvicorn --workers 4`) or multiple replicas
  **multiplies the effective rate limits** by the number of processes.
- There is **no distributed coordination** (no Redis, no shared state) in the
  current implementation.
- Restarting a process clears its buckets. The global and pre-auth bucket
  stores are bounded (10,000 entries by default) with LRU eviction.

**Supported deployment configuration today:**
- Single uvicorn worker behind a reverse proxy (Caddy). The provided service
  unit does not pass `--workers`.
- This is the only configuration that provides the documented global and
  per-agent limits.

**If you need multi-worker or multi-replica deployments:**
- Do not rely on the built-in limiters as cluster-wide controls.
- Options: run a single worker (accept throughput limits), enforce coarse limits
  at the proxy/edge, or implement a shared rate-limit backend as a separate
  infrastructure change (not in scope for this release).

**Disabling built-in limiting:** The three limiters are independent.

- `GREYWATCH_PREAUTH_RATE_LIMIT_ENABLED=0` disables **pre-auth** limiting only.
- `GREYWATCH_AGENT_RATE_LIMIT_ENABLED=0` disables **per-agent** limiting only.
- `GREYWATCH_RATE_LIMIT_ENABLED=0` disables **global** limiting only.
- Set all three to disable all built-in limiting, then enforce limits at the
  proxy layer.

See [`docs/RATE_LIMITING.md`](RATE_LIMITING.md) for the complete configuration
and bucket behavior.

### F. Request-body limits
- [ ] POST `/api/v1/events/ingest` with a body > `GREYWATCH_MAX_REQUEST_BYTES` returns `413`.
- [ ] Body within the limit is accepted.

### G. Health checks
- [ ] `curl https://.../health` returns `{"status":"ok",...}` with `200`.
- [ ] Caddy admin API reachable on `127.0.0.1:2019` only (not public).

### H. Service restarts
- [ ] `sudo systemctl restart greywatch-api caddy` comes back healthy.
- [ ] After restart, the backend re-reads `GREYWATCH_API_TOKEN` from the env file
  and token auth still works.
- [ ] After restart, Caddy re-reads `GREYWATCH_API_TOKEN` from its env and
  `X-Greywatch-Token` injection still works.
- [ ] After restart, the SQLite database is intact (`PRAGMA integrity_check` = `ok`).

### I. Loopback binding (uvicorn not public)
- [ ] `ss -ltnp | grep 8000` shows uvicorn listening on `127.0.0.1:8000` only.
- [ ] A direct `curl http://<vps-public-ip>:8000/` from another host fails
  (connection refused / timed out).

### J. Browser does not see API token
- [ ] Browser DevTools → Network tab shows no `Authorization` or `X-Greywatch-Token` header on API requests from the dashboard.
- [ ] `/__greywatch-token.js` does not exist (returns 404).
- [ ] `window.__GREYWATCH_API_TOKEN__` is `undefined` in browser console.

---

## Unresolved blockers and manual steps

These are accepted beta risks / items that require operator action before a real
VPS deployment:

1. **No cloud/DNS changes made.** DNS for `{REPLACE_ME_WITH_DOMAIN}` must be
   created and TLS certs obtained before this config works on a live host.
2. **No real token generated.** `scripts/generate_staging_token.sh` must be run
   as root on the target host to produce `/etc/greywatch/greywatch.env`. The
   same token must be set in Caddy's environment.
3. **Caddy basicauth hash.** The operator must run `caddy hash-password` and
   insert the hash into the Caddyfile `basicauth` block.
4. **Shared staging token.** `GREYWATCH_API_TOKEN` is one secret shared by all
   dashboard/API callers in this deployment. Agent API keys are available for
   ingestion-only integrations and can be revoked or rotated, but they do not
   replace the shared dashboard token. Compromise of the shared token
   compromises all API access. Accepted beta risk.
5. **Event retention is now implemented** (see [Event retention and database
   maintenance](#event-retention-and-database-maintenance)). Events older than
   `GREYWATCH_EVENT_RETENTION_DAYS` are pruned only when that variable is set to
   a positive integer; unset (the default) is non-destructive. Incident-linked
   events and open-alert evidence are always preserved, and `VACUUM` remains a
   separate manual operation requiring service downtime. Set a cron schedule
   (see [Scheduling maintenance](#scheduling-maintenance)) before long-term
   operation.
6. **Frontend build artifacts.** `frontend/dist/` must be built and copied to
   `/var/www/greywatch/dist/` on each release.
7. **Caddy env injection.** `GREYWATCH_API_TOKEN` must be available in Caddy's
   process environment (systemd `EnvironmentFile` or equivalent) for
   `header_up X-Greywatch-Token {env.GREYWATCH_API_TOKEN}` to work. The
   dedicated agent-ingest routes intentionally do not reference this variable.

---

## Related security documentation

- `README.md` §API Security (local mode, token auth, body limits, rate limits,
  dashboard deployment).
- [`docs/RATE_LIMITING.md`](RATE_LIMITING.md) (canonical global and per-agent
  rate-limit configuration, scope, and deployment guidance).
- `docs/DB_SAFETY_INCIDENT.md` (database migration safety; production DB never
  touched by tests).
- `docs/JOURNAL_COLLECTOR.md`, `docs/SURICATA.md` (optional collectors).
