# Greywatch Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Added

- **Per-agent API keys** (`gw_...`): Secure authentication for ingestion-only integrations.
  - Create, list, and retrieve agents with lifecycle management (active, inactive, revoked).
  - Generate API keys with optional expiration (`expires_at`), rotation, and revocation.
  - Agent keys are authenticated exclusively: a `gw_...` credential is never downgraded to the shared token, even if a valid token is also present. Invalid, revoked, or expired agent keys return 401.
  - Agent keys are restricted to `POST /api/v1/events/ingest`; use on any other endpoint returns 403.
  - Per-agent rate limiting for ingestion (configurable via `GREYWATCH_AGENT_RATE_*`).
  - Audit logging for all agent/key lifecycle events (`agent_created`, `agent_updated`, `agent_deactivated`, `key_generated`, `key_revoked`, `key_rotated`, `auth_failure`, `key_rehashed`).

- **Tamper-evident audit chain** with insertion-order verification:
  - Migration v3 (`audit_log_integrity`) added `prev_hash` and `chain_hash` columns to `audit_log` and backfilled existing rows in timestamp order.
  - Migration v4 (`audit_chain_order`) rebuilds the chain in canonical insertion order (`id ASC`), which is immune to system-clock rollback. The rebuild validates against the known v3 history (timestamp-ordered backfill + legacy appends) and refuses to run if the existing chain content or linkage does not match either known shape — detecting tampering instead of silently repairing it.
  - Read-only chain verification via `gw_migrate audit-verify <db>` (exit 0 = valid, exit 1 = invalid).
  - Chain verification is used by the migration runner after every migration and by the admin API.

- **Mandatory-by-default migration backup preflight** (M4):
  - Both application startup and the manual `gw_migrate migrate` CLI enforce a verified backup before any schema migration.
  - Policy controlled by `GREYWATCH_REQUIRE_BACKUP`:
    - **Unset (default) = REQUIRED** — fail-safe production default.
    - Explicit `0`, `false`, `no`, `off` = intentional development opt-out.
    - Any other value = configuration error.
  - `GREYWATCH_BACKUP_DIR` must point to a dedicated backup directory (mode 0700) containing `greywatch.db.*` backups created by `scripts/gw_db_backup.sh backup`.
  - `GREYWATCH_MAX_BACKUP_AGE_HOURS` (default 24) limits the age of the newest backup.
  - Preflight selects the newest backup by mtime, rejects it if it is the live database (same file, hardlink, or symlink), checks age, and verifies it with `PRAGMA integrity_check` + `PRAGMA foreign_key_check`.
  - A failed preflight aborts **before** opening a write connection; the database is left byte-for-byte unchanged.

- **Pre-authentication agent-key rate limiting** (M1):
  - New outermost middleware (`PreAuthAgentRateLimitMiddleware`) limits `gw_*` attempts before authentication and audit writes.
  - Counts every agent-key attempt (valid or not) per client identity.
  - Client identity is the immediate ASGI peer unless that peer is in `GREYWATCH_TRUSTED_PROXIES` (default: loopback); then `X-Greywatch-Client-IP` (preferred) or the right-most `X-Forwarded-For` hop is used.
  - Untrusted peers cannot spoof forwarding headers.
  - Bounded LRU bucket store (`GREYWATCH_PREAUTH_RATE_MAX_ENTRIES=10000`).
  - Returns HTTP 429 with numeric `Retry-After` and `{"detail":"Agent authentication rate limit exceeded"}`.

- **Global rate limiting** (unchanged scope, documented):
  - Token-bucket per client identity for all non-public routes.
  - Categories: ingestion, reads, collector, alert_close.
  - In token mode, all callers share one bucket keyed by the token value.

- **Per-agent rate limiting** (post-authentication):
  - Bucket keyed by `(agent_id, category)`; currently only ingestion is enforced.
  - Configurable via `GREYWATCH_AGENT_RATE_*`.

- **PBKDF2 verification moved off the async event loop** (M2):
  - Agent-key authentication (PBKDF2-HMAC-SHA256, 600k iterations default) runs in Starlette's threadpool via `run_in_threadpool`.
  - Prevents blocking the event loop during authentication; health checks and other requests remain responsive.

- **Startup migration integration**:
  - FastAPI lifespan handler now calls the migration runner (`migrations.runner.migrate`) after inspecting database state.
  - Atomic database file creation with no-replace publication (os.link) for safe concurrent startup.
  - Backup preflight runs as part of the runner (shared code path with CLI).
  - Legacy `initialize_database()` is guarded by a process-wide flag after lifespan completes; it cannot bypass the runner in production.

### Changed

- **Audit chain canonical order is now insertion order (`id ASC`)**.
  - Migration v4 rebuilds any pre-v4 chain in this order.
  - The `verify_chain()` function and the migration runner verify in this order.
  - Timestamp order is no longer used for chain linkage (it remains a display order for audit-log pagination).

- **Agent API key expiration parsing is now strict**:
  - ISO-8601 timestamps with `Z` or explicit offsets are parsed to UTC.
  - Naive timestamps are interpreted as UTC.
  - Malformed `expires_at` values cause authentication failure (no longer treated as non-expiring).
  - Time-expired keys are rejected and audited; their `status` remains `active` in admin listings (operators should check `expires_at`).

- **Key rotation drops `expires_at`**:
  - The replacement key is created without an expiry, even if the original key had one.
  - Recreate with an explicit expiry when required.

### Database Compatibility Warning (Critical)

**v0.2.0 introduces audit-chain ordering through migration v4 (`audit_chain_order`).**

- After migration v4 runs, the audit chain is rebuilt in canonical insertion order (`id ASC`).
- **Pre-v0.2 binaries (which verify the chain in timestamp order) will consider a v4 database's audit chain INVALID and may refuse to start or operate incorrectly.**
- If you must roll back the application version to a pre-v0.2 release:
  1. Stop the service.
  2. Restore a **pre-v4 database backup** (one taken before the v4 migration ran).
  3. Verify the restored database with `gw_migrate verify`.
  4. Start the older binary.
- **Do not run a pre-v0.2 binary against a v4 database expecting it to work.** The audit chain order changed and cannot be reconciled without a restore.
- Operators must follow the migration and backup instructions in `docs/MIGRATION_RUNNER.md` and `docs/DEPLOYMENT.md` before applying v4.

### Security

- Authentication failure audit records (`auth_failure`) are best-effort and do not change authentication outcomes.
- Lifecycle mutations (agent/key create, update, deactivate, rotate, revoke) are transactional with their audit record: the state change and its audit row commit together or roll back together. No unaudited state changes can persist.
- PBKDF2 iteration count is stored with each key; on authentication, keys hashed with fewer iterations than the current default are rehashed atomically with an audit event (`key_rehashed`). The rehash is optional and rolls back if audit persistence fails.
- Caddy deployment: dedicated agent-ingest routes bypass dashboard basic auth and do not inject the shared token. `Authorization` header is forwarded untouched so agent keys are never overwritten by the shared token.

### Documentation

- `docs/DEPLOYMENT.md`: Added migration backup preflight section with policy variables, commands, and warnings.
- `docs/MIGRATION_RUNNER.md`: Added preflight runbook, **STOP WRITERS** warning, and **NEVER RUN PRE-v4 BINARIES** warning.
- `docs/ADMIN_API.md`: Full operator reference for 10 admin endpoints with security warnings.
- `docs/RATE_LIMITING.md`: Complete configuration reference for all three limiters, process-local caveats, and deployment guidance.
- `backend/.env.example`: Added backup preflight variables, pre-auth rate limit variables, trusted proxies, and `GREYWATCH_KEY_HASH_ITERATIONS`.

### Fixed

- Pre-v0.2 code paths that called `initialize_database()` in request handlers, collectors, and Suricata have been removed; the FastAPI lifespan is now the sole schema initialization owner.
- Schema verification is version-aware and cumulative: a database is `inconsistent` if any required table, column, index, or FK is missing, regardless of ledger contents.
- Migration runner validates the ledger and verifies schema/FKs after each migration, all inside a single `BEGIN IMMEDIATE` transaction.
- WAL-mode databases are copied to a private temp directory for read-only inspection, avoiding sidecar creation beside the live file.

---

## [0.1.0] - 2026-10-14

### Added

- HTTP event ingestion and normalization.
- Rule-based SSH brute-force detection.
- Alert evidence and investigation.
- Alert resolution.
- Incident correlation and lifecycle (open → acknowledge → resolved) with related events.
- Optional systemd journal collection.
- Optional Suricata EVE JSON collection.
- API trust-boundary enforcement (loopback, shared token).
- Global API rate limiting.
- React dashboard.
- Automated backend tests and frontend checks.
- Transactional migration runner (v1 baseline, v2 agents/audit, v3 audit integrity).
- SQLite online backup API with integrity and FK verification.
- Event retention with preservation rules (incident-referenced, open-alert evidence).
- Database VACUUM during downtime.