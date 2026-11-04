# Greywatch Migration Runner — Operator Guide

This document describes the transactional migration runner, the
`scripts/gw_migrate` command-line tool, and the integrated application startup
lifecycle. It covers inspection, planning, verification, backups, running
migrations, failure handling, recovery, and the current limits of automatic
migration.

As of this version, the migration runner **is** invoked by FastAPI application
startup via the lifespan handler. On startup, the application:
1. Resolves the configured database path
2. Atomically creates the database file if missing (no-replace publication)
3. Inspects the migration state
4. Performs backup preflight when required by policy
5. Executes pending migrations transactionally
6. Verifies the final database state
7. Starts the service only after successful initialization

Manual migration via `scripts/gw_migrate` remains supported for operator-initiated
maintenance windows.

## Contents

1. [Architecture overview](#architecture-overview)
2. [Application startup lifecycle](#application-startup-lifecycle)
3. [Database status inspection](#database-status-inspection)
4. [Migration plan preview](#migration-plan-preview)
5. [Database verification](#database-verification)
6. [Schema requirements by migration version](#schema-requirements-by-migration-version)
7. [Backup creation before migration](#backup-creation-before-migration)
8. [Running a migration interactively](#running-a-migration-interactively)
9. [Running with `--yes`](#running-with---yes)
10. [Dry-run behavior](#dry-run-behavior)
11. [Failure behavior and transactional rollback](#failure-behavior-and-transactional-rollback)
12. [Recovery by restoring a verified backup](#recovery-by-restoring-a-verified-backup)
13. [Why automatic downgrade is unsupported](#why-automatic-downgrade-is-unsupported)
14. [Concurrent startup behavior](#concurrent-startup-behavior)
15. [Legacy initialization guard](#legacy-initialization-guard)
16. [Recovery instructions](#recovery-instructions)
17. [Operational limitations](#operational-limitations)

---

## Architecture overview

The migration system is split into read-only inspection and a single
transactional write path:

| Component | Responsibility |
|-----------|----------------|
| `backend/app/migration_state.py` | Read-only database inspection and state classification. |
| `backend/app/migration_schema.py` | Version-aware expected schema descriptors and structural comparison. |
| `backend/app/migration_registry.py` | Ordered migration registry (`v1: baseline` … `v4: audit_chain_order`) and ledger/version validation. |
| `backend/app/migrations/v001_baseline.py` | Baseline schema creation and permitted additive legacy changes. |
| `backend/app/migrations/v002_agents.py` | Agent, API-key, and audit-log tables plus `events.agent_id`. |
| `backend/app/migrations/v003_audit_log_integrity.py` | Audit hash-chain columns and `idx_audit_log_chain`. |
| `backend/app/migrations/v004_audit_chain_order.py` | Data-only rebuild of audit-chain ordering (no schema changes). |
| `backend/app/migrations/runner.py` | Transactional `status`, `plan`, `verify`, and `migrate` operations. |
| `backend/app/migration_ledger.py` | The `schema_migrations` ledger table. |
| `scripts/gw_migrate` | Operator-facing CLI wrapper around the runner. |

The ledger records each applied migration as `(version, name, applied_at)`.
Migration versions are validated against the registry; the runner never
repairs or rewrites an existing ledger.

`migrate()` performs these steps:

1. Resolve the path safely (missing files and broken symlinks are rejected).
2. Inspect the database read-only and classify its state.
3. Refuse unsafe states, return a no-op for `CURRENT`, or continue.
4. Open a read-write connection with WAL mode and a 10-second busy timeout.
5. Execute `BEGIN IMMEDIATE`, acquiring the write lock.
6. Re-inspect the database under the lock, because another process may have
   changed it in the meantime.
7. Validate the existing ledger, if present.
8. Apply the baseline migration or stamp the ledger as appropriate.
9. Re-check schema completeness and foreign keys.
10. Insert the ledger row and commit.

Any failure rolls the whole transaction back. There is no partial schema or
partial ledger state.

For operational work, run the CLI from the repository root (or use the
absolute path to `/opt/greywatch/scripts/gw_migrate`). Run migration and
verification commands as the database owner — normally the `greywatch`
service user — so SQLite WAL sidecar files are created with the correct
ownership. A root-run migration can leave root-owned `-wal`/`-shm` files next
to a service-owned database.

```bash
cd /opt/greywatch

# Preferred: run as the database/service owner.
sudo -u greywatch ./scripts/gw_migrate status ./data/greywatch.db
```

The code default database path is `<repo>/data/greywatch.db`
(`backend/app/siem.py`). The examples below use `./data/greywatch.db` from the
repository root. If the service is configured with a different `GREYWATCH_DB`,
pass that same path explicitly to both CLIs; neither CLI reads the variable for
its target.

---

## Application startup lifecycle

FastAPI's lifespan handler (in `backend/app/main.py`) orchestrates database
initialization on service startup. The sequence is:

1. **Resolve database path** — reads `GREYWATCH_DB` (default:
   `<repo>/data/greywatch.db` from `backend/app/siem.py`).

2. **Ensure parent directory exists** — creates `db_path.parent` if needed.

3. **Safely create database file if missing** — calls
   `migration_state.ensure_database_file_exists()`. This uses atomic no-replace
   publication:
   - Creates a temporary file in the same directory.
   - Initializes it as a valid SQLite database (`PRAGMA user_version=0`).
   - Closes the connection (forces SQLite to write the database header/page).
   - Verifies the temp file is a valid non-zero SQLite database (`PRAGMA quick_check`).
   - Attempts `os.link()` to publish atomically without replacing an existing file.
   - On `EEXIST`: another process won the race; uses their file.
   - On `EXDEV`/`ENOTSUP`: fails closed (cross-device or filesystem without hard links).
   - On success: explicitly unlinks the temporary pathname.

   **Guarantees:** Any process inspecting the path sees either nothing or a
   fully initialized valid SQLite database (state `FRESH`). No zero-byte window
   is visible. No replacement of an existing destination. The temporary
   pathname is removed after successful publication. Orphaned temporary files
   from crashed processes are harmless and not automatically cleaned (manual
   removal or next deployment).

4. **Inspect migration state** — calls `migration_state.inspect_path()`.

5. **Backup preflight (when required)** — if `GREYWATCH_REQUIRE_BACKUP=1` and
   the database state is migratable (`FRESH`, `LEDGER_ONLY`, `LEGACY_READY`,
   `PENDING`):
   - Finds the latest backup in `GREYWATCH_BACKUP_DIR`.
   - Verifies it with `scripts.gw_db_backup.verify_database()` (integrity +
     foreign key check).
   - Checks backup age against `GREYWATCH_MAX_BACKUP_AGE_HOURS` (default 24h).
   - Fails startup if no valid backup exists.

   **CURRENT** databases skip the backup check entirely.

6. **Execute migration** — calls `migrations.runner.migrate()` if the state is
   migratable. The runner:
   - Opens a write connection with WAL mode and 10s busy timeout.
   - Acquires write lock with `BEGIN IMMEDIATE`.
   - Re-inspects under lock (state may have changed).
   - Validates existing ledger if present.
   - Applies baseline migration or stamps ledger.
   - Verifies schema completeness and foreign keys.
   - Commits transaction.

7. **Verify final state** — re-inspects the database. Must be `CURRENT` or
   `UNVERSIONED` (no migrations registered). Fails closed otherwise.

8. **Activate legacy guard** — sets process-wide flag
   `_SCHEMA_MANAGED_BY_RUNNER = True` in `siem.py` so
   `initialize_database()` cannot bypass the migration runner after startup.

9. **Start application** — only after all steps succeed.

**Failure behavior:** Any error in steps 1–8 causes startup to fail closed.
The service does not start. Errors are logged with `logger.error`. Exit code
follows uvicorn's `STARTUP_FAILURE` (exit 3).

**Health endpoint:** `GET /health` returns `schema_ready: true` when the
database is `CURRENT` or `UNVERSIONED`, and `migration_applied: 1` if a
migration ran during this startup.

---

## Concurrent startup behavior

Multiple application processes starting simultaneously (e.g., behind a load
balancer, or multiple `uvicorn` workers, or `TestClient` instances in tests)
race to create the database file:

- The first process to successfully `os.link()` its temporary file publishes
  the database.
- Other processes receive `EEXIST` and use the already-published database.
- All processes then inspect the same database state and proceed through
  migration logic.
- The migration runner's `BEGIN IMMEDIATE` lock ensures only one process
  actually applies the migration; others re-inspect under the lock, see
  `CURRENT`, and no-op.

**Competing publisher edge cases:**
- **Valid destination exists:** Loser uses it (correct).
- **Missing destination:** Fails closed — does not create a partial
  destination.
- **Invalid destination (corrupt/empty):** Fails closed — does not overwrite.

**⚠️ Multi-worker deployment limitation:** The FastAPI lifespan handler runs
independently in each uvicorn worker process. While the atomic file creation
and `BEGIN IMMEDIATE` lock provide safety against corruption, there is a
TOCTOU window between a worker's initial `inspect_path()` (step 4) and its
`migrate()` call under lock (step 6). If Worker A publishes the database and
completes migration before Worker B's initial inspection, Worker B may see
`FRESH` initially, then re-inspect under lock and see `CURRENT` (no-op). This
is safe but adds latency.

However, if Worker B's initial inspection races with Worker A's WAL checkpoint
(the `inspect_path()` WAL-copy mechanism copies the database and `-wal`/`-shm`
separately), Worker B may observe an inconsistent intermediate state and fail
startup with "database disappeared while acquiring lock" or similar errors.
This is a known SQLite WAL-mode inspection limitation, not a corruption risk.

**Supported deployment models:**
- **Single uvicorn worker** (recommended for simplicity): No concurrent
  startup race.
- **External coordination:** Use a process manager (systemd, Kubernetes init
  containers, etc.) to run `gw_migrate migrate` once before starting multiple
  workers, or use a leader-election sidecar to ensure only one process runs the
  lifespan at a time.
- **`GREYWATCH_REQUIRE_BACKUP=1` does NOT provide concurrency coordination.**
  It only enforces backup existence; it does not serialize startup across
  workers.

**Test isolation:** The `isolate_schema_guard` fixture in `conftest.py`
resets the process-wide guard for each test via `monkeypatch`.

---

## Legacy initialization guard

Once the FastAPI lifespan completes successfully, a process-wide guard
(`_SCHEMA_MANAGED_BY_RUNNER` in `siem.py`) prevents the legacy
`initialize_database()` from bypassing the migration runner.

- Guard is checked **FIRST**, before any environment variable bypass.
- `GREYWATCH_ALLOW_LEGACY_INIT=1` cannot bypass the guard after lifespan.
- No production reset function exists; tests use `monkeypatch` for isolation.
- Standalone tools/scripts can still use `initialize_database()` by setting
  `GREYWATCH_ALLOW_LEGACY_INIT=1` (emits deprecation warning unless set).

This ensures the migration runner is the single source of truth for schema
management in production.

---

## Recovery instructions

**Startup fails with "Database initialization failed" or "Database migration failed":**
1. Check the logs for the specific error.
2. If the database file is corrupt/missing, restore from a verified backup:
   ```bash
   sudo systemctl stop greywatch-api
   sudo python3 ./scripts/gw_db_backup.py verify /var/backups/greywatch/greywatch.db.<timestamp>
   sudo python3 ./scripts/gw_db_backup.py restore /var/backups/greywatch/greywatch.db.<timestamp> ./data/greywatch.db --yes
   sudo systemctl start greywatch-api
   ```
3. If migration failed due to lock/contention, retry startup (the lock is
   released on failure).
4. If the database is `inconsistent`, `newer`, or `corrupt`, inspect it
   read-only and record the detail before restoring:
   ```bash
   sudo -u greywatch ./scripts/gw_migrate status ./data/greywatch.db
   ```
   The `Detail:` line names the missing or incompatible table, column, index,
   foreign key, or table option. Do **not** attempt manual `ALTER`/`DROP`,
   ledger edits, or hand-created indexes. Verification never repairs a schema,
   and neither should an operator. Restore a verified backup (see
   [Recovery by restoring a verified backup](#recovery-by-restoring-a-verified-backup))
   taken before the failed migration.

**Orphaned temporary files:** Files matching `.<dbname>.init.*.tmp` in the
database directory are from crashed initializations. They are harmless and can
be removed manually:
```bash
rm -f /path/to/data/.greywatch.db.init.*.tmp
```

---

## Operational limitations

1. **Filesystem must support hard links** — `os.link()` is used for atomic
   publication. Cross-device (EXDEV), NFS (ENOTSUP), and some network
   filesystems will fail closed with a clear error. Use a local filesystem.

2. **No automatic downgrade** — The baseline migration has no `down()`
   implementation. Recovery is backup-based only.

3. **Backup is a point-in-time snapshot, not an atomic restore point** — The
   online backup API captures a consistent snapshot at backup time. Writes
   after the backup are not included. For a true pre-migration restore point,
   stop the service before backing up.

4. **`verify_database()` does not validate backup identity** — It confirms
   structural validity and foreign key integrity, but not that the backup
   originated from the current source database. Manually verify backup
   timestamps and run `gw_migrate status` against the backup if needed.

5. **WAL sidecars are not atomically backed up** — The backup tool uses
   SQLite's online backup API which converts to DELETE journal mode, so the
   backup is a single self-contained file. Restore moves stale `-wal`/`-shm`
   sidecars aside but does not atomically restore them with the main file.

6. **Concurrent startup with external migration runner** — If an operator
   runs `gw_migrate migrate` while application processes are starting, the
   runner's `BEGIN IMMEDIATE` lock serializes with the lifespan's migration
   attempt. One will apply, the other will no-op. This is safe but may cause
   brief startup delay.

7. **Orphaned temp files are not auto-cleaned** — By design, to avoid
   deleting a temp file another active worker is initializing. They are
   small, have distinctive names, and are never published. Clean manually or
   on next deployment.

`status` inspects the database without modifying it:

```bash
sudo -u greywatch ./scripts/gw_migrate status ./data/greywatch.db
```

Example output on a database that has not been migrated:

```text
State: fresh
Applied version: 0
Latest version: 4
Ledger present: no
```

Example output on a fully migrated database:

```text
State: current
Tables: agents, alerts, api_keys, audit_log, collector_state, events, incident_events, incidents, schema_migrations
Applied version: 4
Latest version: 4
Ledger present: yes
```

`Tables` lists the tables that exist, not the tables the ledger claims. A
database can therefore be `inconsistent` while still showing all expected
tables if a required column or index is missing; the `Detail:` line names the
missing or incompatible object.

Common states:

| State | Meaning |
|-------|---------|
| `fresh` | Valid SQLite database with no application tables. |
| `ledger_only` | Migration ledger exists but the application schema does not. |
| `pending` | Schema matches the applied ledger version, but the ledger is behind the registry. |
| `current` | Schema matches the latest version and the ledger matches it. |
| `legacy_ready` | All application tables exist but need additive column/index changes. |
| `inconsistent` | Ledger/schema disagreement (a missing or incompatible table, column, index, foreign key, or table option), gaps, duplicates, or an invalid ledger. |
| `newer` | Ledger version is newer than this Greywatch release supports. |
| `unrelated` | Valid SQLite database containing no Greywatch tables. |
| `corrupt` | SQLite integrity/schema validation failed. |
| `locked` | The database could not be inspected because of a lock. |
| `permission_denied` | The inspector could not open/read the database. |
| `missing` / `empty` | Path does not exist or the file is zero bytes. |

`status` is read-only, but its exit code only means the inspection completed.
It exits `0` for states such as `corrupt` or `unrelated` if a report could be
produced. Always read the `State:` line. Use `verify` when you need a
pass/fail readiness check.

`status` exits non-zero when the target cannot be inspected at all, such as a
missing path:

```text
ERROR: database path does not exist: ./data/greywatch.db
```

---

## Migration plan preview

`plan` shows what the runner would apply, without writing anything:

```bash
sudo -u greywatch ./scripts/gw_migrate plan ./data/greywatch.db
```

Example:

```text
Pending migrations (4):
  v1: baseline
  v2: agents_and_api_keys
  v3: audit_log_integrity
  v4: audit_chain_order
```

A current database prints:

```text
No pending migrations
```

`plan` is a preview, not a health check. It returns no pending migrations for
refused states such as `corrupt` or `unrelated`. The runner re-inspects the
database under the write lock before applying anything, so the plan can change
if another process modifies the database first.

---

## Database verification

`verify` is the readiness gate. It exits `0` only when the database is
`current`:

```bash
sudo -u greywatch ./scripts/gw_migrate verify ./data/greywatch.db
```

Success:

```text
OK: database at ./data/greywatch.db is current
```

A database that needs migration or is otherwise not current fails with exit
code `1`:

```text
FAILED: database at ./data/greywatch.db is not current
```

Inspection errors are reported on stderr:

```text
ERROR: database path does not exist: ./data/greywatch.db
```

`verify` never changes the database. It is safe to run before starting the
service and as a post-migration check.

---

## Schema requirements by migration version

The migration ledger records what was applied; it is not proof that the schema
exists. Verification is **version-aware and cumulative**: a database whose
validated ledger reports version *N* must contain every object introduced by
versions 1 through *N*.

| Ledger version | Required schema |
|----------------|-----------------|
| v1 `baseline` | `events`, `alerts`, `incidents`, `incident_events`, `collector_state` with all baseline columns and indexes. |
| v2 `agents_and_api_keys` | Everything in v1 plus `agents`, `api_keys`, and `audit_log`; nullable `events.agent_id` with `REFERENCES agents(id) ON DELETE SET NULL`; indexes `idx_events_agent_id`, `idx_agents_status`, `idx_agents_last_seen`, `idx_api_keys_agent_id`, `idx_api_keys_key_prefix`, `idx_api_keys_status`, `idx_audit_log_timestamp`, `idx_audit_log_agent_id`, and `idx_audit_log_event_type`. |
| v3 `audit_log_integrity` | Everything in v2 plus `audit_log.prev_hash`, `audit_log.chain_hash`, and `idx_audit_log_chain`. |
| v4 `audit_chain_order` | Same schema as v3. v4 rebuilds chain ordering data only; it adds no tables, columns, or indexes. |

Consequences operators should know:

- **No ledger or an empty ledger** is compared against the v1 baseline. A
  pre-agent legacy database (five core tables, no agent/audit tables) is
  therefore `pending`, not `inconsistent`, and remains migratable.
- **A v3-shaped database with a v1–v4 ledger is `current`**, because v4 adds no
  schema objects.
- **A v4-shaped database with a v1–v3 ledger is `pending`**, because the ledger
  is behind even though the extra objects are harmless.
- **A ledger version with no registered descriptor fails closed** as
  `inconsistent`; verification never falls back to a different version.
- **Extra objects are tolerated.** The check is "at least the expected schema",
  so a later schema with an older ledger is reported as pending rather than
  corrupted.

### What an inconsistent report looks like

`status`, `verify`, migration refusal, and startup logs all use the same
structural report. The `Detail:` line names every missing or incompatible
object, for example:

```text
State: inconsistent
Tables: alerts, collector_state, events, incident_events, incidents, schema_migrations
Applied version: 4
Latest version: 4
Ledger present: yes
Detail: ledger claims applied version 4 but the schema does not match the expected v4 schema: missing table(s): agents, api_keys, audit_log; events missing column(s): agent_id; events missing index(es): idx_events_agent_id; events missing foreign key agent_id -> agents.id
```

The runner refuses to migrate such a database and leaves the file byte-for-byte
unchanged:

```text
ERROR: database in incompatible state: inconsistent: ledger claims applied version 4 but the schema does not match the expected v4 schema: missing table(s): agents, ...
```

If post-migration verification fails, the entire transaction — schema changes
and the ledger row — is rolled back, and the error names the missing object:

```text
ERROR: schema incomplete after migration v2: agents missing index(es): idx_agents_status
```

### Read-only inspection

All verification is read-only. It uses `PRAGMA table_info`, `index_list`,
`index_xinfo`, `foreign_key_list`, and `table_list` against a read-only
connection. It never runs `CREATE`, `ALTER`, `DROP`, `INSERT`, `UPDATE`, or
`DELETE`, and it never "repairs" a missing object or stamps the ledger.

To inspect a database by hand without risking a write, use SQLite's read-only
URI mode:

```bash
sqlite3 'file:./data/greywatch.db?mode=ro' '.tables'
sqlite3 'file:./data/greywatch.db?mode=ro' 'PRAGMA table_info(events);'
sqlite3 'file:./data/greywatch.db?mode=ro' 'PRAGMA index_list(agents);'
sqlite3 'file:./data/greywatch.db?mode=ro' \
    'SELECT version, name, applied_at FROM schema_migrations ORDER BY version;'
```

If SQLite cannot open a WAL-mode database read-only because its `-shm` file is
absent or not writable, use `gw_migrate status` (it inspects a private copy) or
copy the database and its `-wal`/`-shm` sidecars to a scratch directory and
inspect that copy.

Do not use `sqlite3` in read-write mode to "fix" an inconsistent database.
Adding a missing table, column, or index by hand can leave the ledger and schema
in a state the runner cannot validate. Restore a verified backup instead.

---

## Backup creation before migration

Create a verified backup before any migration. The backup CLI is
`scripts/gw_db_backup.py`. It is a Python program (not executable directly),
takes every path as an explicit argument, and does not read `GREYWATCH_*`
environment variables.

Invoke it with `python3` from the repository root:

```bash
sudo python3 ./scripts/gw_db_backup.py backup \
    ./data/greywatch.db \
    /var/backups/greywatch
```

### Migration backup preflight (v0.2+)

The migration runner enforces a verified backup before **any** schema migration
— whether triggered by application startup or the manual `gw_migrate migrate`
CLI. This is the production-safe default: the database is never modified unless
a valid backup exists.

**Policy variables (read from environment):**

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

The operator-facing wrapper `scripts/gw_db_backup.sh` reads these same
environment variables and is the recommended way to create backups in production.

The CLI synopsis is:

```text
scripts/gw_db_backup.py backup <source_db> <backup_dir> [--prefix P] [--retention-days N]
scripts/gw_db_backup.py verify <db>
scripts/gw_db_backup.py restore <backup_file> <dest_db> --yes [--owner user[:group]] [--prefix P]
scripts/gw_db_backup.py retain <backup_dir> <days> [--prefix P]
```

| Argument / option | Used by | Meaning |
|-------------------|---------|---------|
| `source_db` | `backup` | Existing regular SQLite database file to back up. |
| `backup_dir` | `backup` | Destination directory. Created if missing; backups are written `0600` and the directory is set to `0700` where possible. |
| `--prefix P` | `backup`, `restore`, `retain` | Backup filename prefix, default `greywatch.db.`. `backup` uses it for the generated name and retention filter; `retain` uses it to select candidates. `restore` accepts it for interface symmetry, but the current restore implementation does not use it. |
| `--retention-days N` | `backup` | Positive integer; after a successful backup, prune matching backups older than `N` days. Default `0` disables pruning. |
| `db` | `verify` | Database or backup file to check with `PRAGMA integrity_check` and `PRAGMA foreign_key_check`. |
| `backup_file` | `restore` | Verified backup file to restore. |
| `dest_db` | `restore` | Destination database file to replace. |
| `--yes` | `restore` | Required confirmation. Without it, restore refuses to run. |
| `--owner user[:group]` | `restore` | Optional ownership for the restored file. An unresolvable owner produces a warning and existing ownership is preserved. |
| `backup_dir`, `days` | `retain` | Prune matching regular backup files older than `days` in `backup_dir`. |

A successful backup prints its path:

```text
Backup created: /var/backups/greywatch/greywatch.db.<timestamp>
```

Record that path and verify the backup independently:

```bash
sudo python3 ./scripts/gw_db_backup.py verify \
    /var/backups/greywatch/greywatch.db.<timestamp>
```

`verify` runs `PRAGMA integrity_check` and `PRAGMA foreign_key_check`; it
prints `OK: <path>` on success and exits non-zero on failure.

To prune old backups with the same prefix:

```bash
sudo python3 ./scripts/gw_db_backup.py retain /var/backups/greywatch 30
```

### Backup is a point-in-time snapshot, not an atomic pre-migration marker

The online backup API captures a consistent snapshot at the time the backup is
taken. It does **not** include writes committed after that snapshot. If
Greywatch keeps ingesting events or accepting API writes between the backup
and the migration, the backup is not an exact "pre-migration state" restore
point — restoring it would also discard everything written after the backup.

For a true pre-migration restore point, quiesce writes for the maintenance
window:

```bash
sudo systemctl stop greywatch-api
sudo python3 ./scripts/gw_db_backup.py backup \
    ./data/greywatch.db \
    /var/backups/greywatch
```

Then run the migration while the service is stopped, verify the database, and
start the service afterwards. If the service must remain available, accept
that the backup is only a point-in-time snapshot and that a restore will lose
later writes.

---

## Running a migration interactively

With the backup complete and the service stopped (recommended for a
maintenance window):

```bash
sudo systemctl stop greywatch-api
sudo -u greywatch ./scripts/gw_migrate migrate \
    ./data/greywatch.db
```

The CLI asks for confirmation:

```text
Apply pending migrations? [y/N]
```

Only `y` or `Y` proceeds. Any other response aborts without changing the
database:

```text
Aborted
```

The command exits `1` when aborted. If stdin is unavailable or reaches EOF, it
also aborts:

```text
Aborted (no confirmation)
```

On success it prints one of:

```text
Applied 1 migration(s)
No migrations to apply
```

Then verify and restart the service:

```bash
sudo -u greywatch ./scripts/gw_migrate verify \
    ./data/greywatch.db
sudo systemctl start greywatch-api
```

The interactive prompt is deliberately conservative; there is no "force"
variant that skips state validation.

---

## Running with `--yes`

`--yes` bypasses only the interactive confirmation. It does **not** skip path
safety, state classification, ledger validation, schema checks, or foreign-key
checks:

```bash
sudo systemctl stop greywatch-api
sudo -u greywatch ./scripts/gw_migrate migrate \
    ./data/greywatch.db --yes
```

Use `--yes` for scripted maintenance after the backup and service-stop steps
have succeeded. The command still exits non-zero and rolls back on any
validation or migration failure.

---

## Dry-run behavior

`--dry-run` reports what would happen without requesting confirmation and
without modifying the database:

```bash
sudo -u greywatch ./scripts/gw_migrate migrate \
    ./data/greywatch.db --dry-run
```

Possible output:

```text
Would apply 1 migration(s)
```

or:

```text
No migrations to apply
```

Dry-run does not open a write transaction and does not create tables or ledger
rows. It still performs read-only inspection and refuses missing, corrupt,
unrelated, inconsistent, or otherwise unsupported databases with a non-zero
exit code.

Because the database is re-inspected under the write lock during a real
migration, a dry-run result is advisory. Another process can change the
database between the dry run and the real run.

---

## Failure behavior and transactional rollback

All migration writes occur inside one SQLite transaction:

- Schema creation, additive legacy changes, ledger validation, schema
  verification, foreign-key checking, and the ledger insert are part of the
  same transaction.
- Any exception triggers `ROLLBACK`.
- The ledger row is inserted only after the schema passes post-migration
  verification and the foreign-key check is clean.
- A failed run leaves the database at its pre-run schema and ledger state.

Error messages are written to stderr:

```text
ERROR: cannot access database: ...
ERROR: database is not a Greywatch database
ERROR: database in incompatible state: inconsistent: <missing/incompatible objects>
ERROR: ledger validation failed: ...
ERROR: schema incomplete after migration vN: <missing/incompatible objects>
ERROR: schema verification failed before ledger stamp: <missing/incompatible objects>
```

Exit codes:

| Code | Meaning |
|------|---------|
| `0` | Command completed successfully, including an intentional no-op. |
| `1` | Migration refused, verification failed, confirmation declined, EOF, or runtime error. |
| `2` | Argparse usage error: missing command/argument or unknown option. |

Refusals happen before any write whenever possible. If another process holds
the SQLite write lock, the runner waits up to its 10-second busy timeout; if it
still cannot acquire the lock, it fails with an error rather than proceeding.

Do not manually edit `schema_migrations`, delete ledger rows, or run ad-hoc
`ALTER`/`DROP` statements to "fix" a failed migration. Restore a verified
backup instead.

---

## Recovery by restoring a verified backup

If a migration fails or the result is not acceptable, restore the backup taken
before the migration. Restore requires downtime because it replaces the
database file and its sidecars:

**⚠️ STOP WRITERS BEFORE MIGRATION OR RESTORE**

The Greywatch API service (`greywatch-api`) and any collector processes
(`greywatch-collector`, `suricata`, etc.) **must be stopped** before running a
migration or a restore. Writers that are running concurrently can:
- Extend the `-wal` file during backup, making the backup larger than necessary
- Cause the backup to capture a mid-transaction state (though the online backup
  API ensures consistency, the age policy applies to the backup's mtime)
- Corrupt the database if they write during a restore's atomic replacement
- Race with the migration runner's write lock, causing spurious lock timeouts

Always stop the service and collectors before any maintenance window:

```bash
sudo systemctl stop greywatch-api
# If running collectors, stop them too:
# sudo systemctl stop greywatch-collector
# sudo systemctl stop suricata
```

Then create and verify the backup:

```bash
# Create backup
sudo -u greywatch GREYWATCH_DB=/var/lib/greywatch/greywatch.db \
  GREYWATCH_BACKUP_DIR=/var/backups/greywatch \
  /opt/greywatch/scripts/gw_db_backup.sh backup

# Verify the backup before using it.
sudo python3 ./scripts/gw_db_backup.py verify \
    /var/backups/greywatch/greywatch.db.<timestamp>
```

**⚠️ NEVER RUN PRE-v4 BINARIES AGAINST A v4 DATABASE**

A database that has been migrated to v4 (`audit_chain_order` ledger stamp) has
an audit chain rebuilt in canonical insertion order (`id ASC`). Any binary
older than v0.2 (which expects timestamp-order verification) will report the
chain as **invalid** and may refuse to start or operate incorrectly.

If you must roll back the application version:
1. Stop the service.
2. Restore a pre-v4 backup (one taken before the v4 migration ran).
3. Verify the restored database with `gw_migrate verify`.
4. Start the older binary.

Do **not** run a pre-v4 binary against a v4 database expecting it to work — the
audit chain order changed and cannot be reconciled without a restore.

```bash
sudo systemctl stop greywatch-api

# Verify the backup before using it.
sudo python3 ./scripts/gw_db_backup.py verify \
    /var/backups/greywatch/greywatch.db.<timestamp>

# Restore requires --yes and both the backup and destination paths.
sudo python3 ./scripts/gw_db_backup.py restore \
    /var/backups/greywatch/greywatch.db.<timestamp> \
    ./data/greywatch.db --yes
```

Add `--owner greywatch:greywatch` to the restore command when the restored
file must be owned by the service user; an unresolvable owner warns and
preserves existing ownership.

The restore tool:

- verifies the backup before touching the destination;
- makes a recoverable online copy of the current database
  (`greywatch.db.pre-restore.<timestamp>`) in the database directory;
- stages and verifies the replacement, then atomically replaces the main file;
- moves stale `-wal`/`-shm` sidecars aside;
- reports the pre-restore copy and any moved sidecars.

After restoring, confirm the database state before starting the service:

```bash
sudo -u greywatch ./scripts/gw_migrate status ./data/greywatch.db
sudo -u greywatch ./scripts/gw_migrate verify ./data/greywatch.db
sudo systemctl start greywatch-api
```

A restored backup may predate the migration and therefore report `fresh`,
`ledger_only`, or `pending` rather than `current`. That is expected if the
backup was taken before the migration ran; do not treat it as a restore
failure. Verification of the restored file uses the schema required by *its own*
ledger version — a valid v2 backup is checked against the v2 schema, not against
v4 — so an older backup is not misreported as inconsistent simply for lacking
later objects. Starting the service will then migrate it forward through the
remaining versions.

If the restored backup reports `inconsistent`, the backup itself is incomplete
or was taken from an already-damaged database. Do not try to repair it. Choose an
earlier backup, verify it, and restore again:

```bash
sudo python3 ./scripts/gw_db_backup.py verify \
    /var/backups/greywatch/greywatch.db.<earlier-timestamp>
sudo python3 ./scripts/gw_db_backup.py restore \
    /var/backups/greywatch/greywatch.db.<earlier-timestamp> \
    ./data/greywatch.db --yes
```

If restore itself fails, the original database should still be in place. Look
for `greywatch.db.pre-restore.<timestamp>` in the database directory, verify
whichever copy you intend to keep, and correct ownership/mode before starting
the service.

---

## Why automatic downgrade is unsupported

The baseline migration has no `down()` implementation. Calling it raises:

```text
NotImplementedError: Baseline migration v1 has no safe automatic downgrade;
restore a pre-migration database backup instead.
```

There is also no `gw_migrate down` command. A downgrade would have to remove
tables or columns and could destroy event, alert, and incident data. The runner
is intentionally forward-only: it validates ledger versions and refuses
inconsistent states rather than guessing how to reverse a schema change.

Recovery is therefore backup-based:

1. Stop the service.
2. Restore the verified pre-migration backup.
3. Verify the restored database.
4. Start the service.

---

## Application startup lifecycle integration

As of this version, the migration runner **is** invoked by FastAPI application
startup via the lifespan handler. On startup, the application:
1. Resolves the configured database path
2. Atomically creates the database file if missing (no-replace publication)
3. Inspects the migration state
4. Performs backup preflight when required by policy
5. Executes pending migrations transactionally
6. Verifies the final database state
7. Starts the service only after successful initialization

Manual migration via `scripts/gw_migrate` remains supported for operator-initiated
maintenance windows.
