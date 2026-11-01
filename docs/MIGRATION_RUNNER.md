# Greywatch Migration Runner — Operator Guide

This document describes the transactional migration runner and the
`scripts/gw_migrate` command-line tool. It covers inspection, planning,
verification, backups, running migrations, failure handling, recovery, and the
current limits of automatic migration.

The migration runner is **not** invoked by application startup. Schema changes
are an explicit operator action.

## Contents

1. [Architecture overview](#architecture-overview)
2. [Database status inspection](#database-status-inspection)
3. [Migration plan preview](#migration-plan-preview)
4. [Database verification](#database-verification)
5. [Backup creation before migration](#backup-creation-before-migration)
6. [Running a migration interactively](#running-a-migration-interactively)
7. [Running with `--yes`](#running-with---yes)
8. [Dry-run behavior](#dry-run-behavior)
9. [Failure behavior and transactional rollback](#failure-behavior-and-transactional-rollback)
10. [Recovery by restoring a verified backup](#recovery-by-restoring-a-verified-backup)
11. [Why automatic downgrade is unsupported](#why-automatic-downgrade-is-unsupported)
12. [Application startup does not run migrations](#application-startup-does-not-run-migrations)

---

## Architecture overview

The migration system is split into read-only inspection and a single
transactional write path:

| Component | Responsibility |
|-----------|----------------|
| `backend/app/migration_state.py` | Read-only database inspection and state classification. |
| `backend/app/migration_registry.py` | Ordered migration registry (`v1: baseline`) and ledger/version validation. |
| `backend/app/migrations/v001_baseline.py` | Baseline schema creation and permitted additive legacy changes. |
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

## Database status inspection

`status` inspects the database without modifying it:

```bash
sudo -u greywatch ./scripts/gw_migrate status ./data/greywatch.db
```

Example output on a database that has not been migrated:

```text
State: fresh
Applied version: 0
Latest version: 1
Ledger present: no
```

Example output on a migrated database:

```text
State: current
Tables: alerts, collector_state, events, incident_events, incidents, schema_migrations
Applied version: 1
Latest version: 1
Ledger present: yes
```

Common states:

| State | Meaning |
|-------|---------|
| `fresh` | Valid SQLite database with no application tables. |
| `ledger_only` | Migration ledger exists but the application schema does not. |
| `pending` | Schema is complete but the ledger is behind the registry. |
| `current` | Schema is complete and the ledger matches the latest version. |
| `legacy_ready` | All application tables exist but need additive column/index changes. |
| `inconsistent` | Ledger/schema disagreement, gaps, duplicates, or an invalid ledger. |
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
Pending migrations (1):
  v1: baseline
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
ERROR: database in incompatible state: inconsistent
ERROR: ledger validation failed: ...
ERROR: schema incomplete after migration
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
failure.

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

## Application startup does not run migrations

The migration runner is **not** wired into FastAPI startup, `uvicorn`, or
`initialize_database()`. Starting Greywatch does not inspect the migration
ledger, apply migrations, or fail because a migration is pending.

`initialize_database()` remains the existing application schema path and does
not write the `schema_migrations` ledger. Migration execution is an explicit
operator action through `scripts/gw_migrate`.

This separation is intentional:

- a service restart cannot silently alter the database schema;
- operators choose the maintenance window and take a backup first;
- the migration CLI can be tested and audited independently of application
  startup.

Future integration, if desired, must be a separate reviewed change. Until
then, run `status`, take a backup, run `migrate`, and run `verify` as documented
above.
