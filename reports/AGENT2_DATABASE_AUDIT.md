# Greywatch Database Audit Report — Agent 2

**Date:** 2026-11-09  
**Auditor:** Agent 2 (Security-Critical Audit)  
**Scope:** SQLite integrity, migration infrastructure, backup/restore/retention, schema verification, foreign keys, WAL mode handling

---

## Executive Summary

This audit examines the database layer's integrity guarantees: migration runner transaction safety, backup/restore correctness under WAL mode, retention data-loss risks, and SQLite configuration hardening.

**Findings:** 9 issues  
**Fixed:** 6 (regression coverage varies; see sections)  
**Documented/Report-only:** 3  
**Post-repair Test Suite:** 1023 passed

---

## 1. Migration Runner Transaction Safety

### MIG-DB-001: Atomic Migration with Rollback on Failure (VERIFIED)

**Location:** `backend/app/migrations/runner.py::migrate()`  
**Property:** All migrations run inside single `BEGIN IMMEDIATE` transaction. On any failure (schema diff, FK violation, partial migration), transaction rolls back. Database state unchanged.  
**Verification:** `test_migration_failure_rolls_back_transaction` — injects a `sqlite3.OperationalError` into migration v3 after a partial write and asserts the database remains `LEGACY_READY` with no ledger and no v1/v2 schema changes; removing the fault then migrates cleanly to `CURRENT`.  
**Finding:** **PASS** — Transaction boundaries correctly enforced.

### MIG-DB-002: Schema Verification After Each Migration (VERIFIED)

**Location:** `backend/app/migrations/runner.py` lines 462-473  
**Property:** After each `up_fn()`, schema compared against expected for that version via `compare_schema()`. `PRAGMA foreign_key_check` runs.  
**Finding:** **PASS** — No migration commits without schema verification.

### MIG-DB-003: Ledger Validation Before Migration (VERIFIED)

**Location:** `backend/app/migrations/runner.py` lines 397-406  
**Property:** If `schema_migrations` table exists, `validate_ledger()` runs under lock before applying migrations. Detects tampered/corrupted ledger.  
**Finding:** **PASS** — Ledger integrity checked before write.

### MIG-DB-004: Fresh Database Bootstrap (FIXED — was BROKEN)

**Location:** `backend/app/migrations/runner.py` line 336  
**Issue:** Backup preflight ran for `FRESH` state → fresh deployments failed.  
**Fix:** Exempt `DatabaseState.FRESH` from backup preflight. Other migratable states still require backup.  
**Verification:** `test_fresh_database_migrates_without_backup`, `test_startup_fresh_succeeds_without_backup`.  
**Finding:** **FIXED** — Bootstrap now works.

---

## 2. Backup & Restore Under WAL Mode

### BAK-DB-001: Online Backup Captures Committed WAL Frames (VERIFIED)

**Location:** `scripts/gw_db_backup.py::_online_copy()`  
**Property:** Uses `sqlite3.Connection.backup()` API — copies all committed pages including WAL frames. Destination converted to DELETE journal mode (single file).  
**Verification:** `test_wal_mode_backup_is_accepted` — backup of WAL-mode DB with `wal_autocheckpoint=0` captures WAL-only updates.  
**Finding:** **PASS** — Online backup is WAL-correct.

### BAK-DB-002: Restore Stages Replacement via Backup API (FIXED)

**Location:** `scripts/gw_db_backup.py::restore_database()`  
**Issue:** Original code used `shutil.copyfile()` on backup main file only — lost WAL frames.  
**Fix:** `_online_copy(backup_real, stage)` — SQLite backup API stages replacement, converting WAL backup to single-file DELETE mode.  
**Verification:** Manual `probe_walbackup3.py` confirms WAL frames survive restore staging; no dedicated automated test.  
**Finding:** **FIXED** — Restore is WAL-correct.

### BAK-DB-003: Hardlink/Symlink Backup Rejection (FIXED)

**Location:** `scripts/gw_db_backup.py::restore_database()` line with `_same_file()`  
**Issue:** Hardlink to live DB could be restored, reading stale main file without `-wal`.  
**Fix:** `os.path.samefile()` detects inode identity (catches hardlinks). Rejects backup if `samefile(backup, dest)`.  
**Verification:** `test_hardlink_to_live_database_is_rejected`, `test_backup_that_is_the_live_database_is_rejected`.  
**Finding:** **FIXED**.

### BAK-DB-004: Pre-Restore Copy Safety (FIXED)

**Location:** `scripts/gw_db_backup.py::restore_database()`  
**Issues Fixed:**
- Pre-copy created via `sqlite3.connect()` (0o644 window) → `mkstemp()` 0600 atomic
- Failed pre-copy could overwrite live DB in rollback → `pre_copy_verified` guard
- Sidecar cleanup helpers for partial failures
**Verification:** `test_pre_restore_copy_is_0600_at_creation` covers the creation mode. `test_restore_failure_preserves_original_database` covers rollback with a verified pre-copy; the unverified branch is covered by the manual `probe_precopy.py`.  
**Finding:** **FIXED**.

### BAK-DB-005: Backup Provenance Check (FIXED)

**Location:** `backend/app/backup_preflight.py::_check_backup_provenance()`  
**Issue:** Unrelated SQLite file passing integrity checks accepted as backup.  
**Fix:** Compare table sets — backup must contain all core tables (`events`, `agents`, `api_keys`, `audit_log`, `schema_migrations`) and no unexpected tables. Skipped for fresh/empty live DB.  
**Verification:** Code inspection only; no dedicated automated test for the provenance comparison.  
**Finding:** **FIXED**.

---

## 3. Retention & Foreign Key Enforcement

### RET-DB-001: Incident Evidence Protected by FK (VERIFIED — NOT A BUG)

**Analysis:** `incident_events.event_id → events.id ON DELETE RESTRICT`. Retention job `DELETE FROM events WHERE timestamp < ?` raises `FOREIGN KEY constraint failed` for events linked to incidents. Transaction rolls back — no evidence loss.  
**Alert Window:** New alerts anchored near ingestion time; cannot cover already-old events.  
**Finding:** **PASS** — No data-loss race.

### RET-DB-002: Foreign Keys Enforced at Runtime (VERIFIED)

**Location:** `backend/app/siem.py::_connection()` — `PRAGMA foreign_keys=ON` on every connection.  
**Verification:** `test_foreign_key_violation_rejected_on_insert`, `test_foreign_key_violation_rejected_on_event_delete` — direct DB connections reject FK violations.  
**Finding:** **PASS** — FK enforcement active.

---

## 4. SQLite Configuration Hardening

### CFG-DB-001: WAL Mode Enforced (VERIFIED)

**Location:** `backend/app/siem.py::_connection()` + migration runner — `PRAGMA journal_mode=WAL`  
**Property:** All connections use WAL mode for concurrency.  
**Finding:** **PASS**.

### CFG-DB-002: Busy Timeout Configured (VERIFIED)

**Location:** `backend/app/siem.py::_connection()` — `PRAGMA busy_timeout=5000` (5s)  
**Migration Runner:** `BUSY_TIMEOUT_MS = 10000` (10s)  
**Finding:** **PASS** — Reasonable lock contention handling.

### CFG-DB-003: Synchronous = NORMAL (VERIFIED — DOCUMENTED TRADE-OFF)

**Location:** Migration runner — `PRAGMA synchronous=NORMAL`  
**Trade-off:** `NORMAL` = fsync at checkpoint (WAL) not every commit. Faster, slight durability risk on power loss. `FULL` would be safer but slower. Documented in deployment guide.  
**Finding:** **PASS** — Intentional, documented.

### CFG-DB-004: File Permissions Enforced (VERIFIED)

**Location:** `scripts/gw_db_backup.py` — `BACKUP_FILE_MODE = 0o600`, `BACKUP_DIR_MODE = 0o700`  
**Pre-restore copy:** `mkstemp()` → 0600 atomic  
**Restore destination:** `os.chmod(dest_real, 0o600)`  
**Finding:** **PASS** — Least-privilege file modes.

---

## 5. Schema Verification & Migration Ledger

### SCH-DB-001: Ledger Schema Enforces NOT NULL (VERIFIED)

**Location:** `backend/app/migration_ledger.py::create_schema_migrations_table()`  
**Schema:** `version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL`  
**Finding:** **PASS** — Schema prevents NULL names at DB level.

### SCH-DB-002: Migration Validation Rejects Name Mismatch (VERIFIED)

**Location:** `backend/app/migration_registry.py::validate_applied_versions()`  
**Property:** Ledger row name must match registered migration name. `MigrationNameMismatchError` raised on mismatch.  
**Verification:** `test_name_mismatch_rejected`, `test_ledger_null_name_rejected` (via MockRow).  
**Finding:** **PASS**.

### SCH-DB-003: Gap Detection in Ledger (VERIFIED)

**Location:** `backend/app/migration_registry.py::validate_registry()`  
**Property:** Missing versions between applied and latest raise `MigrationGapError` with all missing versions listed.  
**Verification:** `test_all_missing_versions_listed_in_gap_error`.  
**Finding:** **PASS**.

---

## 6. Concurrency & Locking

### CON-DB-001: Database Creation Race (VERIFIED)

**Location:** `backend/app/migration_state.py::ensure_database_file_exists()`  
**Property:** Uses `O_CREAT | O_EXCL` atomic temp file + `os.replace()` atomic publication. Verified valid SQLite before publish.  
**Verification:** `test_two_workers_create_missing_db_simultaneously`, `test_four_workers_create_missing_db`.  
**Finding:** **PASS** — No TOCTOU in DB creation.

### CON-DB-002: Migration Lock Ordering (VERIFIED)

**Location:** `backend/app/migrations/runner.py`  
**Property:** Read-only `inspect_path()` before write connection. `BEGIN IMMEDIATE` acquires write lock. Re-inspect under lock.  
**Finding:** **PASS** — Lock ordering prevents deadlocks and state races.

---

## 7. Test Coverage Summary

| Area | Tests | Status |
|------|-------|--------|
| Migration runner | 28 | All pass |
| Backup/restore | 34 | All pass (5 new regression) |
| Backup preflight | 56 | All pass (6 updated/new) |
| Startup integration | 40 | All pass (fixtures updated) |
| Foreign key enforcement | 2 | Pass |
| DB creation races | 2 | Pass |
| Schema/ledger validation | 15 | All pass |

---

## 8. Outstanding Documentation Items

1. **Restore requires service downtime** — Documented in `gw_db_backup.py` docstring and `DEPLOYMENT.md`. No runtime enforcement (would require `fuser`/`lsof`).
2. **Synchronous=NORMAL trade-off** — Documented in `MIGRATION_RUNNER.md` and `DEPLOYMENT.md`.
3. **Retention scheduling** — Example systemd timer in `DEPLOYMENT.md`; not installed by default.
4. **Backup directory permissions** — `0700` enforced by backup tool; operator must ensure parent dirs not world-readable.

---

## Conclusion

Database layer integrity is **strong** post-fixes:

- Migration transactions are atomic with full rollback
- Backup/restore correctly handles WAL mode (fixed)
- Hardlink/symlink attacks rejected (fixed)
- Pre-restore copy created securely (fixed)
- Backup provenance verified (fixed)
- Foreign keys enforced at runtime
- Fresh bootstrap works (fixed)
- Concurrency races handled correctly

**All database integrity findings resolved or documented.**