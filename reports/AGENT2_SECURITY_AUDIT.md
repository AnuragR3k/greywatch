# Greywatch Security Audit Report — Agent 2

**Date:** 2026-11-09  
**Auditor:** Agent 2 (Security-Critical Audit)  
**Scope:** API authentication/authorization, agent/shared tokens, rate limiting, trusted proxies, body limits, audit-chain integrity, migrations, backups/restore, retention, SQLite integrity  
**Baseline Commit:** `3f23135` (main)  
**Verified Baseline (uncommitted fix set, 2026-11-09):** `python3 -m pytest backend/tests -q` → **11 failed, 1011 passed, 240 warnings** (all 11 failures came from a missing test helper in the uncommitted diff, not from product code)

---

## Executive Summary

This audit covers security-critical backend components not addressed by Agent 1's API key design audit. The review focused on runtime enforcement gaps, cryptographic boundary conditions, operational failure modes, and data integrity guarantees.

**Findings:** 14 distinct issues across 5 categories  
**Fixed:** 8 issues (dedicated regression coverage varies; see findings register)  
**Report-only (architectural limitations):** 4 issues  
**Release-blocking:** 1 (fresh-DB bootstrap failure) — **RESOLVED**  
**Post-repair Test Suite:** **1023 passed, 240 warnings in 27.73s**

---

## Category 1: Backup & Restore Integrity

### BAK-001: Hardlink Restore Data Loss (HIGH — FIXED)

**Location:** `scripts/gw_db_backup.py::restore_database()`  
**Attack Vector:** Attacker with write access to backup directory creates hardlink to live database (`ln live.db greywatch.db.backup`), operator runs restore.  
**Impact:** Restore verifies the hardlink (opens read-only, ignoring `-wal`), then overwrites live DB with stale main file only. Committed WAL frames lost.  
**Root Cause:** `_same_file()` used `realpath()` comparison, which does not detect hardlinks. SQLite opens hardlink read-only without the live DB's `-wal` sidecar.  
**Reproduction:** See `probe_hardlink.py` — live DB reverts from `wal-value` to `main-value` after restore.  
**Fix:** `os.path.samefile()` (detects inode identity including hardlinks). Backup path rejected if `samefile(backup, dest)`.  
**Verification:** `test_hardlink_to_live_database_is_rejected` (`test_backup_preflight.py`). Hardlink backup now raises `BackupError`.

---

### BAK-002: WAL-Mode Backup Restore Loses Committed Frames (HIGH — FIXED)

**Location:** `scripts/gw_db_backup.py::restore_database()`  
**Attack Vector:** Valid WAL-mode backup (main + `-wal`) verified successfully, but restore copies only main file via `shutil.copyfile()`.  
**Impact:** Live database loses WAL-only updates. Pre-restore copy retains them — data divergence.  
**Root Cause:** Restore used `shutil.copyfile()` on backup main file only. Backup API with WAL mode leaves committed frames in `-wal`; copying main alone is lossy.  
**Reproduction:** `probe_walbackup3.py` — verified backup has `wal-value` in main after checkpoint, but original code path would lose it.  
**Fix:** `_online_copy()` using SQLite's backup API (copies WAL frames into main file, converts to DELETE journal mode). Verification re-runs after copy.  
**Verification:** `test_wal_mode_backup_is_accepted` (`test_backup_preflight.py`).

---

### BAK-003: Pre-Restore Copy Readable by Local Users (MEDIUM — FIXED)

**Location:** `scripts/gw_db_backup.py::restore_database()` — pre-copy creation  
**Impact:** Pre-copy created via `sqlite3.connect()` (mode 0o644 under umask 0002), then `chmod 0600`. Window of ~ms where local users can read full DB snapshot.  
**Root Cause:** Database connection creates file before permissions applied.  
**Fix:** `tempfile.mkstemp(dir=dest_dir, ...)` creates the pre-copy at 0600 atomically; the fd is closed, `_online_copy()` copies into it, and a same-directory `os.replace()` publishes it under its stable name with the mode preserved. The `pre_copy_verified` rollback guard is unchanged.  
**Verification:** `test_pre_restore_copy_is_0600_at_creation` (new) — asserts the destination is 0600 before `_online_copy()` runs and after publication.

---

### BAK-004: Restore Rollback Overwrites Live DB with Failed Pre-Copy (HIGH — FIXED)

**Location:** `scripts/gw_db_backup.py::restore_database()` — exception handler  
**Impact:** If pre-copy creation/verification fails, exception handler still replaces live DB with `pre_copy` (which may be partial/invalid).  
**Root Cause:** Rollback logic did not check `pre_copy_verified` flag before `os.replace(pre_copy, dest_real)`.  
**Reproduction:** `probe_precopy.py` — simulated disk-full during pre-copy leaves live DB unreadable.  
**Fix:** Track `pre_copy_verified` boolean. Rollback only restores verified pre-copy. Failed pre-copy → cleanup only, live DB untouched.  
**Verification:** `test_restore_failure_preserves_original_database` covers rollback with a verified pre-copy. The unverified-pre-copy branch was verified by the manual `probe_precopy.py`; no dedicated automated test.

---

### BAK-005: Restore Does Not Verify Service Stopped (DOCUMENTED — REPORT-ONLY)

**Location:** `scripts/gw_db_backup.py::restore_database()` docstring  
**Impact:** Concurrent writes during sidecar moves (`-wal`/`-shm`) can corrupt database or cause races.  
**Mitigation:** Docstring explicitly states: "The service must be stopped by the operator before restoring. The service is never stopped or started; the caller must ensure the database is not in use."  
**Recommendation:** Add runtime check for open SQLite connections (e.g., `fuser` or `lsof`) and warn/fail if DB in use.

---

### BAK-006: Preflight Accepts Unrelated SQLite Database (MEDIUM — FIXED)

**Location:** `backend/app/backup_preflight.py::run_backup_preflight()`  
**Attack Vector:** Unrelated SQLite file named `greywatch.db.unrelated` placed in backup dir. Passes integrity/FK checks, accepted as valid backup.  
**Impact:** Migration runs against wrong data; schema verification may pass but data is unrelated.  
**Root Cause:** Only `PRAGMA integrity_check` and `foreign_key_check` performed — no schema provenance.  
**Fix:** `_check_backup_provenance(live_db, candidate)` — compares table sets. Backup must contain all core Greywatch tables (`events`, `agents`, `api_keys`, `audit_log`, `schema_migrations`) and no unexpected tables. Skipped for fresh/empty live DBs.  
**Verification:** Code inspection only; no dedicated automated test for the provenance comparison.

---

## Category 2: Authentication & Cryptographic Boundaries

### AUTH-001: Malformed Per-Agent Rate Config Crashes Startup (MEDIUM — FIXED)

**Location:** `backend/app/agents.py::get_agent_rate_limit_config()`  
**Attack Vector:** `GREYWATCH_AGENT_RATE_INGESTION=not-a-number` → unguarded `int()` raises `ValueError` at import/module load time.  
**Impact:** Application fails to start; configuration error becomes crash.  
**Fix:** `_env_positive_int()` / `_env_positive_float()` helpers — validate digits, positivity, fail closed with actionable error messages.  
**Verification:** Code inspection only; no dedicated automated test for malformed env values.

---

### AUTH-002: Unbounded PBKDF2 Iterations in Stored Hash (HIGH — FIXED)

**Location:** `backend/app/agents.py::_verify_key()`  
**Attack Vector:** Malicious/corrupted hash stores iteration count `10**20` → `hashlib.pbkdf2_hmac()` raises `OverflowError` or consumes unbounded CPU. Triggered by any auth attempt against that key.  
**Impact:** DoS via CPU exhaustion; 500 errors on login; potential DB write path amplification (rehash-on-auth).  
**Root Cause:** No ceiling on stored iteration count.  
**Fix:** `MAX_KEY_HASH_ITERATIONS = 10_000_000`. `_verify_key()` rejects stored iterations > ceiling. Catches `OverflowError` from platform PBKDF2 limit. Logs and returns `False`.  
**Verification:** Code inspection only; no dedicated automated test for the iteration ceiling.

---

### AUTH-003: Pre-Auth Identity Spoofing via Loopback Trust (REPORT-ONLY — ARCHITECTURAL LIMITATION)

**Location:** `backend/app/main.py::PreAuthAgentRateLimitMiddleware` + trust boundary logic  
**Attack Vector:** From loopback peer (trusted by default), rotate `X-Greywatch-Client-IP` header → distinct limiter identities per request. Bypasses per-IP rate limit.  
**Impact:** Local attacker can exhaust pre-auth bucket store, causing legitimate loopback clients to be rate-limited.  
**Root Cause:** Loopback peers are trusted by default (`TRUSTED_PROXIES` defaults to loopback CIDRs). Header spoofing works because trust boundary evaluates `client` as loopback → trusted → uses header.  
**Mitigation Documented:** Deployment guide recommends configuring `GREYWATCH_TRUSTED_PROXIES` explicitly in production; loopback trust is a development convenience. No code fix — documented limitation.  
**Verification:** `test_untrusted_peer_cannot_spoof_forwarded_headers` confirms non-loopback peers blocked; loopback behavior is by design.

---

### AUTH-004: Pre-Auth Limiter Thread Safety (MEDIUM — FIXED)

**Location:** `backend/app/main.py::PreAuthAgentRateLimitMiddleware`  
**Issue:** `_buckets` OrderedDict accessed without lock under concurrent threads (threadpool / multiple workers).  
**Fix:** Added `threading.Lock` guarding all `_buckets` operations.  
**Verification:** `test_preauth_limiter_thread_safety` (existing, now passes).

---

## Category 3: Audit Chain Integrity

### AUD-001: Unkeyed SHA-256 Chain Allows Full Rewrite (REPORT-ONLY — ARCHITECTURAL LIMITATION)

**Location:** `backend/app/audit_chain.py` — `compute_chain_hash`, `verify_chain`  
**Attack Vector:** Delete/rewrite any audit row, recompute entire chain from genesis using public helpers. `verify_chain()` returns `(True, [])`. Tail truncation also verifies.  
**Impact:** Audit log provides tamper-evidence only against accidental corruption, not malicious rewrite. No external anchor (HSM, KMS, remote log, Merkle root).  
**Root Cause:** Chain hash is `SHA256(prev_hash || canonical_row)` — unkeyed, deterministic, reproducible.  
**Mitigation Documented:** Design explicitly states "unkeyed hash chain provides insertion-order integrity, not tamper-proofing against privileged access." No code fix — documented as limitation.  
**Verification:** `probe_audit_chain_rewrite.py` confirms full chain recompute passes verification.

---

### AUD-002: Best-Effort Auth-Failure Audit May Drop Events (REPORT-ONLY — ARCHITECTURAL LIMITATION)

**Location:** `backend/app/agents.py::_audit_log()`  
**Issue:** Authentication failures use `_audit_log()` (best-effort, swallows exceptions). If audit DB unavailable, auth failures are silently dropped.  
**Impact:** Attacker can trigger audit unavailability (disk full, lock contention) to avoid leaving auth-failure trail.  
**Root Cause:** Design decision: "Authentication failures must not turn into a different failure mode when audit storage is unavailable."  
**Mitigation Documented:** This is explicitly documented in `_audit_log()` docstring. Lifecycle events (key gen, rotation, revocation) use `_audit_connection()` (IMMEDIATE transaction, atomic with state change). No code fix — documented trade-off.

---

## Category 4: Migration & Bootstrap

### MIG-001: Fresh-DB Bootstrap Fails with Default Config (CRITICAL — RELEASE-BLOCKING — FIXED)

**Location:** `backend/app/migrations/runner.py::migrate()` + `backend/app/backup_preflight.py::run_backup_preflight()`  
**Trigger:** New deployment with no `GREYWATCH_BACKUP_DIR` configured. `GREYWATCH_REQUIRE_BACKUP` defaults to required.  
**Error:** `RuntimeError: Database migration failed: GREYWATCH_REQUIRE_BACKUP defaults to required ... GREYWATCH_BACKUP_DIR is not configured`  
**Impact:** README quick-start and `.env.example` (backup vars commented out) are broken. First-run impossible without manual backup dir creation.  
**Root Cause:** Backup preflight ran for ALL migratable states including `FRESH`. A fresh database has no backup to verify.  
**Fix:** Exempt `DatabaseState.FRESH` from backup preflight in `migrate()`. Other states (`LEDGER_ONLY`, `PENDING`, `LEGACY_READY`) still require backup because they have existing data at risk.  
**Verification:** `test_fresh_database_migrates_without_backup` (new in `test_backup_preflight.py`), `test_startup_fresh_succeeds_without_backup` (new in `test_startup_integration.py`). All bootstrap paths now work.

---

### MIG-002: Ledger NULL Name Constraint Enforcement (TEST FIX — NOT A PROD BUG)

**Location:** `backend/app/migration_ledger.py::create_schema_migrations_table()`  
**Issue:** Test `test_ledger_null_name_rejected` attempted to insert `NULL` name directly via SQL, but schema has `NOT NULL` constraint. Test failed with `IntegrityError` before validation logic ran.  
**Fix:** Test updated to use `MockRow` dict simulating `sqlite3.Row` with `name=None` (bypassing DB constraint), exercising validation logic `validate_applied_versions()` directly.  
**Verification:** Test now passes.

---

## Category 5: Retention & Data Loss

### RET-001: Retention Incident Race (LOW — NOT A FINDING)

**Analysis:** Retention job deletes events older than threshold. Incident-evidence FK (`incident_events.event_id → events.id ON DELETE RESTRICT`) blocks deletion of events still linked to incidents. Delete raises `FOREIGN KEY constraint failed`, transaction rolls back — no evidence loss. New alerts cannot cover already-old events because alert windows anchored near ingestion time.  
**Conclusion:** Race is theoretical/low; FK enforcement prevents data loss. No fix needed.

---

### RET-002: Retention Requires Manual Scheduling (DOCUMENTED)

**Location:** `scripts/gw_db_backup.py::prune_backups()` — no cron/systemd timer installed by default.  
**Impact:** Operator must configure retention schedule manually.  
**Mitigation Documented:** Deployment guide includes example systemd timer.

---

## Summary of Fixes Applied

| File | Changes |
|------|---------|
| `scripts/gw_db_backup.py` | Hardlink/symlink rejection; `_online_copy` WAL-safe staging; `mkstemp` 0600 pre-copy; verified-only rollback; sidecar cleanup helpers |
| `backend/app/backup_preflight.py` | `_check_backup_provenance()` schema comparison; skip provenance for fresh DB |
| `backend/app/migrations/runner.py` | Exempt `FRESH` state from backup preflight |
| `backend/app/agents.py` | `_env_positive_int/float` safe parsing; `MAX_KEY_HASH_ITERATIONS=10M` ceiling; `OverflowError` catch |
| `backend/app/main.py` | `threading.Lock` for pre-auth bucket store |
| `backend/tests/test_db_backup.py` | 1 new regression test (`test_pre_restore_copy_is_0600_at_creation`) |
| `backend/tests/test_backup_preflight.py` | 2 new FRESH-exemption tests; `LEGACY_READY` fixture updates |
| `backend/tests/test_preauth_rate_limit.py` | Thread-safety regression tests |
| `backend/tests/test_startup_integration.py` | Fixtures updated to `LEGACY_READY`; 1 new FRESH-exemption test; rollback test rewritten as a real injected-failure test |
| `docs/DEPLOYMENT.md` | Documented backup/restore requirements, retention scheduling |
| `docs/MIGRATION_RUNNER.md` | Documented FRESH exemption, backup policy |
| `backend/.env.example` | Added comment clarifying backup dir requirement for non-fresh DBs |

---

## Test Evidence

```
$ python3 -m pytest backend/tests -q
1023 passed, 240 warnings in 27.73s
```

All tests pass. Dedicated regression tests cover BAK-001, BAK-002, BAK-003, BAK-004's rollback path, and MIG-001; BAK-004's unverified-pre-copy branch, BAK-006, AUTH-001, and AUTH-002 rest on code inspection/manual probes.

---

## Release Readiness

**Status: READY FOR HUMAN REVIEW** — No release blockers within this audit's scope. Report-only findings are documented architectural limitations, not hidden bugs. Open Agent 1 follow-ups outside this fix set: AUTH-002 per-agent bucket eviction, API-001/002/004, DB-002, MIG-003, RL-001.