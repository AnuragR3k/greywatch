# Greywatch Agent 2 — Security Findings Register

**Audit Date:** 2026-11-09  
**Baseline:** `3f23135` (main)  
**Post-Fix Test Suite:** 1023 passed, 240 warnings (verified 2026-11-09 repair pass)

---

## Finding Format

| Field | Description |
|-------|-------------|
| **ID** | Unique identifier (CAT-NNN) |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| **Status** | FIXED / REPORT-ONLY / DOCUMENTED / WONT-FIX |
| **Component** | File:function or module |
| **Attack Scenario** | How an attacker/operator triggers the issue |
| **Impact** | Confidentiality / Integrity / Availability / Operational |
| **Root Cause** | Code-level explanation |
| **Reproduction** | Steps or probe script reference |
| **Remediation** | Fix applied or mitigation |
| **Test Evidence** | Regression test name / location |
| **Release Blocker** | Yes/No — blocks release if unfixed |

---

## Backup & Restore (BAK-*)

### BAK-001: Hardlink Restore Data Loss
| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Status** | FIXED |
| **Component** | `scripts/gw_db_backup.py::restore_database()` |
| **Attack Scenario** | Attacker with backup dir write access: `ln /var/lib/greywatch/live.db /var/backups/greywatch/greywatch.db.backup`. Operator runs `gw_db_backup.sh restore`. |
| **Impact** | Integrity (silent data loss) — live DB reverts to stale main file; committed WAL frames lost. |
| **Root Cause** | `os.path.realpath()` comparison doesn't detect hardlinks. SQLite opens hardlink read-only without live DB's `-wal`. |
| **Reproduction** | `probe_hardlink.py` — live DB content changes from `wal-value` to `main-value` after restore. |
| **Remediation** | `os.path.samefile()` detects inode identity. Rejects backup if `samefile(backup, dest)`. |
| **Test Evidence** | `test_hardlink_to_live_database_is_rejected` (`backend/tests/test_backup_preflight.py`) |
| **Release Blocker** | No (fixed) |

---

### BAK-002: WAL-Mode Backup Restore Loses Committed Frames
| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Status** | FIXED |
| **Component** | `scripts/gw_db_backup.py::restore_database()` |
| **Attack Scenario** | Valid WAL-mode backup (main + `-wal`) created. Restore copies only main file via `shutil.copyfile()`. |
| **Impact** | Integrity — live DB loses WAL-only updates. Pre-restore copy retains them (divergence). |
| **Root Cause** | Restore used `shutil.copyfile()` on main file only. WAL backup keeps committed frames in `-wal`; copying main alone is lossy. |
| **Reproduction** | `probe_walbackup3.py` — verified backup has `wal-value` in main after checkpoint; original restore would lose it. |
| **Remediation** | `_online_copy()` using SQLite backup API (copies WAL frames into main, converts to DELETE journal mode). |
| **Test Evidence** | `test_wal_mode_backup_is_accepted` (`test_backup_preflight.py`) |
| **Release Blocker** | No (fixed) |

---

### BAK-003: Pre-Restore Copy Readable by Local Users
| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Status** | FIXED |
| **Component** | `scripts/gw_db_backup.py::restore_database()` — pre-copy creation |
| **Attack Scenario** | Local user watches `/var/lib/greywatch/` during restore. Pre-copy created at 0o644 for ~ms before `chmod 0600`. |
| **Impact** | Confidentiality — full DB snapshot readable by local users during window. |
| **Root Cause** | `sqlite3.connect()` creates file before permissions applied. |
| **Reproduction** | Code inspection — file mode 0o644 under umask 0002 between `connect()` and `chmod()`. |
| **Remediation** | `tempfile.mkstemp(dir=dest_dir, ...)` creates the pre-copy at 0600 atomically; the fd is closed, `_online_copy()` copies into it, then a same-directory `os.replace()` publishes it under its stable name (mode preserved). `verify_database()` sets `pre_copy_verified`, so the rollback guard only restores a verified copy. |
| **Test Evidence** | `test_pre_restore_copy_is_0600_at_creation` (`test_db_backup.py`) — intercepts `_online_copy()` and asserts the destination is 0600 before the copy runs, then asserts the published copy is 0600. |
| **Release Blocker** | No (fixed) |

> Note: an earlier revision of this report claimed this fix before it was implemented. The code and test above are the corrected, verified implementation (2026-11-09).

---

### BAK-004: Restore Rollback Overwrites Live DB with Failed Pre-Copy
| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Status** | FIXED |
| **Component** | `scripts/gw_db_backup.py::restore_database()` — exception handler |
| **Attack Scenario** | Disk full / permission error during pre-copy creation. Exception handler replaces live DB with partial/invalid pre-copy. |
| **Impact** | Availability + Integrity — live DB becomes unreadable/corrupted. |
| **Root Cause** | Rollback logic didn't check `pre_copy_verified` before `os.replace(pre_copy, dest_real)`. |
| **Reproduction** | `probe_precopy.py` — simulated disk-full during pre-copy leaves live DB unreadable (`DatabaseError: file is not a database`). |
| **Remediation** | Track `pre_copy_verified` boolean. Rollback only restores verified pre-copy. Failed pre-copy → cleanup only, live DB untouched. |
| **Test Evidence** | `test_restore_failure_preserves_original_database` (`test_db_backup.py`) covers rollback with a verified pre-copy. The unverified-pre-copy branch was verified by the manual `probe_precopy.py`; no dedicated automated test. |
| **Release Blocker** | No (fixed) |

---

### BAK-005: Restore Does Not Verify Service Stopped
| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Status** | DOCUMENTED |
| **Component** | `scripts/gw_db_backup.py::restore_database()` docstring |
| **Attack Scenario** | Operator runs restore while `greywatch-api` service running. Concurrent writes during sidecar moves (`-wal`/`-shm`) corrupt DB or race. |
| **Impact** | Integrity — database corruption; Availability — service may crash. |
| **Root Cause** | Tool does not check for open connections; assumes operator stops service. |
| **Remediation** | Docstring: "The service must be stopped by the operator before restoring. The service is never stopped or started; the caller must ensure the database is not in use." |
| **Test Evidence** | N/A (documented requirement) |
| **Release Blocker** | No (documented) |

---

### BAK-006: Preflight Accepts Unrelated SQLite Database
| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Status** | FIXED |
| **Component** | `backend/app/backup_preflight.py::run_backup_preflight()` |
| **Attack Scenario** | Unrelated SQLite file named `greywatch.db.unrelated` placed in backup dir. Passes integrity/FK checks, accepted as backup. Migration runs against wrong data. |
| **Impact** | Integrity — migration applies to unrelated data; operational confusion. |
| **Root Cause** | Only `PRAGMA integrity_check` and `foreign_key_check` performed — no schema provenance. |
| **Reproduction** | Create unrelated SQLite DB with same prefix in backup dir; preflight passes. |
| **Remediation** | `_check_backup_provenance(live_db, candidate)` — compares table sets. Backup must contain all core tables and no unexpected tables. Skipped for fresh/empty live DB. |
| **Test Evidence** | Code inspection only; no dedicated automated test for the provenance comparison. |
| **Release Blocker** | No (fixed) |

---

## Authentication & Cryptographic Boundaries (AUTH-*)

### AUTH-001: Malformed Per-Agent Rate Config Crashes Startup
| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Status** | FIXED |
| **Component** | `backend/app/agents.py::get_agent_rate_limit_config()` |
| **Attack Scenario** | `GREYWATCH_AGENT_RATE_INGESTION=not-a-number` in environment. Module load → `int()` raises `ValueError`. |
| **Impact** | Availability — application fails to start; config error becomes crash. |
| **Root Cause** | Unguarded `int()`/`float()` on environment variables. |
| **Reproduction** | `python -c "import os; os.environ['GREYWATCH_AGENT_RATE_INGESTION']='x'; from backend.app.agents import get_agent_rate_limit_config; get_agent_rate_limit_config()"` → `ValueError`. |
| **Remediation** | `_env_positive_int()` / `_env_positive_float()` helpers — validate digits, positivity, fail closed with actionable messages. |
| **Test Evidence** | Code inspection only; no dedicated automated test for malformed env values. |
| **Release Blocker** | No (fixed) |

---

### AUTH-002: Unbounded PBKDF2 Iterations in Stored Hash
| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Status** | FIXED |
| **Component** | `backend/app/agents.py::_verify_key()` |
| **Attack Scenario** | Malicious/corrupted hash stores iterations=`10**20`. Any auth attempt against that key → `OverflowError` or unbounded CPU. |
| **Impact** | Availability (DoS) — CPU exhaustion; 500 errors on login; rehash-on-auth amplifies. |
| **Root Cause** | No ceiling on stored iteration count. `hashlib.pbkdf2_hmac()` raises `OverflowError` for large values. |
| **Reproduction** | `_verify_key('key', 'pbkdf2_sha256$100000000000000000000$...$...')` → `OverflowError`. |
| **Remediation** | `MAX_KEY_HASH_ITERATIONS = 10_000_000`. Reject stored iterations > ceiling. Catch `OverflowError`, log, return `False`. |
| **Test Evidence** | Code inspection only; no dedicated automated test for the iteration ceiling. |
| **Release Blocker** | No (fixed) |

---

### AUTH-003: Pre-Auth Identity Spoofing via Loopback Trust
| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Status** | REPORT-ONLY (architectural limitation) |
| **Component** | `backend/app/main.py::PreAuthAgentRateLimitMiddleware` + trust boundary |
| **Attack Scenario** | From loopback peer (trusted by default), rotate `X-Greywatch-Client-IP` header → distinct limiter identities per request. Bypasses per-IP rate limit. |
| **Impact** | Availability — local attacker exhausts pre-auth bucket store, legitimate loopback clients rate-limited. |
| **Root Cause** | Loopback peers trusted by default (`TRUSTED_PROXIES` defaults to loopback CIDRs). Header spoofing works because trust boundary evaluates `client` as loopback → trusted → uses header. |
| **Reproduction** | `test_trusted_proxy_supplies_client_identity` — loopback peer with `X-Greywatch-Client-IP` gets that identity. |
| **Remediation** | Documented: Deployment guide recommends configuring `GREYWATCH_TRUSTED_PROXIES` explicitly in production; loopback trust is development convenience. |
| **Test Evidence** | `test_untrusted_peer_cannot_spoof_forwarded_headers` confirms non-loopback blocked |
| **Release Blocker** | No (documented limitation) |

---

### AUTH-004: Pre-Auth Limiter Thread Safety
| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Status** | FIXED |
| **Component** | `backend/app/main.py::PreAuthAgentRateLimitMiddleware` |
| **Attack Scenario** | Concurrent requests via threadpool / multiple workers access `_buckets` OrderedDict without lock. |
| **Impact** | Integrity — bucket corruption; Availability — potential crashes. |
| **Root Cause** | No lock guarding `_buckets` operations. |
| **Reproduction** | `test_preauth_limiter_thread_safety` — 50 concurrent requests from 5 threads. |
| **Remediation** | Added `threading.Lock` guarding all `_buckets` operations. |
| **Test Evidence** | `test_preauth_limiter_thread_safety` (`test_preauth_rate_limit.py`) — now passes |
| **Release Blocker** | No (fixed) |

---

## Audit Chain Integrity (AUD-*)

### AUD-001: Unkeyed SHA-256 Chain Allows Full Rewrite
| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Status** | REPORT-ONLY (architectural limitation) |
| **Component** | `backend/app/audit_chain.py::compute_chain_hash`, `verify_chain` |
| **Attack Scenario** | Delete/rewrite any audit row, recompute entire chain from genesis using public helpers. `verify_chain()` returns `(True, [])`. Tail truncation also verifies. |
| **Impact** | Integrity — audit log provides tamper-evidence only against accidental corruption, not malicious rewrite. No external anchor. |
| **Root Cause** | Chain hash = `SHA256(prev_hash || canonical_row)` — unkeyed, deterministic, reproducible. |
| **Reproduction** | `probe_audit_chain_rewrite.py` — delete row, recompute chain, `verify_chain()` passes. |
| **Remediation** | Documented limitation: "unkeyed hash chain provides insertion-order integrity, not tamper-proofing against privileged access." No code fix — requires external anchor (HSM, KMS, remote log) for tamper-proofing. |
| **Test Evidence** | N/A (design property) |
| **Release Blocker** | No (documented limitation) |

---

### AUD-002: Best-Effort Auth-Failure Audit May Drop Events
| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Status** | REPORT-ONLY (documented trade-off) |
| **Component** | `backend/app/agents.py::_audit_log()` |
| **Attack Scenario** | Attacker triggers audit unavailability (disk full, lock contention) during auth attempts. Auth failures silently dropped. |
| **Impact** | Integrity — no audit trail of authentication failures under adversarial conditions. |
| **Root Cause** | Design decision: `_audit_log()` swallows exceptions. "Authentication failures must not turn into a different failure mode when audit storage is unavailable." |
| **Reproduction** | Fill audit DB disk; attempt auth with invalid key; no audit row written. |
| **Remediation** | Documented in `_audit_log()` docstring. Lifecycle events (key gen, rotation, revocation) use `_audit_connection()` (IMMEDIATE transaction, atomic with state change). |
| **Test Evidence** | N/A (design trade-off) |
| **Release Blocker** | No (documented trade-off) |

---

## Migration & Bootstrap (MIG-*)

### MIG-001: Fresh-DB Bootstrap Fails with Default Config
| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Status** | FIXED |
| **Component** | `backend/app/migrations/runner.py::migrate()` + `backend/app/backup_preflight.py::run_backup_preflight()` |
| **Attack Scenario** | New deployment, no `GREYWATCH_BACKUP_DIR` configured. `GREYWATCH_REQUIRE_BACKUP` defaults to required. Startup fails. |
| **Impact** | Availability — README quick-start and `.env.example` broken. First-run impossible without manual backup dir. |
| **Root Cause** | Backup preflight ran for ALL migratable states including `FRESH`. Fresh DB has no backup to verify. |
| **Reproduction** | Fresh temp DB, `GREYWATCH_REQUIRE_BACKUP=1`, no `GREYWATCH_BACKUP_DIR` → `RuntimeError: Database migration failed... GREYWATCH_BACKUP_DIR is not configured`. |
| **Remediation** | Exempt `DatabaseState.FRESH` from backup preflight in `migrate()`. Other states (`LEDGER_ONLY`, `PENDING`, `LEGACY_READY`) still require backup. |
| **Test Evidence** | `test_fresh_database_migrates_without_backup` (`test_backup_preflight.py`), `test_startup_fresh_succeeds_without_backup` (`test_startup_integration.py`) |
| **Release Blocker** | **YES** (was blocking; now fixed) |

---

### MIG-002: Ledger NULL Name Constraint Enforcement
| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Status** | TEST FIX (not a prod bug) |
| **Component** | `backend/app/migration_ledger.py::create_schema_migrations_table()` |
| **Attack Scenario** | Test attempted to insert `NULL` name via SQL, but schema has `NOT NULL` constraint. Test failed before validation logic ran. |
| **Impact** | Test failure only — production DB schema prevents NULL. |
| **Root Cause** | Test used direct SQL insert instead of simulating corrupted row via `MockRow`. |
| **Remediation** | Test updated to use `MockRow` dict simulating `sqlite3.Row` with `name=None`, exercising `validate_applied_versions()` directly. |
| **Test Evidence** | `test_ledger_null_name_rejected` (`test_migration_registry.py`) — now passes |
| **Release Blocker** | No |

---

## Retention & Data Loss (RET-*)

### RET-001: Retention Incident Race
| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Status** | NOT A FINDING (verified safe) |
| **Component** | `scripts/gw_db_backup.py::prune_backups()` + FK constraints |
| **Analysis** | Retention `DELETE FROM events WHERE timestamp < ?` raises `FOREIGN KEY constraint failed` for events linked via `incident_events`. Transaction rolls back — no evidence loss. Alert windows anchored near ingestion; cannot cover already-old events. |
| **Impact** | None — FK enforcement prevents data loss. |
| **Remediation** | No fix needed. |
| **Test Evidence** | `test_foreign_key_violation_rejected_on_event_delete` (`test_startup_integration.py`) |
| **Release Blocker** | No |

---

### RET-002: Retention Requires Manual Scheduling
| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Status** | DOCUMENTED |
| **Component** | `scripts/gw_db_backup.py::prune_backups()` — no cron/systemd timer installed |
| **Impact** | Operational — operator must configure retention schedule. |
| **Remediation** | Deployment guide includes example systemd timer. |
| **Release Blocker** | No |

---

## Summary Matrix

| ID | Severity | Status | Release Blocker |
|----|----------|--------|-----------------|
| BAK-001 | HIGH | FIXED | No |
| BAK-002 | HIGH | FIXED | No |
| BAK-003 | MEDIUM | FIXED | No |
| BAK-004 | HIGH | FIXED | No |
| BAK-005 | MEDIUM | DOCUMENTED | No |
| BAK-006 | MEDIUM | FIXED | No |
| AUTH-001 | MEDIUM | FIXED | No |
| AUTH-002 | HIGH | FIXED | No |
| AUTH-003 | LOW | REPORT-ONLY | No |
| AUTH-004 | MEDIUM | FIXED | No |
| AUD-001 | HIGH | REPORT-ONLY | No |
| AUD-002 | MEDIUM | REPORT-ONLY | No |
| MIG-001 | CRITICAL | FIXED | **WAS — NOW FIXED** |
| MIG-002 | LOW | TEST FIX | No |
| RET-001 | LOW | NOT A FINDING | No |
| RET-002 | INFO | DOCUMENTED | No |

**Total:** 16 entries  
**Fixed:** 8  
**Report-only (architectural):** 3  
**Documented:** 3  
**Test fix:** 1  
**Not a finding:** 1

---

## Verification Checklist

- [ ] All FIXED findings have dedicated regression tests — BAK-004's unverified-pre-copy branch, BAK-006, AUTH-001, and AUTH-002 currently rest on code inspection/manual probes.
- [x] Full test suite passes: `python3 -m pytest backend/tests -q` → 1023 passed
- [x] Isolated probes confirm fixes: `probe_hardlink.py`, `probe_walbackup3.py`, `probe_precopy.py`
- [x] Documentation updated: `DEPLOYMENT.md`, `MIGRATION_RUNNER.md`, `.env.example`
- [x] No credentials/secrets in reports
- [x] No security controls weakened to make tests pass