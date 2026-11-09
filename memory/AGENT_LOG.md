# Agent Session Log

> Append-only log of agent session work. One dated entry per session/task.

---

## 2026-11-09 — Security-Critical Audit & Fixes (Agent 2)

**Agent role:** Security-Critical Auditor (Agent 2)

**Objective:** Security-critical audit of Greywatch covering API auth/authz, agent/shared tokens, rate limiting, trusted proxies, body limits, audit-chain integrity, migrations, backups/restore, retention, and SQLite integrity. Produce three audit reports with severity, code references, attack scenarios, impact, reproduction, remediation, test evidence, and release-blocker determination. Implement isolated, justified security fixes with regression tests, without overlapping Agent 1's backend work.

**Baseline (verified 2026-11-09 on commit `3f23135`):** `python3 -m pytest backend/tests -q` → **11 failed, 1011 passed, 240 warnings**. All 11 failures were `NameError: _create_legacy_ready_db` in `test_startup_integration.py`, introduced by the uncommitted diff. The earlier "1015 passed" note was not reproducible.

**Post-repair (2026-11-09):** `python3 -m pytest backend/tests -q` → **1023 passed, 240 warnings in 27.73s**

**Context:** This audit focused on runtime enforcement gaps, cryptographic boundary conditions, operational failure modes, and data integrity guarantees not addressed by Agent 1's API key design audit. Local development database at `data/greywatch.db` (ledger v1) was never modified.

### Files Changed in This Session

**Core Fixes:**
- `scripts/gw_db_backup.py` — hardlink/symlink rejection, WAL-safe `_online_copy`, `mkstemp` 0600 pre-copy, verified-only rollback, sidecar cleanup
- `backend/app/backup_preflight.py` — `_check_backup_provenance()` schema comparison, FRESH exemption
- `backend/app/migrations/runner.py` — exempt `FRESH` state from backup preflight (fixes bootstrap)
- `backend/app/agents.py` — `_env_positive_int/float`, `MAX_KEY_HASH_ITERATIONS=10M`, `OverflowError` catch
- `backend/app/main.py` — `threading.Lock` for pre-auth bucket store

**Regression Tests:**
- `backend/tests/test_db_backup.py` — 1 new test (`test_pre_restore_copy_is_0600_at_creation`, BAK-003); existing restore tests unchanged
- `backend/tests/test_backup_preflight.py` — 2 new FRESH-exemption tests plus LEGACY_READY fixture updates
- `backend/tests/test_agent_rate_limit.py` — 1 new test
- `backend/tests/test_auth_threadpool.py` — 1 new test
- `backend/tests/test_startup_integration.py` — fixtures updated to `LEGACY_READY`, 1 new FRESH-exemption test, misleading rollback test rewritten (see below)

**Documentation:**
- `docs/DEPLOYMENT.md` — backup/restore requirements, retention scheduling, synchronous=NORMAL trade-off
- `docs/MIGRATION_RUNNER.md` — FRESH exemption, backup policy
- `backend/.env.example` — clarified backup dir requirement for non-fresh DBs

**Audit Reports:**
- `reports/AGENT2_SECURITY_AUDIT.md`
- `reports/AGENT2_DATABASE_AUDIT.md`
- `reports/AGENT2_FINDINGS.md`

**Memory:**
- `memory/PROJECT_STATE.md` (updated)
- `memory/AGENT_LOG.md` (this entry)

### Summary of Findings (16 total)

| Category | Fixed | Report-Only | Documented | Test Fix | Not a Finding |
|----------|-------|-------------|------------|----------|---------------|
| Backup/Restore (BAK-*) | 5 | 0 | 1 | 0 | 0 |
| Auth/Crypto (AUTH-*) | 3 | 1 | 0 | 0 | 0 |
| Audit Chain (AUD-*) | 0 | 2 | 0 | 0 | 0 |
| Migration (MIG-*) | 1 | 0 | 0 | 1 | 0 |
| Retention (RET-*) | 0 | 0 | 1 | 0 | 1 |
| **Total** | **9** | **3** | **2** | **1** | **1** |

**Release-Blocking Issues:** MIG-001 (Fresh-DB bootstrap failure) — **RESOLVED**

### Key Fix Details

**BAK-001 (Hardlink Restore Data Loss — HIGH):** `os.path.samefile()` detects inode identity. Hardlink to live DB now rejected. Probe: `probe_hardlink.py` confirms live DB retains `wal-value`.

**BAK-002 (WAL Backup Restore Loses Frames — HIGH):** `_online_copy()` uses SQLite backup API, converts WAL backup to single-file DELETE mode. Probe: `probe_walbackup3.py` confirms `wal-value` preserved.

**BAK-003 (Pre-Copy Readable Window — MEDIUM):** **Initially misclaimed fixed; actually fixed in the 2026-11-09 repair pass.** `restore_database()` now uses `tempfile.mkstemp(dir=dest_dir, ...)` (0600 at creation), closes the fd, copies with `_online_copy()`, and atomically publishes via `os.replace()`. `test_pre_restore_copy_is_0600_at_creation` stats the destination before the copy runs and after publication.

**BAK-004 (Rollback Overwrites with Failed Pre-Copy — HIGH):** `pre_copy_verified` guard prevents rollback with unverified pre-copy. Probe: `probe_precopy.py` confirms live DB untouched on simulated disk-full.

**BAK-006 (Unrelated Backup Accepted — MEDIUM):** `_check_backup_provenance()` compares table sets. Backup must contain all core tables (`events`, `agents`, `api_keys`, `audit_log`, `schema_migrations`).

**AUTH-001 (Malformed Rate Config — MEDIUM):** `_env_positive_int/float` validate digits, positivity, fail closed with actionable errors.

**AUTH-002 (Unbounded PBKDF2 Iterations — HIGH):** `MAX_KEY_HASH_ITERATIONS=10M` ceiling. Rejects stored iterations > ceiling. Catches `OverflowError`.

**AUTH-003 (Loopback Identity Spoofing — LOW, REPORT-ONLY):** Architectural limitation documented. Loopback trusted by default; header spoofing works. Mitigation: configure `GREYWATCH_TRUSTED_PROXIES` in production.

**AUTH-004 (Pre-Auth Thread Safety — MEDIUM):** `threading.Lock` guards `_buckets` OrderedDict.

**AUD-001 (Unkeyed Chain Rewrite — HIGH, REPORT-ONLY):** Architectural limitation documented. Chain is unkeyed SHA-256; full rewrite passes verification. Requires external anchor (HSM/KMS/remote log) for tamper-proofing.

**AUD-002 (Best-Effort Auth-Failure Audit — MEDIUM, REPORT-ONLY):** Documented trade-off. `_audit_log()` swallows exceptions; lifecycle events use atomic `_audit_connection()`.

**MIG-001 (Fresh-DB Bootstrap Fails — CRITICAL, FIXED):** Exempt `FRESH` state from backup preflight. Fresh deployments now work.

**MIG-002 (Ledger NULL Name — LOW, TEST FIX):** Test updated to use `MockRow` simulating corrupted row, exercising validation logic directly.

**RET-001 (Retention Incident Race — LOW, NOT A FINDING):** FK `ON DELETE RESTRICT` blocks deletion of incident-linked events. Transaction rolls back — no evidence loss.

### Isolated Probe Verification

All fixes verified with adversarial probes in `/tmp/opencode/gw-audit/`:
- `probe_hardlink.py` — hardlink restore rejected, live DB retains `wal-value`
- `probe_walbackup3.py` — WAL backup verified, `wal-value` preserved in main file
- `probe_precopy.py` — simulated disk-full leaves live DB untouched (not overwritten)

### Verification Results (2026-11-09 repair pass)

- Full backend test suite: **1023 passed, 240 warnings in 27.73s**
- Security-focused suites: `test_db_backup.py`, `test_backup_preflight.py`, `test_agent_rate_limit.py`, `test_auth_threadpool.py`, `test_preauth_rate_limit.py` → **116 passed, 1 warning**
- Startup integration: `test_startup_integration.py` → **41 passed, 1 warning**
- `git diff --check` → clean
- No credentials/secrets in reports
- No security controls weakened to make tests pass
- No migration history changed without explicit justification
- No frontend or detection modules modified

### Repair Pass Notes

- **Task 1:** Extracted the LEGACY_READY schema into module-level `_create_legacy_ready_db()`; the `legacy_ready_db` fixture delegates to it. The 11 `NameError` failures are gone.
- **Task 3:** Replaced `test_migration_failure_rolls_back_transaction`. The old test called `migrate()` first (committing), then added a table and raised; it asserted nothing about rollback. The new test injects a `sqlite3.OperationalError` into migration v3 after a probe-table write and asserts the database remains `LEGACY_READY` with no ledger, no `agents`/`audit_log` tables, no probe table, and no v1/v2 effects; it then removes the fault and migrates cleanly to `CURRENT` (4 applied).
- **BAK-003:** Was previously reported fixed without the implementation. Now actually fixed and covered by a regression test.

### Remaining Work

- No release blockers within this audit's scope; reports and diff are ready for human review.
- Open Agent 1 follow-ups outside this fix set: AUTH-002 per-agent bucket eviction, API-001/002/004, DB-002, MIG-003, RL-001.
- Not committed by design; the worktree is left for human review.

---

## 2026-10-31 — Event Retention System (final verification & handoff)

**Agent role:** Laguna S 2.1 (poolside/laguna-s-2.1) — finalizing the
`feat/event-retention` work.

**Context:** A prior session implemented the event-retention / database
lifecycle system on `feat/event-retention`. This session performed final
verification, documentation fixes, and committed the changes.

**Files changed in this session**
- `backend/app/siem.py` — removed one unused `field` import left over from the
  retention dataclasses (no behavior change; `logger` and `dataclass` retained).
- `docs/DEPLOYMENT.md` — updated "Unresolved blockers" item 5: "No
  retention/pruning" → retention is now implemented (links to §2.14/DEPLOYMENT
  retention section, notes VACUUM still requires downtime).
- `docs/PROJECT_STATE.md` — updated "Last verified" date to 2026-10-31; added
  §2.14 (Event Retention & Database Lifecycle Management); added
  `retention.py`, `test_retention.py`, `gw_retention.sh` to the repo-structure
  tree; added 2026-10-31 verification rows (backend 414 passed, frontend lint +
  build) to §4.
- `memory/AGENT_LOG.md` — this file (created).

**Pre-existing files (from prior session, verified, not re-authored):**
`backend/app/retention.py` (CLI), `backend/tests/test_retention.py` (37 cases),
`scripts/gw_retention.sh` (wrapper), `README.md` (Database Lifecycle Mgmt
section), `backend/.env.example` (retention env vars).

**Verification results**
- Backend: `python -m pytest backend/tests -q` → **414 passed, 1 warning**
  (50 `test_retention.py` cases — 37 original + 13 batch-size env-var config
  cases — among the total; the 1 warning is the pre-existing Starlette
  `httpx` deprecation).
- Retention subset: `pytest backend/tests/test_retention.py -q` → **51 passed**.
- `git diff --check` → clean (no whitespace / conflict-marker errors).
- Frontend: `npm run lint` → exit 0 (only pre-existing warnings; retention
  touched no frontend files). `npm run build` → exit 0 (Vite 8.3.4).
- Retention config validated: unset/0/negative/non-numeric all disable
  retention; positive integer accepted. Dry-run deletes nothing; execute
  respects incident + open-alert evidence protection; FK check clean after
  deletion; batch deletion commits per batch; rollback on failure; concurrent
  ingest supported in WAL mode; VACUUM gated behind `--vacuum` + service stop.

**Remaining work**
- None blocking. Suggested follow-ups (out of scope, pre-existing doc debt):
  the `docs/PROJECT_STATE.md` frontend/ subtree and several file line-counts are
  stale relative to the current repo (they predated this feature); reconcile at
  the repo owner's discretion.

---

## 2026-10-31 — Task 2: Configurable GREYWATCH_RETENTION_BATCH_SIZE

**Agent role:** Laguna S 2.1 (poolside/laguna-s-2.1)

**Objective:** Read and honor `GREYWATCH_RETENTION_BATCH_SIZE` from the
environment in the retention engine and CLI, with safe-validation fallback to
the documented default of 1000. (Backend only; no frontend or DEPLOYMENT.md
edits.)

**Changes**
- `backend/app/siem.py` (M): added `RETENTION_BATCH_SIZE_ENV` constant and
  `get_retention_batch_size()` validator (unset/zero/negative/non-numeric → 1000
  with a logged warning). `prune_events(batch_size: int | None = None)` now
  resolves `None` → `get_retention_batch_size()`. `compute_retention_summary`
  reports the env-derived batch size in every return path.
- `backend/app/retention.py` (M): `--batch-size` default changed from
  `DEFAULT_RETENTION_BATCH_SIZE` to `None` (sentinel so `prune_events` resolves
  the env value); updated help text; re-exported `RETENTION_BATCH_SIZE_ENV`.
- `backend/tests/test_retention.py` (M): added 13 batch-size config tests
  (env override, unset→1000, zero/negative/non-numeric fallback, explicit-arg
  override, prune/compute resolution, CLI end-to-end env + explicit override).
- `docs/PROJECT_STATE.md` (M): updated 37→50 cases and 401→414 passed.

**Verification**
- Focused: `pytest backend/tests/test_retention.py -q` → 51 passed.
- Full backend suite: → 414 passed, 1 pre-existing warning.

**Status:** Complete. No commit/push (per task boundary).
