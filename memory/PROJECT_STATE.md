# Greywatch — Session Project State

> Session-memory snapshot. The canonical verified project document is
> `docs/PROJECT_STATE.md`; this file records the most recent agent tasks.

- **Date:** 2026-11-09
- **Branch:** `main`
- **Base commit:** `3f23135` (Merge pull request #11 from AnuragR3k/feat/migration-startup-integration)

## Objective

Perform a security-critical audit of Greywatch covering API auth/authz, agent/shared tokens, rate limiting, trusted proxies, body limits, audit-chain integrity, migrations, backups/restore, retention, and SQLite integrity. Produce `reports/AGENT2_SECURITY_AUDIT.md`, `reports/AGENT2_DATABASE_AUDIT.md`, and `reports/AGENT2_FINDINGS.md` with severity, code references, attack scenarios, impact, reproduction, remediation, test evidence, and release-blocker determination. Implement isolated, justified security fixes with regression tests, without overlapping Agent 1's backend work.

## Status

Complete for this audit's scope. Post-repair suite is green (1023 passed). Reports written. No commits yet; the worktree is left for human review.

## Completed Work

### Security Audit & Fixes (Agent 2)

**Baseline (verified 2026-11-09 on `3f23135`):** `python3 -m pytest backend/tests -q` → **11 failed, 1011 passed, 240 warnings**. All 11 failures were `NameError: _create_legacy_ready_db` in `test_startup_integration.py`.

**Post-repair (2026-11-09):** `python3 -m pytest backend/tests -q` → **1023 passed, 240 warnings in 27.73s**

**Repair pass:** extracted `_create_legacy_ready_db()` (Task 1); implemented the real BAK-003 `mkstemp` pre-copy, which had previously been misclaimed as fixed (Task 2); replaced the misleading rollback test with an injected-failure test that asserts a true rollback (Task 3).

---

#### Category 1: Backup & Restore Integrity (BAK-*)

| ID | Finding | Status |
|----|---------|--------|
| BAK-001 | Hardlink restore data loss | FIXED |
| BAK-002 | WAL-mode backup restore loses committed frames | FIXED |
| BAK-003 | Pre-restore copy readable by local users | FIXED |
| BAK-004 | Restore rollback overwrites live DB with failed pre-copy | FIXED |
| BAK-005 | Restore does not verify service stopped | DOCUMENTED |
| BAK-006 | Preflight accepts unrelated SQLite database | FIXED |

#### Category 2: Authentication & Cryptographic Boundaries (AUTH-*)

| ID | Finding | Status |
|----|---------|--------|
| AUTH-001 | Malformed per-agent rate config crashes startup | FIXED |
| AUTH-002 | Unbounded PBKDF2 iterations in stored hash | FIXED |
| AUTH-003 | Pre-auth identity spoofing via loopback trust | REPORT-ONLY |
| AUTH-004 | Pre-auth limiter thread safety | FIXED |

#### Category 3: Audit Chain Integrity (AUD-*)

| ID | Finding | Status |
|----|---------|--------|
| AUD-001 | Unkeyed SHA-256 chain allows full rewrite | REPORT-ONLY |
| AUD-002 | Best-effort auth-failure audit may drop events | REPORT-ONLY |

#### Category 4: Migration & Bootstrap (MIG-*)

| ID | Finding | Status |
|----|---------|--------|
| MIG-001 | Fresh-DB bootstrap fails with default config | **FIXED (was CRITICAL release-blocker)** |
| MIG-002 | Ledger NULL name constraint enforcement | TEST FIX |

#### Category 5: Retention & Data Loss (RET-*)

| ID | Finding | Status |
|----|---------|--------|
| RET-001 | Retention incident race | NOT A FINDING (FK protects) |
| RET-002 | Retention requires manual scheduling | DOCUMENTED |

---

### Key Fixes Implemented

#### `scripts/gw_db_backup.py`
- Reject backup hardlink/symlink destination via `os.path.samefile()`
- Stage restore via `_online_copy()` (WAL-safe, uses SQLite backup API)
- Create pre-copy at `0600` from creation with `mkstemp()`, copy into it with `_online_copy()`, then atomically publish with `os.replace()`
- Guard rollback so only verified pre-copy can replace live DB
- Cleanup helpers for sidecars

#### `backend/app/backup_preflight.py`
- `_check_backup_provenance()` — schema comparison (core tables must match)
- Skip provenance check for fresh/empty live DB

#### `backend/app/migrations/runner.py`
- Exempt `DatabaseState.FRESH` from backup preflight (fixes bootstrap)
- Other states (`LEDGER_ONLY`, `PENDING`, `LEGACY_READY`) still require backup

#### `backend/app/agents.py`
- `_env_positive_int()` / `_env_positive_float()` — safe env parsing, fail closed
- `MAX_KEY_HASH_ITERATIONS = 10_000_000` ceiling in `_verify_key()`
- Catch `OverflowError` from platform PBKDF2 limit

#### `backend/app/main.py`
- Added `threading.Lock` to `PreAuthAgentRateLimitMiddleware` bucket store

#### Regression Tests Added
- `backend/tests/test_db_backup.py`: 1 new test (`test_pre_restore_copy_is_0600_at_creation`, BAK-003); existing restore tests unchanged
- `backend/tests/test_backup_preflight.py`: 2 new FRESH-exemption tests plus LEGACY_READY fixture updates
- `backend/tests/test_agent_rate_limit.py`: 1 new test (malformed config)
- `backend/tests/test_auth_threadpool.py`: 1 new test (PBKDF2 iteration ceiling)
- `backend/tests/test_startup_integration.py`: fixtures updated to use `LEGACY_READY`; 1 new FRESH-exemption test; misleading rollback test rewritten as a real injected-failure test

#### Documentation Updated
- `docs/DEPLOYMENT.md`: Backup/restore requirements, retention scheduling, synchronous=NORMAL trade-off
- `docs/MIGRATION_RUNNER.md`: FRESH exemption, backup policy
- `backend/.env.example`: Clarified backup dir requirement for non-fresh DBs

---

### Isolated Probe Verification

All fixes verified with adversarial probes in `/tmp/opencode/gw-audit/`:

- `probe_hardlink.py` — hardlink restore correctly rejected, live DB retains `wal-value`
- `probe_walbackup3.py` — WAL backup verified, main file contains `wal-value` after checkpoint
- `probe_precopy.py` — simulated disk-full during pre-copy leaves live DB untouched (not overwritten with invalid pre-copy)

---

### Reports Produced

- `reports/AGENT2_SECURITY_AUDIT.md` — Full security audit with executive summary, all findings, fix summary, test evidence
- `reports/AGENT2_DATABASE_AUDIT.md` — Database-layer integrity audit (migrations, backup/restore, FK, WAL, schema, concurrency)
- `reports/AGENT2_FINDINGS.md` — Structured findings register with all 16 entries (ID, severity, status, component, attack scenario, impact, root cause, reproduction, remediation, test evidence, release blocker)

---

## Verification

- Full backend test suite: `python3 -m pytest backend/tests -q` → **1023 passed, 240 warnings in 27.73s**
- Security-focused suites: `test_db_backup.py`, `test_backup_preflight.py`, `test_agent_rate_limit.py`, `test_auth_threadpool.py`, `test_preauth_rate_limit.py` → **116 passed, 1 warning**
- Startup integration: `test_startup_integration.py` → **41 passed, 1 warning**
- `git diff --check` → clean
- No credentials/secrets in reports
- No security controls weakened to make tests pass
- No migration history changed without explicit justification
- No frontend or detection modules modified

---

## Known Issues / Blockers

- No release blockers within this audit's scope; the full suite is green.
- Open Agent 1 follow-ups outside this fix set: AUTH-002 per-agent bucket eviction, API-001/002/004, DB-002, MIG-003, RL-001.
- BAK-003 was initially misclaimed as fixed; it is now actually implemented and covered by a regression test.

---

## Next Concrete Action

1. Review the three audit reports and diff
2. If approved, commit the intended files:
   - `scripts/gw_db_backup.py`
   - `backend/app/backup_preflight.py`
   - `backend/app/migrations/runner.py`
   - `backend/app/agents.py`
   - `backend/app/main.py`
   - `backend/tests/test_db_backup.py`
   - `backend/tests/test_backup_preflight.py`
   - `backend/tests/test_agent_rate_limit.py`
   - `backend/tests/test_auth_threadpool.py`
   - `backend/tests/test_startup_integration.py`
   - `docs/DEPLOYMENT.md`
   - `docs/MIGRATION_RUNNER.md`
   - `backend/.env.example`
   - `reports/AGENT2_SECURITY_AUDIT.md`
   - `reports/AGENT2_DATABASE_AUDIT.md`
   - `reports/AGENT2_FINDINGS.md`
   - `memory/PROJECT_STATE.md`
   - `memory/AGENT_LOG.md`
3. Do not commit pre-existing audit reports (`AGENT1_*`, `AUDIT_REPORT.md`, etc.) or unrelated modified files