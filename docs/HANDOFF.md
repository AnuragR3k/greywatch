# Greywatch Backend — Handoff Note

**Date:** 2026-11-10
**Branch:** `main`
**HEAD:** `cb78819`
**Suite:** `python3 -m pytest backend/tests -q` → 1027 passed, 240 warnings

## What is merged

Agent 2 security hardening is on `main`. The two highest-consequence fixes were
confirmed post-merge by reading the code on `main`:
- `scripts/gw_db_backup.py::restore_database` — pre-restore copy via `tempfile.mkstemp`
  (0600 at creation), `pre_copy_verified` rollback guard present.
- `backend/app/agents.py::_verify_key` — iteration ceiling check runs before
  `hashlib.pbkdf2_hmac`; `OverflowError` handler present.

### Fixed findings — test status (verified by grep, not guessed)

| Finding | What it is | Committed test |
|---|---|---|
| BAK-001 | Reject hardlink/symlink backup→live | `test_hardlink_to_live_database_is_rejected` |
| BAK-002 | WAL-safe restore via SQLite backup API | `test_wal_mode_backup_is_accepted` |
| BAK-003 | Pre-restore copy 0600 at creation | `test_pre_restore_copy_is_0600_at_creation` |
| BAK-004 | Rollback only restores verified pre-copy | `test_restore_rollback_guard_prevents_unverified_pre_copy_overwrite` |
| BAK-006 | Backup provenance | none — code inspection only |
| AUTH-001 | Env parsing fails closed | none — code inspection only |
| AUTH-002 | PBKDF2 iteration ceiling | `test_verify_key_rejects_excessive_iterations_before_hashing` (+ malformed-field, normal-hash) |
| AUTH-004 | Pre-auth bucket lock | `test_preauth_limiter_thread_safety` |
| MIG-001 | FRESH DB exempt from backup preflight | `test_fresh_database_migrates_without_backup` |
| MIG-002 | Ledger NULL-name rejection | `test_ledger_null_name_rejected` |

## Deferred

**Missing committed tests:** BAK-006 (provenance), AUTH-001 (env parsing).

**Manual verification not performed:** backup/restore drill against a copy of a
production-shaped DB. Do this before production deployment.

**Agent 1 follow-ups:** per-agent bucket eviction; API-001 (ingest duplicate-id
mapping); API-002 (`GET /events` offset); API-004 (`/health` schema check);
DB-002 (connection-timeout unification); MIG-003 (WAL snapshot atomicity);
RL-001 (shared token-mode bucket).

**Architectural limitations (need design):** AUTH-003 (loopback spoofing,
mitigate with `GREYWATCH_TRUSTED_PROXIES`); AUD-001 (unkeyed audit chain, needs
external anchor); AUD-002 (best-effort auth-failure audit).

## Repo hygiene

- 14 untracked audit files at root and `reports/` (AGENT1/3/4) — intentionally
  untracked.
- `reports/AGENT2_*.md` (3) tracked and merged.
- `data/greywatch.db` not touched; tests use temporary databases.

## Recommended next task

Manual backup/restore drill against a copy of a realistic DB; write
`docs/BACKUP_RESTORE_DRILL.md` and execute once. Then add BAK-006 and AUTH-001
committed tests (fail-without-fix, pass-with-fix standard).

## Caution for the next agent

A prior agent produced a "state of the backend" summary that invented test names
and mislabeled findings (claimed BAK-006 had a committed test; mislabeled
API-001/002, DB-002, MIG-003, AUTH-003, AUD-001). The table above was verified
against `git grep` on `main`. Always verify test names with
`git grep -n "<name>" backend/tests/` before trusting a summary.