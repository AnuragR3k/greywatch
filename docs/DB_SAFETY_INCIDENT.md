# Database Safety Incident — `data/greywatch.db` schema migration

> Part of the Day 5.1 "Database Safety" review. See also `./SURICATA.md` §10
> (Running the tests safely).

## Summary

A verification/test/CLI operation was run **without** `GREYWATCH_DB` set. Because
`siem._connection()` falls back to the default production database
(`data/greywatch.db`) whenever `GREYWATCH_DB` is unset, that operation invoked
`initialize_database()`, which ran the Suricata migration against the production
database. The migration is **non-destructive** (`ALTER TABLE ... ADD COLUMN` only
appends nullable `NULL` columns), so **no production data was lost or altered**
— only the `alerts` table schema gained seven nullable columns.

This document is the authoritative, accurate record of the incident. It does
**not** claim the database was completely untouched: the schema *was* changed.
The decision below is to **keep** the seven columns, because they are required by
the current application. No destructive `DROP COLUMN` is performed or recommended.

## Timeline / root cause

- `backend/app/siem.py` defines `DEFAULT_DB_PATH = .../data/greywatch.db` and
  `_connection()` resolves `db_path = os.environ.get("GREYWATCH_DB", DEFAULT_DB_PATH)`.
- `initialize_database()` is **not** called at import time of `backend.app.main`
  — it is invoked lazily, on the first database-touching call inside request
  handlers / functions (`list_events`, `list_alerts`, `get_alert_detail`,
  `ingest_events`, `ingest_lines`, the journal/suricata collector `get_collector_setting`,
  `set_collector_setting`, and the CLI `collect_once`/`status` paths).
- Therefore "merely importing the app" is safe; it is a **call that touches the
  database without `GREYWATCH_DB` set** that triggers the migration. Reproducing
  the exact trigger is not necessary to remediate: the guard in the next section
  makes it impossible for tests/verification to reach the production default.

## What changed on the production database

`PRAGMA table_info(alerts)` after the incident — 18 columns (11 original + 7 new):

| cid | name          | type    |
|-----|---------------|---------|
| 0–10 | (11 original columns: id, created_at, rule_id, title, severity, source_ip, description, event_count, status, closed_at, last_triggered_at) | — |
| 11   | dest_ip       | TEXT (nullable) |
| 12   | src_port      | INTEGER (nullable) |
| 13   | dest_port     | INTEGER (nullable) |
| 14   | proto         | TEXT (nullable) |
| 15   | signature     | TEXT (nullable) |
| 16   | signature_id  | INTEGER (nullable) |
| 17   | category      | TEXT (nullable) |

The single pre-existing row is the `SSH_BRUTE_FORCE` alert (`id=1`). On that row
the seven new columns are **all NULL**, and every original column value is
**unchanged** (verified byte-for-byte against the pre-incident values recorded in
earlier sessions).

## Required? — keep the columns

The seven columns are **required by the current application version**:

- `siem._detect_suricata_alerts` performs `INSERT INTO alerts (... dest_ip,
  src_port, dest_port, proto, signature, signature_id, category ...)`.
- `siem.get_alert_detail` reads these columns in the `SURICATA_ALERT` branch.
- `siem._migrate_alerts_table` re-adds them idempotently on every
  `initialize_database()` call (PRAGMA-guarded, so a future run will add them
  again even if they were removed).

Consequence: the migration will **re-add** the seven columns on the next
`initialize_database()` call regardless of any manual schema change. Dropping
them would therefore be pointless churn — at best it would only persist until the
next run, and at worst it would risk data if any Suricata alert were present.
**Decision: keep the columns; do not drop them.**

## Data-integrity verification (independent re-inspection)

Run locally with `sqlite3`/`python` against `data/greywatch.db` (read-only):

```
alerts          rows = 1   (rule_id = SSH_BRUTE_FORCE, id = 1)
alerts.SURICATA_ALERT = 0
events          rows = 108
events.suricata_alert = 0
collector_state rows = 4
alerts new columns all NULL on the SSH row = True
original alert values unchanged = True
PRAGMA integrity_check = ok
PRAGMA foreign_key_check = []   (no violations)
```

No data remediation is required: the schema change was additive, all values are
intact, and integrity checks pass.

## Prevention (implemented)

The root cause — "a DB-touching code path runs without `GREYWATCH_DB` set" — is
neutralized for tests and verification by the **test-suite DB-safety guard**:

- `backend/tests/conftest.py` — an `autouse` fixture `_isolate_test_database`:
  - If `GREYWATCH_DB` is **unset**, it redirects it to an isolated temp database
    (so tests can never fall back to the production default).
    Existing tests that set `GREYWATCH_DB` themselves (e.g. the `_db` fixture)
    are unaffected — this guard only handles the unset/explicit-prod cases.
  - If `GREYWATCH_DB` is explicitly pointed at the production path, the test
    **fails loudly** with a clear message instead of using it.
- `backend/app/siem.py::is_production_db_path` — a pure, side-effect-free helper
  used by the guard (and covered by `backend/tests/test_db_safety.py`).
- `backend/tests/test_db_safety.py` — regression tests asserting: the detector
  recognises the default production path; unset `GREYWATCH_DB` is redirected to a
  temp path during tests; an explicit production path is refused (verified via a
  subprocess `pytest` run that exits non-zero with the refusal message).

This guard is **test-only** and does not change normal local application
startup, which intentionally uses the production database.

### Verification scripts

`scripts/live_ssh_brute_force_test.sh` already exports
`GREYWATCH_DB` to a fresh `mktemp` database before starting `uvicorn`, so it can
never touch `data/greywatch.db`. Any ad-hoc verification command must do the
same, e.g.:

```sh
GREYWATCH_DB="$(mktemp -u /tmp/gw-XXXX.db)" python -m pytest          # safe
GREYWATCH_DB="$(mktemp -u /tmp/gw-XXXX.db)" .venv/bin/uvicorn backend.app.main:app --dry-run  # safe
```

## Reversible procedure (NOT executed — kept for reference)

If an operator ever wanted to restore the pre-incident schema for cosmetic
parity, the only safe sequence (and only because the seven columns are currently
all NULL and contain no data) would be, in order:

1. Take a full backup: `cp data/greywatch.db data/greywatch.db.bak`.
2. `PRAGMA integrity_check` → must be `ok`.
3. Only if `SELECT dest_ip,src_port,dest_port,proto,signature,signature_id,category
   FROM alerts` returns **only NULLs**, run seven
   `ALTER TABLE alerts DROP COLUMN ...` statements.
4. Re-run `PRAGMA integrity_check`.

This is **not recommended** and is **not performed here**: the columns are
required (step 1 of "Required?"), and dropping them is purely cosmetic churn
that the next migration would immediately reverse. It is documented only so
there is a reversible, safe, audited path rather than an ad-hoc `DROP COLUMN`.
