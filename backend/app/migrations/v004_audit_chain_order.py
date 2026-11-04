"""Audit log chain ordering migration (version 4).

Migration v003 introduced the audit hash chain and backfilled existing rows in
``timestamp ASC, id ASC`` order.  The original append path selected its
predecessor with ``timestamp DESC, id DESC``.  Those orders diverge when the
system clock moves backwards, so a legitimate append can make verification
fail.

This migration establishes insertion order (``id ASC``) as the single
canonical chain order and deterministically rebuilds existing rows in that
order.  It intentionally leaves migration v003 untouched: v003 may already
have been applied, and editing it would not retrofit existing databases.

Safety rules:

* every row keeps its id, timestamp, event fields, and detail;
* no audit row is deleted;
* the existing chain is validated against the known v003 history before any
  row is updated, so unrelated content tampering aborts the migration;
* validation and rebuilding happen in the migration runner's transaction, so
  any failure rolls back atomically.

Known v003 history accepted by the validator:

1. rows present when v003 ran were backfilled in ``timestamp ASC, id ASC``
   order;
2. rows appended afterwards linked to the row with the greatest
   ``(timestamp, id)`` among earlier inserts.

The validator finds a boundary between those two phases.  A chain that fits no
such boundary is reported as an error instead of being silently repaired.
"""

from __future__ import annotations

import sqlite3

from backend.app.audit_chain import (
    AUDIT_CHAIN_FIELDS,
    canonical_audit_row,
    compute_chain_hash,
    read_chain_rows,
    validate_legacy_rows,
    verify_chain,
)
from backend.app.migration_registry import Migration

#: Descriptor for this migration.
MIGRATION = Migration(4, "audit_chain_order")


class AuditChainMigrationError(sqlite3.DatabaseError):
    """Raised when a pre-v004 chain cannot be validated safely."""


def _ensure_chain_columns(connection: sqlite3.Connection) -> None:
    # ``PRAGMA table_info`` column 1 is the column name.  Positional access
    # keeps this usable for connections without a ``sqlite3.Row`` factory.
    columns = {
        row[1]
        for row in connection.execute("PRAGMA table_info(audit_log)").fetchall()
    }
    missing = {"prev_hash", "chain_hash"} - columns
    if missing:
        raise AuditChainMigrationError(
            "cannot rebuild audit chain: audit_log is missing column(s) "
            f"{', '.join(sorted(missing))}; migration v3 must be applied first"
        )


def _row_payload(row) -> dict:
    return {field: row[field] for field in AUDIT_CHAIN_FIELDS}


def up(connection) -> None:
    """Rebuild the audit chain in canonical insertion order (``id ASC``).

    Precondition:
    - Migrations v1-v3 are applied (``audit_log`` has ``prev_hash`` and
      ``chain_hash``).

    The method is idempotent: if the stored chain already verifies in
    insertion order it only ensures the supporting index exists.
    """
    _ensure_chain_columns(connection)

    already_canonical, _ = verify_chain(connection)
    if already_canonical:
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_chain "
            "ON audit_log(chain_hash)"
        )
        return

    rows = read_chain_rows(connection)
    compatible, errors, _split = validate_legacy_rows(rows)
    if not compatible:
        detail = "; ".join(errors[:5])
        if len(errors) > 5:
            detail += f"; ... ({len(errors) - 5} more error(s))"
        raise AuditChainMigrationError(
            "refusing to rebuild audit chain in insertion order: "
            f"pre-v004 validation failed: {detail}"
        )

    prev_chain_hash: str | None = None
    for row in rows:
        canonical = canonical_audit_row(_row_payload(row))
        chain_hash = compute_chain_hash(prev_chain_hash, canonical)
        connection.execute(
            "UPDATE audit_log SET prev_hash = ?, chain_hash = ? WHERE id = ?",
            (prev_chain_hash, chain_hash, row["id"]),
        )
        prev_chain_hash = chain_hash

    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_log_chain ON audit_log(chain_hash)"
    )

    rebuilt_valid, rebuilt_errors = verify_chain(connection)
    if not rebuilt_valid:
        detail = "; ".join(rebuilt_errors[:5])
        raise AuditChainMigrationError(
            "audit chain still fails verification after insertion-order "
            f"rebuild: {detail}"
        )


def down() -> None:
    """No automatic downgrade for v4.

    Rolling back v4 would restore the timestamp-ordered links that this
    migration exists to correct.  Restore a pre-migration backup instead.
    """
    raise NotImplementedError(
        "Migration v4 (audit_chain_order) has no automatic downgrade; "
        "restore a pre-migration database backup instead."
    )
