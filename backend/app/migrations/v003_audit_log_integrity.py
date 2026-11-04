"""Audit log integrity migration (version 3).

This migration adds hash chaining to the audit_log table to provide
tamper-evident audit records. Each record stores a hash of its canonical
fields plus the previous record's chain hash, forming a verifiable chain.

Canonical serialization:
  JSON with sorted keys, no whitespace: {"event_type":"...",...}
  Fields included: timestamp, event_type, agent_id, api_key_id, actor, detail
  NULL fields are omitted from the canonical representation.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from backend.app.migration_registry import Migration
from backend.app.migration_ledger import SCHEMA_MIGRATIONS_TABLE, create_schema_migrations_table

#: Descriptor for this migration.
MIGRATION = Migration(3, "audit_log_integrity")


def _canonical_audit_row(row: dict[str, Any]) -> str:
    """Produce a deterministic canonical JSON string for an audit log row.

    Only includes non-NULL fields, with keys sorted for determinism.
    """
    # Filter out None values and sort keys
    canonical = {k: v for k, v in row.items() if v is not None}
    return json.dumps(canonical, separators=(",", ":"), sort_keys=True)


def _compute_chain_hash(prev_hash: str | None, canonical_row: str) -> str:
    """Compute the chain hash for an audit log entry.

    Chain hash = SHA256(prev_hash + canonical_row)
    For the first entry, prev_hash is the empty string.
    """
    prev = prev_hash or ""
    combined = (prev + canonical_row).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def up(connection) -> None:
    """Add hash chaining columns to audit_log and backfill existing records.

    Precondition:
    - Migration v1 (baseline) and v2 (agents_and_api_keys) must already be applied.
    - The schema_migrations ledger table must exist.
    """
    # Add prev_hash and chain_hash columns to audit_log
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(audit_log)").fetchall()
    }

    if "prev_hash" not in columns:
        connection.execute(
            "ALTER TABLE audit_log ADD COLUMN prev_hash TEXT"
        )
    if "chain_hash" not in columns:
        connection.execute(
            "ALTER TABLE audit_log ADD COLUMN chain_hash TEXT"
        )

    # Backfill existing records in timestamp order (oldest first)
    rows = connection.execute(
        """
        SELECT id, timestamp, event_type, agent_id, api_key_id, actor, detail
        FROM audit_log
        ORDER BY timestamp ASC, id ASC
        """
    ).fetchall()

    prev_chain_hash = None
    for row in rows:
        row_dict = dict(row)
        canonical = _canonical_audit_row(row_dict)
        chain_hash = _compute_chain_hash(prev_chain_hash, canonical)

        connection.execute(
            "UPDATE audit_log SET prev_hash = ?, chain_hash = ? WHERE id = ?",
            (prev_chain_hash, chain_hash, row_dict["id"]),
        )
        prev_chain_hash = chain_hash

    # Create index for chain verification
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_log_chain ON audit_log(chain_hash)"
    )


def verify_chain(connection) -> tuple[bool, list[str]]:
    """Verify the audit log hash chain integrity in canonical id order.

    The canonical chain order is insertion order (``id ASC``).  This verifier
    is read-only and never repairs the chain.  It returns ``(is_valid,
    errors)`` where ``errors`` is a list of violation descriptions.

    The migration's ``up()`` backfill above is frozen for compatibility with
    databases that already applied v3.  Migration v004 rebuilds any such
    timestamp-ordered chain in insertion order; after that point this verifier
    and the stored chain agree.
    """
    from backend.app.audit_chain import verify_chain as _verify_canonical

    return _verify_canonical(connection)


def verify_chain_timestamp_order(connection) -> tuple[bool, list[str]]:
    """Verify the historical v003 timestamp ordering (read-only).

    This reproduces the pre-v004 verifier (timestamp order, id-exclusive hash
    formula).  Because v003's frozen backfill wrote id-inclusive hashes, use
    ``audit_chain.validate_legacy_rows`` for pre-v004 compatibility checks.
    Application code must use :func:`verify_chain` (insertion order).
    """
    from backend.app.audit_chain import (
        verify_chain_timestamp_order as _verify_timestamp_order,
    )

    return _verify_timestamp_order(connection)


def down() -> None:
    """No automatic downgrade for v3.

    Rolling back v3 requires restoring a verified database backup taken
    before the migration was applied. No programmatic downgrade is provided.
    """
    raise NotImplementedError(
        "Migration v3 (audit_log_integrity) has no safe automatic downgrade; "
        "restore a pre-migration database backup instead."
    )