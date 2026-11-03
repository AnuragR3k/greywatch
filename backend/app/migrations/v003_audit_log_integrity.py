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
    """Verify the audit log hash chain integrity.

    Returns (is_valid, errors) where errors is a list of violation descriptions.
    """
    rows = connection.execute(
        """
        SELECT id, timestamp, event_type, agent_id, api_key_id, actor, detail,
               prev_hash, chain_hash
        FROM audit_log
        ORDER BY timestamp ASC, id ASC
        """
    ).fetchall()

    errors = []
    prev_chain_hash = None

    for row in rows:
        row_dict = dict(row)
        stored_prev_hash = row_dict.get("prev_hash")
        stored_chain_hash = row_dict.get("chain_hash")

        # Check prev_hash linkage
        if stored_prev_hash != prev_chain_hash:
            errors.append(
                f"Record id={row_dict['id']}: prev_hash mismatch "
                f"(expected {prev_chain_hash}, got {stored_prev_hash})"
            )

        # Verify chain_hash
        canonical = _canonical_audit_row({
            "timestamp": row_dict["timestamp"],
            "event_type": row_dict["event_type"],
            "agent_id": row_dict["agent_id"],
            "api_key_id": row_dict["api_key_id"],
            "actor": row_dict["actor"],
            "detail": row_dict["detail"],
        })
        expected_chain_hash = _compute_chain_hash(stored_prev_hash, canonical)
        if stored_chain_hash != expected_chain_hash:
            errors.append(
                f"Record id={row_dict['id']}: chain_hash mismatch "
                f"(expected {expected_chain_hash}, got {stored_chain_hash})"
            )

        prev_chain_hash = stored_chain_hash

    return len(errors) == 0, errors


def down() -> None:
    """No automatic downgrade for v3.

    Rolling back v3 requires restoring a verified database backup taken
    before the migration was applied. No programmatic downgrade is provided.
    """
    raise NotImplementedError(
        "Migration v3 (audit_log_integrity) has no safe automatic downgrade; "
        "restore a pre-migration database backup instead."
    )