"""Agent and API key schema migration (version 2).

This migration adds tables for agent management and secure API key storage.
"""

from __future__ import annotations

from backend.app.migration_registry import Migration
from backend.app.migration_ledger import SCHEMA_MIGRATIONS_TABLE, create_schema_migrations_table

#: Descriptor for this migration.
MIGRATION = Migration(2, "agents_and_api_keys")


def up(connection) -> None:
    """Create agent and API key tables with foreign keys and indexes.

    Precondition:
    - Migration v1 (baseline) must already be applied.
    - The schema_migrations ledger table must exist.

    This migration adds:
    - agents: agent registry with lifecycle tracking
    - api_keys: secure credential storage (hashes only, never plaintext)
    - audit_log: immutable audit trail for agent/key lifecycle
    """
    # Create agents table
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            display_name TEXT,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'revoked')),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_seen_at TEXT,
            deactivated_at TEXT,
            deactivated_reason TEXT
        )
        """
    )

    # Create api_keys table
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            key_hash TEXT NOT NULL,
            key_prefix TEXT NOT NULL,  -- First 8 chars for identification (e.g., "gw_abc123")
            name TEXT,                  -- Optional human-readable name for the key
            status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked', 'expired')),
            created_at TEXT NOT NULL,
            expires_at TEXT,            -- Optional expiration timestamp
            revoked_at TEXT,
            revoked_reason TEXT,
            last_used_at TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE
        )
        """
    )

    # Create audit_log table
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,   -- agent_created, agent_deactivated, key_generated, key_rotated, key_revoked, auth_failure, etc.
            agent_id INTEGER,           -- NULL for auth failures on unknown agents
            api_key_id INTEGER,         -- NULL when not applicable
            actor TEXT,                 -- Who performed the action (admin user, system, etc.)
            detail TEXT,                -- JSON detail, never contains secrets
            FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE SET NULL,
            FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL
        )
        """
    )

    # Create indexes
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_api_keys_agent_id ON api_keys(agent_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_log_agent_id ON audit_log(agent_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_audit_log_event_type ON audit_log(event_type)"
    )

    # Add events.agent_id column for attribution (nullable for backward compatibility)
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(events)").fetchall()
    }
    if "agent_id" not in columns:
        connection.execute(
            "ALTER TABLE events ADD COLUMN agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL"
        )

    # Ensure the supporting index independently of the column snapshot above.
    # A previous or partial migration may have added agent_id without creating
    # its index; CREATE INDEX IF NOT EXISTS makes this safe to rerun.
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events(agent_id)"
    )


def down() -> None:
    """No automatic downgrade for v2.

    Rolling back v2 requires restoring a verified database backup taken
    before the migration was applied. No programmatic downgrade is provided.
    """
    raise NotImplementedError(
        "Migration v2 (agents_and_api_keys) has no safe automatic downgrade; "
        "restore a pre-migration database backup instead."
    )