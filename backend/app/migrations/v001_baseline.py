"""Baseline schema migration (version 1).

This migration establishes the complete current Greywatch schema as defined by
:func:`backend.app.siem.initialize_database` and
:data:`backend.app.migration_schema.EXPECTED_SCHEMA`.

Transaction ownership
---------------------
The caller (future migration runner) **owns** the transaction. ``up()``
assumes an active transaction is already open and:

* MUST NOT call ``connection.commit()`` or ``connection.rollback()``.
* MUST NOT issue ``BEGIN`` or ``BEGIN IMMEDIATE``.
* MUST NOT close the connection.
* MUST let exceptions propagate to the caller so the runner can roll back.

The future runner is responsible for:

1. Opening a connection with appropriate isolation / PRAGMA settings.
2. Starting ``BEGIN IMMEDIATE``.
3. Calling :func:`create_schema_migrations_table` to create the ledger table.
4. Calling ``up(connection)`` *after* the ledger table exists.
5. Inserting ``(1, 'baseline')`` into ``schema_migrations``.
6. Committing or rolling back the whole transaction.

This module creates schema only — it does **not** create the migration ledger
or insert a version row.
"""

from __future__ import annotations

from backend.app.migration_registry import Migration
from backend.app.migration_schema import APP_TABLES

#: Descriptor for this migration.
MIGRATION = Migration(1, "baseline")

#: Columns/types that can only be added by this migration to the events table.
#: Must stay in sync with ``backend.app.siem._migrate_events_table``.
_EVENTS_ADDABLE: list[tuple[str, str]] = [
    ("source", "TEXT"),
    ("source_record_id", "TEXT"),
    ("content_hash", "TEXT"),
    ("dest_ip", "TEXT"),
    ("src_port", "INTEGER"),
    ("dest_port", "INTEGER"),
    ("proto", "TEXT"),
    ("signature", "TEXT"),
    ("signature_id", "INTEGER"),
    ("category", "TEXT"),
]

#: Columns/types that can only be added by this migration to the alerts table.
#: Must stay in sync with ``backend.app.siem._migrate_alerts_table``.
_ALERTS_ADDABLE: list[tuple[str, str]] = [
    ("last_triggered_at", "TEXT"),
    ("dest_ip", "TEXT"),
    ("src_port", "INTEGER"),
    ("dest_port", "INTEGER"),
    ("proto", "TEXT"),
    ("signature", "TEXT"),
    ("signature_id", "INTEGER"),
    ("category", "TEXT"),
]


def up(connection) -> None:
    """Create the baseline schema and apply permitted additive changes.

    On a fresh database this creates all five application tables and eight
    indexes. On a compatible legacy database it adds only the columns and
    indexes listed in :data:`ADDABLE_COLUMNS` / :data:`ADDABLE_INDEXES`
    (using ``IF NOT EXISTS`` or column-presence checks) and backfills
    ``alerts.last_triggered_at`` from ``created_at`` where NULL.

    Precondition
    ------------
    Before any DDL the existing SQLite table names are inspected:

    * **None** of the five application tables exist — treated as a fresh
      database; all tables and indexes are created.
    * **All five** application tables exist — treated as a legacy database;
      only additive columns and indexes are applied.
    * **A subset** of application tables exists — raises
      :class:`~backend.app.migrations.v001_baseline.PartialSchemaError`.

    This prevents silently creating missing required tables when ``up()`` is
    called against a partially damaged database.

    Parameters
    ----------
    connection:
        An open :class:`sqlite3.Connection` with an active transaction.

    Raises
    ------
    PartialSchemaError
        A subset (but not all) of the five application tables already exist.
    sqlite3.Error
        Any SQLite error other than the precondition propagates to the caller
        unchanged.
    """
    _check_schema_state(connection)
    _create_tables(connection)
    _create_indexes(connection)
    _migrate_events_table(connection)
    _migrate_alerts_table(connection)


class PartialSchemaError(RuntimeError):
    """Raised when a subset of Greywatch application tables already exists.

    This guard prevents ``up()`` from silently creating missing tables on a
    partially damaged database. Restore the missing tables from backup before
    running the migration.
    """


def _check_schema_state(connection) -> None:
    """Verify the database is either fresh or fully legacy before mutating it.

    Raises :class:`PartialSchemaError` if only a subset of the five
    application tables already exists.
    """
    existing = {
        row["name"]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    present = [t for t in APP_TABLES if t in existing]

    if len(present) not in (0, len(APP_TABLES)):
        missing = set(APP_TABLES) - set(present)
        raise PartialSchemaError(
            "refusing to migrate a partially existing schema: "
            f"present tables = {sorted(present)}, "
            f"missing tables = {sorted(missing)}; "
            "restore missing tables from backup before running this migration"
        )


def _create_tables(connection) -> None:
    """Create all five application tables (idempotent via IF NOT EXISTS)."""
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            host TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            source_ip TEXT,
            severity TEXT NOT NULL,
            raw_message TEXT NOT NULL,
            source TEXT,
            source_record_id TEXT,
            content_hash TEXT,
            dest_ip TEXT,
            src_port INTEGER,
            dest_port INTEGER,
            proto TEXT,
            signature TEXT,
            signature_id INTEGER,
            category TEXT
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS collector_state (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            description TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            closed_at TEXT,
            last_triggered_at TEXT,
            dest_ip TEXT,
            src_port INTEGER,
            dest_port INTEGER,
            proto TEXT,
            signature TEXT,
            signature_id INTEGER,
            category TEXT
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            source_ip TEXT NOT NULL,
            description TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            closed_at TEXT
        )
        """
    )

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_events (
            incident_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            added_at TEXT NOT NULL,
            PRIMARY KEY (incident_id, event_id),
            FOREIGN KEY (incident_id) REFERENCES incidents(id),
            FOREIGN KEY (event_id) REFERENCES events(id)
        )
        """
    )


def _create_indexes(connection) -> None:
    """Create all non-additive indexes (idempotent via IF NOT EXISTS)."""
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events(source_ip, timestamp)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, created_at)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incidents_rule_ip ON incidents(rule_id, source_ip, status)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events(event_id)"
    )


def _existing_columns(connection, table: str) -> set[str]:
    """Return the set of existing column names for *table*."""
    return {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _migrate_events_table(connection) -> None:
    """Add provenance / network columns and indexes missing from legacy events.

    Mirrors ``backend.app.siem._migrate_events_table``. Existing rows are
    preserved and new columns are left NULL so legacy SSH/journal events do not
    gain guessed values.
    """
    columns = _existing_columns(connection, "events")
    for column, dtype in _EVENTS_ADDABLE:
        if column not in columns:
            connection.execute(f"ALTER TABLE events ADD COLUMN {column} {dtype}")

    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_events_source_record
            ON events(source, source_record_id)
            WHERE source_record_id IS NOT NULL
        """
    )

    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_events_content_hash
            ON events(content_hash)
            WHERE content_hash IS NOT NULL
        """
    )


def _migrate_alerts_table(connection) -> None:
    """Add Suricata-specific columns missing from legacy alerts.

    Mirrors ``backend.app.siem._migrate_alerts_table``. ``last_triggered_at``
    is backfilled from ``created_at`` for pre-existing rows so they keep their
    old evidence-window behavior.
    """
    columns = _existing_columns(connection, "alerts")
    for column, dtype in _ALERTS_ADDABLE:
        if column not in columns:
            connection.execute(f"ALTER TABLE alerts ADD COLUMN {column} {dtype}")

    connection.execute(
        """
        UPDATE alerts
        SET last_triggered_at = created_at
        WHERE last_triggered_at IS NULL
        """
    )


def down() -> None:
    """No automatic downgrade exists for the baseline migration.

    Rolling back v1 means discarding the established schema and all data.
    This requires restoring a verified database backup taken before the
    migration was applied. No programmatic downgrade is provided.
    """
    raise NotImplementedError(
        "Baseline migration v1 has no safe automatic downgrade; "
        "restore a pre-migration database backup instead."
    )
