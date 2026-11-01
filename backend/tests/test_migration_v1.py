"""Tests for the v1 baseline migration module.

These tests verify that ``v001_baseline.up()`` produces a schema matching
``EXPECTED_SCHEMA`` from :mod:`backend.app.migration_schema`, preserves
existing user data during legacy additive migration, respects transaction
ownership, and does not touch the migration ledger.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from backend.app.migration_ledger import SCHEMA_MIGRATIONS_TABLE, create_schema_migrations_table
from backend.app.migration_registry import Migration
from backend.app.migration_schema import (
    ADDABLE_COLUMNS,
    ADDABLE_INDEXES,
    APP_TABLES,
    EXPECTED_SCHEMA,
    compare_schema,
    schema_fingerprint,
)
from backend.app.migrations.v001_baseline import (
    MIGRATION,
    PartialSchemaError,
    down,
    up,
)
from backend.app.migration_state import DatabaseState, inspect_path


def _connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _legacy_core_ddl() -> str:
    """Legacy schema: all 5 tables with only core (non-addable) columns + core indexes.

    Mirrors ``_legacy_complete_ddl`` from test_migration_state.py so the
    additive migration path is exercised the same way.
    """
    return """
    CREATE TABLE events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        host TEXT NOT NULL,
        event_type TEXT NOT NULL,
        username TEXT,
        source_ip TEXT,
        severity TEXT NOT NULL,
        raw_message TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_events_ip_time
        ON events(source_ip, timestamp);

    CREATE TABLE collector_state (
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        created_at TEXT NOT NULL,
        rule_id TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        description TEXT NOT NULL,
        event_count INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        closed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_alerts_status
        ON alerts(status, created_at);

    CREATE TABLE incidents (
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
    );
    CREATE INDEX IF NOT EXISTS idx_incidents_status
        ON incidents(status, created_at);
    CREATE INDEX IF NOT EXISTS idx_incidents_rule_ip
        ON incidents(rule_id, source_ip, status);

    CREATE TABLE incident_events (
        incident_id INTEGER NOT NULL,
        event_id INTEGER NOT NULL,
        added_at TEXT NOT NULL,
        PRIMARY KEY (incident_id, event_id),
        FOREIGN KEY (incident_id) REFERENCES incidents(id),
        FOREIGN KEY (event_id) REFERENCES events(id)
    );
    CREATE INDEX IF NOT EXISTS idx_incident_events_incident
        ON incident_events(incident_id);
    CREATE INDEX IF NOT EXISTS idx_incident_events_event
        ON incident_events(event_id);
    """


# --------------------------------------------------------------------------- #
# Migration descriptor
# --------------------------------------------------------------------------- #


def test_migration_descriptor():
    """The module exposes the correct Migration descriptor."""
    assert MIGRATION == Migration(1, "baseline")


def test_down_not_implemented():
    """Baseline has no automatic downgrade."""
    with pytest.raises(NotImplementedError, match="restore a pre-migration"):
        down()


# --------------------------------------------------------------------------- #
# Partial-schema guard (Correction 1)
# --------------------------------------------------------------------------- #


def test_partial_schema_is_refused(tmp_path: Path):
    """A database with only some Greywatch tables is refused, no DDL applied."""
    db_path = tmp_path / "partial.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    # Create only a subset of the five application tables.
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL)")
    conn.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL)")

    with pytest.raises(PartialSchemaError, match="partially existing schema"):
        up(conn)

    conn.rollback()
    conn.close()


def test_partial_schema_remains_unchanged_after_refusal(tmp_path: Path):
    """After refusal, the partial schema and any data are untouched."""
    db_path = tmp_path / "partial_preserved.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL)")
    conn.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL)")
    conn.execute("INSERT INTO events(timestamp) VALUES ('2026-01-01T00:00:00Z')")
    conn.commit()
    conn.close()

    # Reopen and attempt migration — should refuse without modifying anything.
    conn = _connect(db_path)
    conn.execute("BEGIN")
    with pytest.raises(PartialSchemaError):
        up(conn)
    conn.rollback()
    conn.close()

    # Verify the database is unchanged.
    conn = _connect(db_path)
    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert tables == {"events", "alerts"}
    row = conn.execute("SELECT timestamp FROM events WHERE id=1").fetchone()
    assert row["timestamp"] == "2026-01-01T00:00:00Z"
    conn.close()


# --------------------------------------------------------------------------- #
# Fresh schema creation
# --------------------------------------------------------------------------- #


def test_fresh_schema_is_complete(tmp_path: Path):
    """up() on a fresh database produces a schema matching EXPECTED_SCHEMA."""
    db_path = tmp_path / "fresh.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    try:
        up(conn)
        conn.commit()
    except Exception:
        conn.rollback()
        raise

    diffs = compare_schema(conn)
    assert diffs.complete
    assert diffs.missing_tables == []
    assert diffs.missing_columns == {}
    assert diffs.incompatible_columns == {}
    assert diffs.missing_indexes == {}
    assert diffs.incompatible_indexes == {}
    assert diffs.incompatible_foreign_keys == {}
    assert diffs.incompatible_table_options == {}
    conn.close()


def test_fresh_schema_fingerprint_matches_expected(tmp_path: Path, monkeypatch):
    """up() produces the same fingerprint as initialize_database()."""
    # Database A: built via siem.initialize_database()
    db_a = tmp_path / "via_init.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_a))
    from backend.app.siem import initialize_database

    initialize_database()

    # Database B: built via v001_baseline.up() inside a caller-managed tx
    db_b = tmp_path / "via_migration.db"
    conn_b = _connect(db_b)
    conn_b.execute("BEGIN")
    up(conn_b)
    conn_b.commit()

    conn_a = _connect(db_a)
    try:
        fp_a = schema_fingerprint(conn_a)
        fp_b = schema_fingerprint(conn_b)
        # Fingerprint parity
        assert fp_a == fp_b
        # Schema completeness on the migration-built database
        assert compare_schema(conn_b).complete
    finally:
        conn_a.close()
        conn_b.close()


def test_up_does_not_commit(tmp_path: Path):
    """up() must not commit the caller's transaction."""
    db_path = tmp_path / "nocommit.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)

    # The tables should exist within the transaction (uncommitted).
    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "events" in tables

    # Roll back — if up() had committed, the tables would persist.
    conn.rollback()
    tables_after = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "events" not in tables_after
    conn.close()


# --------------------------------------------------------------------------- #
# Transaction ownership
# --------------------------------------------------------------------------- #


def test_caller_transaction_remains_active(tmp_path: Path):
    """The caller's transaction is still usable after up() returns."""
    db_path = tmp_path / "tx.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)

    # Should still be able to execute SQL within the same transaction.
    conn.execute("INSERT INTO collector_state(key, value) VALUES ('test_key', 'test_value')")

    conn.commit()
    row = conn.execute("SELECT value FROM collector_state WHERE key='test_key'").fetchone()
    assert row["value"] == "test_value"
    conn.close()


def test_rollback_undoes_schema_creation(tmp_path: Path):
    """Rolling back after up() undoes all schema changes."""
    db_path = tmp_path / "rollback.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)
    # Verify tables are present in the transaction
    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "events" in tables
    conn.rollback()

    # Verify tables are gone after rollback
    tables_after = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert not tables_after
    conn.close()


def test_failure_rolls_back_all_changes(tmp_path: Path):
    """When up() is interrupted, the caller can roll back everything."""
    db_path = tmp_path / "failure.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")

    class _ExplodingConnection:
        """Wrap a connection so the second execute raises."""

        def __init__(self, inner):
            self._inner = inner
            self._count = 0

        def execute(self, sql, *args):
            self._count += 1
            if self._count == 2:
                raise RuntimeError("simulated failure mid-migration")
            return self._inner.execute(sql, *args)

    exploding = _ExplodingConnection(conn)
    with pytest.raises(RuntimeError, match="simulated failure"):
        up(exploding)

    # Caller rolls back.
    conn.rollback()
    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert not tables
    conn.close()


def test_up_does_not_close_connection(tmp_path: Path):
    """up() must not close the caller's connection."""
    db_path = tmp_path / "noclose.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)
    assert conn.execute("SELECT 1").fetchone() is not None
    conn.rollback()
    conn.close()


# --------------------------------------------------------------------------- #
# Legacy additive behavior
# --------------------------------------------------------------------------- #


def test_legacy_schema_is_migrated_to_current(tmp_path: Path):
    """A legacy schema missing only addable columns is upgraded to current."""
    db_path = tmp_path / "legacy.db"
    conn = _connect(db_path)
    conn.executescript(_legacy_core_ddl())
    conn.commit()
    conn.close()

    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)
    conn.commit()

    diffs = compare_schema(conn)
    assert diffs.complete
    assert diffs.missing_tables == []
    assert diffs.missing_columns == {}
    assert diffs.missing_indexes == {}
    conn.close()


def test_legacy_data_preserved(tmp_path: Path):
    """Existing rows in all five tables survive the additive migration."""
    db_path = tmp_path / "legacy_data.db"
    conn = _connect(db_path)
    conn.executescript(_legacy_core_ddl())
    conn.execute(
        "INSERT INTO events(timestamp, host, event_type, username, source_ip, severity, raw_message) "
        "VALUES ('2026-01-01T00:00:00Z', 'host1', 'auth', 'user1', '10.0.0.1', 'info', 'raw')"
    )
    conn.execute(
        "INSERT INTO alerts(created_at, rule_id, title, severity, source_ip, description, event_count) "
        "VALUES ('2026-01-01T00:00:00Z', 'rule1', 'Test Alert', 'high', '10.0.0.1', 'desc', 5)"
    )
    conn.execute(
        "INSERT INTO incidents(created_at, updated_at, rule_id, title, severity, status, source_ip, description, event_count, first_seen_at, last_seen_at) "
        "VALUES ('2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'rule1', 'Incident 1', 'high', 'open', '10.0.0.1', 'desc', 1, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')"
    )
    conn.execute(
        "INSERT INTO incident_events(incident_id, event_id, added_at) VALUES (1, 1, '2026-01-01T00:00:00Z')"
    )
    conn.execute("INSERT INTO collector_state(key, value) VALUES ('state_key', 'state_val')")
    conn.commit()
    conn.close()

    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)
    conn.commit()

    assert conn.execute("SELECT host FROM events WHERE id=1").fetchone()["host"] == "host1"
    alert = conn.execute("SELECT rule_id, event_count FROM alerts WHERE id=1").fetchone()
    assert alert["rule_id"] == "rule1"
    assert alert["event_count"] == 5
    assert conn.execute("SELECT title FROM incidents WHERE id=1").fetchone()["title"] == "Incident 1"
    assert conn.execute("SELECT event_id FROM incident_events WHERE incident_id=1").fetchone()["event_id"] == 1
    assert conn.execute("SELECT value FROM collector_state WHERE key='state_key'").fetchone()["value"] == "state_val"
    conn.close()


def test_last_triggered_at_backfilled_from_created_at(tmp_path: Path):
    """last_triggered_at is backfilled from created_at for legacy rows that are NULL."""
    db_path = tmp_path / "backfill.db"
    conn = _connect(db_path)
    conn.executescript(_legacy_core_ddl())
    conn.execute(
        "INSERT INTO alerts(created_at, rule_id, title, severity, source_ip, description, event_count) "
        "VALUES ('2026-01-01T00:00:00Z', 'rule1', 'Alert 1', 'high', '10.0.0.1', 'desc', 1)"
    )
    conn.execute(
        "INSERT INTO alerts(created_at, rule_id, title, severity, source_ip, description, event_count) "
        "VALUES ('2026-01-02T00:00:00Z', 'rule2', 'Alert 2', 'high', '10.0.0.2', 'desc', 1)"
    )
    conn.commit()
    conn.close()

    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)
    conn.commit()

    # Both rows should have last_triggered_at backfilled from created_at.
    for row in conn.execute("SELECT created_at, last_triggered_at FROM alerts").fetchall():
        assert row["last_triggered_at"] == row["created_at"]
    conn.close()


def test_last_triggered_at_non_null_preserved(tmp_path: Path):
    """Pre-existing non-NULL last_triggered_at values are not overwritten by re-run."""
    db_path = tmp_path / "preserve.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)  # full schema creation
    conn.execute(
        "INSERT INTO alerts(created_at, rule_id, title, severity, source_ip, description, event_count, last_triggered_at) "
        "VALUES ('2026-01-01T00:00:00Z', 'rule1', 'Alert 1', 'high', '10.0.0.1', 'desc', 1, '2025-12-01T00:00:00Z')"
    )
    conn.commit()

    # Re-run up() in a new transaction — the backfill UPDATE should not touch
    # the non-NULL value.
    conn.execute("BEGIN")
    up(conn)
    conn.commit()

    row = conn.execute("SELECT last_triggered_at FROM alerts WHERE id=1").fetchone()
    assert row["last_triggered_at"] == "2025-12-01T00:00:00Z"
    conn.close()


def test_migration_is_idempotent(tmp_path: Path):
    """Running up() twice succeeds and produces the same complete schema."""
    db_path = tmp_path / "idempotent.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)
    conn.commit()

    # Snapshot state, then run again.
    diffs_before = compare_schema(conn)

    conn.execute("BEGIN")
    up(conn)
    conn.commit()

    diffs_after = compare_schema(conn)
    assert diffs_before.complete
    assert diffs_after.complete
    assert diffs_before == diffs_after
    conn.close()


# --------------------------------------------------------------------------- #
# Safety and invariants
# --------------------------------------------------------------------------- #


def test_duplicate_source_record_rejected(tmp_path: Path):
    """The unique partial index rejects duplicate (source, source_record_id)."""
    db_path = tmp_path / "dedup.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)

    conn.execute(
        "INSERT INTO events(timestamp, host, event_type, severity, raw_message, source, source_record_id) "
        "VALUES ('t1', 'h', 'e', 's', 'r', 'suricata', 'rec-001')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO events(timestamp, host, event_type, severity, raw_message, source, source_record_id) "
            "VALUES ('t2', 'h', 'e', 's', 'r', 'suricata', 'rec-001')"
        )
    conn.rollback()
    conn.close()


def test_null_source_record_allows_duplicates(tmp_path: Path):
    """NULL source_record_id rows are excluded from the unique constraint."""
    db_path = tmp_path / "null_dup.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)

    for i in range(3):
        conn.execute(
            "INSERT INTO events(timestamp, host, event_type, severity, raw_message, source) "
            "VALUES ('t', 'h', 'e', 's', 'r', 'suricata')"
        )
    assert conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"] == 3
    conn.rollback()
    conn.close()


def test_duplicate_content_hash_permitted(tmp_path: Path):
    """The non-unique partial index on content_hash allows duplicates."""
    db_path = tmp_path / "hash_dup.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)

    for i in range(3):
        conn.execute(
            "INSERT INTO events(timestamp, host, event_type, severity, raw_message, content_hash) "
            "VALUES ('t', 'h', 'e', 's', 'r', 'same_hash')"
        )
    assert conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"] == 3
    conn.rollback()
    conn.close()


def test_no_ledger_created(tmp_path: Path):
    """up() must not create the schema_migrations table."""
    db_path = tmp_path / "no_ledger.db"
    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)
    conn.commit()

    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert SCHEMA_MIGRATIONS_TABLE not in tables
    conn.close()


def test_incompatible_legacy_schema_not_repaired(tmp_path: Path):
    """An incompatible required column is not silently repaired by up()."""
    db_path = tmp_path / "incompatible.db"
    conn = _connect(db_path)
    # events table missing a required column (raw_message) — incompatible, not
    # just missing addable columns.
    conn.execute(
        """
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            host TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            source_ip TEXT,
            severity TEXT NOT NULL
            -- raw_message intentionally omitted
        )
        """
    )
    conn.execute("CREATE INDEX idx_events_ip_time ON events(source_ip, timestamp)")
    # Create the other tables normally.
    conn.executescript(
        """
        CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            description TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            closed_at TEXT
        );
        CREATE INDEX idx_alerts_status ON alerts(status, created_at);
        CREATE TABLE incidents (
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
        );
        CREATE INDEX idx_incidents_status ON incidents(status, created_at);
        CREATE INDEX idx_incidents_rule_ip ON incidents(rule_id, source_ip, status);
        CREATE TABLE incident_events (
            incident_id INTEGER NOT NULL,
            event_id INTEGER NOT NULL,
            added_at TEXT NOT NULL,
            PRIMARY KEY (incident_id, event_id),
            FOREIGN KEY (incident_id) REFERENCES incidents(id),
            FOREIGN KEY (event_id) REFERENCES events(id)
        );
        CREATE INDEX idx_incident_events_incident ON incident_events(incident_id);
        CREATE INDEX idx_incident_events_event ON incident_events(event_id);
        """
    )
    conn.commit()
    conn.close()

    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)  # should succeed (doesn't try to "fix" the missing core column)
    conn.commit()

    # Schema is still incomplete — raw_message is missing.
    diffs = compare_schema(conn)
    assert not diffs.complete
    assert "raw_message" in diffs.missing_columns.get("events", [])
    conn.close()


def test_extra_columns_preserved(tmp_path: Path):
    """Extra application columns and unrelated tables are preserved."""
    db_path = tmp_path / "extra.db"
    conn = _connect(db_path)
    conn.executescript(_legacy_core_ddl())
    # Add an extra column and an unrelated table.
    conn.execute("ALTER TABLE events ADD COLUMN debug_meta TEXT")
    conn.execute("CREATE TABLE user_notes (id INTEGER PRIMARY KEY, note TEXT)")
    conn.execute("INSERT INTO user_notes(note) VALUES ('keep me')")
    conn.commit()
    conn.close()

    conn = _connect(db_path)
    conn.execute("BEGIN")
    up(conn)
    conn.commit()

    # Extra column survives.
    columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(events)").fetchall()
    }
    assert "debug_meta" in columns

    # Unrelated table survives.
    tables = {
        row["name"]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "user_notes" in tables
    assert conn.execute("SELECT note FROM user_notes WHERE id=1").fetchone()["note"] == "keep me"

    # But the schema is no longer "complete" per EXPECTED_SCHEMA.
    diffs = compare_schema(conn)
    # The extra column is not a failure mode we test here, but compare_schema
    # should not raise.
    assert isinstance(diffs, type(compare_schema(conn)))
    conn.close()


def test_addable_columns_match_addable_set():
    """The columns added by the migration match ADDABLE_COLUMNS."""
    from backend.app.migration_schema import ADDABLE_COLUMNS

    expected_events = ADDABLE_COLUMNS["events"]
    actual_events = {col for col, _ in _EVENTS_ADDABLE_LIST()}
    assert actual_events == expected_events

    expected_alerts = ADDABLE_COLUMNS["alerts"]
    actual_alerts = {col for col, _ in _ALERTS_ADDABLE_LIST()}
    assert actual_alerts == expected_alerts


def _EVENTS_ADDABLE_LIST():
    """Re-export from the migration module to avoid import-time coupling."""
    from backend.app.migrations.v001_baseline import _EVENTS_ADDABLE

    return _EVENTS_ADDABLE


def _ALERTS_ADDABLE_LIST():
    from backend.app.migrations.v001_baseline import _ALERTS_ADDABLE

    return _ALERTS_ADDABLE
