"""Tests for the schema-migration ledger foundation (backend/app/migrations.py).

These exercise only the ledger-table creation: that the table can be created,
that creation is idempotent, that pre-existing tables and data are untouched,
that no application table is dropped or rebuilt, and that the ledger's columns
and primary key match the documented schema.

No migration runner is exercised here. All databases are isolated under
``tmp_path``; the production database is never opened (the autouse conftest
fixture also refuses an explicit production path).
"""

from __future__ import annotations

import sqlite3

from backend.app.migration_ledger import (
    SCHEMA_MIGRATIONS_TABLE,
    create_schema_migrations_table,
)
from backend.app.siem import _connection, initialize_database


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _connect(path) -> sqlite3.Connection:
    """Open a plain SQLite connection (no PRAGMA side effects)."""
    return sqlite3.connect(path)


def _table_names(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()
    return {row[0] for row in rows}


def _columns(connection: sqlite3.Connection, table: str) -> list[tuple]:
    """Return PRAGMA table_info rows for ``table``."""
    return connection.execute(f"PRAGMA table_info({table})").fetchall()


# --------------------------------------------------------------------------- #
# 1. Ledger table can be created
# --------------------------------------------------------------------------- #


def test_ledger_table_can_be_created(tmp_path):
    """create_schema_migrations_table creates the ledger on a fresh database."""
    db = tmp_path / "ledger.db"
    conn = _connect(db)
    try:
        assert SCHEMA_MIGRATIONS_TABLE not in _table_names(conn)

        create_schema_migrations_table(conn)
        conn.commit()

        assert SCHEMA_MIGRATIONS_TABLE in _table_names(conn)
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# 2. Repeated creation is idempotent
# --------------------------------------------------------------------------- #


def test_ledger_creation_is_idempotent(tmp_path):
    """Calling create twice produces no error and exactly one table."""
    db = tmp_path / "ledger.db"
    conn = _connect(db)
    try:
        create_schema_migrations_table(conn)
        create_schema_migrations_table(conn)  # second call must be a no-op
        conn.commit()

        count = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type='table' AND name=?",
            (SCHEMA_MIGRATIONS_TABLE,),
        ).fetchone()[0]
        assert count == 1
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# 3. Existing events and alerts data remains unchanged
# --------------------------------------------------------------------------- #


def test_ledger_creation_preserves_existing_data(tmp_path, monkeypatch):
    """Seeding the real schema, inserting rows, then creating the ledger leaves
    the inserted events and alerts exactly as they were."""
    db_path = str(tmp_path / "gw.db")
    monkeypatch.setenv("GREYWATCH_DB", db_path)
    initialize_database()

    with _connection() as conn:
        event_id = conn.execute(
            "INSERT INTO events "
            "(timestamp, host, event_type, severity, raw_message) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                "2026-01-01T00:00:00+00:00",
                "lab-host",
                "ssh_login_failed",
                "medium",
                "legacy raw line",
            ),
        ).lastrowid
        alert_id = conn.execute(
            "INSERT INTO alerts "
            "(created_at, rule_id, title, severity, source_ip, description, "
            " event_count, status, last_triggered_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "2026-01-02T00:00:00+00:00",
                "SSH_BRUTE_FORCE",
                "Test alert",
                "high",
                "203.0.113.10",
                "desc",
                1,
                "open",
                "2026-01-02T00:00:00+00:00",
            ),
        ).lastrowid

    # Create the migration ledger on the SAME database file.
    conn = _connect(db_path)
    try:
        create_schema_migrations_table(conn)
        conn.commit()
    finally:
        conn.close()

    # Existing tables + data are intact; ledger is present.
    with _connection() as conn:
        tables = _table_names(conn)
        assert SCHEMA_MIGRATIONS_TABLE in tables
        event = conn.execute(
            "SELECT id, host, severity, raw_message FROM events "
            "ORDER BY id ASC LIMIT 1"
        ).fetchone()
        alert = conn.execute(
            "SELECT id, rule_id, source_ip, status FROM alerts "
            "ORDER BY id ASC LIMIT 1"
        ).fetchone()

    assert event["id"] == event_id
    assert event["host"] == "lab-host"
    assert event["severity"] == "medium"
    assert event["raw_message"] == "legacy raw line"

    assert alert["id"] == alert_id
    assert alert["rule_id"] == "SSH_BRUTE_FORCE"
    assert alert["source_ip"] == "203.0.113.10"
    assert alert["status"] == "open"


# --------------------------------------------------------------------------- #
# 4. Existing database tables are not dropped or rebuilt
# --------------------------------------------------------------------------- #


def test_ledger_creation_does_not_drop_existing_tables(tmp_path, monkeypatch):
    """Creating the ledger never removes the application's existing tables."""
    db_path = str(tmp_path / "gw.db")
    monkeypatch.setenv("GREYWATCH_DB", db_path)
    initialize_database()

    # Snapshot the tables that exist before ledger creation.
    with _connection() as conn:
        before = _table_names(conn)

    conn = _connect(db_path)
    try:
        create_schema_migrations_table(conn)
        conn.commit()
    finally:
        conn.close()

    with _connection() as conn:
        after = _table_names(conn)

    # Every pre-existing table is still present (nothing dropped/rebuilt).
    assert before <= after
    for table in (
        "events",
        "alerts",
        "incidents",
        "incident_events",
        "collector_state",
    ):
        assert table in after
    # The ledger itself appeared.
    assert SCHEMA_MIGRATIONS_TABLE in after


# --------------------------------------------------------------------------- #
# 5. Ledger columns and primary key are correct
# --------------------------------------------------------------------------- #


def test_ledger_columns_and_primary_key(tmp_path):
    """The ledger has exactly version/name/applied_at with the documented types,
    NOT NULL constraints, and version as the sole INTEGER PRIMARY KEY."""
    db = tmp_path / "ledger.db"
    conn = _connect(db)
    try:
        create_schema_migrations_table(conn)
        conn.commit()
        info = _columns(conn, SCHEMA_MIGRATIONS_TABLE)
    finally:
        conn.close()

    by_name = {row[1]: row for row in info}
    assert set(by_name) == {"version", "name", "applied_at"}

    # (cid, name, type, notnull, dflt_value, pk)
    version = by_name["version"]
    assert version[2] == "INTEGER"
    assert version[5] == 1  # PRIMARY KEY (notnull may read 0 for INTEGER PK -- SQLite quirk)
    # The NOT NULL constraint is functionally implied by the PRIMARY KEY below.

    name = by_name["name"]
    assert name[2] == "TEXT"
    assert name[3] == 1  # NOT NULL
    assert name[5] == 0  # not a PK column

    applied_at = by_name["applied_at"]
    assert applied_at[2] == "TEXT"
    assert applied_at[3] == 1  # NOT NULL
    assert applied_at[5] == 0  # not a PK column

    # version is the single primary-key column.
    pk_columns = [row[1] for row in info if row[5] == 1]
    assert pk_columns == ["version"]
