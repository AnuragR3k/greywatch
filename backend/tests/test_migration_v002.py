"""Regression tests for v002 ``events.agent_id`` idempotency.

The v2 migration must independently ensure both the ``events.agent_id`` column
and its ``idx_events_agent_id`` index exist. A partial migration may have added
the column without the index; rerunning the migration must repair that state
without duplicating indexes or changing foreign-key behavior.
"""

from __future__ import annotations

import sqlite3

import pytest

from backend.app.migrations.v001_baseline import up as up_v1
from backend.app.migrations.v002_agents import up as up_v2

AGENT_INDEX = "idx_events_agent_id"


@pytest.fixture
def connection():
    """In-memory database with row access and foreign keys enabled."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
    finally:
        conn.close()


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _index_count(conn: sqlite3.Connection, name: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS count FROM sqlite_master "
        "WHERE type = 'index' AND name = ?",
        (name,),
    ).fetchone()
    return row["count"]


def _index_columns(conn: sqlite3.Connection, name: str) -> list[str]:
    return [
        row["name"]
        for row in conn.execute(f"PRAGMA index_info({name})").fetchall()
    ]


def _events_agent_foreign_keys(conn: sqlite3.Connection) -> list[tuple[str, str, str, str]]:
    return sorted(
        (
            row["table"],
            row["from"],
            row["to"],
            row["on_delete"],
        )
        for row in conn.execute("PRAGMA foreign_key_list(events)").fetchall()
        if row["from"] == "agent_id"
    )


def test_adds_missing_agent_id_column_and_index(connection):
    """A v1 events table without agent_id gains both the column and index."""
    up_v1(connection)
    assert "agent_id" not in _columns(connection, "events")
    assert _index_count(connection, AGENT_INDEX) == 0

    up_v2(connection)

    assert "agent_id" in _columns(connection, "events")
    assert _index_count(connection, AGENT_INDEX) == 1
    assert _index_columns(connection, AGENT_INDEX) == ["agent_id"]
    assert _events_agent_foreign_keys(connection) == [
        ("agents", "agent_id", "id", "SET NULL")
    ]


def test_creates_index_when_column_exists_but_index_is_missing(connection):
    """Rerunning v2 repairs a missing index without altering the column/FK."""
    up_v1(connection)
    up_v2(connection)
    connection.execute(f"DROP INDEX {AGENT_INDEX}")

    # Precondition for the regression: the column exists, the index does not.
    assert "agent_id" in _columns(connection, "events")
    assert _index_count(connection, AGENT_INDEX) == 0
    foreign_keys = _events_agent_foreign_keys(connection)
    assert foreign_keys == [("agents", "agent_id", "id", "SET NULL")]

    up_v2(connection)

    assert _index_count(connection, AGENT_INDEX) == 1
    assert _index_columns(connection, AGENT_INDEX) == ["agent_id"]
    assert _events_agent_foreign_keys(connection) == foreign_keys


def test_rerunning_migration_does_not_duplicate_index(connection):
    """A completed v2 migration can be rerun safely without duplicate indexes."""
    up_v1(connection)
    up_v2(connection)
    foreign_keys = _events_agent_foreign_keys(connection)

    up_v2(connection)

    assert _index_count(connection, AGENT_INDEX) == 1
    assert _index_columns(connection, AGENT_INDEX) == ["agent_id"]
    assert _events_agent_foreign_keys(connection) == foreign_keys
