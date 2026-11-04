"""Deterministic tests for canonical audit-chain ordering.

The canonical order is insertion order (``id ASC``).  Timestamps are retained
for display but must never determine the chain predecessor.  A controllable
clock is injected through ``agents._utc_now_datetime``; no test sleeps to
advance time.
"""

from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from backend.app import agents as agents_module
from backend.app.audit_chain import (
    canonical_audit_row,
    compute_chain_hash,
    verify_chain,
)
from backend.app.migration_state import ensure_database_file_exists
from backend.app.migrations import v003_audit_log_integrity as v003
from backend.app.migrations.runner import migrate

CANONICAL_FIELDS = (
    "timestamp",
    "event_type",
    "agent_id",
    "api_key_id",
    "actor",
    "detail",
)

LATEST_HASH_QUERY = """
    SELECT chain_hash FROM audit_log
    ORDER BY id DESC
    LIMIT 1
"""


class FakeClock:
    """Controllable wall clock for audit timestamps."""

    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value

    def set(self, value: datetime) -> None:
        self.value = value

    def advance(self, **kwargs) -> None:
        self.value += timedelta(**kwargs)


@pytest.fixture
def clock(monkeypatch):
    """Replace the application wall clock with a controllable clock."""
    fake = FakeClock(datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc))
    monkeypatch.setattr(agents_module, "_utc_now_datetime", fake)
    return fake


@pytest.fixture
def audit_db(tmp_path, monkeypatch):
    """Create an isolated, fully migrated database for one test."""
    db_path = tmp_path / "audit.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    ensure_database_file_exists(db_path)
    migrate(str(db_path), dry_run=False)
    return db_path


def _rows(order_by: str = "id ASC") -> list[dict]:
    """Return audit rows in canonical (or explicitly requested) order."""
    assert order_by in {"id ASC", "timestamp ASC, id ASC"}
    with agents_module._connection() as conn:
        rows = conn.execute(
            f"""
            SELECT id, timestamp, event_type, agent_id, api_key_id, actor,
                   detail, prev_hash, chain_hash
            FROM audit_log
            ORDER BY {order_by}
            """
        ).fetchall()
    return [dict(row) for row in rows]


def _expected_chain_hash(prev_hash: str | None, row: dict) -> str:
    canonical = canonical_audit_row({field: row[field] for field in CANONICAL_FIELDS})
    return compute_chain_hash(prev_hash, canonical)


def _seed_canonical_rows(entries: list[tuple[str, str]]) -> list[dict]:
    """Seed a valid insertion-order chain directly into the audit table."""
    connection = sqlite3.connect(os.environ["GREYWATCH_DB"])
    connection.row_factory = sqlite3.Row
    try:
        prev_hash = None
        seeded: list[dict] = []
        for timestamp, event_type in entries:
            row = {
                "timestamp": timestamp,
                "event_type": event_type,
                "agent_id": None,
                "api_key_id": None,
                "actor": "seed",
                "detail": None,
            }
            chain_hash = _expected_chain_hash(prev_hash, row)
            cursor = connection.execute(
                """
                INSERT INTO audit_log
                    (timestamp, event_type, agent_id, api_key_id, actor,
                     detail, prev_hash, chain_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    event_type,
                    None,
                    None,
                    "seed",
                    None,
                    prev_hash,
                    chain_hash,
                ),
            )
            seeded.append(
                {
                    "id": cursor.lastrowid,
                    **row,
                    "prev_hash": prev_hash,
                    "chain_hash": chain_hash,
                }
            )
            prev_hash = chain_hash
        connection.commit()
    finally:
        connection.close()
    return seeded


def _verify(audit_db) -> tuple[bool, list[str]]:
    connection = sqlite3.connect(audit_db)
    connection.row_factory = sqlite3.Row
    try:
        return verify_chain(connection)
    finally:
        connection.close()


# --------------------------------------------------------------------------- #
# Append behavior and clock rollback
# --------------------------------------------------------------------------- #


def test_empty_audit_table_starts_chain(audit_db, clock):
    """The first record starts a chain with no previous hash."""
    assert _rows() == []

    agents_module._audit_log(
        "agent_created", actor="admin", detail={"name": "first-agent"}
    )

    rows = _rows()
    assert len(rows) == 1
    assert rows[0]["prev_hash"] is None
    assert rows[0]["chain_hash"] == _expected_chain_hash(None, rows[0])
    assert _verify(audit_db) == (True, [])


def test_normal_sequential_appends_link_by_id(audit_db, clock):
    """Forward timestamps produce the same chain as insertion order."""
    agents_module._audit_log("first_event", actor="system")
    clock.advance(seconds=1)
    agents_module._audit_log("second_event", actor="system", detail={"step": 2})
    clock.advance(seconds=1)
    agents_module._audit_log("third_event", actor="system", detail={"step": 3})

    rows = _rows()
    assert [row["event_type"] for row in rows] == [
        "first_event",
        "second_event",
        "third_event",
    ]
    assert rows[0]["prev_hash"] is None
    for previous, current in zip(rows, rows[1:]):
        assert current["prev_hash"] == previous["chain_hash"]
        assert current["chain_hash"] == _expected_chain_hash(
            previous["chain_hash"], current
        )
    assert _verify(audit_db) == (True, [])


def test_backward_timestamps_still_link_by_id(audit_db, clock):
    """A clock rollback must not change the predecessor of the next append."""
    agents_module._audit_log("first_event", actor="system")
    clock.set(clock.value - timedelta(hours=1))
    agents_module._audit_log("second_event", actor="system")

    rows = _rows()
    assert [row["event_type"] for row in rows] == ["first_event", "second_event"]
    assert rows[0]["timestamp"] > rows[1]["timestamp"]
    assert rows[1]["prev_hash"] == rows[0]["chain_hash"]
    assert rows[1]["chain_hash"] == _expected_chain_hash(
        rows[0]["chain_hash"], rows[1]
    )
    assert _verify(audit_db) == (True, [])


def test_identical_timestamps_use_id_as_tiebreaker(audit_db, clock):
    """Equal timestamps link in insertion order, never by timestamp alone."""
    for index in range(3):
        agents_module._audit_log(f"event_{index}", actor="system")

    rows = _rows()
    assert [row["timestamp"] for row in rows] == [rows[0]["timestamp"]] * 3
    assert rows[0]["prev_hash"] is None
    assert rows[1]["prev_hash"] == rows[0]["chain_hash"]
    assert rows[2]["prev_hash"] == rows[1]["chain_hash"]
    assert _verify(audit_db) == (True, [])


def test_verification_passes_after_clock_rollback(audit_db, clock):
    """Forward, backward, and forward clock changes keep the chain valid."""
    agents_module._audit_log("at_ten", actor="system")
    clock.set(clock.value - timedelta(seconds=10))
    agents_module._audit_log("at_zero", actor="system")
    clock.set(clock.value + timedelta(seconds=5))
    agents_module._audit_log("at_five", actor="system")
    clock.set(clock.value + timedelta(seconds=30))
    agents_module._audit_log("at_thirty_five", actor="system")

    rows = _rows()
    assert [row["event_type"] for row in rows] == [
        "at_ten",
        "at_zero",
        "at_five",
        "at_thirty_five",
    ]
    for previous, current in zip(rows, rows[1:]):
        assert current["prev_hash"] == previous["chain_hash"]
    assert _verify(audit_db) == (True, [])


def test_append_after_rollback_links_last_inserted_not_latest_timestamp(
    audit_db, clock
):
    """The legacy max-timestamp lookup would skip the middle row here."""
    agents_module._audit_log("at_ten", actor="system")
    clock.set(clock.value - timedelta(seconds=10))
    agents_module._audit_log("at_zero", actor="system")
    clock.set(clock.value + timedelta(seconds=5))
    agents_module._audit_log("at_five", actor="system")

    rows = _rows()
    # ``at_ten`` has the greatest timestamp, but ``at_zero`` was inserted last
    # before ``at_five`` and must be the predecessor.
    assert rows[2]["prev_hash"] == rows[1]["chain_hash"]
    assert rows[2]["prev_hash"] != rows[0]["chain_hash"]
    assert _verify(audit_db) == (True, [])


def test_append_to_seeded_out_of_order_timestamps_uses_last_id(audit_db, clock):
    """Seeded rows with non-monotonic timestamps append to the highest id."""
    seeded = _seed_canonical_rows(
        [
            ("2000-01-03T00:00:00+00:00", "first_event"),
            ("2000-01-01T00:00:00+00:00", "second_event"),
            ("2000-01-02T00:00:00+00:00", "third_event"),
        ]
    )
    assert _verify(audit_db) == (True, [])

    clock.set(datetime(1999, 1, 1, tzinfo=timezone.utc))
    agents_module._audit_log("appended_event", actor="system")

    rows = _rows()
    assert rows[-1]["prev_hash"] == seeded[-1]["chain_hash"]
    assert rows[-1]["chain_hash"] == _expected_chain_hash(
        seeded[-1]["chain_hash"], rows[-1]
    )
    assert _verify(audit_db) == (True, [])


def test_latest_hash_lookup_is_indexed_and_sorted_by_id(audit_db, clock):
    """The append lookup must not build a temporary sort or scan timestamps."""
    agents_module._audit_log("first_event", actor="system")

    with agents_module._connection() as conn:
        plan = [
            row["detail"]
            for row in conn.execute(
                f"EXPLAIN QUERY PLAN {LATEST_HASH_QUERY}"
            ).fetchall()
        ]

    assert not any("TEMP B-TREE" in step for step in plan), plan
    assert any("SCAN audit_log" in step for step in plan), plan


def test_concurrent_appends_produce_one_valid_chain(audit_db, clock):
    """Serialized appends leave exactly one predecessor per row."""
    workers = 8

    def append(index: int) -> None:
        agents_module._audit_log(f"concurrent_{index}", actor="system")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(append, index) for index in range(workers)]
        for future in futures:
            future.result()

    rows = _rows()
    assert len(rows) == workers
    assert len({row["id"] for row in rows}) == workers
    assert rows[0]["prev_hash"] is None
    for previous, current in zip(rows, rows[1:]):
        assert current["prev_hash"] == previous["chain_hash"]
        assert current["chain_hash"] == _expected_chain_hash(
            previous["chain_hash"], current
        )
    assert _verify(audit_db) == (True, [])


# --------------------------------------------------------------------------- #
# Tamper detection
# --------------------------------------------------------------------------- #


def test_tampered_record_fails_verification(audit_db, clock):
    """Changing an event field without updating the hash is detected."""
    for index in range(3):
        agents_module._audit_log(f"event_{index}", actor="system")
        clock.advance(seconds=1)

    connection = sqlite3.connect(audit_db)
    try:
        connection.execute(
            "UPDATE audit_log SET detail = ? WHERE event_type = ?",
            ('{"tampered":true}', "event_1"),
        )
        connection.commit()
    finally:
        connection.close()

    valid, errors = _verify(audit_db)
    assert valid is False
    assert any("Record id=2" in error and "chain_hash mismatch" in error for error in errors)


def test_tampered_prev_hash_fails_verification(audit_db, clock):
    """Changing linkage without recomputing the hash is detected."""
    agents_module._audit_log("first_event", actor="system")
    agents_module._audit_log("second_event", actor="system")

    connection = sqlite3.connect(audit_db)
    try:
        connection.execute(
            "UPDATE audit_log SET prev_hash = ? WHERE event_type = ?",
            ("0" * 64, "second_event"),
        )
        connection.commit()
    finally:
        connection.close()

    valid, errors = _verify(audit_db)
    assert valid is False
    assert any("prev_hash mismatch" in error for error in errors)
    assert any("chain_hash mismatch" in error for error in errors)


def test_verification_works_without_row_factory(audit_db):
    """Verification must work on a default tuple-row connection."""
    _seed_canonical_rows(
        [
            ("2000-01-03T00:00:00+00:00", "first_event"),
            ("2000-01-01T00:00:00+00:00", "second_event"),
        ]
    )

    connection = sqlite3.connect(audit_db)  # default tuple row factory
    try:
        assert verify_chain(connection) == (True, [])
    finally:
        connection.close()


def test_verification_is_read_only(audit_db, clock):
    """Verification never repairs or rewrites a tampered chain."""
    agents_module._audit_log("first_event", actor="system")
    agents_module._audit_log("second_event", actor="system")

    connection = sqlite3.connect(audit_db)
    try:
        connection.execute(
            "UPDATE audit_log SET detail = '{\"tampered\":true}' WHERE id = 1"
        )
        connection.commit()
        before = connection.execute(
            "SELECT id, prev_hash, chain_hash FROM audit_log ORDER BY id"
        ).fetchall()
    finally:
        connection.close()

    assert _verify(audit_db)[0] is False

    connection = sqlite3.connect(audit_db)
    try:
        after = connection.execute(
            "SELECT id, prev_hash, chain_hash FROM audit_log ORDER BY id"
        ).fetchall()
    finally:
        connection.close()

    assert after == before


# --------------------------------------------------------------------------- #
# Cross-module compatibility
# --------------------------------------------------------------------------- #


def test_v003_canonical_helpers_match_shared_helpers():
    """The frozen v003 helpers must match the shared canonical helpers."""
    sample = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "event_type": "test_event",
        "agent_id": None,
        "api_key_id": 7,
        "actor": "system",
        "detail": '{"a":1}',
    }

    assert v003._canonical_audit_row(sample) == canonical_audit_row(sample)
    canonical = canonical_audit_row(sample)
    assert v003._compute_chain_hash(None, canonical) == compute_chain_hash(
        None, canonical
    )
    assert v003._compute_chain_hash("abc", canonical) == compute_chain_hash(
        "abc", canonical
    )
