"""Migration v004 compatibility, backfill-ordering, and fail-safe tests."""

from __future__ import annotations

import json
import sqlite3

import pytest

from backend.app.audit_chain import (
    canonical_audit_row,
    compute_chain_hash,
    verify_chain,
)
from backend.app.migration_ledger import (
    SCHEMA_MIGRATIONS_TABLE,
    create_schema_migrations_table,
)
from backend.app.migration_state import DatabaseState, ensure_database_file_exists
from backend.app.migrations.runner import MigrationError, migrate, status
from backend.app.migrations.v001_baseline import up as up_v1
from backend.app.migrations.v002_agents import up as up_v2
from backend.app.migrations.v003_audit_log_integrity import up as up_v3
from backend.app.migrations.v004_audit_chain_order import up as up_v4

EVENT_FIELDS = (
    "id",
    "timestamp",
    "event_type",
    "agent_id",
    "api_key_id",
    "actor",
    "detail",
)


def _stamp(connection: sqlite3.Connection, version: int, name: str) -> None:
    connection.execute(
        f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, name, applied_at) "
        "VALUES (?, ?, ?)",
        (version, name, "2026-01-01T00:00:00+00:00"),
    )


def _insert_raw(
    connection: sqlite3.Connection,
    timestamp: str,
    event_type: str,
    *,
    actor: str = "seed",
    detail: dict | None = None,
) -> None:
    connection.execute(
        "INSERT INTO audit_log (timestamp, event_type, actor, detail) "
        "VALUES (?, ?, ?, ?)",
        (
            timestamp,
            event_type,
            actor,
            json.dumps(detail) if detail is not None else None,
        ),
    )


def _legacy_append(
    connection: sqlite3.Connection,
    timestamp: str,
    event_type: str,
    *,
    actor: str = "legacy",
    detail: dict | None = None,
) -> None:
    """Append exactly as the pre-B2 ``_audit_log`` implementation did."""
    row = connection.execute(
        "SELECT chain_hash FROM audit_log "
        "ORDER BY timestamp DESC, id DESC LIMIT 1"
    ).fetchone()
    prev_hash = row["chain_hash"] if row else None
    detail_json = json.dumps(detail) if detail is not None else None
    payload = {
        "timestamp": timestamp,
        "event_type": event_type,
        "agent_id": None,
        "api_key_id": None,
        "actor": actor,
        "detail": detail_json,
    }
    chain_hash = compute_chain_hash(prev_hash, canonical_audit_row(payload))
    connection.execute(
        "INSERT INTO audit_log "
        "(timestamp, event_type, agent_id, api_key_id, actor, detail, "
        " prev_hash, chain_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            timestamp,
            event_type,
            None,
            None,
            actor,
            detail_json,
            prev_hash,
            chain_hash,
        ),
    )


def _make_v3_db(
    path,
    *,
    pre_rows: list[tuple[str, str]] = (),
    post_appends: list[tuple[str, str]] = (),
) -> None:
    """Create a database stamped at v3 with a real v003-built chain."""
    ensure_database_file_exists(path)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        create_schema_migrations_table(connection)

        up_v1(connection)
        _stamp(connection, 1, "baseline")
        up_v2(connection)
        _stamp(connection, 2, "agents_and_api_keys")

        for timestamp, event_type in pre_rows:
            _insert_raw(connection, timestamp, event_type, detail={"phase": "pre"})

        up_v3(connection)
        _stamp(connection, 3, "audit_log_integrity")

        for timestamp, event_type in post_appends:
            _legacy_append(
                connection, timestamp, event_type, detail={"phase": "post"}
            )

        connection.commit()
    finally:
        connection.close()


def _read_events(path) -> list[dict]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return [
            dict(row)
            for row in connection.execute(
                f"SELECT {', '.join(EVENT_FIELDS)} FROM audit_log ORDER BY id"
            ).fetchall()
        ]
    finally:
        connection.close()


def _read_chain(path) -> list[dict]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT id, prev_hash, chain_hash FROM audit_log ORDER BY id"
            ).fetchall()
        ]
    finally:
        connection.close()


def _verify_path(path) -> tuple[bool, list[str]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return verify_chain(connection)
    finally:
        connection.close()


def _ledger(path) -> list[tuple[int, str]]:
    connection = sqlite3.connect(path)
    try:
        return connection.execute(
            f"SELECT version, name FROM {SCHEMA_MIGRATIONS_TABLE} ORDER BY version"
        ).fetchall()
    finally:
        connection.close()


# --------------------------------------------------------------------------- #
# Ordering and preservation
# --------------------------------------------------------------------------- #


def test_fresh_database_applies_v4(tmp_path):
    path = tmp_path / "fresh.db"
    ensure_database_file_exists(path)

    result = migrate(str(path))

    assert result["applied"] == 4
    assert _ledger(path) == [
        (1, "baseline"),
        (2, "agents_and_api_keys"),
        (3, "audit_log_integrity"),
        (4, "audit_chain_order"),
    ]
    assert status(str(path)).state is DatabaseState.CURRENT
    assert _verify_path(path) == (True, [])


def test_v4_rebuilds_timestamp_backfill_in_insertion_order(tmp_path):
    path = tmp_path / "v3.db"
    # Insertion order (ids 1, 2) deliberately differs from timestamp order.
    _make_v3_db(
        path,
        pre_rows=[
            ("2026-01-01T10:00:20+00:00", "inserted_first"),
            ("2026-01-01T10:00:10+00:00", "inserted_second"),
        ],
    )
    before_events = _read_events(path)
    before_chain = _read_chain(path)

    # v003 backfilled in timestamp order: id 2 starts the chain, id 1 follows.
    assert before_chain[1]["prev_hash"] is None
    assert before_chain[0]["prev_hash"] == before_chain[1]["chain_hash"]
    assert _verify_path(path)[0] is False

    result = migrate(str(path))

    assert result["applied"] == 1
    assert _ledger(path)[-1] == (4, "audit_chain_order")
    assert _read_events(path) == before_events
    assert _verify_path(path) == (True, [])

    after_chain = _read_chain(path)
    assert after_chain[0]["prev_hash"] is None
    assert after_chain[1]["prev_hash"] == after_chain[0]["chain_hash"]
    assert [row["id"] for row in after_chain] == [1, 2]


def test_v4_accepts_legacy_clock_rollback_chain(tmp_path):
    path = tmp_path / "rollback.db"
    _make_v3_db(
        path,
        pre_rows=[
            ("2026-01-01T10:00:20+00:00", "pre_first"),
            ("2026-01-01T10:00:10+00:00", "pre_second"),
        ],
        post_appends=[
            # The legacy max-timestamp lookup links both of these to id 1
            # (timestamp 10:00:20), not to the preceding insert.
            ("2026-01-01T10:00:05+00:00", "post_first"),
            ("2026-01-01T10:00:04+00:00", "post_second"),
            ("2026-01-01T10:00:30+00:00", "post_third"),
        ],
    )
    before_events = _read_events(path)
    before_chain = _read_chain(path)

    # The legacy chain is valid under neither canonical order before v4.
    assert _verify_path(path)[0] is False
    assert before_chain[2]["prev_hash"] == before_chain[0]["chain_hash"]
    assert before_chain[3]["prev_hash"] == before_chain[0]["chain_hash"]

    result = migrate(str(path))

    assert result["applied"] == 1
    assert _read_events(path) == before_events
    assert _verify_path(path) == (True, [])

    after_chain = _read_chain(path)
    assert after_chain[0]["prev_hash"] is None
    for previous, current in zip(after_chain, after_chain[1:]):
        assert current["prev_hash"] == previous["chain_hash"]
    assert [row["id"] for row in after_chain] == [1, 2, 3, 4, 5]


def test_v4_preserves_an_already_canonical_chain(tmp_path):
    path = tmp_path / "canonical.db"
    _make_v3_db(
        path,
        post_appends=[
            ("2026-01-01T10:00:01+00:00", "first"),
            ("2026-01-01T10:00:02+00:00", "second"),
            ("2026-01-01T10:00:03+00:00", "third"),
        ],
    )
    before_chain = _read_chain(path)
    before_events = _read_events(path)
    assert _verify_path(path) == (True, [])

    migrate(str(path))

    assert _read_chain(path) == before_chain
    assert _read_events(path) == before_events
    assert _verify_path(path) == (True, [])


def test_v4_handles_empty_audit_table(tmp_path):
    path = tmp_path / "empty.db"
    _make_v3_db(path)
    assert _read_chain(path) == []

    result = migrate(str(path))

    assert result["applied"] == 1
    assert _read_chain(path) == []
    assert _verify_path(path) == (True, [])


def test_v4_is_idempotent_after_rebuild(tmp_path):
    path = tmp_path / "idempotent.db"
    _make_v3_db(
        path,
        post_appends=[
            ("2026-01-01T10:00:10+00:00", "first"),
            ("2026-01-01T10:00:05+00:00", "second"),
        ],
    )
    migrate(str(path))
    before = _read_chain(path)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        up_v4(connection)
        connection.commit()
    finally:
        connection.close()

    assert _read_chain(path) == before
    assert _verify_path(path) == (True, [])


def test_v4_supports_connections_without_row_factory(tmp_path):
    """The migration must not depend on sqlite3.Row for PRAGMA or chain rows."""
    path = tmp_path / "tuple-rows.db"
    _make_v3_db(
        path,
        pre_rows=[
            ("2026-01-01T10:00:20+00:00", "inserted_first"),
            ("2026-01-01T10:00:10+00:00", "inserted_second"),
        ],
    )

    connection = sqlite3.connect(path)  # default tuple row factory
    try:
        up_v4(connection)
        connection.commit()
    finally:
        connection.close()

    assert _verify_path(path) == (True, [])
    assert [row["id"] for row in _read_chain(path)] == [1, 2]


# --------------------------------------------------------------------------- #
# Fail-safe behavior
# --------------------------------------------------------------------------- #


def test_v4_rejects_tampered_content_and_rolls_back(tmp_path):
    path = tmp_path / "tampered-content.db"
    _make_v3_db(
        path,
        pre_rows=[
            ("2026-01-01T10:00:10+00:00", "first"),
            ("2026-01-01T10:00:20+00:00", "second"),
        ],
    )
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE audit_log SET detail = ? WHERE event_type = ?",
            ('{"tampered":true}', "second"),
        )
        connection.commit()
    finally:
        connection.close()

    before_events = _read_events(path)
    before_chain = _read_chain(path)
    before_ledger = _ledger(path)

    with pytest.raises(MigrationError, match="pre-v004 validation failed"):
        migrate(str(path))

    assert _ledger(path) == before_ledger
    assert _read_events(path) == before_events
    assert _read_chain(path) == before_chain
    assert status(str(path)).state is DatabaseState.PENDING


def test_v4_rejects_tampered_hash_and_rolls_back(tmp_path):
    path = tmp_path / "tampered-hash.db"
    _make_v3_db(
        path,
        pre_rows=[("2026-01-01T10:00:10+00:00", "first")],
    )
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE audit_log SET chain_hash = ? WHERE id = 1",
            ("0" * 64,),
        )
        connection.commit()
    finally:
        connection.close()

    before_events = _read_events(path)
    before_chain = _read_chain(path)
    before_ledger = _ledger(path)

    with pytest.raises(MigrationError, match="pre-v004 validation failed"):
        migrate(str(path))

    assert _ledger(path) == before_ledger
    assert _read_events(path) == before_events
    assert _read_chain(path) == before_chain


def test_v4_rejects_valid_hash_with_unknown_linkage(tmp_path):
    """Re-linking a row and recomputing its hash is still rejected."""
    path = tmp_path / "bad-link.db"
    _make_v3_db(
        path,
        pre_rows=[("2026-01-01T10:00:10+00:00", "first")],
        post_appends=[
            ("2026-01-01T10:00:20+00:00", "second"),
            ("2026-01-01T10:00:30+00:00", "third"),
        ],
    )

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute(
            "SELECT * FROM audit_log WHERE event_type = 'second'"
        ).fetchone()
        payload = {
            "timestamp": row["timestamp"],
            "event_type": row["event_type"],
            "agent_id": row["agent_id"],
            "api_key_id": row["api_key_id"],
            "actor": row["actor"],
            "detail": row["detail"],
        }
        wrong_prev = "0" * 64
        wrong_hash = compute_chain_hash(
            wrong_prev, canonical_audit_row(payload)
        )
        connection.execute(
            "UPDATE audit_log SET prev_hash = ?, chain_hash = ? WHERE id = ?",
            (wrong_prev, wrong_hash, row["id"]),
        )
        connection.commit()
    finally:
        connection.close()

    before_events = _read_events(path)
    before_ledger = _ledger(path)

    with pytest.raises(MigrationError, match="pre-v004 validation failed"):
        migrate(str(path))

    assert _ledger(path) == before_ledger
    assert _read_events(path) == before_events
    assert status(str(path)).state is DatabaseState.PENDING


def test_v4_rejects_null_chain_hash(tmp_path):
    path = tmp_path / "null-hash.db"
    _make_v3_db(
        path,
        pre_rows=[("2026-01-01T10:00:10+00:00", "first")],
    )
    connection = sqlite3.connect(path)
    try:
        connection.execute("UPDATE audit_log SET chain_hash = NULL WHERE id = 1")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(MigrationError, match="pre-v004 validation failed"):
        migrate(str(path))

    assert _ledger(path) == [
        (1, "baseline"),
        (2, "agents_and_api_keys"),
        (3, "audit_log_integrity"),
    ]


# --------------------------------------------------------------------------- #
# Canonical verifier sanity after migration
# --------------------------------------------------------------------------- #


def test_canonical_verifier_detects_post_migration_tampering(tmp_path):
    path = tmp_path / "post-tamper.db"
    _make_v3_db(
        path,
        post_appends=[
            ("2026-01-01T10:00:10+00:00", "first"),
            ("2026-01-01T10:00:20+00:00", "second"),
        ],
    )
    migrate(str(path))

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE audit_log SET actor = 'tampered' WHERE event_type = 'first'"
        )
        connection.commit()
    finally:
        connection.close()

    valid, errors = _verify_path(path)
    assert valid is False
    assert any("chain_hash mismatch" in error for error in errors)
