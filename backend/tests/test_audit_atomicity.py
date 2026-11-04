"""Regression tests for atomic lifecycle mutations and audit records (H1).

Every security-sensitive agent/API-key lifecycle mutation must commit together
with exactly one corresponding audit event. If audit persistence fails, the
state change must roll back instead of surviving as an unaudited mutation.

The failure tests install a SQLite trigger that aborts every ``audit_log``
INSERT. This exercises the real transaction boundary rather than mocking the
application helper: with the old implementation the mutation had already
committed on a separate connection, so the state change survived. It must not.

Covered operations:
  * agent creation, metadata update, and deactivation;
  * API-key creation, rotation, and revocation;
  * rollback preserves the original agent/key state;
  * successful operations emit exactly one event each, without plaintext keys;
  * concurrent lifecycle operations keep the audit chain valid;
  * non-critical observational audit logging remains best-effort.

Tests use an isolated, fully migrated database and a small PBKDF2 iteration
count.
"""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor

import pytest

from backend.app import agents as agents_module
from backend.app.agents import (
    _hash_key,
    authenticate_api_key,
    create_agent,
    create_api_key,
    deactivate_agent,
    get_agent,
    get_agent_by_name,
    get_api_key,
    list_api_keys,
    revoke_api_key,
    rotate_api_key,
    update_agent,
)
from backend.app.audit_chain import verify_chain
from backend.app.migration_state import ensure_database_file_exists
from backend.app.migrations.runner import migrate

TRIGGER = "fail_audit_insert"


# --------------------------------------------------------------------------- #
# Fixtures and helpers
# --------------------------------------------------------------------------- #


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Create an isolated, fully migrated agents/audit database."""
    db_path = tmp_path / "audit-atomicity.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv("GREYWATCH_KEY_HASH_ITERATIONS", "1000")
    ensure_database_file_exists(db_path)
    migrate(str(db_path), dry_run=False)
    return db_path


def _connect(db_path):
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def _install_audit_failure(db_path) -> None:
    """Abort every audit INSERT, simulating audit persistence failure."""
    connection = _connect(db_path)
    try:
        connection.execute(
            f"""
            CREATE TRIGGER {TRIGGER}
            BEFORE INSERT ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'simulated audit persistence failure');
            END
            """
        )
        connection.commit()
    finally:
        connection.close()


def _drop_audit_failure(db_path) -> None:
    connection = _connect(db_path)
    try:
        connection.execute(f"DROP TRIGGER IF EXISTS {TRIGGER}")
        connection.commit()
    finally:
        connection.close()


def _audit_rows(db_path, event_type: str | None = None) -> list[dict]:
    connection = _connect(db_path)
    try:
        if event_type is None:
            rows = connection.execute(
                "SELECT * FROM audit_log ORDER BY id ASC"
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM audit_log WHERE event_type = ? ORDER BY id ASC",
                (event_type,),
            ).fetchall()
    finally:
        connection.close()
    return [dict(row) for row in rows]


def _event_types(db_path) -> list[str]:
    return [row["event_type"] for row in _audit_rows(db_path)]


def _verify(db_path) -> tuple[bool, list[str]]:
    connection = _connect(db_path)
    try:
        return verify_chain(connection)
    finally:
        connection.close()


def _stored_key_hash(db_path, key_id: int) -> str:
    connection = _connect(db_path)
    try:
        row = connection.execute(
            "SELECT key_hash FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    return row["key_hash"]


# --------------------------------------------------------------------------- #
# Audit failure during each lifecycle mutation
# --------------------------------------------------------------------------- #


def test_agent_creation_rolls_back_when_audit_fails(db):
    _install_audit_failure(db)

    with pytest.raises(sqlite3.DatabaseError):
        create_agent("unaudited-agent")

    assert get_agent_by_name("unaudited-agent") is None
    assert _audit_rows(db) == []


def test_key_creation_rolls_back_when_audit_fails(db):
    agent = create_agent("key-creation-target")
    _install_audit_failure(db)

    with pytest.raises(sqlite3.DatabaseError):
        create_api_key(agent.id, name="unaudited-key")

    assert list_api_keys(agent.id) == []
    assert _event_types(db) == ["agent_created"]
    assert _verify(db) == (True, [])


def test_key_rotation_rolls_back_when_audit_fails(db):
    agent = create_agent("rotation-target")
    key = create_api_key(agent.id, name="rotate-me")
    _install_audit_failure(db)

    with pytest.raises(sqlite3.DatabaseError):
        rotate_api_key(key.id)

    # Old key remains active; no replacement key was committed.
    old_key = get_api_key(key.id)
    assert old_key is not None
    assert old_key.status == "active"
    keys = list_api_keys(agent.id)
    assert [item.id for item in keys] == [key.id]
    assert authenticate_api_key(key.plaintext_key) is not None

    assert _event_types(db) == ["agent_created", "key_generated"]
    assert _verify(db) == (True, [])


def test_key_revocation_rolls_back_when_audit_fails(db):
    agent = create_agent("revocation-target")
    key = create_api_key(agent.id, name="revoke-me")
    _install_audit_failure(db)

    with pytest.raises(sqlite3.DatabaseError):
        revoke_api_key(key.id, "test revocation")

    revoked = get_api_key(key.id)
    assert revoked is not None
    assert revoked.status == "active"
    assert revoked.revoked_at is None
    assert authenticate_api_key(key.plaintext_key) is not None

    assert _event_types(db) == ["agent_created", "key_generated"]
    assert _verify(db) == (True, [])


def test_agent_update_rolls_back_when_audit_fails(db):
    agent = create_agent("update-target", display_name="before")
    _install_audit_failure(db)

    with pytest.raises(sqlite3.DatabaseError):
        update_agent(
            agent.id,
            display_name="after",
            description="new description",
        )

    unchanged = get_agent(agent.id)
    assert unchanged is not None
    assert unchanged.display_name == "before"
    assert unchanged.description is None
    assert _event_types(db) == ["agent_created"]
    assert _verify(db) == (True, [])


def test_agent_deactivation_rolls_back_when_audit_fails(db):
    agent = create_agent("deactivation-target")
    key = create_api_key(agent.id, name="must-stay-active")
    _install_audit_failure(db)

    with pytest.raises(sqlite3.DatabaseError):
        deactivate_agent(agent.id, "test deactivation")

    unchanged_agent = get_agent(agent.id)
    assert unchanged_agent is not None
    assert unchanged_agent.status == "active"
    assert unchanged_agent.deactivated_at is None
    assert get_api_key(key.id).status == "active"
    assert authenticate_api_key(key.plaintext_key) is not None

    assert _event_types(db) == ["agent_created", "key_generated"]
    assert _verify(db) == (True, [])


# --------------------------------------------------------------------------- #
# Successful lifecycle events
# --------------------------------------------------------------------------- #


def test_successful_lifecycle_operations_emit_exactly_one_event_each(db):
    """Each mutation emits one event describing the committed state."""
    agent = create_agent("lifecycle-agent", display_name="Initial")
    update_agent(agent.id, description="Updated description")
    key = create_api_key(agent.id, name="primary")
    rotated = rotate_api_key(key.id)
    revoke_api_key(rotated.id, "cleanup")
    deactivate_agent(agent.id, "finished")

    assert _event_types(db) == [
        "agent_created",
        "agent_updated",
        "key_generated",
        "key_rotated",
        "key_revoked",
        "agent_deactivated",
    ]

    generated = _audit_rows(db, "key_generated")[0]
    assert generated["agent_id"] == agent.id
    assert generated["api_key_id"] == key.id

    rotated_row = _audit_rows(db, "key_rotated")[0]
    assert rotated_row["agent_id"] == agent.id
    assert rotated_row["api_key_id"] == rotated.id
    assert f'"old_key_id": {key.id}' in rotated_row["detail"]

    revoked_row = _audit_rows(db, "key_revoked")[0]
    assert revoked_row["api_key_id"] == rotated.id

    deactivated_row = _audit_rows(db, "agent_deactivated")[0]
    assert deactivated_row["agent_id"] == agent.id

    # Plaintext credentials must never appear in the audit trail.
    all_details = " ".join(row["detail"] or "" for row in _audit_rows(db))
    assert key.plaintext_key not in all_details
    assert rotated.plaintext_key not in all_details
    assert "key_hash" not in all_details

    assert _verify(db) == (True, [])


def test_noop_agent_update_emits_no_audit_event(db):
    agent = create_agent("noop-update")

    result = update_agent(agent.id)  # no fields -> no mutation

    assert result is not None
    assert _event_types(db) == ["agent_created"]
    assert _verify(db) == (True, [])


def test_failed_operation_emits_no_audit_event(db):
    """Attempted (not committed) changes must not be audited."""
    create_agent("duplicate-name")
    with pytest.raises(ValueError):
        create_agent("duplicate-name")
    assert _event_types(db) == ["agent_created"]

    with pytest.raises(ValueError):
        create_api_key(999_999, name="missing-agent")
    assert _event_types(db) == ["agent_created"]

    agent = create_agent("failed-rotation")
    key = create_api_key(agent.id)
    revoke_api_key(key.id, "already revoked")
    with pytest.raises(ValueError):
        rotate_api_key(key.id)
    assert _event_types(db) == [
        "agent_created",
        "agent_created",
        "key_generated",
        "key_revoked",
    ]
    assert _verify(db) == (True, [])


# --------------------------------------------------------------------------- #
# Concurrency and chain integrity
# --------------------------------------------------------------------------- #


def test_concurrent_agent_creation_keeps_chain_valid(db):
    workers = 8

    def create(index: int) -> str:
        return create_agent(f"concurrent-agent-{index}").name

    with ThreadPoolExecutor(max_workers=workers) as pool:
        names = [future.result() for future in [pool.submit(create, i) for i in range(workers)]]

    assert sorted(names) == [f"concurrent-agent-{i}" for i in range(workers)]
    assert len(_audit_rows(db, "agent_created")) == workers
    assert _verify(db) == (True, [])


def test_concurrent_key_creation_keeps_chain_valid(db):
    agent = create_agent("shared-key-agent")
    workers = 6

    def create(index: int):
        return create_api_key(agent.id, name=f"concurrent-key-{index}")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        keys = [
            future.result()
            for future in [pool.submit(create, i) for i in range(workers)]
        ]

    assert len({key.id for key in keys}) == workers
    assert len(list_api_keys(agent.id)) == workers
    assert len(_audit_rows(db, "key_generated")) == workers
    assert _verify(db) == (True, [])


# --------------------------------------------------------------------------- #
# Non-critical audit logging and optional rehash
# --------------------------------------------------------------------------- #


def test_noncritical_audit_log_remains_best_effort(db):
    """Observational events do not change authentication behavior."""
    _install_audit_failure(db)

    # Must not raise even though persistence fails.
    agents_module._audit_log("auth_failure", detail={"reason": "test"})

    assert _audit_rows(db) == []
    # A failed auth is still a normal 401/None result, not an outage.
    assert authenticate_api_key("gw_missing-key") is None


def test_rehash_and_audit_roll_back_together_on_failure(db):
    """A failed rehash audit keeps the previous hash; authentication succeeds."""
    agent = create_agent("rehash-failure")
    key = create_api_key(agent.id, name="rehash-me")

    old_hash = _hash_key(key.plaintext_key, 500)
    connection = _connect(db)
    try:
        connection.execute(
            "UPDATE api_keys SET key_hash = ? WHERE id = ?", (old_hash, key.id)
        )
        connection.commit()
    finally:
        connection.close()

    _install_audit_failure(db)

    result = authenticate_api_key(key.plaintext_key)
    assert result is not None

    # UPDATE rolled back with the failed audit insert; old hash still valid.
    assert _stored_key_hash(db, key.id).split("$")[1] == "500"
    assert _audit_rows(db, "key_rehashed") == []
    assert _verify(db) == (True, [])


def test_successful_rehash_and_audit_commit_together(db):
    agent = create_agent("rehash-success")
    key = create_api_key(agent.id, name="rehash-me")

    old_hash = _hash_key(key.plaintext_key, 500)
    connection = _connect(db)
    try:
        connection.execute(
            "UPDATE api_keys SET key_hash = ? WHERE id = ?", (old_hash, key.id)
        )
        connection.commit()
    finally:
        connection.close()

    result = authenticate_api_key(key.plaintext_key)
    assert result is not None

    assert _stored_key_hash(db, key.id).split("$")[1] == "1000"
    assert len(_audit_rows(db, "key_rehashed")) == 1
    assert _verify(db) == (True, [])
