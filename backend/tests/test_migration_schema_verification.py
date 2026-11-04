"""M3 regression tests: version-aware migration schema verification.

The migration ledger is a record of *intent*, not proof that the schema
exists. These tests build databases at every supported migration version, then
remove individual tables, columns, and indexes and prove that inspection and
startup fail closed with actionable diagnostics instead of trusting the ledger.

All databases are created under ``tmp_path``. No test touches the production
database, and the verification-only tests assert byte-for-byte non-mutation.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app.migration_ledger import (
    SCHEMA_MIGRATIONS_TABLE,
    create_schema_migrations_table,
)
from backend.app.migration_registry import MIGRATIONS
from backend.app.migration_schema import (
    AGENT_TABLES,
    APP_TABLES,
    EXPECTED_SCHEMA,
    compare_schema,
    expected_schema_for_version,
    schema_fingerprint,
)
from backend.app.migration_state import DatabaseState, inspect_path
from backend.app.migrations import runner as runner_module
from backend.app.migrations.runner import MigrationError, MigrationStateError, migrate
from backend.app.migrations.v001_baseline import up as up_v1
from backend.app.migrations.v002_agents import up as up_v2
from backend.app.migrations.v003_audit_log_integrity import up as up_v3
from backend.app.migrations.v004_audit_chain_order import up as up_v4

UPS = {1: up_v1, 2: up_v2, 3: up_v3, 4: up_v4}
LATEST = 4


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _build_version(path: Path, version: int) -> Path:
    """Build a database whose schema and ledger are exactly at ``version``."""
    if version not in UPS:
        raise ValueError(version)

    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN")
        create_schema_migrations_table(connection)
        for number in range(1, version + 1):
            UPS[number](connection)
        for number in range(1, version + 1):
            connection.execute(
                f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} "
                "(version, name, applied_at) VALUES (?, ?, ?)",
                (number, MIGRATIONS[number - 1].name, "test"),
            )
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
    return path


def _build_legacy_v1(path: Path) -> Path:
    """Build a pre-agent (v1) database with no migration ledger."""
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("BEGIN")
        up_v1(connection)
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
    return path


def _set_ledger(path: Path, versions: tuple[int, ...]) -> None:
    connection = sqlite3.connect(path)
    try:
        create_schema_migrations_table(connection)
        connection.execute(f"DELETE FROM {SCHEMA_MIGRATIONS_TABLE}")
        connection.executemany(
            f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} "
            "(version, name, applied_at) VALUES (?, ?, ?)",
            [(n, MIGRATIONS[n - 1].name, "test") for n in versions],
        )
        connection.commit()
    finally:
        connection.close()


def _ledger_versions(path: Path) -> list[int]:
    connection = sqlite3.connect(path)
    try:
        return [
            row[0]
            for row in connection.execute(
                f"SELECT version FROM {SCHEMA_MIGRATIONS_TABLE} ORDER BY version"
            )
        ]
    finally:
        connection.close()


def _table_names(path: Path) -> set[str]:
    connection = sqlite3.connect(path)
    try:
        return {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        }
    finally:
        connection.close()


def _column_names(path: Path, table: str) -> set[str]:
    connection = sqlite3.connect(path)
    try:
        return {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
    finally:
        connection.close()


def _execute(path: Path, *statements: str) -> None:
    connection = sqlite3.connect(path)
    try:
        for statement in statements:
            connection.execute(statement)
        connection.commit()
    finally:
        connection.close()


def _assert_inconsistent(report, *needles: str) -> None:
    assert report.state is DatabaseState.INCONSISTENT, report
    assert report.detail, "inconsistent reports must explain what failed"
    for needle in needles:
        assert needle in report.detail, report.detail


# --------------------------------------------------------------------------- #
# Version descriptors
# --------------------------------------------------------------------------- #


def test_v1_descriptor_is_the_core_baseline_only():
    """The v1 descriptor covers the five core tables and no agent tables."""
    assert set(EXPECTED_SCHEMA.tables) == set(APP_TABLES)
    assert not (set(AGENT_TABLES) & set(EXPECTED_SCHEMA.tables))
    assert "agent_id" not in {
        column.name for column in EXPECTED_SCHEMA["events"].columns
    }


def test_v2_descriptor_requires_agent_tables_and_event_attribution():
    """v2 adds agents, api_keys, audit_log, events.agent_id and their indexes."""
    descriptor = expected_schema_for_version(2)
    assert set(AGENT_TABLES) <= set(descriptor.tables)

    events_columns = {column.name for column in descriptor["events"].columns}
    assert "agent_id" in events_columns
    events_indexes = {index.name for index in descriptor["events"].indexes}
    assert "idx_events_agent_id" in events_indexes

    expected_indexes = {
        "idx_agents_status",
        "idx_agents_last_seen",
        "idx_api_keys_agent_id",
        "idx_api_keys_key_prefix",
        "idx_api_keys_status",
        "idx_audit_log_timestamp",
        "idx_audit_log_agent_id",
        "idx_audit_log_event_type",
    }
    actual_indexes = {
        index.name for table in descriptor for index in table.indexes
    }
    assert expected_indexes <= actual_indexes


def test_v3_descriptor_requires_audit_hash_chain():
    """v3 adds prev_hash, chain_hash and idx_audit_log_chain."""
    descriptor = expected_schema_for_version(3)
    audit_columns = {column.name for column in descriptor["audit_log"].columns}
    assert {"prev_hash", "chain_hash"} <= audit_columns
    audit_indexes = {index.name for index in descriptor["audit_log"].indexes}
    assert "idx_audit_log_chain" in audit_indexes


def test_v4_descriptor_is_schema_identical_to_v3():
    """v4 rebuilds chain data only; it must not invent schema objects."""
    v3 = expected_schema_for_version(3)
    v4 = expected_schema_for_version(4)
    assert set(v3.tables) == set(v4.tables)
    for table in v3.tables:
        assert v3[table].columns == v4[table].columns
        assert v3[table].indexes == v4[table].indexes
        assert v3[table].foreign_keys == v4[table].foreign_keys


def test_unknown_version_has_no_descriptor():
    with pytest.raises(ValueError, match="no expected schema"):
        expected_schema_for_version(99)


# --------------------------------------------------------------------------- #
# Correct schema at every supported version
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("version", [1, 2, 3, 4])
def test_correct_schema_at_every_supported_version(tmp_path, version):
    """Each version's schema verifies and is classified without over-claiming."""
    path = _build_version(tmp_path / f"v{version}.db", version)

    connection = sqlite3.connect(path)
    try:
        diffs = compare_schema(
            connection, expected=expected_schema_for_version(version)
        )
        assert diffs.complete, diffs
        fingerprint = schema_fingerprint(
            connection, expected=expected_schema_for_version(version)
        )
        assert fingerprint
    finally:
        connection.close()

    report = inspect_path(path)
    assert report.applied_version == version
    assert report.latest_version == LATEST
    assert report.differences is not None and report.differences.complete
    expected_state = (
        DatabaseState.CURRENT if version == LATEST else DatabaseState.PENDING
    )
    assert report.state is expected_state, report.detail


@pytest.mark.parametrize("version", [1, 2])
def test_previous_version_lacks_the_next_versions_objects(tmp_path, version):
    """A vN database must not satisfy the v(N+1) descriptor.

    v4 is data-only, so v3 legitimately satisfies the v4 descriptor and is
    covered by ``test_v3_schema_with_v4_ledger_is_current`` instead.
    """
    path = _build_version(tmp_path / f"v{version}.db", version)
    connection = sqlite3.connect(path)
    try:
        diffs = compare_schema(
            connection, expected=expected_schema_for_version(version + 1)
        )
    finally:
        connection.close()
    assert not diffs.complete


# --------------------------------------------------------------------------- #
# Missing agent / audit tables
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("table", ["agents", "api_keys", "audit_log"])
def test_missing_agent_or_audit_table_is_inconsistent(tmp_path, table):
    """A ledger claiming v4 cannot hide a missing agent/audit table."""
    path = _build_version(tmp_path / "missing-table.db", 4)
    _execute(path, f"DROP TABLE {table}")

    report = inspect_path(path)
    _assert_inconsistent(report, f"missing table(s): {table}")
    assert table in report.differences.missing_tables
    # Verification must not repair or recreate anything.
    assert table not in _table_names(path)
    assert _ledger_versions(path) == [1, 2, 3, 4]


# --------------------------------------------------------------------------- #
# Missing critical columns
# --------------------------------------------------------------------------- #


def test_missing_events_agent_id_column_is_inconsistent(tmp_path):
    path = _build_version(tmp_path / "missing-agent-id.db", 4)
    _execute(path, "DROP INDEX idx_events_agent_id", "ALTER TABLE events DROP COLUMN agent_id")

    report = inspect_path(path)
    _assert_inconsistent(report, "events missing column(s): agent_id")
    assert "agent_id" in report.differences.missing_columns["events"]
    assert "agent_id" not in _column_names(path, "events")


@pytest.mark.parametrize("column", ["prev_hash", "chain_hash"])
def test_missing_audit_chain_columns_are_inconsistent(tmp_path, column):
    path = _build_version(tmp_path / "missing-hash.db", 4)
    # SQLite refuses to drop an indexed column; remove the chain index first.
    _execute(
        path,
        "DROP INDEX idx_audit_log_chain",
        f"ALTER TABLE audit_log DROP COLUMN {column}",
    )

    report = inspect_path(path)
    _assert_inconsistent(report, f"audit_log missing column(s): {column}")
    assert column in report.differences.missing_columns["audit_log"]


def test_missing_agent_lifecycle_column_is_inconsistent(tmp_path):
    """Critical agent columns are verified, not just table existence."""
    path = _build_version(tmp_path / "missing-agent-column.db", 4)
    # SQLite refuses to drop an indexed column; remove the dependent index first.
    _execute(
        path,
        "DROP INDEX idx_agents_last_seen",
        "ALTER TABLE agents DROP COLUMN last_seen_at",
    )

    report = inspect_path(path)
    _assert_inconsistent(report, "agents missing column(s): last_seen_at")
    assert "last_seen_at" in report.differences.missing_columns["agents"]


# --------------------------------------------------------------------------- #
# Missing required indexes
# --------------------------------------------------------------------------- #


REQUIRED_INDEXES = [
    ("events", "idx_events_agent_id"),
    ("agents", "idx_agents_status"),
    ("agents", "idx_agents_last_seen"),
    ("api_keys", "idx_api_keys_agent_id"),
    ("api_keys", "idx_api_keys_key_prefix"),
    ("api_keys", "idx_api_keys_status"),
    ("audit_log", "idx_audit_log_timestamp"),
    ("audit_log", "idx_audit_log_agent_id"),
    ("audit_log", "idx_audit_log_event_type"),
    ("audit_log", "idx_audit_log_chain"),
]


@pytest.mark.parametrize("table,index", REQUIRED_INDEXES)
def test_missing_required_index_is_inconsistent(tmp_path, table, index):
    path = _build_version(tmp_path / "missing-index.db", 4)
    _execute(path, f"DROP INDEX {index}")

    report = inspect_path(path)
    _assert_inconsistent(report, f"{table} missing index(es): {index}")
    assert index in report.differences.missing_indexes[table]


# --------------------------------------------------------------------------- #
# Legacy (pre-agent) databases remain supported
# --------------------------------------------------------------------------- #


def test_pre_agent_legacy_database_is_not_required_to_have_v2_objects(tmp_path):
    """A v1 legacy database remains migratable, not inconsistent."""
    path = _build_legacy_v1(tmp_path / "legacy.db")

    report = inspect_path(path)
    assert report.state is DatabaseState.PENDING
    assert report.applied_version == 0
    assert report.ledger_present is False
    assert report.differences is not None and report.differences.complete
    assert not (set(AGENT_TABLES) & _table_names(path))

    connection = sqlite3.connect(path)
    try:
        diffs = compare_schema(connection, expected=expected_schema_for_version(1))
    finally:
        connection.close()
    assert diffs.complete


def test_legacy_database_with_v1_ledger_is_pending_not_inconsistent(tmp_path):
    """A v1 ledger accurately describes a v1 database; it is merely behind."""
    path = _build_legacy_v1(tmp_path / "legacy-v1-ledger.db")
    _set_ledger(path, (1,))

    report = inspect_path(path)
    assert report.state is DatabaseState.PENDING
    assert report.applied_version == 1
    assert report.differences is not None and report.differences.complete


# --------------------------------------------------------------------------- #
# Ledger/schema disagreements and schema ahead of ledger
# --------------------------------------------------------------------------- #


def test_v1_schema_with_v2_ledger_is_inconsistent(tmp_path):
    path = _build_legacy_v1(tmp_path / "v1-schema-v2-ledger.db")
    _set_ledger(path, (1, 2))

    report = inspect_path(path)
    _assert_inconsistent(report, "missing table(s): agents", "events")
    assert report.applied_version == 2


def test_v2_schema_with_v4_ledger_is_inconsistent(tmp_path):
    path = _build_version(tmp_path / "v2-schema-v4-ledger.db", 2)
    _set_ledger(path, (1, 2, 3, 4))

    report = inspect_path(path)
    _assert_inconsistent(
        report,
        "audit_log missing column(s): prev_hash",
        "audit_log missing index(es): idx_audit_log_chain",
    )
    assert report.applied_version == 4


def test_v3_schema_with_v4_ledger_is_current(tmp_path):
    """v4 has no schema changes, so a v3-shaped v4 database is valid."""
    path = _build_version(tmp_path / "v3-schema-v4-ledger.db", 3)
    _set_ledger(path, (1, 2, 3, 4))

    report = inspect_path(path)
    assert report.state is DatabaseState.CURRENT
    assert report.differences is not None and report.differences.complete


def test_v4_schema_with_v2_ledger_is_pending(tmp_path):
    """Extra newer objects are tolerated; the ledger is simply behind."""
    path = _build_version(tmp_path / "v4-schema-v2-ledger.db", 4)
    _set_ledger(path, (1, 2))

    report = inspect_path(path)
    assert report.state is DatabaseState.PENDING
    assert report.applied_version == 2
    assert report.latest_version == LATEST


# --------------------------------------------------------------------------- #
# Verification is read-only
# --------------------------------------------------------------------------- #


def test_inspection_does_not_mutate_the_database(tmp_path):
    """A complete verification pass leaves bytes, sidecars, and ledger intact."""
    path = _build_version(tmp_path / "read-only.db", 4)
    before_bytes = path.read_bytes()
    before_entries = sorted(os.listdir(tmp_path))
    before_ledger = _ledger_versions(path)

    report = inspect_path(path)
    assert report.state is DatabaseState.CURRENT

    assert path.read_bytes() == before_bytes
    assert sorted(os.listdir(tmp_path)) == before_entries
    assert _ledger_versions(path) == before_ledger


def test_inconsistent_inspection_does_not_repair_missing_objects(tmp_path):
    """Reporting an invalid schema must not recreate the missing table."""
    path = _build_version(tmp_path / "read-only-invalid.db", 4)
    _execute(path, "DROP TABLE agents")
    before_bytes = path.read_bytes()

    report = inspect_path(path)
    assert report.state is DatabaseState.INCONSISTENT
    assert path.read_bytes() == before_bytes
    assert "agents" not in _table_names(path)


# --------------------------------------------------------------------------- #
# Runner refusal and transactional rollback
# --------------------------------------------------------------------------- #


def test_migrate_refuses_inconsistent_ledger_without_writing(tmp_path):
    """A ledger claiming v4 over a v1 schema is refused before any writer opens."""
    path = _build_legacy_v1(tmp_path / "refuse.db")
    _set_ledger(path, (1, 2, 3, 4))
    before_bytes = path.read_bytes()
    before_tables = _table_names(path)
    before_ledger = _ledger_versions(path)

    with pytest.raises(MigrationError) as excinfo:
        migrate(path)

    message = str(excinfo.value)
    assert "incompatible" in message
    assert "missing table(s): agents" in message

    assert path.read_bytes() == before_bytes
    assert _table_names(path) == before_tables
    assert _ledger_versions(path) == before_ledger
    assert "agents" not in before_tables


def test_post_migration_verification_failure_rolls_back_the_whole_transaction(
    tmp_path, monkeypatch
):
    """A failed vN verification must not leave partial vN schema or ledger rows."""
    path = _build_version(tmp_path / "rollback.db", 1)
    real_compare = runner_module.compare_schema

    def fail_v2_verification(connection, expected=None):
        diffs = real_compare(connection, expected=expected)
        if expected is not None and "agents" in expected:
            diffs.missing_indexes.setdefault("agents", []).append(
                "synthetic_missing_index"
            )
        return diffs

    monkeypatch.setattr(runner_module, "compare_schema", fail_v2_verification)

    with pytest.raises(
        MigrationStateError,
        match="schema incomplete after migration v2",
    ):
        migrate(path)

    # v2's tables, events.agent_id, and ledger row were all rolled back.
    assert "agents" not in _table_names(path)
    assert "api_keys" not in _table_names(path)
    assert "audit_log" not in _table_names(path)
    assert "agent_id" not in _column_names(path, "events")
    assert _ledger_versions(path) == [1]
    assert inspect_path(path).state is DatabaseState.PENDING


# --------------------------------------------------------------------------- #
# Startup fails closed / valid startup continues
# --------------------------------------------------------------------------- #


def test_startup_fails_when_ledger_claims_applied_migration_with_missing_schema(
    tmp_path, monkeypatch
):
    """FastAPI must not start on a ledger/schema disagreement, and must not repair it."""
    path = _build_version(tmp_path / "startup-invalid.db", 4)
    _execute(path, "DROP TABLE agents")
    before_bytes = path.read_bytes()
    before_tables = _table_names(path)
    before_ledger = _ledger_versions(path)
    monkeypatch.setenv("GREYWATCH_DB", str(path))

    from backend.app.main import app

    with pytest.raises(
        RuntimeError,
        match="Database in unexpected state after startup: inconsistent",
    ):
        with TestClient(app):
            pass

    assert path.read_bytes() == before_bytes
    assert _table_names(path) == before_tables
    assert _ledger_versions(path) == before_ledger
    assert "agents" not in _table_names(path)


def test_valid_v4_database_starts_normally(tmp_path, monkeypatch):
    """A genuinely complete v4 database still starts without migration."""
    path = _build_version(tmp_path / "startup-valid.db", 4)
    monkeypatch.setenv("GREYWATCH_DB", str(path))

    from backend.app.main import app

    with TestClient(app) as client:
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["schema_ready"] is True
        assert body["migration_applied"] == 0

    assert inspect_path(path).state is DatabaseState.CURRENT
