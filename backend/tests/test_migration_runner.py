"""Tests for the transactional migration runner.

This module tests the migration runner with isolated temporary databases,
ensuring all state transitions work correctly.
"""

from __future__ import annotations

import multiprocessing
import os
import sqlite3
import tempfile
from pathlib import Path
from pathlib import PurePath

import pytest

from backend.app.migration_ledger import create_schema_migrations_table, SCHEMA_MIGRATIONS_TABLE
from backend.app.migration_registry import MIGRATIONS, Migration, validate_ledger
from backend.app.migration_schema import APP_TABLES, compare_schema
from backend.app.migration_state import DatabaseReport, DatabaseState, inspect_path
from backend.app.migrations.runner import (
    MigrationConflictError,
    MigrationError,
    MigrationStateError,
    migrate,
    plan,
    status,
    verify,
)


# --------------------------------------------------------------------------- #
# Helper fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def temp_db_path(tmp_path):
    """Provide a temporary database file path for testing."""
    db_path = tmp_path / "test.db"
    return str(db_path)


@pytest.fixture
def fresh_db_path(tmp_path):
    """Provide a path to a fresh valid SQLite database (FRESH state = file with no app tables)."""
    db_path = tmp_path / "fresh.db"
    # Create a valid SQLite file with minimal content
    # SQLite only creates the file when there's actual SQL content
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE IF NOT EXISTS __vacuum__ (id INTEGER PRIMARY KEY)")  # placeholder
    conn.commit()
    conn.execute("DROP TABLE __vacuum__")
    conn.commit()
    conn.close()
    # File should now exist with valid SQLite header
    return str(db_path)


@pytest.fixture
def complete_db_path(tmp_path):
    """Provide a path to a database with complete schema but no ledger (LEDGER_ONLY -> PENDING)."""
    db_path = tmp_path / "complete.db"

    # Create the database with complete schema but no ledger
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        # Create all application tables
        conn.execute("""
            CREATE TABLE events (
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
        """)

        conn.execute("""
            CREATE TABLE collector_state (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        conn.execute("""
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
        """)

        conn.execute("""
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
            )
        """)

        conn.execute("""
            CREATE TABLE incident_events (
                incident_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                added_at TEXT NOT NULL,
                PRIMARY KEY (incident_id, event_id),
                FOREIGN KEY (incident_id) REFERENCES incidents(id),
                FOREIGN KEY (event_id) REFERENCES events(id)
            )
        """)

        # Create ALL indexes (including addable ones for PENDING state)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events(source_ip, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_rule_ip ON incidents(rule_id, source_ip, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events(event_id)")

        # Addable indexes (required for complete schema / PENDING state)
        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_events_source_record
            ON events(source, source_record_id)
            WHERE source_record_id IS NOT NULL
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_content_hash
            ON events(content_hash)
            WHERE content_hash IS NOT NULL
        """)

        conn.commit()
    finally:
        conn.close()

    return str(db_path)


@pytest.fixture
def legacy_ready_db_path(tmp_path):
    """Provide a path to a database with all tables but missing addable columns."""
    db_path = tmp_path / "legacy.db"

    # Create a database with all tables but missing some addable columns
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        # Create all application tables WITHOUT addable columns
        conn.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                host TEXT NOT NULL,
                event_type TEXT NOT NULL,
                username TEXT,
                source_ip TEXT,
                severity TEXT NOT NULL,
                raw_message TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE collector_state (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        conn.execute("""
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
                closed_at TEXT,
                last_triggered_at TEXT
            )
        """)

        conn.execute("""
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
            )
        """)

        conn.execute("""
            CREATE TABLE incident_events (
                incident_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                added_at TEXT NOT NULL,
                PRIMARY KEY (incident_id, event_id),
                FOREIGN KEY (incident_id) REFERENCES incidents(id),
                FOREIGN KEY (event_id) REFERENCES events(id)
            )
        """)

        # Create only non-addable indexes
        conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events(source_ip, timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status, created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incidents_rule_ip ON incidents(rule_id, source_ip, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_incident ON incident_events(incident_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_incident_events_event ON incident_events(event_id)")

        conn.commit()
    finally:
        conn.close()

    return str(db_path)


@pytest.fixture
def partial_schema_db_path(tmp_path):
    """Provide a path to a database with a partial schema (subset of tables)."""
    db_path = tmp_path / "partial.db"

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        # Only create 2 of 5 app tables
        conn.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                host TEXT NOT NULL,
                event_type TEXT NOT NULL,
                username TEXT,
                source_ip TEXT,
                severity TEXT NOT NULL,
                raw_message TEXT NOT NULL
            )
        """)

        conn.execute("""
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
                closed_at TEXT,
                last_triggered_at TEXT
            )
        """)

        conn.commit()
    finally:
        conn.close()

    return str(db_path)


@pytest.fixture
def ledger_only_db_path(tmp_path):
    """Provide a path to a database with only the ledger table (no app tables)."""
    db_path = tmp_path / "ledger_only.db"

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        # Create only the ledger table
        conn.execute(f"""
            CREATE TABLE {SCHEMA_MIGRATIONS_TABLE} (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
        """)

        conn.commit()
    finally:
        conn.close()

    return str(db_path)


@pytest.fixture
def ledger_with_records_db_path(tmp_path):
    """Provide a path to a database with ledger records but no app tables (invalid state)."""
    db_path = tmp_path / "ledger_with_records.db"

    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        # Create ledger with a record
        conn.execute(f"""
            CREATE TABLE {SCHEMA_MIGRATIONS_TABLE} (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
        """)

        from datetime import datetime, timezone
        from backend.app.migration_registry import MIGRATIONS
        utc_now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, name, applied_at) VALUES (?, ?, ?)",
            (MIGRATIONS[0].version, MIGRATIONS[0].name, utc_now)
        )

        conn.commit()
    finally:
        conn.close()

    return str(db_path)


@pytest.fixture
def empty_db_path(tmp_path):
    """Provide a path to an empty (zero-byte) database file."""
    db_path = tmp_path / "empty.db"
    with open(db_path, "wb") as f:
        pass  # Creates zero-byte file
    return str(db_path)


# --------------------------------------------------------------------------- #
# Test: Missing path refused
# --------------------------------------------------------------------------- #


def test_missing_path_refused(tmp_path):
    """Missing database path should be refused."""
    db_path = str(tmp_path / "does_not_exist.db")

    # Database doesn't exist
    assert not os.path.exists(db_path)

    # status() should raise MigrationStateError for missing database
    with pytest.raises(MigrationStateError) as exc_info:
        status(db_path)

    assert "does not exist" in str(exc_info.value)

    # migrate() should also raise for missing path
    with pytest.raises(MigrationStateError) as exc_info:
        migrate(db_path)

    assert "does not exist" in str(exc_info.value)


def test_missing_path_file_remains_absent(tmp_path):
    """File should remain absent after migration attempt on missing path."""
    db_path = str(tmp_path / "does_not_exist.db")

    # Migration attempt should fail
    with pytest.raises(MigrationStateError):
        migrate(db_path)

    # File should still not exist
    assert not os.path.exists(db_path)


# --------------------------------------------------------------------------- #
# Test: Empty file refused
# --------------------------------------------------------------------------- #


def test_empty_file_refused(empty_db_path):
    """Empty (zero-byte) database file should be refused."""
    with pytest.raises(MigrationStateError) as exc_info:
        status(empty_db_path)

    assert "empty" in str(exc_info.value).lower()


def test_empty_file_migration_refused(empty_db_path):
    """Migration on empty file should be refused and file unchanged."""
    with pytest.raises(MigrationStateError):
        migrate(empty_db_path)

    # File should remain empty (zero bytes)
    assert os.path.getsize(empty_db_path) == 0


# --------------------------------------------------------------------------- #
# Test: Fresh database migration
# --------------------------------------------------------------------------- #


def test_fresh_database_migration(fresh_db_path):
    """Fresh (non-existent tables) database should be migrated."""
    report = status(fresh_db_path)
    assert report.state == DatabaseState.FRESH

    result = migrate(fresh_db_path)

    assert result["applied"] == 1
    assert result["skipped"] == 0

    # Verify the migration happened
    report = status(fresh_db_path)
    assert report.state == DatabaseState.CURRENT
    assert report.ledger_present

    # Check ledger entry
    conn = sqlite3.connect(fresh_db_path)
    try:
        cursor = conn.execute(f"SELECT version, name FROM {SCHEMA_MIGRATIONS_TABLE} ORDER BY version")
        rows = cursor.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == 1
        assert rows[0][1] == "baseline"
    finally:
        conn.close()


def test_fresh_database_all_tables_present(fresh_db_path):
    """Verify all expected tables are created in fresh migration."""
    migrate(fresh_db_path)

    conn = sqlite3.connect(fresh_db_path)
    try:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = {row[0] for row in cursor.fetchall()}

        assert "schema_migrations" in tables
        assert "events" in tables
        assert "alerts" in tables
        assert "incidents" in tables
        assert "incident_events" in tables
        assert "collector_state" in tables
    finally:
        conn.close()


def test_fresh_database_dry_run(fresh_db_path):
    """Dry run should not modify the database."""
    result = migrate(fresh_db_path, dry_run=True)

    assert result["applied"] == 1

    # Database should remain FRESH (not migrated)
    report = status(fresh_db_path)
    assert report.state == DatabaseState.FRESH


# --------------------------------------------------------------------------- #
# Test: LEDGER_ONLY (empty ledger, no app tables)
# --------------------------------------------------------------------------- #


def test_ledger_only_empty_migration(ledger_only_db_path):
    """Database with empty ledger and no app tables should be migrated."""
    report = status(ledger_only_db_path)
    assert report.state == DatabaseState.LEDGER_ONLY

    result = migrate(ledger_only_db_path)

    assert result["applied"] == 1

    # All tables should now exist
    report = status(ledger_only_db_path)
    assert report.state == DatabaseState.CURRENT


def test_ledger_only_with_records_refused(ledger_with_records_db_path):
    """Database with ledger records but no app tables should be refused."""
    report = status(ledger_with_records_db_path)
    assert report.state == DatabaseState.INCONSISTENT

    with pytest.raises((MigrationStateError, MigrationError)):
        migrate(ledger_with_records_db_path)


# --------------------------------------------------------------------------- #
# Test: LEGACY_READY (complete schema, no ledger)
# --------------------------------------------------------------------------- #


def test_legacy_ready_with_missing_columns(legacy_ready_db_path):
    """LEGACY_READY with missing addable columns should add them."""
    report = status(legacy_ready_db_path)
    assert report.state == DatabaseState.LEGACY_READY

    result = migrate(legacy_ready_db_path)
    assert result["applied"] == 1

    # Verify schema is complete
    report = status(legacy_ready_db_path)
    assert report.state == DatabaseState.CURRENT

    # Verify addable columns were added
    conn = sqlite3.connect(legacy_ready_db_path)
    try:
        cursor = conn.execute("PRAGMA table_info(events)")
        cols = {row[1] for row in cursor.fetchall()}
        assert "source" in cols
        assert "dest_ip" in cols
        assert "src_port" in cols
    finally:
        conn.close()


def test_legacy_ready_already_complete(tmp_path):
    """LEGACY_READY with already complete schema should only stamp ledger."""
    # Create a complete database with no ledger
    db_path = tmp_path / "already_complete.db"

    # Create with all tables and columns
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        conn.execute("""
            CREATE TABLE events (
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
        """)

        conn.execute("CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT)")

        conn.execute("""
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
        """)

        conn.execute("""
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
            )
        """)

        conn.execute("""
            CREATE TABLE incident_events (
                incident_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                added_at TEXT NOT NULL,
                PRIMARY KEY (incident_id, event_id),
                FOREIGN KEY (incident_id) REFERENCES incidents(id),
                FOREIGN KEY (event_id) REFERENCES events(id)
            )
        """)

        conn.execute("CREATE INDEX idx_events_ip_time ON events(source_ip, timestamp)")
        conn.execute("CREATE INDEX idx_alerts_status ON alerts(status, created_at)")
        conn.execute("CREATE INDEX idx_incidents_status ON incidents(status, created_at)")
        conn.execute("CREATE INDEX idx_incidents_rule_ip ON incidents(rule_id, source_ip, status)")
        conn.execute("CREATE INDEX idx_incident_events_incident ON incident_events(incident_id)")
        conn.execute("CREATE INDEX idx_incident_events_event ON incident_events(event_id)")
        conn.execute("CREATE UNIQUE INDEX idx_events_source_record ON events(source, source_record_id) WHERE source_record_id IS NOT NULL")
        conn.execute("CREATE INDEX idx_events_content_hash ON events(content_hash) WHERE content_hash IS NOT NULL")

        conn.commit()
    finally:
        conn.close()

    # Should be PENDING (complete schema, no ledger)
    report = status(str(db_path))
    assert report.state == DatabaseState.PENDING

    result = migrate(str(db_path))
    assert result["applied"] == 1  # Only ledger stamping

    # Should now be CURRENT
    report = status(str(db_path))
    assert report.state == DatabaseState.CURRENT


# --------------------------------------------------------------------------- #
# Test: PENDING state (schema complete, empty ledger)
# --------------------------------------------------------------------------- #


def test_pending_schema_stamp_only(complete_db_path):
    """PENDING schema should only stamp the ledger, not run up()."""
    report = status(complete_db_path)
    assert report.state == DatabaseState.PENDING
    assert not report.ledger_present

    result = migrate(complete_db_path)

    assert result["applied"] == 1
    assert result["skipped"] == 0

    # Verify it's now current
    report = status(complete_db_path)
    assert report.state == DatabaseState.CURRENT
    assert report.ledger_present


def test_pending_ledger_validation(complete_db_path, monkeypatch):
    """The PENDING branch validates the ledger while the transaction is held.

    A malformed ledger never reaches PENDING: ``inspect_path()`` classifies it
    as INCONSISTENT first (covered by ``test_malformed_ledger_refused``).  A
    *valid but empty* ledger does reach PENDING, so the runner's PENDING branch
    takes the ``ledger_present`` path and calls ``validate_ledger()`` under the
    transaction lock.  Injecting a validation failure proves that call happens
    there and that the transaction rolls back without modifying the database.
    """
    import backend.app.migration_registry as migration_registry

    # Add an empty, valid ledger so ledger_present is True in the PENDING state.
    conn = sqlite3.connect(complete_db_path)
    try:
        create_schema_migrations_table(conn)
        conn.commit()
    finally:
        conn.close()

    report = status(complete_db_path)
    assert report.state == DatabaseState.PENDING
    assert report.ledger_present is True
    assert report.applied_version == 0

    calls: list[bool] = []

    def failing_validate_ledger(connection, *args, **kwargs):
        # Record whether the runner's explicit transaction is active.
        calls.append(connection.in_transaction)
        raise migration_registry.MigrationLedgerError(
            "injected ledger validation failure"
        )

    monkeypatch.setattr(
        migration_registry, "validate_ledger", failing_validate_ledger
    )

    with pytest.raises(MigrationStateError, match="ledger validation failed"):
        migrate(complete_db_path)

    # validate_ledger() ran exactly once, under an active transaction.
    assert calls == [True]

    # The failed transaction rolled back; the database is unchanged.
    after = status(complete_db_path)
    assert after.state == DatabaseState.PENDING
    assert after.ledger_present is True

    conn = sqlite3.connect(complete_db_path)
    try:
        count = conn.execute(
            f"SELECT COUNT(*) FROM {SCHEMA_MIGRATIONS_TABLE}"
        ).fetchone()[0]
    finally:
        conn.close()
    assert count == 0


def test_malformed_ledger_refused(complete_db_path):
    """A malformed ledger is classified INCONSISTENT and refused unchanged.

    The ledger is missing its required ``name`` column, so inspection fails
    before the runner ever considers PENDING.  ``migrate()`` must refuse and
    leave the database byte-for-byte untouched.
    """
    conn = sqlite3.connect(complete_db_path)
    try:
        conn.execute(
            f"CREATE TABLE {SCHEMA_MIGRATIONS_TABLE} "
            "(version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        conn.commit()
    finally:
        conn.close()

    report = status(complete_db_path)
    assert report.state == DatabaseState.INCONSISTENT
    assert report.ledger_present is True

    with pytest.raises(MigrationError):
        migrate(complete_db_path)

    # Still INCONSISTENT; the malformed ledger was neither repaired nor stamped.
    after = status(complete_db_path)
    assert after.state == DatabaseState.INCONSISTENT

    conn = sqlite3.connect(complete_db_path)
    try:
        columns = {
            row[1]
            for row in conn.execute(
                f"PRAGMA table_info({SCHEMA_MIGRATIONS_TABLE})"
            ).fetchall()
        }
        count = conn.execute(
            f"SELECT COUNT(*) FROM {SCHEMA_MIGRATIONS_TABLE}"
        ).fetchone()[0]
    finally:
        conn.close()
    assert columns == {"version", "applied_at"}
    assert count == 0


# --------------------------------------------------------------------------- #
# Test: LOCKED inspection is refused
# --------------------------------------------------------------------------- #


def test_locked_inspection_refused(fresh_db_path, monkeypatch):
    """A pre-flight LOCKED report is refused before any writer is opened.

    Deterministic: ``inspect_path`` returns a LOCKED report, mirroring the
    inspector's mapping of a SQLite lock error.  ``migrate()`` must raise an
    access error (not return a no-op), preserve the underlying SQLite cause,
    and leave the database byte-for-byte unchanged.
    """
    from backend.app.migrations import runner as runner_module

    db_path = fresh_db_path
    original_inspect = runner_module.inspect_path
    before = Path(db_path).read_bytes()

    cause = sqlite3.OperationalError("database is locked")
    locked = DatabaseReport(
        state=DatabaseState.LOCKED,
        detail="database is locked",
        error=cause,
    )
    monkeypatch.setattr(runner_module, "inspect_path", lambda path: locked)

    with pytest.raises(MigrationError, match="cannot access database") as excinfo:
        migrate(db_path)

    # The underlying SQLite error is preserved as the cause.
    assert excinfo.value.__cause__ is cause

    # No writer was opened: the file is untouched and no ledger exists.
    assert Path(db_path).read_bytes() == before
    conn = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    finally:
        conn.close()
    assert SCHEMA_MIGRATIONS_TABLE not in tables
    assert not any(table in tables for table in APP_TABLES)

    # The real inspector still sees an untouched FRESH database.
    assert original_inspect(db_path).state == DatabaseState.FRESH


def test_locked_under_transaction_refused(fresh_db_path, monkeypatch):
    """A LOCKED report after BEGIN IMMEDIATE is refused and rolled back.

    The first inspection reports FRESH so the runner opens a writer and begins
    its transaction; the second (under-lock) inspection reports LOCKED.  The
    runner must not fall through to a successful no-op.
    """
    from backend.app.migrations import runner as runner_module

    db_path = fresh_db_path
    original_inspect = runner_module.inspect_path
    calls: list[str] = []
    cause = sqlite3.OperationalError("database is locked")

    def fake_inspect(path):
        calls.append(str(path))
        if len(calls) == 1:
            return DatabaseReport(state=DatabaseState.FRESH)
        return DatabaseReport(
            state=DatabaseState.LOCKED,
            detail="database is locked",
            error=cause,
        )

    monkeypatch.setattr(runner_module, "inspect_path", fake_inspect)

    with pytest.raises(
        MigrationError, match="cannot access database under lock"
    ) as excinfo:
        migrate(db_path)

    assert excinfo.value.__cause__ is cause
    assert len(calls) == 2

    # The transaction rolled back; the database is still FRESH with no ledger.
    assert original_inspect(db_path).state == DatabaseState.FRESH
    conn = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    finally:
        conn.close()
    assert SCHEMA_MIGRATIONS_TABLE not in tables
    assert not any(table in tables for table in APP_TABLES)


def test_status_and_verify_locked_behavior(fresh_db_path, monkeypatch):
    """status() reports LOCKED and verify() reports it as not ready.

    Neither function is changed by the migrate() fix: status() returns the
    LOCKED report without raising, and verify() returns False because the
    database is not CURRENT.
    """
    from backend.app.migrations import runner as runner_module

    locked = DatabaseReport(
        state=DatabaseState.LOCKED,
        detail="database is locked",
        error=sqlite3.OperationalError("database is locked"),
    )
    monkeypatch.setattr(runner_module, "inspect_path", lambda path: locked)

    report = status(fresh_db_path)
    assert report.state == DatabaseState.LOCKED
    assert report.detail == "database is locked"

    assert verify(fresh_db_path) is False


# --------------------------------------------------------------------------- #
# Test: CURRENT is a no-op
# --------------------------------------------------------------------------- #


def test_current_is_no_op(fresh_db_path):
    """Running migrate on a CURRENT database should be a no-op."""
    # First migrate
    result1 = migrate(fresh_db_path)
    assert result1["applied"] == 1

    # Second run should be no-op
    result2 = migrate(fresh_db_path)
    assert result2["applied"] == 0
    assert result2["skipped"] == 0


def test_current_remains_unchanged(fresh_db_path):
    """Running migrate on CURRENT should not modify database."""
    migrate(fresh_db_path)

    # Get ledger count before
    conn = sqlite3.connect(fresh_db_path)
    count_before = conn.execute(f"SELECT COUNT(*) FROM {SCHEMA_MIGRATIONS_TABLE}").fetchone()[0]
    conn.close()

    # Run migrate again
    migrate(fresh_db_path)

    # Should still have same count
    conn = sqlite3.connect(fresh_db_path)
    count_after = conn.execute(f"SELECT COUNT(*) FROM {SCHEMA_MIGRATIONS_TABLE}").fetchone()[0]
    conn.close()

    assert count_before == count_after == 1


# --------------------------------------------------------------------------- #
# Test: Partial schema refusal
# --------------------------------------------------------------------------- #


def test_partial_schema_refused(partial_schema_db_path):
    """Partial schema should be refused."""
    report = status(partial_schema_db_path)
    assert report.state in (DatabaseState.LEGACY_PARTIAL, DatabaseState.LEGACY_INCOMPATIBLE)

    with pytest.raises((MigrationStateError, MigrationError)):
        migrate(partial_schema_db_path)


# --------------------------------------------------------------------------- #
# Test: Invalid ledger rejection
# --------------------------------------------------------------------------- #


def test_inconsistent_ledger_refused(tmp_path):
    """Ledger with gaps should be refused."""
    db_path = tmp_path / "bad_ledger.db"

    # Create a database with inconsistent ledger (gap in versions)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        # Create all tables with COMPLETE schema
        conn.execute("""
            CREATE TABLE events (
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
        """)
        conn.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, created_at TEXT, rule_id TEXT, title TEXT, severity TEXT, source_ip TEXT, description TEXT, event_count INTEGER, status TEXT DEFAULT 'open')")
        conn.execute("CREATE TABLE incidents (id INTEGER PRIMARY KEY, created_at TEXT, updated_at TEXT, rule_id TEXT, title TEXT, severity TEXT, status TEXT DEFAULT 'open', source_ip TEXT, description TEXT, event_count INTEGER, first_seen_at TEXT, last_seen_at TEXT)")
        conn.execute("CREATE TABLE incident_events (incident_id INTEGER NOT NULL, event_id INTEGER NOT NULL, added_at TEXT NOT NULL, PRIMARY KEY (incident_id, event_id), FOREIGN KEY (incident_id) REFERENCES incidents(id), FOREIGN KEY (event_id) REFERENCES events(id))")
        conn.execute("CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT)")

        # Create indexes
        conn.execute("CREATE INDEX idx_events_ip_time ON events(source_ip, timestamp)")
        conn.execute("CREATE INDEX idx_alerts_status ON alerts(status, created_at)")
        conn.execute("CREATE INDEX idx_incidents_status ON incidents(status, created_at)")
        conn.execute("CREATE INDEX idx_incidents_rule_ip ON incidents(rule_id, source_ip, status)")
        conn.execute("CREATE INDEX idx_incident_events_incident ON incident_events(incident_id)")
        conn.execute("CREATE INDEX idx_incident_events_event ON incident_events(event_id)")
        conn.execute("CREATE UNIQUE INDEX idx_events_source_record ON events(source, source_record_id) WHERE source_record_id IS NOT NULL")
        conn.execute("CREATE INDEX idx_events_content_hash ON events(content_hash) WHERE content_hash IS NOT NULL")

        # Create ledger with gap (skip version 1, add version 2)
        conn.execute(f"""
            CREATE TABLE {SCHEMA_MIGRATIONS_TABLE} (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
        """)

        from datetime import datetime, timezone
        utc_now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, name, applied_at) VALUES (2, 'unknown', ?)",
            (utc_now,)
        )

        conn.commit()
    finally:
        conn.close()

    report = status(str(db_path))
    # Should be NEWER (ledger has version 2, only v1 registered)
    assert report.state == DatabaseState.NEWER

    with pytest.raises(MigrationError):
        migrate(str(db_path))


def test_future_ledger_version_refused(tmp_path):
    """Future ledger version should be refused."""
    db_path = tmp_path / "future.db"

    # Create a database with ledger claiming version 99
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")

        # Create all tables
        conn.execute("""
            CREATE TABLE events (
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
        """)
        conn.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY, created_at TEXT, rule_id TEXT, title TEXT, severity TEXT, source_ip TEXT, description TEXT, event_count INTEGER, status TEXT DEFAULT 'open')")
        conn.execute("CREATE TABLE incidents (id INTEGER PRIMARY KEY, created_at TEXT, updated_at TEXT, rule_id TEXT, title TEXT, severity TEXT, status TEXT DEFAULT 'open', source_ip TEXT, description TEXT, event_count INTEGER, first_seen_at TEXT, last_seen_at TEXT)")
        conn.execute("CREATE TABLE incident_events (incident_id INTEGER NOT NULL, event_id INTEGER NOT NULL, added_at TEXT NOT NULL, PRIMARY KEY (incident_id, event_id), FOREIGN KEY (incident_id) REFERENCES incidents(id), FOREIGN KEY (event_id) REFERENCES events(id))")
        conn.execute("CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT)")

        conn.execute("CREATE INDEX idx_events_ip_time ON events(source_ip, timestamp)")
        conn.execute("CREATE INDEX idx_alerts_status ON alerts(status, created_at)")
        conn.execute("CREATE INDEX idx_incidents_status ON incidents(status, created_at)")
        conn.execute("CREATE INDEX idx_incidents_rule_ip ON incidents(rule_id, source_ip, status)")

        # Future version
        conn.execute(f"""
            CREATE TABLE {SCHEMA_MIGRATIONS_TABLE} (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
        """)

        from datetime import datetime, timezone
        utc_now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, name, applied_at) VALUES (99, 'future', ?)",
            (utc_now,)
        )

        conn.commit()
    finally:
        conn.close()

    with pytest.raises(MigrationError) as exc_info:
        migrate(str(db_path))

    assert "newer" in str(exc_info.value).lower() or "future" in str(exc_info.value).lower()


# --------------------------------------------------------------------------- #
# Test: Symlink handling
# --------------------------------------------------------------------------- #


def test_valid_symlink_path(fresh_db_path, tmp_path):
    """Valid symlink should be resolved and followed."""
    # First create a database
    migrate(fresh_db_path)

    # Create a symlink to it
    symlink_path = tmp_path / "symlink.db"
    os.symlink(fresh_db_path, str(symlink_path))

    # Should work through the symlink
    result = migrate(str(symlink_path))
    assert result["applied"] == 0  # Already current


def test_broken_symlink_path(tmp_path):
    """Broken symlink should be refused."""
    symlink_path = tmp_path / "broken.db"
    os.symlink("/nonexistent/path/db.sqlite", str(symlink_path))

    # status() should raise MigrationStateError for broken symlink
    with pytest.raises(MigrationStateError):
        status(str(symlink_path))

    # migrate() should also fail
    with pytest.raises(MigrationStateError):
        migrate(str(symlink_path))


# --------------------------------------------------------------------------- #
# Test: Special characters in path
# --------------------------------------------------------------------------- #


def test_special_characters_in_path(tmp_path):
    """Database path with special characters should work."""
    special_path = tmp_path / "test#db with spaces.db"
    # Create a valid FRESH database (valid SQLite file, no user tables)
    conn = sqlite3.connect(str(special_path))
    conn.execute("CREATE TABLE IF NOT EXISTS __placeholder__ (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.execute("DROP TABLE __placeholder__")
    conn.commit()
    conn.close()

    result = migrate(str(special_path))
    assert result["applied"] == 1

    # Verify it works
    report = status(str(special_path))
    assert report.state == DatabaseState.CURRENT


# --------------------------------------------------------------------------- #
# Test: Foreign key verification
# --------------------------------------------------------------------------- #


def test_foreign_key_violation_check(complete_db_path):
    """Verify FK constraints exist after migration."""
    migrate(complete_db_path)

    conn = sqlite3.connect(complete_db_path)
    try:
        # Check FK is defined on incident_events
        cursor = conn.execute("PRAGMA foreign_key_list(incident_events)")
        fks = cursor.fetchall()
        assert len(fks) == 2  # Two FKs: incident_id and event_id
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Test: Idempotency
# --------------------------------------------------------------------------- #


def test_idempotent_migration(fresh_db_path):
    """Running migration multiple times should be safe."""
    # First run
    result1 = migrate(fresh_db_path)
    assert result1["applied"] == 1

    # Second run
    result2 = migrate(fresh_db_path)
    assert result2["applied"] == 0

    # Verify database is still valid
    report = status(fresh_db_path)
    assert report.state == DatabaseState.CURRENT

    # Verify only one ledger entry
    conn = sqlite3.connect(fresh_db_path)
    count = conn.execute(f"SELECT COUNT(*) FROM {SCHEMA_MIGRATIONS_TABLE}").fetchone()[0]
    conn.close()
    assert count == 1


# --------------------------------------------------------------------------- #
# Test: Ledger row should not be duplicated
# --------------------------------------------------------------------------- #


def test_ledger_single_insert(fresh_db_path):
    """Verify only one ledger entry is created."""
    migrate(fresh_db_path)

    conn = sqlite3.connect(fresh_db_path)
    cursor = conn.execute(f"SELECT COUNT(*) FROM {SCHEMA_MIGRATIONS_TABLE}")
    count = cursor.fetchone()[0]
    conn.close()
    assert count == 1


# --------------------------------------------------------------------------- #
# Test: verify() function
# --------------------------------------------------------------------------- #


def test_verify_current(fresh_db_path):
    """verify() returns True for CURRENT database."""
    migrate(fresh_db_path)
    assert verify(fresh_db_path)


def test_verify_pending(complete_db_path):
    """verify() returns False for PENDING database."""
    assert not verify(complete_db_path)


def test_verify_missing_raises(fresh_db_path):
    """verify() raises MigrationStateError for missing database."""
    db_path = str(Path(fresh_db_path).parent / "nonexistent.db")
    with pytest.raises(MigrationStateError):
        verify(db_path)


# --------------------------------------------------------------------------- #
# Test: plan() function
# --------------------------------------------------------------------------- #


def test_plan_empty_for_current(fresh_db_path):
    """plan() returns empty list for CURRENT database."""
    migrate(fresh_db_path)
    assert plan(fresh_db_path) == []


def test_plan_has_migration_for_pending(complete_db_path):
    """plan() returns migration for PENDING database."""
    migrations = plan(complete_db_path)
    assert len(migrations) == 1
    assert migrations[0].version == 1
    assert migrations[0].name == "baseline"


def test_plan_empty_for_missing(fresh_db_path):
    """plan() returns empty list for missing database."""
    db_path = str(Path(fresh_db_path).parent / "nonexistent.db")
    assert plan(db_path) == []


# --------------------------------------------------------------------------- #
# Test: status() function
# --------------------------------------------------------------------------- #


def test_status_missing_raises(fresh_db_path):
    """status() raises MigrationStateError for missing database."""
    db_path = str(Path(fresh_db_path).parent / "nonexistent.db")
    with pytest.raises(MigrationStateError):
        status(db_path)


def test_status_current(fresh_db_path):
    """status() returns CURRENT for migrated database."""
    migrate(fresh_db_path)
    report = status(fresh_db_path)
    assert report.state == DatabaseState.CURRENT


# --------------------------------------------------------------------------- #
# Test: Dry-run never writes
# --------------------------------------------------------------------------- #


def test_dry_run_never_writes(fresh_db_path):
    """Dry run should never modify the database."""
    # Create a copy to verify no changes
    import shutil
    backup = fresh_db_path + ".backup"
    shutil.copy(fresh_db_path, backup) if os.path.exists(fresh_db_path) else None

    # Dry run
    result = migrate(fresh_db_path, dry_run=True)
    assert result["applied"] == 1  # Would apply

    # Database should remain FRESH
    report = status(fresh_db_path)
    assert report.state == DatabaseState.FRESH


# --------------------------------------------------------------------------- #
# Test: Dry-run requires no confirmation
# --------------------------------------------------------------------------- #


def test_dry_run_no_confirmation_required(tmp_path):
    """Dry run should not require interactive confirmation."""
    db_path = tmp_path / "dryrun.db"
    # Create a valid FRESH database (valid SQLite file, no user tables)
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE IF NOT EXISTS __placeholder__ (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.execute("DROP TABLE __placeholder__")
    conn.commit()
    conn.close()

    # Should not raise EOFError
    result = migrate(str(db_path), dry_run=True)
    assert result["applied"] == 1


# --------------------------------------------------------------------------- #
# Test: Concurrency - second process waits for the first transaction
# --------------------------------------------------------------------------- #


def _migration_holder_process(
    db_path: str,
    lock_held_event,
    begin_probe_event,
    result_dict: dict,
) -> None:
    """Process A: hold ``BEGIN IMMEDIATE`` and apply v1 while B is blocked.

    Acquires the write lock, then waits for Process B's non-blocking probe to
    confirm the lock is held.  Only then does it perform a valid v1 migration
    and commit, guaranteeing B's own ``BEGIN IMMEDIATE`` waits for this
    transaction rather than starting after it finished.
    """
    import sqlite3 as _sqlite3

    from backend.app.migration_ledger import (
        SCHEMA_MIGRATIONS_TABLE as _LEDGER,
        create_schema_migrations_table as _create_ledger,
    )
    from backend.app.migration_schema import compare_schema as _compare_schema
    from backend.app.migrations.runner import _utc_now
    from backend.app.migrations.v001_baseline import up as _up

    conn = _sqlite3.connect(db_path, timeout=30)
    conn.row_factory = _sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("BEGIN IMMEDIATE")
        lock_held_event.set()

        # B sets this only after its zero-timeout probe saw the lock held.
        if not begin_probe_event.wait(timeout=30):
            raise RuntimeError("Process B never probed for the write lock")

        # Complete a real v1 migration while still holding the write lock.
        _create_ledger(conn)
        _up(conn)
        diffs = _compare_schema(conn)
        if not diffs.complete:
            raise RuntimeError("migration produced an incomplete schema")
        conn.execute(
            f"INSERT INTO {_LEDGER} (version, name, applied_at) VALUES (?, ?, ?)",
            (1, "baseline", _utc_now().isoformat()),
        )
        conn.commit()  # releases the write lock
        result_dict["applied"] = 1
        result_dict["error"] = None
    except Exception as exc:  # noqa: BLE001
        conn.rollback()
        result_dict["applied"] = -1
        result_dict["error"] = str(exc)
    finally:
        conn.close()


def _waiting_migrate_process(
    db_path: str,
    lock_held_event,
    begin_probe_event,
    result_dict: dict,
) -> None:
    """Process B: call ``migrate()`` while Process A holds the write lock.

    The runner's write connection is wrapped so that, immediately before
    ``BEGIN IMMEDIATE``, a second zero-timeout connection probes the lock.
    A ``locked`` probe proves the processes genuinely overlap.  The wrapper
    then signals A to commit and delegates the real blocking ``BEGIN
    IMMEDIATE``, so the runner waits for A's transaction and re-inspects after
    acquiring the lock.
    """
    import sqlite3 as _sqlite3

    import backend.app.migrations.runner as runner_module

    if not lock_held_event.wait(timeout=30):
        result_dict["applied"] = -1
        result_dict["error"] = "Process A never acquired the write lock"
        return

    observed_states: list[str] = []
    probe_result: dict[str, str] = {}

    original_inspect = runner_module.inspect_path
    original_open = runner_module._open_write_connection

    def recording_inspect(path):
        report = original_inspect(path)
        observed_states.append(report.state.value)
        return report

    class _ProbingConnection:
        """Probe the write lock immediately before ``BEGIN IMMEDIATE``."""

        def __init__(self, inner, path):
            self._inner = inner
            self._path = path
            self._probed = False

        def execute(self, sql, *args):
            if not self._probed and sql.strip().upper().startswith("BEGIN IMMEDIATE"):
                self._probed = True
                probe = _sqlite3.connect(self._path, timeout=0)
                try:
                    probe.execute("BEGIN IMMEDIATE")
                    probe.rollback()
                    probe_result["state"] = "acquired"
                except _sqlite3.OperationalError:
                    probe_result["state"] = "locked"
                finally:
                    probe.close()
                # Only now may A commit; B is about to block on the real BEGIN.
                begin_probe_event.set()
            return self._inner.execute(sql, *args)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    def probing_open(path):
        return _ProbingConnection(original_open(path), db_path)

    runner_module.inspect_path = recording_inspect
    runner_module._open_write_connection = probing_open
    try:
        result = runner_module.migrate(db_path)
        result_dict["applied"] = result["applied"]
        result_dict["error"] = None
    except Exception as exc:  # noqa: BLE001
        result_dict["applied"] = -1
        result_dict["error"] = str(exc)
    finally:
        runner_module.inspect_path = original_inspect
        runner_module._open_write_connection = original_open
        result_dict["observed_states"] = observed_states
        result_dict["probe"] = probe_result.get("state")


def test_concurrent_second_process_waits_for_lock(tmp_path):
    """Process B genuinely waits for A's transaction, then re-inspects as CURRENT.

    Process A holds ``BEGIN IMMEDIATE`` and applies a real v1 migration.  B
    calls ``migrate()`` while A still holds the lock, proves via a zero-timeout
    probe that the lock is held, then blocks in its own ``BEGIN IMMEDIATE``.
    A commits and releases the lock; B proceeds, re-inspects, sees CURRENT, and
    returns a no-op.  Exactly one v1 ledger row must exist.
    """
    db_path = str(tmp_path / "concurrent.db")

    # Create a valid, empty SQLite database (FRESH state).
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS __placeholder__ (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.execute("DROP TABLE __placeholder__")
    conn.commit()
    conn.close()

    ctx = multiprocessing.get_context()
    lock_held = ctx.Event()
    begin_probe = ctx.Event()
    manager = ctx.Manager()
    results_a = manager.dict()
    results_b = manager.dict()

    proc_a = ctx.Process(
        target=_migration_holder_process,
        args=(db_path, lock_held, begin_probe, results_a),
    )
    proc_b = ctx.Process(
        target=_waiting_migrate_process,
        args=(db_path, lock_held, begin_probe, results_b),
    )

    snapshot_a: dict = {}
    snapshot_b: dict = {}
    try:
        proc_a.start()
        assert lock_held.wait(timeout=30), "Process A never acquired the write lock"
        # Start B only while A is still holding the transaction.
        proc_b.start()

        proc_a.join(timeout=30)
        proc_b.join(timeout=30)

        assert not proc_a.is_alive(), "Process A did not finish"
        assert not proc_b.is_alive(), "Process B did not finish"
        assert proc_a.exitcode == 0, f"Process A failed: {results_a.get('error')}"
        assert proc_b.exitcode == 0, f"Process B failed: {results_b.get('error')}"
    finally:
        for proc in (proc_a, proc_b):
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=10)
        # Copy manager-backed results before shutting the manager down.
        snapshot_a = dict(results_a)
        snapshot_b = dict(results_b)
        manager.shutdown()

    assert snapshot_a.get("applied") == 1, snapshot_a.get("error")
    assert snapshot_b.get("applied") == 0, snapshot_b.get("error")

    # B observed A's lock at the exact point it tried to acquire the writer.
    assert snapshot_b.get("probe") == "locked"

    # B re-inspected after acquiring the lock: the last observation is CURRENT.
    observed = snapshot_b.get("observed_states") or []
    assert observed, "Process B recorded no inspection states"
    # First inspection happened before A committed; the last one after the lock.
    assert observed[0] == DatabaseState.FRESH.value
    assert observed[-1] == DatabaseState.CURRENT.value
    assert DatabaseState.CURRENT.value in observed

    # Exactly one v1 ledger row, and the database is CURRENT.
    report = status(db_path)
    assert report.state == DatabaseState.CURRENT
    conn = sqlite3.connect(db_path)
    try:
        rows = conn.execute(
            f"SELECT version, name FROM {SCHEMA_MIGRATIONS_TABLE} ORDER BY version"
        ).fetchall()
    finally:
        conn.close()
    assert rows == [(1, "baseline")]


def _hold_sqlite_write_lock(db_path: str, hold_seconds: float, result_dict: dict) -> None:
    """Module-level target that holds a SQLite write lock for a duration."""
    import time
    import sqlite3 as _sqlite3

    conn = _sqlite3.connect(db_path, timeout=1)
    try:
        conn.execute("BEGIN IMMEDIATE")
        result_dict["locked"] = True
        time.sleep(hold_seconds)
        conn.rollback()
    except Exception as exc:  # noqa: BLE001
        result_dict["locked"] = False
        result_dict["error"] = str(exc)
    finally:
        conn.close()


def test_lock_timeout_no_partial_changes(tmp_path):
    """Lock timeout should leave no partial changes."""
    import multiprocessing
    import time

    db_path = str(tmp_path / "timeout.db")

    # Create a FRESH database first
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS __placeholder__ (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.execute("DROP TABLE __placeholder__")
    conn.commit()
    conn.close()

    # Process A: hold a SQLite write lock
    manager = multiprocessing.Manager()
    results = manager.dict()
    blocker = multiprocessing.Process(target=_hold_sqlite_write_lock, args=(db_path, 5.0, results))
    blocker.start()
    time.sleep(0.5)  # Give blocker time to acquire lock

    # Process B: try to migrate with very short busy_timeout - should fail
    from backend.app.migrations.runner import migrate, MigrationConflictError

    # Temporarily override the busy timeout by monkeypatching
    import backend.app.migrations.runner as runner_module
    original_open = runner_module._open_write_connection

    def fast_timeout_open(path):
        conn = original_open(path)
        # Override busy timeout to be very short
        conn.execute("PRAGMA busy_timeout=100")
        return conn

    runner_module._open_write_connection = fast_timeout_open

    try:
        try:
            migrate(db_path)
            assert False, "Should have raised MigrationConflictError"
        except MigrationConflictError:
            pass  # Expected
    finally:
        runner_module._open_write_connection = original_open

    # Verify no partial changes were made
    report = status(db_path)
    assert report.state == DatabaseState.FRESH, f"State should still be FRESH, got {report.state}"

    blocker.join(timeout=10)


# --------------------------------------------------------------------------- #
# Test: Rollback after failure during migration
# --------------------------------------------------------------------------- #


def test_rollback_after_ddl_failure(tmp_path, monkeypatch):
    """Failure after DDL should roll back all changes including ledger."""
    from backend.app.migrations import runner as runner_module

    db_path = str(tmp_path / "rollback.db")

    # Create a FRESH database first
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE IF NOT EXISTS __placeholder__ (id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.execute("DROP TABLE __placeholder__")
    conn.commit()
    conn.close()

    # Verify initial state
    report = status(db_path)
    assert report.state == DatabaseState.FRESH

    # Patch up() to raise after creating tables but before ledger insert
    original_up = runner_module.up_migration

    def failing_up(connection):
        """Simulate failure after DDL but before ledger insert."""
        # Let the DDL happen (tables created)
        original_up(connection)
        # Then raise an error to trigger rollback
        raise sqlite3.Error("simulated failure after DDL")

    monkeypatch.setattr(runner_module, "up_migration", failing_up)

    try:
        with pytest.raises(MigrationError):
            migrate(db_path)
    finally:
        monkeypatch.undo()

    # Verify rollback: database should still be FRESH (no tables created, no ledger)
    report = status(db_path)
    assert report.state == DatabaseState.FRESH, f"State should be FRESH after rollback, got {report.state}"

    # Verify no ledger table was created
    conn = sqlite3.connect(db_path)
    ledger_exists = conn.execute(
        f"SELECT name FROM sqlite_master WHERE type='table' AND name='{SCHEMA_MIGRATIONS_TABLE}'"
    ).fetchone()
    conn.close()
    assert ledger_exists is None, "Ledger table should not exist after rollback"


# --------------------------------------------------------------------------- #
# Notes on concurrency tests
# --------------------------------------------------------------------------- #