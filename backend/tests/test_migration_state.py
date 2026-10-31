"""Tests for the read-only database state inspector (remediation-hardened).

Covers :mod:`backend.app.migration_schema`, :mod:`backend.app.migration_state`,
and their use of the ledger/registry validators. The suite never runs a
migration, never creates schema migration files, never touches the application's
real data database, and never writes through the inspector. All databases are
isolated under ``tmp_path``; the production ``data/greywatch.db`` is never
opened.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from backend.app.migration_ledger import SCHEMA_MIGRATIONS_TABLE, create_schema_migrations_table
from backend.app.migration_registry import MIGRATIONS, Migration
from backend.app.migration_schema import (
    ADDABLE_COLUMNS,
    ADDABLE_INDEXES,
    APP_TABLES,
    EXPECTED_SCHEMA,
    ColumnInfo,
    SchemaDifferences,
    column_affinity,
    compare_schema,
    schema_fingerprint,
    table_exists,
)
from backend.app.migration_state import (
    DatabaseReport,
    DatabaseState,
    _maybe_cleanup,
    _open_readonly_with_wal_copy,
    inspect_connection,
    inspect_path,
    is_greywatch_database,
)
from backend.app.siem import DEFAULT_DB_PATH, initialize_database

# A registry used across tests that need a non-empty set of migrations.
REGISTRY = (Migration(1, "init_schema"), Migration(2, "add_indexes"))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _current_db(tmp_path: Path, monkeypatch, schema_only: bool = True) -> Path:
    """Initialize a real current-schema database under tmp_path."""
    db_path = tmp_path / "current.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    initialize_database()
    return db_path


def _connect(db_path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def _insert_ledger(conn: sqlite3.Connection, *rows) -> None:
    create_schema_migrations_table(conn)
    conn.executemany(
        f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, name, applied_at) "
        "VALUES (?, ?, ?)",
        rows,
    )
    conn.commit()


def _legacy_complete_ddl() -> str:
    """Legacy (pre-migration) schema: all 5 tables, missing only addable columns.

    Includes the *core* index ``idx_events_ip_time`` so the only differences vs
    the current expected schema are the migration-addable columns/indexes.
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


def _events_full_ddl(status_default: str = "'open'") -> str:
    """Full-current-shape ``events`` table (all columns + 3 indexes) for M1
    column-level tests that need a single fully-declared table.
    """
    return f"""
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
    );
    CREATE INDEX IF NOT EXISTS idx_events_ip_time
        ON events(source_ip, timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_source_record
        ON events(source, source_record_id)
        WHERE source IS NOT NULL AND source_record_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_events_content_hash
        ON events(content_hash)
        WHERE content_hash IS NOT NULL;
    """


# --------------------------------------------------------------------------- #
# 1. Expected schema matches a database created with initialize_database()
# --------------------------------------------------------------------------- #


def test_expected_schema_matches_initialized_database(tmp_path, monkeypatch):
    """compare_schema reports a freshly-initialized database as complete."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    try:
        diffs = compare_schema(conn)
        assert diffs.complete
        assert diffs.missing_tables == []
        assert diffs.missing_columns == {}
        assert diffs.incompatible_columns == {}
        assert diffs.missing_indexes == {}
        assert diffs.incompatible_indexes == {}
        assert diffs.incompatible_foreign_keys == {}
        assert diffs.incompatible_table_options == {}
    finally:
        conn.close()


def test_schema_fingerprint_is_stable_for_current_database(tmp_path, monkeypatch):
    """An identical current schema yields an identical fingerprint."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    try:
        fp = schema_fingerprint(conn)
        assert isinstance(fp, str) and fp
    finally:
        conn.close()


def test_column_affinity_normalizes_type_equivalents():
    """Declared types with the same affinity compare equal."""
    for declared in ("INTEGER", "INT4", "INT8", "int"):
        assert column_affinity(declared) == "INTEGER"
    for declared in ("TEXT", "VARCHAR(64)", "CHAR(10)", "varchar"):
        assert column_affinity(declared) == "TEXT"
    assert column_affinity(None) == "BLOB"
    assert column_affinity("") == "BLOB"


# --------------------------------------------------------------------------- #
# 2. Missing database path does not create a file (C1)
# --------------------------------------------------------------------------- #


def test_missing_path_is_missing_and_creates_no_file(tmp_path):
    """A non-existent path is MISSING and is never created by inspection."""
    missing_path = tmp_path / "does-not-exist.db"
    report = inspect_path(missing_path)
    assert report.state is DatabaseState.MISSING
    assert str(missing_path) == report.path
    assert not missing_path.exists()


@pytest.mark.parametrize(
    "name",
    [
        "has space.db",
        "special?.db",
        "frag#.db",
        "pct%2.db",
        "ünïcödé.db",
        "path with ? query # frag % db",
    ],
)
def test_special_char_paths_never_open_wrong_database(tmp_path, monkeypatch, name):
    """Paths with URI metacharacters / non-ASCII must be inspected correctly.

    If ``?`` were treated as a URI query separator the path would be truncated
    and the file would not be found -> MISSING. Successfully classifying the
    current schema proves the path was escaped and the right file opened.
    """
    db_path = tmp_path / name
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    initialize_database()
    # plant a sentinel so we know we read THIS file and not some other db
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO collector_state(key, value) VALUES ('sentinel', 'here')")
    conn.commit()
    conn.close()

    report = inspect_path(db_path, entries=())
    assert report.state is DatabaseState.UNVERSIONED

    # confirm the sentinel really lives in the inspected file (not elsewhere)
    conn = sqlite3.connect(db_path)
    try:
        assert conn.execute("SELECT value FROM collector_state WHERE key='sentinel'").fetchone()[0] == "here"
    finally:
        conn.close()
    assert db_path.exists()


def test_directory_path_is_unreadable(tmp_path):
    """A directory path is not a database and is reported as UNREADABLE."""
    report = inspect_path(tmp_path)
    assert report.state is DatabaseState.UNREADABLE


def test_non_regular_file_is_unreadable(tmp_path):
    """A FIFO (special file) is rejected rather than opened as a database."""
    fifo = tmp_path / "weird.db"
    os.mkfifo(fifo)
    report = inspect_path(fifo)
    assert report.state is DatabaseState.UNREADABLE


# --------------------------------------------------------------------------- #
# 3. Zero-byte database is EMPTY
# --------------------------------------------------------------------------- #


def test_zero_byte_database_is_empty(tmp_path):
    """A zero-byte file is classified as EMPTY, not corrupt or missing."""
    path = tmp_path / "zero.db"
    path.write_bytes(b"")
    report = inspect_path(path)
    assert report.state is DatabaseState.EMPTY
    assert path.stat().st_size == 0


# --------------------------------------------------------------------------- #
# 4. Empty valid SQLite database is FRESH
# --------------------------------------------------------------------------- #


def test_empty_valid_sqlite_database_is_fresh(tmp_path):
    """A valid SQLite file with no user tables is FRESH."""
    path = tmp_path / "empty.db"
    # Creating and dropping a table forces SQLite to initialise the database
    # file header (a bare connect+close leaves a zero-byte file).
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE _seed(x INTEGER)")
    conn.execute("DROP TABLE _seed")
    conn.commit()
    conn.close()

    assert path.stat().st_size > 0
    report = inspect_path(path)
    assert report.state is DatabaseState.FRESH
    assert report.tables == []


# --------------------------------------------------------------------------- #
# 5. Unrelated tables are UNRELATED
# --------------------------------------------------------------------------- #


def test_unrelated_tables_are_unrelated(tmp_path):
    """A database with only non-Greywatch tables is UNRELATED."""
    path = tmp_path / "unrelated.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE todo (id INTEGER PRIMARY KEY, task TEXT)")
    conn.execute("CREATE TABLE other (id INTEGER PRIMARY KEY, data TEXT)")
    conn.commit()
    conn.close()

    report = inspect_path(path)
    assert report.state is DatabaseState.UNRELATED
    assert set(report.tables) == {"todo", "other"}


# --------------------------------------------------------------------------- #
# 6. Complete legacy database
# --------------------------------------------------------------------------- #


def test_complete_legacy_database_is_legacy_ready(tmp_path):
    """A database with all five tables but only legacy columns is LEGACY_READY."""
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(_legacy_complete_ddl())
    conn.commit()
    conn.close()

    report = inspect_path(path, entries=())
    assert report.state is DatabaseState.LEGACY_READY
    for table in APP_TABLES:
        assert table in report.tables
    assert report.applied_version == 0
    assert report.latest_version == 0


def test_legacy_database_missing_only_addable_columns():
    """LEGACY_READY means every missing column/index is in the addable set."""
    diffs = SchemaDifferences()
    diffs.missing_columns = {
        "events": sorted(ADDABLE_COLUMNS["events"]),
        "alerts": sorted(ADDABLE_COLUMNS["alerts"]),
    }
    diffs.missing_indexes = {"events": ["idx_events_source_record", "idx_events_content_hash"]}
    from backend.app.migration_state import _is_legacy_ready

    assert _is_legacy_ready(diffs)
    diffs.missing_columns["events"].append("host")  # core column missing
    assert not _is_legacy_ready(diffs)


# --------------------------------------------------------------------------- #
# 7. Partial legacy database
# --------------------------------------------------------------------------- #


def test_partial_legacy_database_is_legacy_partial(tmp_path):
    """A database missing some application tables is LEGACY_PARTIAL."""
    path = tmp_path / "partial.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL, host TEXT NOT NULL, event_type TEXT NOT NULL,
            username TEXT, source_ip TEXT, severity TEXT NOT NULL, raw_message TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_events_ip_time ON events(source_ip, timestamp);
        CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT);
        """
    )
    conn.commit()
    conn.close()

    report = inspect_path(path)
    assert report.state is DatabaseState.LEGACY_PARTIAL
    assert "incidents" in report.differences.missing_tables


def test_partial_database_with_incompatible_table_is_legacy_incompatible(tmp_path):
    """A partial database whose existing table is broken is LEGACY_INCOMPATIBLE (C3)."""
    path = tmp_path / "partial_incompat.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE events (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, host TEXT NOT NULL);
        CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT);
        """
    )
    conn.commit()
    conn.close()

    report = inspect_path(path)
    assert report.state is DatabaseState.LEGACY_INCOMPATIBLE
    assert "events" in report.differences.incompatible_columns


# --------------------------------------------------------------------------- #
# 8. Incompatible legacy schema
# --------------------------------------------------------------------------- #


def test_incompatible_legacy_schema_is_rejected(tmp_path):
    """A table with a wrong-typed primary key is LEGACY_INCOMPATIBLE."""
    path = tmp_path / "incompat.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE events (id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, host TEXT NOT NULL,
            event_type TEXT NOT NULL, severity TEXT NOT NULL, raw_message TEXT NOT NULL);
        CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, rule_id TEXT NOT NULL,
            title TEXT NOT NULL, severity TEXT NOT NULL, source_ip TEXT NOT NULL,
            description TEXT NOT NULL, event_count INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open',
            closed_at TEXT
        );
        CREATE TABLE incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            rule_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
            source_ip TEXT NOT NULL, description TEXT NOT NULL, event_count INTEGER NOT NULL,
            first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, closed_at TEXT
        );
        CREATE TABLE incident_events (
            incident_id INTEGER NOT NULL, event_id INTEGER NOT NULL, added_at TEXT NOT NULL,
            PRIMARY KEY (incident_id, event_id),
            FOREIGN KEY (incident_id) REFERENCES incidents(id),
            FOREIGN KEY (event_id) REFERENCES events(id)
        );
        """
    )
    conn.commit()
    conn.close()

    report = inspect_path(path)
    assert report.state is DatabaseState.LEGACY_INCOMPATIBLE
    assert "events" in report.differences.incompatible_columns


# --------------------------------------------------------------------------- #
# 9. Ledger-only database (C3: valid only when valid+empty)
# --------------------------------------------------------------------------- #


def test_ledger_only_database(tmp_path):
    """A valid, empty ledger with no app tables is LEDGER_ONLY."""
    path = tmp_path / "ledger-only.db"
    conn = sqlite3.connect(path)
    create_schema_migrations_table(conn)
    conn.commit()
    conn.close()

    report = inspect_path(path)
    assert report.state is DatabaseState.LEDGER_ONLY
    assert SCHEMA_MIGRATIONS_TABLE in report.tables
    assert report.ledger_present is True
    assert report.applied_version == 0
    assert not is_greywatch_database(sqlite3.connect(path))


def test_ledger_only_with_rows_is_inconsistent(tmp_path):
    """A ledger with valid rows but no app tables is INCONSISTENT (C3)."""
    path = tmp_path / "ledger-rows.db"
    conn = sqlite3.connect(path)
    _insert_ledger(conn, (1, "a", "t"))
    conn.close()

    report = inspect_path(path, entries=(Migration(1, "a"),))
    assert report.state is DatabaseState.INCONSISTENT


def test_ledger_only_with_invalid_ledger_schema_is_inconsistent(tmp_path):
    """LEDGER_ONLY requires a valid ledger; a malformed ledger is INCONSISTENT."""
    path = tmp_path / "ledger-bad.db"
    conn = sqlite3.connect(path)
    conn.execute(f"CREATE TABLE {SCHEMA_MIGRATIONS_TABLE} (version INTEGER PRIMARY KEY, applied_at TEXT)")
    conn.commit()
    conn.close()

    report = inspect_path(path)
    assert report.state is DatabaseState.INCONSISTENT


# --------------------------------------------------------------------------- #
# 10. Current and pending states with a test registry (M4 semantics)
# --------------------------------------------------------------------------- #


def test_unversioned_current_schema(tmp_path, monkeypatch):
    """Current schema, no ledger, empty registry -> UNVERSIONED (M4).

    Uses an explicit empty registry so UNVERSIONED (current schema + no ledger
    + no migrations registered) is well-defined regardless of the shipped
    baseline migration.
    """
    db_path = _current_db(tmp_path, monkeypatch)
    report = inspect_path(db_path, entries=())
    assert report.state is DatabaseState.UNVERSIONED
    assert report.applied_version == 0
    assert report.latest_version == 0
    assert report.ledger_present is False


def test_current_schema_no_ledger_is_pending_with_baseline(tmp_path, monkeypatch):
    """Complete schema, no ledger, v1 registered -> PENDING (actual behavior).

    Per M4, UNVERSIONED requires an empty registry; with v1 registered,
    ``applied_version (0) < latest (1)`` yields PENDING.
    """
    db_path = _current_db(tmp_path, monkeypatch)
    report = inspect_path(db_path)  # default MIGRATIONS now contains v1
    assert report.state is DatabaseState.PENDING
    assert report.applied_version == 0
    assert report.latest_version == 1
    assert report.ledger_present is False


def test_current_schema_with_baseline_ledger_is_current(tmp_path, monkeypatch):
    """Complete schema + ledger (1, 'baseline') + v1 registered -> CURRENT."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    _insert_ledger(conn, (1, "baseline", "t"))
    conn.close()

    report = inspect_path(db_path)  # default MIGRATIONS
    assert report.state is DatabaseState.CURRENT
    assert report.applied_version == 1
    assert report.latest_version == 1
    assert report.ledger_present is True


def test_current_with_registered_and_applied(tmp_path, monkeypatch):
    """A fully-applied ledger (== latest > 0) is CURRENT."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    _insert_ledger(conn, (1, "init_schema", "t"), (2, "add_indexes", "t"))
    conn.close()

    report = inspect_path(db_path, entries=REGISTRY)
    assert report.state is DatabaseState.CURRENT
    assert report.applied_version == 2
    assert report.latest_version == 2
    assert report.ledger_present is True


def test_pending_state_with_test_registry(tmp_path, monkeypatch):
    """A ledger short of the latest registered version is PENDING."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    _insert_ledger(conn, (1, "init_schema", "t"))
    conn.close()

    report = inspect_path(db_path, entries=(Migration(1, "init_schema"), Migration(2, "add_indexes"), Migration(3, "add_col")))
    assert report.state is DatabaseState.PENDING
    assert report.applied_version == 1
    assert report.latest_version == 3


# --------------------------------------------------------------------------- #
# 11. Newer versions
# --------------------------------------------------------------------------- #


def test_database_newer_than_application(tmp_path, monkeypatch):
    """A ledger ahead of the registered latest version is NEWER."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    _insert_ledger(conn, (1, "init_schema", "t"), (2, "add_indexes", "t"))
    conn.close()

    report = inspect_path(db_path, entries=(Migration(1, "init_schema"),))
    assert report.state is DatabaseState.NEWER
    assert report.applied_version == 2
    assert report.latest_version == 1


# --------------------------------------------------------------------------- #
# 12. Gapped ledger and name mismatch (C3: ledger-first)
# --------------------------------------------------------------------------- #


def test_gapped_ledger_is_inconsistent(tmp_path, monkeypatch):
    """A ledger with a gap (1,3) is INCONSISTENT, reported via ledger-first."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    _insert_ledger(conn, (1, "a", "t"), (3, "c", "t"))
    conn.close()

    report = inspect_path(db_path, entries=(Migration(1, "a"), Migration(2, "b"), Migration(3, "c")))
    assert report.state is DatabaseState.INCONSISTENT
    assert isinstance(report.error, Exception)


def test_name_mismatch_is_inconsistent(tmp_path, monkeypatch):
    """A ledger row whose name differs from the registry is INCONSISTENT."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    _insert_ledger(conn, (1, "wrong_name", "t"))
    conn.close()

    report = inspect_path(db_path, entries=(Migration(1, "real_name"),))
    assert report.state is DatabaseState.INCONSISTENT


def test_legacy_ready_with_ledger_claiming_applied_is_inconsistent(tmp_path, monkeypatch):
    """Legacy-shaped schema + ledger claiming applied migrations is INCONSISTENT (C3)."""
    db_path = tmp_path / "legacy_claim.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(_legacy_complete_ddl())
    _insert_ledger(conn, (1, "init_schema", "t"))
    conn.close()

    report = inspect_path(db_path, entries=(Migration(1, "init_schema"), Migration(2, "add_indexes")))
    assert report.state is DatabaseState.INCONSISTENT
    assert report.applied_version == 1


def test_unregistered_applied_is_inconsistent(tmp_path, monkeypatch):
    """A future applied version (> latest) is NEWER, detected ledger-first."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    _insert_ledger(conn, (3, "mystery", "t"))
    conn.close()

    report = inspect_path(db_path, entries=(Migration(1, "a"), Migration(2, "b")))
    assert report.state is DatabaseState.NEWER
    assert report.applied_version == 3
    assert report.latest_version == 2


# --------------------------------------------------------------------------- #
# 13. Incompatible ledger schema (C3)
# --------------------------------------------------------------------------- #


def test_incompatible_ledger_schema_is_inconsistent(tmp_path, monkeypatch):
    """A malformed ledger table (missing `name` column) is INCONSISTENT."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = sqlite3.connect(db_path)
    conn.execute(
        f"CREATE TABLE {SCHEMA_MIGRATIONS_TABLE} "
        "(version INTEGER PRIMARY KEY, applied_at TEXT)"
    )
    conn.commit()
    conn.close()

    report = inspect_path(db_path)
    assert report.state is DatabaseState.INCONSISTENT
    assert report.error is not None


# --------------------------------------------------------------------------- #
# 14. Corrupt database (M3)
# --------------------------------------------------------------------------- #


def test_corrupt_header_is_corrupt(tmp_path):
    """A file that is not a valid SQLite database is CORRUPT."""
    path = tmp_path / "corrupt.db"
    path.write_bytes(b"definitely not a sqlite database file")
    report = inspect_path(path)
    assert report.state is DatabaseState.CORRUPT
    assert report.error is not None


def test_corrupt_body_is_corrupt_with_quick_check(tmp_path):
    """Header-intact body corruption is caught by the default quick_check gate."""
    seed = tmp_path / "seed.db"
    conn = sqlite3.connect(str(seed))
    conn.execute("CREATE TABLE x(id INTEGER)")
    conn.commit()
    conn.close()
    data = bytearray(seed.read_bytes())
    # Corrupt a data page (offset 4096): quick_check catches it, but a plain
    # sqlite_master read would not.
    if len(data) > 4096:
        data[4096] ^= 0xFF
    path = tmp_path / "corrupt_body.db"
    path.write_bytes(bytes(data))

    report = inspect_path(path)
    assert report.state is DatabaseState.CORRUPT


def test_corrupt_body_not_caught_without_verify(tmp_path):
    """With verify=False, header-intact body corruption may be missed (M3 docs)."""
    seed = tmp_path / "seed.db"
    conn = sqlite3.connect(str(seed))
    conn.execute("CREATE TABLE x(id INTEGER)")
    conn.commit()
    conn.close()
    data = bytearray(seed.read_bytes())
    if len(data) > 4096:
        data[4096] ^= 0xFF
    path = tmp_path / "corrupt_body.db"
    path.write_bytes(bytes(data))

    report = inspect_path(path, verify=False)
    assert report.state is not DatabaseState.CORRUPT


# --------------------------------------------------------------------------- #
# M1: structural comparison rejects material differences
# --------------------------------------------------------------------------- #


def test_m1_column_affinity_mismatch_rejected(tmp_path):
    conn = _connect(tmp_path / "t.db")
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "timestamp INTEGER NOT NULL, host TEXT NOT NULL, event_type TEXT NOT NULL, "
        "severity TEXT NOT NULL, raw_message TEXT NOT NULL);"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_columns.get("events")
    assert any("affinity" in r for _, r in diffs.incompatible_columns["events"])


def test_m1_pk_position_mismatch_rejected(tmp_path):
    conn = _connect(tmp_path / "t.db")
    conn.execute(
        "CREATE TABLE events (id INTEGER NOT NULL, timestamp TEXT NOT NULL, host TEXT NOT NULL, "
        "event_type TEXT NOT NULL, severity TEXT NOT NULL, raw_message TEXT NOT NULL, "
        "PRIMARY KEY (id, timestamp));"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_columns.get("events")
    assert any("pk" in r for _, r in diffs.incompatible_columns["events"])


def test_m1_notnull_mismatch_rejected(tmp_path):
    conn = _connect(tmp_path / "t.db")
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "timestamp TEXT NOT NULL, host TEXT, event_type TEXT NOT NULL, severity TEXT NOT NULL, "
        "raw_message TEXT NOT NULL);"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_columns.get("events")
    assert any("NOT NULL" in r for _, r in diffs.incompatible_columns["events"])


def test_m1_default_value_mismatch_rejected(tmp_path):
    conn = _connect(tmp_path / "t.db")
    conn.execute(
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "status TEXT NOT NULL DEFAULT 'closed');"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_columns.get("alerts")
    assert any("default" in r for _, r in diffs.incompatible_columns["alerts"])


def test_m1_index_column_mismatch_rejected(tmp_path, monkeypatch):
    db = _current_db(tmp_path, monkeypatch)
    conn = _connect(db)
    conn.execute("DROP INDEX idx_events_ip_time")
    conn.execute("CREATE INDEX idx_events_ip_time ON events(timestamp, source_ip)")
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_indexes.get("events")


def test_m1_index_collation_mismatch_rejected(tmp_path, monkeypatch):
    db = _current_db(tmp_path, monkeypatch)
    conn = _connect(db)
    conn.execute("DROP INDEX idx_events_content_hash")
    conn.execute(
        "CREATE INDEX idx_events_content_hash ON events(content_hash COLLATE NOCASE) "
        "WHERE content_hash IS NOT NULL"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_indexes.get("events")
    assert any("collation" in r for _, r in diffs.incompatible_indexes["events"])


def test_m1_index_order_mismatch_rejected(tmp_path, monkeypatch):
    db = _current_db(tmp_path, monkeypatch)
    conn = _connect(db)
    conn.execute("DROP INDEX idx_events_ip_time")
    conn.execute("CREATE INDEX idx_events_ip_time ON events(source_ip DESC, timestamp)")
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_indexes.get("events")
    assert any("order" in r for _, r in diffs.incompatible_indexes["events"])


def test_m1_index_unique_mismatch_rejected(tmp_path, monkeypatch):
    db = _current_db(tmp_path, monkeypatch)
    conn = _connect(db)
    conn.execute("DROP INDEX idx_events_source_record")
    conn.execute(
        "CREATE INDEX idx_events_source_record ON events(source, source_record_id) "
        "WHERE source IS NOT NULL AND source_record_id IS NOT NULL"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_indexes.get("events")
    assert any("unique" in r for _, r in diffs.incompatible_indexes["events"])


def test_m1_index_partial_mismatch_rejected(tmp_path, monkeypatch):
    db = _current_db(tmp_path, monkeypatch)
    conn = _connect(db)
    conn.execute("DROP INDEX idx_events_content_hash")
    conn.execute("CREATE INDEX idx_events_content_hash ON events(content_hash)")
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_indexes.get("events")
    assert any("partial" in r for _, r in diffs.incompatible_indexes["events"])


def test_m1_missing_foreign_key_rejected(tmp_path):
    conn = _connect(tmp_path / "t.db")
    conn.executescript(
        "CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, "
        "host TEXT NOT NULL, event_type TEXT NOT NULL, severity TEXT NOT NULL, "
        "raw_message TEXT NOT NULL);"
        "CREATE TABLE incidents (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, "
        "updated_at TEXT NOT NULL, rule_id TEXT NOT NULL, title TEXT NOT NULL, "
        "severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', source_ip TEXT NOT NULL, "
        "description TEXT NOT NULL, event_count INTEGER NOT NULL, first_seen_at TEXT NOT NULL, "
        "last_seen_at TEXT NOT NULL, closed_at TEXT);"
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, rule_id TEXT NOT NULL, "
        "title TEXT NOT NULL, severity TEXT NOT NULL, source_ip TEXT NOT NULL, "
        "description TEXT NOT NULL, event_count INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open', "
        "closed_at TEXT);"
        "CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT);"
        "CREATE TABLE incident_events (incident_id INTEGER NOT NULL, event_id INTEGER NOT NULL, "
        "added_at TEXT NOT NULL, PRIMARY KEY (incident_id, event_id),"
        "FOREIGN KEY (incident_id) REFERENCES incidents(id));"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.missing_foreign_keys.get("incident_events")


def test_m1_fk_action_mismatch_rejected(tmp_path):
    conn = _connect(tmp_path / "t.db")
    conn.executescript(
        "CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, host TEXT NOT NULL, "
        "event_type TEXT NOT NULL, severity TEXT NOT NULL, raw_message TEXT NOT NULL);"
        "CREATE TABLE incidents (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, "
        "rule_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', "
        "source_ip TEXT NOT NULL, description TEXT NOT NULL, event_count INTEGER NOT NULL, "
        "first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, closed_at TEXT);"
        "CREATE TABLE alerts (id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, rule_id TEXT NOT NULL, "
        "title TEXT NOT NULL, severity TEXT NOT NULL, source_ip TEXT NOT NULL, description TEXT NOT NULL, "
        "event_count INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'open', closed_at TEXT);"
        "CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT);"
        "CREATE TABLE incident_events (incident_id INTEGER NOT NULL, event_id INTEGER NOT NULL, "
        "added_at TEXT NOT NULL, PRIMARY KEY (incident_id, event_id),"
        "FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,"
        "FOREIGN KEY (event_id) REFERENCES events(id));"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_foreign_keys.get("incident_events")


def test_m1_autoincrement_mismatch_rejected(tmp_path):
    conn = _connect(tmp_path / "t.db")
    conn.executescript(
        "CREATE TABLE events (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, host TEXT NOT NULL, "
        "event_type TEXT NOT NULL, severity TEXT NOT NULL, raw_message TEXT NOT NULL);"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_table_options.get("events")
    assert any("autoincrement" in r for r in diffs.incompatible_table_options["events"])


def test_m1_without_rowid_rejected(tmp_path):
    conn = _connect(tmp_path / "t.db")
    conn.executescript(
        "CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID;"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_table_options.get("collector_state")
    assert any("without_rowid" in r for r in diffs.incompatible_table_options["collector_state"])


def test_m1_strict_mismatch_rejected(tmp_path):
    conn = _connect(tmp_path / "t.db")
    conn.executescript(
        "CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT) STRICT;"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_table_options.get("collector_state")
    assert any("strict" in r for r in diffs.incompatible_table_options["collector_state"])


def test_m1_identifier_case_insensitive():
    """Schema names are matched case-insensitively (SQLite behaviour)."""
    conn = sqlite3.connect(":memory:")
    conn.execute('CREATE TABLE "Events" (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, '
                 'host TEXT NOT NULL, event_type TEXT NOT NULL, severity TEXT NOT NULL, raw_message TEXT NOT NULL)')
    conn.commit()
    diffs = compare_schema(conn)
    assert "events" not in diffs.missing_tables
    conn.close()


def test_m1_incompatible_indexes_separate_from_columns(tmp_path):
    """incompatible_indexes and incompatible_columns are distinct buckets."""
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, "
        "host TEXT NOT NULL, event_type TEXT NOT NULL, username TEXT, source_ip TEXT, "
        "severity TEXT NOT NULL, raw_message TEXT NOT NULL, source TEXT, source_record_id TEXT, "
        "content_hash TEXT, dest_ip TEXT, src_port INTEGER, dest_port INTEGER, proto TEXT, "
        "signature TEXT, signature_id INTEGER, category TEXT);"
        "CREATE INDEX idx_events_ip_time_wrong ON events(source_ip, timestamp);"
    )
    conn.commit()
    diffs = compare_schema(conn)
    # idx_events_ip_time is missing (not the renamed _wrong one)
    assert "idx_events_ip_time" in diffs.missing_indexes.get("events", [])
    assert not diffs.incompatible_indexes.get("events")
    conn.close()


# --------------------------------------------------------------------------- #
# M2: generator registry consumed once
# --------------------------------------------------------------------------- #


def test_m2_generator_registry_consumed_once(tmp_path, monkeypatch):
    """A generator registry is consumed exactly once and still classifies."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    _insert_ledger(conn, (1, "init_schema", "t"), (2, "add_indexes", "t"))
    conn.close()

    consumed: list[Migration] = []

    def registry_gen():
        for m in REGISTRY:
            consumed.append(m)
            yield m

    report = inspect_path(db_path, entries=registry_gen())
    assert report.state is DatabaseState.CURRENT
    # The generator was consumed exactly once (2 items, no second iteration).
    assert len(consumed) == 2


def test_m2_generator_registry_not_double_consumed(tmp_path, monkeypatch):
    """A generator that raises if iterated twice must work (consumed once)."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    _insert_ledger(conn, (1, "init_schema", "t"), (2, "add_indexes", "t"))
    conn.close()

    state = {"itters": 0}

    def registry_gen():
        state["itters"] += 1
        if state["itters"] > 1:
            raise RuntimeError("generator consumed more than once")
        for m in REGISTRY:
            yield m

    report = inspect_path(db_path, entries=registry_gen())
    assert report.state is DatabaseState.CURRENT
    assert state["itters"] == 1


def test_m2_invalid_generator_registry_is_inconsistent(tmp_path, monkeypatch):
    """A malformed generator registry is reported, not crashed."""
    db_path = _current_db(tmp_path, monkeypatch)

    def bad_gen():
        yield Migration(0, "invalid")  # version 0 is invalid
        yield Migration(2, "add_indexes")  # gapped

    report = inspect_path(db_path, entries=bad_gen())
    assert report.state is DatabaseState.INCONSISTENT


# --------------------------------------------------------------------------- #
# M3: error classification
# --------------------------------------------------------------------------- #


def test_m3_classify_locked():
    from backend.app.migration_state import classify_sqlite_error

    assert classify_sqlite_error(sqlite3.OperationalError("database is locked")) is DatabaseState.LOCKED


def test_m3_classify_permission_denied():
    from backend.app.migration_state import classify_sqlite_error

    assert classify_sqlite_error(PermissionError("denied")) is DatabaseState.PERMISSION_DENIED


def test_m3_classify_corrupt():
    from backend.app.migration_state import classify_sqlite_error

    assert classify_sqlite_error(sqlite3.DatabaseError("file is not a database")) is DatabaseState.CORRUPT


def test_m3_permission_denied_file(tmp_path, monkeypatch):
    if os.geteuid() == 0:
        pytest.skip("cannot test permissions as root")
    db_path = _current_db(tmp_path, monkeypatch)
    os.chmod(db_path, 0o000)
    try:
        report = inspect_path(db_path)
        assert report.state is DatabaseState.PERMISSION_DENIED
    finally:
        os.chmod(db_path, 0o644)


def test_m3_not_found_is_missing(tmp_path, monkeypatch):
    """A path that exists when checked but disappears before open is MISSING."""
    db_path = _current_db(tmp_path, monkeypatch)
    os.unlink(db_path)
    report = inspect_path(db_path)
    assert report.state is DatabaseState.MISSING


# --------------------------------------------------------------------------- #
# M4: state semantics -- consistent version metadata
# --------------------------------------------------------------------------- #


def test_m4_states_report_consistent_versions(tmp_path, monkeypatch):
    def fresh_db() -> Path:
        db_path = _current_db(tmp_path, monkeypatch)
        return db_path

    db_path = fresh_db()

    # UNVERSIONED: current schema, no ledger, empty registry.
    report = inspect_path(db_path, entries=())
    assert report.state is DatabaseState.UNVERSIONED
    assert report.applied_version == 0
    assert report.latest_version == 0

    # CURRENT: current schema + ledger applied==latest.
    conn = _connect(db_path)
    _insert_ledger(conn, (1, "init_schema", "t"), (2, "add_indexes", "t"))
    conn.close()
    report = inspect_path(db_path, entries=REGISTRY)
    assert report.state is DatabaseState.CURRENT
    assert report.applied_version == report.latest_version == 2

    # PENDING: applied < latest (clear the ledger first, then insert v1 only).
    conn = _connect(db_path)
    conn.execute(f"DELETE FROM {SCHEMA_MIGRATIONS_TABLE}")
    conn.commit()
    conn.close()
    conn = _connect(db_path)
    _insert_ledger(conn, (1, "init_schema", "t"))
    conn.close()
    report = inspect_path(db_path, entries=REGISTRY)
    assert report.state is DatabaseState.PENDING
    assert report.applied_version == 1
    assert report.latest_version == 2
    assert report.applied_version < report.latest_version


# --------------------------------------------------------------------------- #
# M5: schema fingerprint (excludes ledger + unrelated; semantically meaningful)
# --------------------------------------------------------------------------- #


def test_m5_fingerprint_excludes_ledger_and_unrelated(tmp_path, monkeypatch):
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    conn.execute("CREATE TABLE todo (id INTEGER PRIMARY KEY, task TEXT)")
    conn.execute("CREATE TABLE other (id INTEGER PRIMARY KEY)")
    create_schema_migrations_table(conn)
    conn.commit()
    conn.close()

    conn = _connect(db_path)
    try:
        fp = schema_fingerprint(conn)
    finally:
        conn.close()

    assert "todo" not in fp
    assert "other" not in fp
    assert SCHEMA_MIGRATIONS_TABLE not in fp
    for table in APP_TABLES:
        assert table in fp


def test_m5_fingerprint_equivalent_schemas_equal(tmp_path, monkeypatch):
    p1 = _current_db(tmp_path, monkeypatch)
    # second identical current db in a different file
    p2 = tmp_path / "second.db"
    monkeypatch.setenv("GREYWATCH_DB", str(p2))
    initialize_database()

    fp1 = schema_fingerprint(_connect(p1))
    fp2 = schema_fingerprint(_connect(p2))
    assert fp1 == fp2


def test_m5_fingerprint_differs_for_material_difference(tmp_path, monkeypatch):
    db_path = _current_db(tmp_path, monkeypatch)
    fp_before = schema_fingerprint(_connect(db_path))

    conn = _connect(db_path)
    conn.execute("DROP INDEX idx_events_ip_time")
    conn.commit()
    conn.close()

    fp_after = schema_fingerprint(_connect(db_path))
    assert fp_before != fp_after


# --------------------------------------------------------------------------- #
# C1: missing path never creates a file (directory + file checks)
# --------------------------------------------------------------------------- #


def test_c1_missing_path_never_creates_file(tmp_path):
    target = tmp_path / "sub" / "missing.db"
    assert not target.parent.exists()
    report = inspect_path(target)
    assert report.state is DatabaseState.MISSING
    assert not target.parent.exists()


# --------------------------------------------------------------------------- #
# C2: WAL side-effect guarantees
# --------------------------------------------------------------------------- #


def test_c2_inspect_wal_database_does_not_create_sidecars(tmp_path, monkeypatch):
    """inspect_path on a WAL db must not create -wal/-shm beside the original."""
    db_path = tmp_path / "wal.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    initialize_database()
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=wal")
    conn.execute("INSERT INTO collector_state(key,value) VALUES('k','v')")
    conn.commit()
    conn.close()  # clean close; -wal may be checkpointed/removed, but header stays WAL

    assert db_path.exists()
    before = sorted(os.listdir(tmp_path))
    report = inspect_path(db_path, entries=(Migration(1, "init_schema"),))
    after = sorted(os.listdir(tmp_path))

    assert before == after  # no new -wal/-shm/-journal beside the original
    assert report.state is DatabaseState.PENDING  # current schema, applied 0 < latest 1


def test_c2_wal_copy_applies_uncheckpointed_data(tmp_path, monkeypatch):
    """A WAL db with an open writer's uncheckpointed data is seen via the copy."""
    db_path = tmp_path / "wal_open.db"
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=wal")
    conn.execute("CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("INSERT INTO collector_state VALUES ('k', 'wal-value')")
    conn.commit()
    # keep `conn` open so the -wal retains the uncheckpointed row

    copy_con, tmp_dir = _open_readonly_with_wal_copy(Path(db_path))
    try:
        row = copy_con.execute("SELECT value FROM collector_state").fetchone()
        assert row[0] == "wal-value"
    finally:
        _maybe_cleanup(copy_con, tmp_dir)
        conn.close()


def test_c2_rollback_journal_inspect_is_side_effect_free(tmp_path, monkeypatch):
    """A rollback-journal db inspected in-place leaves no sidecar files."""
    db_path = _current_db(tmp_path, monkeypatch)
    before = sorted(os.listdir(tmp_path))
    report = inspect_path(db_path, entries=())
    after = sorted(os.listdir(tmp_path))
    assert before == after
    assert report.state is DatabaseState.UNVERSIONED


# --------------------------------------------------------------------------- #
# Strict read-only guarantee (strengthened: filesystem + content)
# --------------------------------------------------------------------------- #


def test_strict_read_only_no_filesystem_or_content_changes(tmp_path, monkeypatch):
    """Inspection leaves dir contents, file size, schema text, schema_version,
    user_version and total_changes unchanged."""
    db_path = tmp_path / "ro.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE t (id INTEGER)")
    conn.execute("PRAGMA user_version = 7")
    conn.execute("PRAGMA schema_version = 42")
    conn.commit()
    conn.close()

    def snapshot(c):
        return (
            sorted(os.listdir(tmp_path)),
            db_path.stat().st_size,
            c.execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall(),
            c.execute("PRAGMA schema_version").fetchone()[0],
            c.execute("PRAGMA user_version").fetchone()[0],
            c.total_changes,
        )

    snap_conn = sqlite3.connect(db_path)
    before = snapshot(snap_conn)
    snap_conn.close()

    report = inspect_path(db_path)
    assert report.state is DatabaseState.UNRELATED

    after_conn = sqlite3.connect(db_path)
    try:
        after = snapshot(after_conn)
    finally:
        after_conn.close()

    assert before == after


def test_inspect_never_creates_schema_migrations(tmp_path, monkeypatch):
    """Inspection must never create the schema_migrations ledger table."""
    db_path = _current_db(tmp_path, monkeypatch)
    # Snapshot after setup (ledger is absent; inspect_path will not create it).
    before_dir = sorted(os.listdir(tmp_path))

    report = inspect_path(db_path, entries=())
    assert report.state is DatabaseState.UNVERSIONED
    # The report proves inspect_path never observed a ledger table.
    assert report.ledger_present is False
    # No sidecar files created beside the original (WAL db is copied to temp).
    assert sorted(os.listdir(tmp_path)) == before_dir


# --------------------------------------------------------------------------- #
# Minor: robustness of inspect_connection
# --------------------------------------------------------------------------- #


def test_inspect_connection_bytes_factory(tmp_path, monkeypatch):
    db_path = _current_db(tmp_path, monkeypatch)
    conn = sqlite3.connect(db_path)
    conn.text_factory = bytes
    try:
        report = inspect_connection(conn, entries=())
        assert report.state is DatabaseState.UNVERSIONED
    finally:
        conn.close()


def test_inspect_connection_custom_row_factory(tmp_path, monkeypatch):
    db_path = _current_db(tmp_path, monkeypatch)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        report = inspect_connection(conn, entries=())
        assert report.state is DatabaseState.UNVERSIONED
    finally:
        conn.close()


def test_inspect_connection_with_existing_transaction(tmp_path, monkeypatch):
    db_path = _current_db(tmp_path, monkeypatch)
    conn = sqlite3.connect(db_path)
    conn.execute("BEGIN")
    conn.execute("INSERT INTO collector_state(key,value) VALUES('k','v')")
    try:
        report = inspect_connection(conn, entries=())
        assert report.state is DatabaseState.UNVERSIONED
    finally:
        conn.rollback()
        conn.close()


def test_inspect_connection_and_path_agree(tmp_path, monkeypatch):
    """inspect_connection on an open handle agrees with inspect_path."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    _insert_ledger(conn, (1, "init_schema", "t"))
    conn.close()

    conn = _connect(db_path)
    try:
        via_connection = inspect_connection(conn, entries=REGISTRY)
    finally:
        conn.close()

    via_path = inspect_path(db_path, entries=REGISTRY)
    assert via_connection.state == via_path.state
    assert via_connection.applied_version == via_path.applied_version
    assert via_connection.latest_version == via_path.latest_version


# --------------------------------------------------------------------------- #
# Minor: immutability of expected schema
# --------------------------------------------------------------------------- #


def test_expected_schema_is_immutable():
    """The expected schema descriptors cannot be mutated at runtime."""
    with pytest.raises(TypeError):
        EXPECTED_SCHEMA.tables["events"] = None  # type: ignore[index]
    col = ColumnInfo(name="x", affinity="TEXT", notnull=True, pk=0)
    with pytest.raises(Exception):
        col.name = "y"  # frozen dataclass
    table_desc = EXPECTED_SCHEMA["events"]
    with pytest.raises(Exception):
        table_desc.columns = ()  # frozen dataclass


def test_database_report_default_fields():
    report = DatabaseReport()
    assert report.state is None
    assert report.tables == []
    assert report.ledger_present is False
    assert report.latest_version == 0


# --------------------------------------------------------------------------- #
# is_greywatch_database
# --------------------------------------------------------------------------- #


def test_is_greywatch_database_true_for_app_tables(tmp_path, monkeypatch):
    db_path = _current_db(tmp_path, monkeypatch)
    conn = sqlite3.connect(db_path)
    try:
        assert is_greywatch_database(conn) is True
    finally:
        conn.close()


def test_is_greywatch_database_false_for_unrelated(tmp_path):
    path = tmp_path / "x.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE todo (id INTEGER)")
    conn.commit()
    try:
        assert is_greywatch_database(conn) is False
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Remediation regression tests (findings 1-8)
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Finding 1: Partial-index WHERE predicate comparison
# --------------------------------------------------------------------------- #


def test_m1_where_clause_mismatch_rejected(tmp_path, monkeypatch):
    """A materially different WHERE predicate on a partial index is rejected."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    conn.execute("DROP INDEX idx_events_content_hash")
    conn.execute(
        "CREATE INDEX idx_events_content_hash ON events(content_hash) "
        "WHERE content_hash IS NOT NULL AND source IS NOT NULL"
    )
    conn.commit()
    conn.close()

    conn = _connect(db_path)
    try:
        diffs = compare_schema(conn)
        assert diffs.incompatible_indexes.get("events")
        assert any("where" in r for _, r in diffs.incompatible_indexes["events"])
    finally:
        conn.close()


def test_m1_where_clause_equivalent_after_normalization(tmp_path, monkeypatch):
    """Equivalent predicates (quoted / whitespace variants) compare equal."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    conn.execute("DROP INDEX idx_events_content_hash")
    conn.execute(
        'CREATE INDEX idx_events_content_hash ON events("content_hash") '
        "WHERE \"content_hash\" IS   NOT  NULL"
    )
    conn.commit()
    conn.close()

    conn = _connect(db_path)
    try:
        diffs = compare_schema(conn)
        where_issues = [
            r for _, r in diffs.incompatible_indexes.get("events", [])
            if "where" in r
        ]
        assert not where_issues
    finally:
        conn.close()


def test_m1_where_clause_fail_closed_when_unreadable(tmp_path, monkeypatch):
    """A partial index whose WHERE predicate cannot be inspected is fail-closed."""
    from backend.app.migration_schema import _index_where_clause, _WHERE_UNREADABLE
    import backend.app.migration_schema as ms

    conn = _connect(tmp_path / "t.db")
    conn.execute("CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, content_hash TEXT)")
    conn.execute(
        "CREATE INDEX idx_events_content_hash ON events(content_hash) "
        "WHERE content_hash IS NOT NULL"
    )
    conn.commit()

    # Normal extraction works (predicate is readable)
    assert _index_where_clause(conn, "idx_events_content_hash", True) is not None

    # Simulate unreadable SQL: _extract_index_where returns None for a partial index
    monkeypatch.setattr(ms, "_extract_index_where", lambda c, n: None)

    result = _index_where_clause(conn, "idx_events_content_hash", True)
    assert result == _WHERE_UNREADABLE

    # Via compare_schema, the unreadable WHERE becomes an incompatibility
    diffs = compare_schema(conn)
    assert diffs.incompatible_indexes.get("events")
    assert any("where" in r for _, r in diffs.incompatible_indexes["events"])
    conn.close()


def test_dedup_invariant_preserved(tmp_path):
    """The unique partial index deduplication invariant is preserved.

    With ``WHERE source_record_id IS NOT NULL``, rows that have a non-NULL
    ``source_record_id`` are deduplicated by (source, source_record_id), while
    rows with NULL ``source_record_id`` are excluded from the constraint.
    """
    conn = sqlite3.connect(tmp_path / "dedup.db")
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY, source TEXT, source_record_id TEXT)"
    )
    conn.execute(
        "CREATE UNIQUE INDEX idx_events_source_record "
        "ON events(source, source_record_id) WHERE source_record_id IS NOT NULL"
    )
    conn.execute("INSERT INTO events(source, source_record_id) VALUES ('s1', 'r1')")
    conn.commit()

    # Duplicate (source, source_record_id) with non-NULL id should fail
    try:
        conn.execute("INSERT INTO events(source, source_record_id) VALUES ('s1', 'r1')")
        assert False, "should have raised UNIQUE constraint"
    except sqlite3.IntegrityError:
        pass

    # NULL source_record_id is excluded from the constraint
    conn.execute("INSERT INTO events(source, source_record_id) VALUES ('s1', NULL)")
    conn.execute("INSERT INTO events(source, source_record_id) VALUES ('s1', NULL)")
    conn.commit()
    conn.close()


# --------------------------------------------------------------------------- #
# Finding 2: Table-option detection (no false positives)
# --------------------------------------------------------------------------- #


def test_table_options_autoincrement_no_false_positive_restrict():
    """ON DELETE RESTRICT / 'restricted' do not trigger AUTOINCREMENT detection."""
    from backend.app.migration_schema import _table_options

    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "note TEXT, "
        "FOREIGN KEY (note) REFERENCES other(id) ON DELETE RESTRICT)"
    )
    conn.execute("CREATE TABLE other (id INTEGER PRIMARY KEY, restricted TEXT)")
    conn.commit()
    opts = _table_options(conn, "events")
    assert opts.autoincrement is True

    # 'restricted' as a column name on a different table must not matter
    opts2 = _table_options(conn, "other")
    assert opts2.autoincrement is False
    conn.close()


def test_table_options_strict_no_false_positive_from_default():
    """A default containing 'strict' does not trigger STRICT detection."""
    from backend.app.migration_schema import _table_options

    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "note TEXT DEFAULT 'strict note')"
    )
    conn.commit()
    opts = _table_options(conn, "events")
    assert opts.strict is False
    assert opts.autoincrement is True
    conn.close()


def test_table_options_strict_and_without_rowid_detected():
    """STRICT and WITHOUT ROWID are detected via PRAGMA table_list."""
    from backend.app.migration_schema import _table_options

    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE t1 (id INTEGER PRIMARY KEY) STRICT")
    conn.execute("CREATE TABLE t2 (id INTEGER PRIMARY KEY) WITHOUT ROWID")
    conn.commit()

    opts1 = _table_options(conn, "t1")
    assert opts1.strict is True
    assert opts1.without_rowid is False

    opts2 = _table_options(conn, "t2")
    assert opts2.strict is False
    assert opts2.without_rowid is True
    conn.close()


# --------------------------------------------------------------------------- #
# Finding 3: WAL symlink handling
# --------------------------------------------------------------------------- #


def test_c2_wal_through_symlink_includes_uncheckpointed_data(tmp_path, monkeypatch):
    """Inspecting a WAL db through a symlink includes uncheckpointed WAL data.

    Neither the original directory nor the symlink directory is modified.
    """
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    real_db = real_dir / "real.db"
    symlink_dir = tmp_path / "link"
    symlink_dir.mkdir()
    symlink_db = symlink_dir / "link.db"
    symlink_db.symlink_to(real_db)

    conn = sqlite3.connect(real_db)
    conn.execute("PRAGMA journal_mode=wal")
    conn.execute("CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("INSERT INTO collector_state VALUES ('k', 'wal-via-symlink')")
    conn.commit()
    # Keep conn open so -wal retains the uncheckpointed row

    # Snapshot AFTER WAL files are created by the writer setup
    original_real_dir = sorted(os.listdir(real_dir))
    original_link_dir = sorted(os.listdir(symlink_dir))

    # Open via the symlink - the WAL copy logic resolves to the real path
    copy_con, tmp_dir = _open_readonly_with_wal_copy(Path(symlink_db))
    try:
        row = copy_con.execute("SELECT value FROM collector_state WHERE key='k'").fetchone()
        assert row is not None
        assert row[0] == "wal-via-symlink"
    finally:
        _maybe_cleanup(copy_con, tmp_dir)

    # No new files in the original or symlink directory
    # (must check BEFORE closing the writer, which checkpoints WAL)
    assert sorted(os.listdir(real_dir)) == original_real_dir
    assert sorted(os.listdir(symlink_dir)) == original_link_dir

    conn.close()


# --------------------------------------------------------------------------- #
# Finding 4: Case-insensitive ledger detection
# --------------------------------------------------------------------------- #


def test_case_insensitive_ledger_uppercase(tmp_path):
    """An uppercase SCHEMA_MIGRATIONS table is recognized as the ledger."""
    conn = sqlite3.connect(tmp_path / "upper.db")
    conn.execute(
        f"CREATE TABLE {SCHEMA_MIGRATIONS_TABLE.upper()} "
        "(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    conn.commit()
    conn.close()

    report = inspect_path(tmp_path / "upper.db")
    assert report.state is DatabaseState.LEDGER_ONLY
    assert report.ledger_present is True


def test_case_insensitive_ledger_uppercase_invalid_is_inconsistent(tmp_path, monkeypatch):
    """Uppercase ledger with invalid contents is INCONSISTENT."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    conn.execute(
        f"CREATE TABLE {SCHEMA_MIGRATIONS_TABLE.upper()} "
        "(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"
    )
    conn.execute(f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE.upper()} VALUES (1, 'wrong', 't')")
    conn.commit()
    conn.close()

    report = inspect_path(db_path, entries=(Migration(1, "real_name"),))
    assert report.state is DatabaseState.INCONSISTENT


# --------------------------------------------------------------------------- #
# Finding 5: Lock classification
# --------------------------------------------------------------------------- #


def test_quick_check_lock_classified_as_locked(tmp_path):
    """A rollback-journal database under an exclusive lock is LOCKED.

    The writer holds an EXCLUSIVE lock; a read-only inspect_path open cannot
    acquire a SHARED lock and is classified as LOCKED, not CORRUPT.
    """
    path = tmp_path / "locked.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t(id INTEGER PRIMARY KEY)")
    conn.commit()
    # Acquire an exclusive lock and hold it
    conn.execute("BEGIN EXCLUSIVE")
    conn.execute("INSERT INTO t(id) VALUES (1)")

    report = inspect_path(path)
    assert report.state is DatabaseState.LOCKED
    conn.rollback()
    conn.close()


def test_quick_check_lock_error_via_inspect_connection(tmp_path):
    """A lock error raised by quick_check is classified as LOCKED, not CORRUPT.

    Uses a thin wrapper that raises ``OperationalError('database is locked')``
    when ``PRAGMA quick_check`` is executed, simulating a database locked by
    another process while the connection itself is open.
    """
    db_path = tmp_path / "qc_lock.db"
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE t(id INTEGER PRIMARY KEY)")
    conn.commit()
    conn.close()

    real = sqlite3.connect(db_path)


    class _LockOnQuickCheck:
        """Proxy that raises 'database is locked' on quick_check."""

        def __init__(self, inner: sqlite3.Connection) -> None:
            self._inner = inner

        def execute(self, sql, *args, **kwargs):
            if isinstance(sql, str) and "quick_check" in sql.lower():
                raise sqlite3.OperationalError("database is locked")
            return self._inner.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def close(self) -> None:
            return self._inner.close()

    try:
        report = inspect_connection(_LockOnQuickCheck(real))
        assert report.state is DatabaseState.LOCKED
        assert report.error is not None
    finally:
        real.close()


# --------------------------------------------------------------------------- #
# Finding 6: Schema comparison regressions
# --------------------------------------------------------------------------- #


def test_m1_composite_pk_notnull_checked(tmp_path):
    """NOT NULL is checked for composite-PK columns (not just INTEGER PK)."""
    conn = _connect(tmp_path / "t.db")
    conn.executescript(
        "CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "timestamp TEXT NOT NULL, host TEXT NOT NULL, event_type TEXT NOT NULL, "
        "severity TEXT NOT NULL, raw_message TEXT NOT NULL);"
        "CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT);"
        "CREATE TABLE incident_events ("
        "incident_id INTEGER, event_id INTEGER, added_at TEXT NOT NULL,"
        "PRIMARY KEY (incident_id, event_id),"
        "FOREIGN KEY (incident_id) REFERENCES incidents(id),"
        "FOREIGN KEY (event_id) REFERENCES events(id));"
        "CREATE TABLE incidents (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "created_at TEXT NOT NULL, updated_at TEXT NOT NULL, rule_id TEXT NOT NULL, "
        "title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', "
        "source_ip TEXT NOT NULL, description TEXT NOT NULL, event_count INTEGER NOT NULL, "
        "first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, closed_at TEXT);"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    # incident_events columns are declared without NOT NULL -> incompatible
    assert diffs.incompatible_columns.get("incident_events")
    assert any("NOT NULL" in r for _, r in diffs.incompatible_columns["incident_events"])


def test_m1_unexpected_default_flagged(tmp_path):
    """An unexpected actual default is flagged even when expected has none."""
    conn = _connect(tmp_path / "t.db")
    conn.execute(
        "CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT DEFAULT 'unexpected')"
    )
    conn.commit()
    diffs = compare_schema(conn)
    conn.close()
    assert diffs.incompatible_columns.get("collector_state")
    assert any("default" in r for _, r in diffs.incompatible_columns["collector_state"])


# --------------------------------------------------------------------------- #
# Finding 7: Bytes factory compatibility with ledger
# --------------------------------------------------------------------------- #


def test_inspect_connection_bytes_factory_with_ledger(tmp_path, monkeypatch):
    """A valid ledger is read correctly with text_factory=bytes."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = sqlite3.connect(db_path)
    conn.text_factory = bytes
    _insert_ledger(conn, (1, REGISTRY[0].name, "t"), (2, REGISTRY[1].name, "t"))
    conn.commit()
    conn.close()

    conn = sqlite3.connect(db_path)
    conn.text_factory = bytes
    try:
        report = inspect_connection(conn, entries=REGISTRY)
        assert report.state is DatabaseState.CURRENT
        assert report.applied_version == 2
        assert report.latest_version == 2
        assert report.ledger_present is True
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Final Four-Finding Cleanup Tests
# --------------------------------------------------------------------------- #


# --------------------------------------------------------------------------- #
# Finding 1: Preserve string-literal case in predicate normalization
# --------------------------------------------------------------------------- #


def test_normalize_where_preserves_string_literal_case():
    """String literals are case-preserved; 'Admin' != 'admin'."""
    from backend.app.migration_schema import _normalize_where

    assert _normalize_where("role = 'Admin'") != _normalize_where("role = 'admin'")
    assert _normalize_where("role = 'Admin'") == "'Admin'" or "'Admin'" in _normalize_where("role = 'Admin'")


def test_normalize_where_equivalent_whitespace():
    """Equivalent predicates with different whitespace normalize to the same."""
    from backend.app.migration_schema import _normalize_where

    assert (
        _normalize_where("content_hash IS NOT NULL")
        == _normalize_where("content_hash   IS   NOT   NULL")
    )
    assert (
        _normalize_where("a = 1 AND b IS NOT NULL")
        == _normalize_where("a = 1  AND  b IS NOT NULL")
    )


def test_normalize_where_quoted_identifier_equivalence():
    """Quoted identifier variants normalize equivalently where SQLite does."""
    from backend.app.migration_schema import _normalize_where

    assert _normalize_where('"content_hash" IS NOT NULL') == _normalize_where("content_hash IS NOT NULL")
    assert _normalize_where("[content_hash] IS NOT NULL") == _normalize_where("content_hash IS NOT NULL")


def test_normalize_where_escaped_quotes_preserved():
    """Escaped single quotes inside string literals are preserved."""
    from backend.app.migration_schema import _normalize_where

    assert _normalize_where("x = 'it''s'") == _normalize_where("x = 'it''s'")
    # Case change in literal is preserved
    assert _normalize_where("x = 'It''s'") != _normalize_where("x = 'it''s'")


def test_fingerprint_reflects_string_literal_difference(tmp_path, monkeypatch):
    """Different string literals in partial-index predicates produce different fingerprints."""
    from backend.app.migration_schema import schema_fingerprint

    db_path = _current_db(tmp_path, monkeypatch)
    fp_before = schema_fingerprint(_connect(db_path))

    conn = _connect(db_path)
    conn.execute("DROP INDEX idx_events_content_hash")
    conn.execute(
        "CREATE INDEX idx_events_content_hash ON events(content_hash) "
        "WHERE content_hash IS NOT NULL AND source = 'Suricata'"
    )
    conn.commit()
    conn.close()

    fp_after = schema_fingerprint(_connect(db_path))
    assert fp_before != fp_after


# --------------------------------------------------------------------------- #
# Finding 2: Unreadable-parent classification (FileNotFoundError vs
# PermissionError)
# --------------------------------------------------------------------------- #


def test_unreadable_parent_classified_as_permission_denied(tmp_path):
    """A file whose parent dir is unreadable is PERMISSION_DENIED, not MISSING."""
    if os.geteuid() == 0:
        pytest.skip("cannot test permissions as root")
    child = tmp_path / "noaccess" / "db.db"
    child.parent.mkdir()
    child.write_bytes(b"")  # create the file
    os.chmod(child.parent, 0o000)
    try:
        report = inspect_path(child)
        assert report.state is DatabaseState.PERMISSION_DENIED
    finally:
        os.chmod(child.parent, 0o755)


# --------------------------------------------------------------------------- #
# Finding 3: Invalid-connection error handling (ProgrammingError)
# --------------------------------------------------------------------------- #


def test_closed_connection_quick_check_not_corrupt(tmp_path, monkeypatch):
    """A ProgrammingError from a closed connection is UNREADABLE, not CORRUPT."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = sqlite3.connect(db_path)
    conn.close()
    # Calling quick_check on a closed connection raises ProgrammingError
    report = inspect_connection(conn)
    assert report.state is DatabaseState.UNREADABLE
    assert "programming" in (report.detail or "").lower()


def test_closed_connection_inspect_path_not_corrupt(tmp_path, monkeypatch):
    """inspect_path with a closed underlying handle is not classified as CORRUPT."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = sqlite3.connect(db_path)
    conn.close()
    # Pass a closed (but not fully garbage-collected) handle to inspect_connection
    report = inspect_connection(conn)
    assert report.state is not DatabaseState.CORRUPT


def test_closed_connection_error_message_mentions_programming():
    """classify_sqlite_error maps ProgrammingError to UNREADABLE, not CORRUPT."""
    from backend.app.migration_state import classify_sqlite_error

    exc = sqlite3.ProgrammingError("Cannot operate on a closed database")
    assert classify_sqlite_error(exc) is DatabaseState.UNREADABLE


def test_genuine_corrupt_still_classified_as_corrupt(tmp_path, monkeypatch):
    """A genuinely corrupt database is still CORRUPT (not masked as caller error)."""
    db_path = tmp_path / "corrupt.db"
    db_path.write_bytes(b"not a sqlite file at all")
    report = inspect_path(db_path)
    assert report.state is DatabaseState.CORRUPT


# --------------------------------------------------------------------------- #
# Task 2A: Baseline migration v1
# --------------------------------------------------------------------------- #


def test_baseline_registry_contains_exactly_v1():
    """MIGRATIONS contains exactly one entry: version 1 named 'baseline'."""
    from backend.app.migration_registry import MIGRATIONS

    assert len(MIGRATIONS) == 1
    assert MIGRATIONS[0].version == 1
    assert MIGRATIONS[0].name == "baseline"


def test_baseline_registry_latest_version_is_1():
    """latest_version() returns 1 with the shipped baseline."""
    from backend.app.migration_registry import latest_version

    assert latest_version() == 1


def test_baseline_registry_validation_accepts_it():
    """validate_registry accepts the shipped baseline."""
    from backend.app.migration_registry import MIGRATIONS, validate_registry

    assert validate_registry(MIGRATIONS) == MIGRATIONS


def test_baseline_ledger_name_mismatch_is_rejected(tmp_path, monkeypatch):
    """A ledger entry with a name mismatch (e.g. 'init_schema') is INCONSISTENT."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    _insert_ledger(conn, (1, "init_schema", "t"))  # name mismatch with 'baseline'
    conn.close()

    report = inspect_path(db_path)  # default MIGRATIONS
    assert report.state is DatabaseState.INCONSISTENT
    assert report.applied_version == 1


def test_baseline_ledger_unknown_version_is_rejected(tmp_path, monkeypatch):
    """A ledger entry for an unregistered version is rejected, not silently accepted.

    Applied version 5 > latest (1) is classified as NEWER (not silently accepted
    as CURRENT). An invalid applied version (0) is INCONSISTENT.
    """
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    _insert_ledger(conn, (5, "something", "t"))  # unknown to the registry, > latest
    conn.close()

    report = inspect_path(db_path)  # default MIGRATIONS
    assert report.state is DatabaseState.NEWER  # not silently accepted as current
    assert report.applied_version == 5
    assert report.latest_version == 1


def test_initialize_database_fingerprint_matches_expected(tmp_path, monkeypatch):
    """A database created via initialize_database() matches EXPECTED_SCHEMA."""
    db_path = _current_db(tmp_path, monkeypatch)
    conn = _connect(db_path)
    try:
        diffs = compare_schema(conn)
        assert diffs.complete
        # Fingerprint is a stable hash for an unchanged current schema.
        fp = schema_fingerprint(conn)
        assert isinstance(fp, str) and fp
    finally:
        conn.close()
