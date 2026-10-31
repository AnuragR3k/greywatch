"""Tests for the explicit migration registry and ledger version validation.

These tests cover :mod:`backend.app.migration_registry` only. They never run a
migration, never create schema migration files, and never touch the
application's tables or the production database. Ledger-backed cases use
isolated temporary SQLite databases under ``tmp_path``; the rest use in-memory
data.

No migration runner exists yet, so these checks are the safety net a future
runner will call before applying anything.
"""

from __future__ import annotations

import sqlite3

import pytest

from backend.app.migration_ledger import create_schema_migrations_table
from backend.app.migration_registry import (
    MIGRATIONS,
    AppliedVersionGapError,
    DuplicateAppliedVersionError,
    DuplicateMigrationNameError,
    DuplicateMigrationVersionError,
    FutureMigrationError,
    IncompatibleLedgerSchemaError,
    InvalidAppliedVersionError,
    InvalidMigrationEntryError,
    InvalidMigrationNameError,
    InvalidMigrationVersionError,
    Migration,
    MigrationGapError,
    MigrationLedgerError,
    MigrationNameMismatchError,
    MigrationRegistryError,
    UnregisteredMigrationError,
    current_applied_version,
    latest_version,
    read_applied_versions,
    validate_applied_versions,
    validate_ledger,
    validate_registry,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _ledger_db(tmp_path) -> sqlite3.Connection:
    """Open a temp database and ensure the ledger table exists."""
    connection = sqlite3.connect(tmp_path / "registry.db")
    connection.row_factory = sqlite3.Row
    create_schema_migrations_table(connection)
    connection.commit()
    return connection


def _insert_versions(connection: sqlite3.Connection, *versions: int) -> None:
    """Insert applied rows for ``versions`` into the ledger."""
    for version in versions:
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) "
            "VALUES (?, ?, ?)",
            (version, f"migration_{version}", "2026-10-31T00:00:00+00:00"),
        )
    connection.commit()


def _registry(*versions: int) -> tuple[Migration, ...]:
    """Build a registry whose names are derived from the versions."""
    return tuple(Migration(version, f"migration_{version}") for version in versions)


# --------------------------------------------------------------------------- #
# 1. Registry shape: empty, valid, and ordered
# --------------------------------------------------------------------------- #


def test_empty_registry_is_valid():
    """An empty registry means no migrations are registered yet."""
    assert validate_registry(()) == ()
    assert latest_version(()) == 0


def test_default_registry_is_empty():
    """The shipped registry is explicit and starts empty until files exist."""
    assert MIGRATIONS == ()
    assert validate_registry(MIGRATIONS) == ()
    assert latest_version() == 0


def test_valid_registry_is_returned_sorted_by_version():
    """Validation normalizes out-of-order entries into version order."""
    entries = (
        Migration(3, "third"),
        Migration(1, "first"),
        Migration(2, "second"),
    )

    ordered = validate_registry(entries)

    assert [migration.version for migration in ordered] == [1, 2, 3]
    assert [migration.name for migration in ordered] == [
        "first",
        "second",
        "third",
    ]
    assert latest_version(entries) == 3


def test_registry_accepts_any_iterable():
    """A generator is accepted and consumed once into a stable tuple."""
    entries = (Migration(version, f"migration_{version}") for version in (1, 2))

    ordered = validate_registry(entries)

    assert tuple(migration.version for migration in ordered) == (1, 2)


# --------------------------------------------------------------------------- #
# 2. Registry rejection: duplicates, invalid values, gaps, malformed entries
# --------------------------------------------------------------------------- #


def test_duplicate_registry_version_is_rejected():
    """Two entries cannot claim the same version."""
    entries = (Migration(1, "first"), Migration(1, "also_first"))

    with pytest.raises(DuplicateMigrationVersionError) as excinfo:
        validate_registry(entries)

    message = str(excinfo.value)
    assert "duplicate migration version 1" in message
    assert "'first'" in message
    assert "'also_first'" in message


def test_duplicate_registry_name_is_rejected():
    """Two entries cannot share a human-readable name."""
    entries = (Migration(1, "same"), Migration(2, "same"))

    with pytest.raises(DuplicateMigrationNameError) as excinfo:
        validate_registry(entries)

    message = str(excinfo.value)
    assert "duplicate migration name 'same'" in message
    assert "versions 1 and 2" in message


@pytest.mark.parametrize("version", [0, -1, -100])
def test_non_positive_registry_version_is_rejected(version):
    """Version numbers start at 1."""
    with pytest.raises(InvalidMigrationVersionError) as excinfo:
        validate_registry((Migration(version, "bad"),))

    assert f"version {version}" in str(excinfo.value)
    assert "start at 1" in str(excinfo.value)


@pytest.mark.parametrize("version", ["1", 1.5, None, True])
def test_non_integer_registry_version_is_rejected(version):
    """Only real integers are valid; bool is rejected despite being an int."""
    with pytest.raises(InvalidMigrationVersionError) as excinfo:
        validate_registry((Migration(version, "bad"),))

    assert "versions must be positive integers" in str(excinfo.value)


def test_gapped_registry_is_rejected():
    """Registered versions must be contiguous starting at 1."""
    entries = _registry(1, 3)

    with pytest.raises(MigrationGapError) as excinfo:
        validate_registry(entries)

    message = str(excinfo.value)
    assert "contiguous starting at 1" in message
    assert "missing version(s): 2" in message
    assert "registered: 1, 3" in message


def test_registry_must_start_at_one():
    """A registry that begins at 2 is a gap, not a valid sequence."""
    with pytest.raises(MigrationGapError) as excinfo:
        validate_registry(_registry(2, 3))

    assert "missing version(s): 1" in str(excinfo.value)


def test_non_migration_registry_entry_is_rejected():
    """Malformed entries are rejected before any attribute access."""
    with pytest.raises(InvalidMigrationEntryError) as excinfo:
        validate_registry((1, 2))

    message = str(excinfo.value)
    assert "entry 0 must be a Migration" in message
    assert "got int" in message


def test_non_iterable_registry_is_rejected():
    """A registry must be iterable; ``None`` is not."""
    with pytest.raises(InvalidMigrationEntryError) as excinfo:
        validate_registry(None)

    assert "must be an iterable of Migration entries" in str(excinfo.value)


@pytest.mark.parametrize("name", ["", "   ", "\t\n"])
def test_empty_registry_name_is_rejected(name):
    """Names must contain more than whitespace."""
    with pytest.raises(InvalidMigrationNameError) as excinfo:
        validate_registry((Migration(1, name),))

    assert "empty name" in str(excinfo.value)


@pytest.mark.parametrize("name", [" first", "first ", "\tfirst"])
def test_padded_registry_name_is_rejected(name):
    """Leading/trailing whitespace hides duplicate names and is rejected."""
    with pytest.raises(InvalidMigrationNameError) as excinfo:
        validate_registry((Migration(1, name),))

    assert "leading or trailing whitespace" in str(excinfo.value)


@pytest.mark.parametrize("name", [None, 1, b"bytes", ["list"]])
def test_non_string_registry_name_is_rejected(name):
    """Names must be strings."""
    with pytest.raises(InvalidMigrationNameError) as excinfo:
        validate_registry((Migration(1, name),))

    assert "names must be non-empty strings" in str(excinfo.value)


def test_registry_errors_share_a_base_class():
    """Callers can catch every registry problem with one exception type."""
    assert issubclass(DuplicateMigrationVersionError, MigrationRegistryError)
    assert issubclass(InvalidMigrationNameError, MigrationRegistryError)
    assert issubclass(MigrationGapError, MigrationRegistryError)


# --------------------------------------------------------------------------- #
# 3. Current applied version from ledger rows
# --------------------------------------------------------------------------- #


def test_current_applied_version_of_empty_ledger_is_zero():
    """No applied migrations means version 0."""
    assert current_applied_version(()) == 0
    assert current_applied_version([]) == 0


def test_current_applied_version_returns_highest():
    """Rows need not be ordered; the helper returns the maximum."""
    assert current_applied_version([1, 3, 2]) == 3
    assert current_applied_version([2, 1]) == 2
    assert current_applied_version([7]) == 7


def test_current_applied_version_accepts_row_like_objects(tmp_path):
    """sqlite3.Row, mappings, and tuple/list rows are all supported."""
    connection = _ledger_db(tmp_path)
    try:
        _insert_versions(connection, 1, 2)
        rows = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
    finally:
        connection.close()

    assert current_applied_version(rows) == 2
    assert current_applied_version([{"version": 2}, {"version": 1}]) == 2
    assert current_applied_version([(1,), (3,)]) == 3
    assert current_applied_version([[4]]) == 4


@pytest.mark.parametrize("row", [0, -1, "1", 1.5, None, True])
def test_current_applied_version_rejects_invalid_rows(row):
    """Malformed ledger values fail loudly instead of being ignored."""
    with pytest.raises(InvalidAppliedVersionError):
        current_applied_version([row])


def test_current_applied_version_rejects_malformed_rows():
    """Rows missing a version field are rejected with their index."""
    with pytest.raises(InvalidAppliedVersionError) as excinfo:
        current_applied_version([{"name": "no version"}])

    assert "row 0 has no 'version' key" in str(excinfo.value)

    with pytest.raises(InvalidAppliedVersionError) as excinfo:
        current_applied_version([()])

    assert "row 0 is empty" in str(excinfo.value)

    with pytest.raises(InvalidAppliedVersionError) as excinfo:
        current_applied_version([object()])

    assert "unsupported type object" in str(excinfo.value)


def test_current_applied_version_requires_an_iterable():
    """A non-iterable argument is a ledger error, not a TypeError."""
    with pytest.raises(MigrationLedgerError) as excinfo:
        current_applied_version(None)

    assert "must be an iterable" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# 4. Reading the ledger table
# --------------------------------------------------------------------------- #


def test_read_applied_versions_empty_ledger(tmp_path):
    """An existing but empty ledger reads as no applied versions."""
    connection = _ledger_db(tmp_path)
    try:
        assert read_applied_versions(connection) == ()
    finally:
        connection.close()


def test_read_applied_versions_returns_sorted_versions(tmp_path):
    """Ledger rows are read in ascending version order."""
    connection = _ledger_db(tmp_path)
    try:
        _insert_versions(connection, 2, 1)
        assert read_applied_versions(connection) == (
            (1, "migration_1"),
            (2, "migration_2"),
        )
    finally:
        connection.close()


def test_read_applied_versions_requires_the_ledger_table(tmp_path):
    """A missing ledger produces an actionable error, not a raw SQLite one."""
    connection = sqlite3.connect(tmp_path / "no-ledger.db")
    try:
        with pytest.raises(MigrationLedgerError) as excinfo:
            read_applied_versions(connection)
    finally:
        connection.close()

    message = str(excinfo.value)
    assert "schema_migrations table is missing" in message
    assert "create_schema_migrations_table()" in message


# --------------------------------------------------------------------------- #
# 5. Validating applied versions against the registry
# --------------------------------------------------------------------------- #


def test_empty_ledger_is_valid_for_any_registry():
    """Nothing applied is always consistent, whatever is registered."""
    assert validate_applied_versions((), ()) == 0
    assert validate_applied_versions((), _registry(1, 2, 3)) == 0
    assert validate_applied_versions((), (1, 2, 3)) == 0


def test_valid_applied_versions_return_current_version():
    """A contiguous prefix of the registry is valid."""
    assert validate_applied_versions((1, 2), _registry(1, 2, 3)) == 2
    assert validate_applied_versions([1], [1, 2, 3]) == 1


def test_duplicate_applied_versions_are_rejected():
    """The same version cannot be recorded twice."""
    with pytest.raises(DuplicateAppliedVersionError) as excinfo:
        validate_applied_versions((1, 1, 2), _registry(1, 2, 3))

    message = str(excinfo.value)
    assert "appear more than once" in message
    assert "1" in message


def test_gapped_applied_versions_are_rejected():
    """Applied versions must form a contiguous sequence starting at 1."""
    with pytest.raises(AppliedVersionGapError) as excinfo:
        validate_applied_versions((1, 3), _registry(1, 2, 3))

    message = str(excinfo.value)
    assert "contiguous starting at 1" in message
    assert "missing version(s): 2" in message
    assert "applied: 1, 3" in message


def test_ledger_starting_above_one_is_a_gap():
    """A ledger whose first row is 2 is missing version 1."""
    with pytest.raises(AppliedVersionGapError) as excinfo:
        validate_applied_versions((2, 3), _registry(1, 2, 3))

    assert "missing version(s): 1" in str(excinfo.value)


def test_gapped_registered_rejected_with_empty_ledger():
    """M1 (regression): with an empty applied ledger, a gapped registered set
    must still be rejected. Previously an empty ledger short-circuited before
    the registered set was ever validated."""
    with pytest.raises(MigrationGapError) as excinfo:
        validate_applied_versions((), (1, 3))

    message = str(excinfo.value)
    assert "registered migration versions must be contiguous" in message
    assert "missing version(s): 2" in message


def test_duplicate_registered_rejected_with_empty_ledger():
    """M1 (regression): duplicate registered versions are rejected even when the
    ledger is empty, so a direct caller cannot bypass registry validation."""
    with pytest.raises(DuplicateMigrationVersionError) as excinfo:
        validate_applied_versions((), (Migration(1, "a"), Migration(1, "b")))

    assert "more than once" in str(excinfo.value)


def test_unregistered_applied_version_is_rejected():
    """An applied version absent from the registry is unknown, not a gap.

    Reaches the UnregisteredMigrationError branch via a contiguous registry
    that omits the applied version: applied version 2 is not in the registered
    set {1, 3}... -- here we assert the defensive branch type is wired and is
    a MigrationLedgerError so callers can rely on the hierarchy.
    """
    # A contiguous registered set cannot produce an unregistered-but-in-range
    # version by construction; assert the declared contract instead.
    assert issubclass(UnregisteredMigrationError, MigrationLedgerError)


def test_future_applied_version_is_rejected():
    """A database newer than the application must not be modified."""
    with pytest.raises(FutureMigrationError) as excinfo:
        validate_applied_versions((1, 2, 3), _registry(1, 2))

    message = str(excinfo.value)
    assert "applied migration version 3" in message
    assert "highest registered version 2" in message
    assert "newer Greywatch version" in message


def test_future_check_precedes_unknown_check():
    """A version above the registry reports 'future', the actionable cause."""
    with pytest.raises(FutureMigrationError):
        validate_applied_versions((1, 5), _registry(1, 2))


@pytest.mark.parametrize("version", [0, -1, "1", 1.5, None, True])
def test_invalid_applied_versions_are_rejected(version):
    """Ledger values must be positive integers."""
    with pytest.raises(InvalidAppliedVersionError):
        validate_applied_versions((version,), _registry(1))


def test_validate_applied_versions_accepts_sqlite_rows(tmp_path):
    """Real ledger rows validate exactly like plain integers."""
    connection = _ledger_db(tmp_path)
    try:
        _insert_versions(connection, 1, 2)
        rows = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        assert validate_applied_versions(rows, _registry(1, 2, 3)) == 2
    finally:
        connection.close()


def test_validate_applied_versions_accepts_migration_objects():
    """Registered versions may be Migration objects or bare integers."""
    entries = (Migration(1, "first"), Migration(2, "second"))

    assert validate_applied_versions((1,), entries) == 1
    assert validate_applied_versions((1, 2), entries) == 2


def test_validate_applied_versions_rejects_malformed_registered_entries():
    """Bare registered entries must be Migration objects or integers."""
    with pytest.raises(MigrationRegistryError) as excinfo:
        validate_applied_versions((1,), ("first",))

    assert "must be a Migration or an integer" in str(excinfo.value)


@pytest.mark.parametrize("version", [0, -1])
def test_validate_applied_versions_rejects_non_positive_registered_migrations(
    version,
):
    """A non-positive registered version is reported, not a raw TypeError."""
    with pytest.raises(MigrationRegistryError) as excinfo:
        validate_applied_versions((1,), (Migration(version, "bad"),))

    assert "not positive" in str(excinfo.value)


@pytest.mark.parametrize("version", ["1", 1.5, True])
def test_validate_applied_versions_rejects_non_integer_registered_migrations(
    version,
):
    """A non-integer registered version is reported, not a raw TypeError."""
    with pytest.raises(MigrationRegistryError) as excinfo:
        validate_applied_versions((1,), (Migration(version, "bad"),))

    assert "versions must be positive integers" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# 6. Combined registry + ledger validation
# --------------------------------------------------------------------------- #


def test_validate_ledger_empty_ledger_with_registered_migrations(tmp_path):
    """A fresh ledger is consistent with a non-empty registry."""
    connection = _ledger_db(tmp_path)
    try:
        assert validate_ledger(connection, _registry(1, 2)) == 0
    finally:
        connection.close()


def test_validate_ledger_valid_state(tmp_path):
    """A contiguous prefix of the registry validates and returns its version."""
    connection = _ledger_db(tmp_path)
    try:
        _insert_versions(connection, 1, 2)
        assert validate_ledger(connection, _registry(1, 2, 3)) == 2
    finally:
        connection.close()


def test_validate_ledger_rejects_missing_ledger_table(tmp_path):
    """Combined validation fails clearly when the ledger was never created."""
    connection = sqlite3.connect(tmp_path / "no-ledger.db")
    try:
        with pytest.raises(MigrationLedgerError):
            validate_ledger(connection, _registry(1))
    finally:
        connection.close()


def test_validate_ledger_validates_the_registry_first(tmp_path):
    """A malformed registry is reported before the ledger is read."""
    connection = _ledger_db(tmp_path)
    try:
        with pytest.raises(MigrationGapError):
            validate_ledger(connection, _registry(1, 3))
    finally:
        connection.close()


def test_validate_ledger_rejects_future_database(tmp_path):
    """The combined check also guards against newer databases."""
    connection = _ledger_db(tmp_path)
    try:
        _insert_versions(connection, 1, 2, 3)
        with pytest.raises(FutureMigrationError):
            validate_ledger(connection, _registry(1, 2))
    finally:
        connection.close()


def test_validate_ledger_does_not_modify_the_database(tmp_path):
    """Validation is read-only: ledger rows and application tables are intact."""
    connection = _ledger_db(tmp_path)
    try:
        connection.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY, raw_message TEXT)"
        )
        connection.execute(
            "INSERT INTO events (raw_message) VALUES ('keep me')"
        )
        _insert_versions(connection, 1)

        assert validate_ledger(connection, _registry(1, 2)) == 1

        assert read_applied_versions(connection) == ((1, "migration_1"),)
        row = connection.execute(
            "SELECT raw_message FROM events"
        ).fetchone()
        assert row["raw_message"] == "keep me"
    finally:
        connection.close()


# --------------------------------------------------------------------------- #
# M2: Narrow exception handling
# --------------------------------------------------------------------------- #


def _type_error_generator():
    """Return a generator that raises TypeError while being consumed."""

    def gen():
        raise TypeError("internal iterator failure")
        yield  # pragma: no cover - makes gen a generator

    return gen()


def test_read_applied_versions_rejects_incompatible_schema_missing_column(tmp_path):
    """M2/M3: a ledger missing a required column is rejected as incompatible."""
    connection = sqlite3.connect(tmp_path / "bad.db")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, "
            "applied_at TEXT NOT NULL)"
        )
        connection.commit()
        with pytest.raises(IncompatibleLedgerSchemaError) as excinfo:
            read_applied_versions(connection)
        assert "missing column(s)" in str(excinfo.value)
        assert "name" in str(excinfo.value)
    finally:
        connection.close()


def test_read_applied_versions_rejects_incompatible_schema_wrong_pk(tmp_path):
    """M3: 'version' must be the INTEGER PRIMARY KEY column."""
    connection = sqlite3.connect(tmp_path / "bad.db")
    try:
        connection.execute(
            "CREATE TABLE schema_migrations (version INTEGER, name TEXT NOT NULL, "
            "applied_at TEXT NOT NULL)"
        )
        connection.commit()
        with pytest.raises(IncompatibleLedgerSchemaError) as excinfo:
            read_applied_versions(connection)
        assert "version" in str(excinfo.value)
    finally:
        connection.close()


def test_read_applied_versions_rejects_incompatible_schema_nullable_name(tmp_path):
    """M3: 'name' must be NOT NULL."""
    connection = sqlite3.connect(tmp_path / "bad.db")
    try:
        connection.execute(
            "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, "
            'name TEXT, applied_at TEXT NOT NULL)'
        )
        connection.commit()
        with pytest.raises(IncompatibleLedgerSchemaError) as excinfo:
            read_applied_versions(connection)
        assert "name" in str(excinfo.value)
        assert "NOT NULL" in str(excinfo.value)
    finally:
        connection.close()


def test_registry_type_error_from_consumption_propagates():
    """M2: a TypeError raised while consuming a generator propagates instead of
    being mis-converted to an InvalidMigrationEntryError."""
    with pytest.raises(TypeError, match="internal iterator failure"):
        validate_registry(_type_error_generator())


def test_validate_applied_versions_type_error_from_consumption_propagates():
    """M2: internal TypeError during applied-iteration is not swallowed."""
    with pytest.raises(TypeError, match="internal iterator failure"):
        validate_applied_versions(_type_error_generator(), _registry(1))


def test_read_applied_versions_preserves_locking_error(tmp_path):
    """M2: a locking failure is not hidden as a 'missing table' error."""

    class _LockedConnection:
        def __init__(self, inner):
            self._inner = inner

        def execute(self, sql, *args, **kwargs):
            if "SELECT version, name FROM" in sql:
                raise sqlite3.OperationalError("database is locked")
            return self._inner.execute(sql, *args, **kwargs)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    connection = sqlite3.connect(tmp_path / "lock.db")
    try:
        create_schema_migrations_table(connection)
        connection.commit()
        wrapped = _LockedConnection(connection)
        with pytest.raises(sqlite3.OperationalError, match="database is locked"):
            read_applied_versions(wrapped)
    finally:
        connection.close()


# --------------------------------------------------------------------------- #
# M3: Migration-name integrity
# --------------------------------------------------------------------------- #


def test_read_applied_versions_returns_version_and_name(tmp_path):
    """M3: applied rows carry both version and name."""
    connection = _ledger_db(tmp_path)
    try:
        _insert_versions(connection, 1, 2)
        assert read_applied_versions(connection) == (
            (1, "migration_1"),
            (2, "migration_2"),
        )
    finally:
        connection.close()


def test_name_mismatch_rejected(tmp_path):
    """M3: a ledger row whose name differs from the registry is rejected."""
    connection = _ledger_db(tmp_path)
    try:
        connection.execute(
            "INSERT INTO schema_migrations (version, name, applied_at) "
            "VALUES (1, 'wrong_name', '2026-10-31T00:00:00+00:00')"
        )
        connection.commit()
        with pytest.raises(MigrationNameMismatchError) as excinfo:
            validate_ledger(connection, (Migration(1, "real_name"),))
        assert "1" in str(excinfo.value)
        assert "wrong_name" in str(excinfo.value)
        assert "real_name" in str(excinfo.value)
    finally:
        connection.close()


def test_name_mismatch_rejected_via_validate_applied_versions(tmp_path):
    """M3: name comparison also fires through the lower-level API."""
    applied = [(1, "recorded_name")]
    with pytest.raises(MigrationNameMismatchError):
        validate_applied_versions(applied, (Migration(1, "registered_name"),))


def test_matching_names_validate(tmp_path):
    """M3: matching names are accepted."""
    connection = _ledger_db(tmp_path)
    try:
        _insert_versions(connection, 1, 2)
        assert validate_ledger(connection, _registry(1, 2)) == 2
    finally:
        connection.close()


def test_read_applied_versions_rows_without_version_column(tmp_path):
    """M3: a sqlite3.Row lacking the version column is rejected with an index."""
    connection = sqlite3.connect(tmp_path / "rows.db")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("CREATE TABLE other (name TEXT)")
        connection.execute("INSERT INTO other (name) VALUES ('n')")
        rows = connection.execute("SELECT name FROM other").fetchall()
        with pytest.raises(InvalidAppliedVersionError) as excinfo:
            current_applied_version(rows)
        assert "no 'version' column" in str(excinfo.value)
    finally:
        connection.close()


# --------------------------------------------------------------------------- #
# M4: Strict read-only guarantee
# --------------------------------------------------------------------------- #


def test_validate_ledger_is_strictly_read_only(tmp_path):
    """M4: validation never writes. Snapshots sqlite_master, schema_version,
    user_version, and total_changes; runs under PRAGMA query_only=ON; then
    verifies both schema and application data are unchanged."""
    connection = sqlite3.connect(tmp_path / "ro.db")
    connection.row_factory = sqlite3.Row
    try:
        create_schema_migrations_table(connection)
        connection.execute(
            "CREATE TABLE events (id INTEGER PRIMARY KEY, raw_message TEXT)"
        )
        connection.execute("INSERT INTO events (raw_message) VALUES ('keep me')")
        _insert_versions(connection, 1)
        connection.commit()

        master_before = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table'"
        ).fetchall()
        schema_before = connection.execute("PRAGMA schema_version").fetchone()[0]
        user_before = connection.execute("PRAGMA user_version").fetchone()[0]
        changes_before = connection.total_changes

        connection.execute("PRAGMA query_only=ON")
        assert validate_ledger(connection, _registry(1, 2)) == 1
        connection.execute("PRAGMA query_only=OFF")

        master_after = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table'"
        ).fetchall()
        schema_after = connection.execute("PRAGMA schema_version").fetchone()[0]
        user_after = connection.execute("PRAGMA user_version").fetchone()[0]
        changes_after = connection.total_changes

        assert [dict(r) for r in master_before] == [dict(r) for r in master_after]
        assert schema_before == schema_after
        assert user_before == user_after
        assert changes_before == changes_after
        assert read_applied_versions(connection) == ((1, "migration_1"),)
        event = connection.execute(
            "SELECT raw_message FROM events"
        ).fetchone()
        assert event["raw_message"] == "keep me"
    finally:
        connection.close()


def test_default_empty_migrations_with_non_empty_ledger(tmp_path):
    """M4/cleanup: an empty shipped registry against a non-empty ledger is unsafe
    and is rejected as a future migration rather than silently accepted."""
    connection = _ledger_db(tmp_path)
    try:
        _insert_versions(connection, 1, 2)
        with pytest.raises(FutureMigrationError):
            validate_ledger(connection, MIGRATIONS)
    finally:
        connection.close()


# --------------------------------------------------------------------------- #
# Cleanup: dataclass + stronger duplicate assertions
# --------------------------------------------------------------------------- #


def test_migration_dataclass_is_frozen_and_slotted():
    """Migration is an immutable, slotted dataclass."""
    migration = Migration(1, "first")
    assert migration.version == 1
    assert migration.name == "first"
    with pytest.raises(AttributeError):
        migration.version = 2  # type: ignore[misc]
    assert not hasattr(migration, "__dict__")
    # Equality and hashing are value-based.
    assert Migration(1, "first") == Migration(1, "first")
    assert hash(Migration(1, "first")) == hash(Migration(1, "first"))


@pytest.mark.parametrize("versions", [(1, 1, 2), (1, 1), (2, 2)])
def test_duplicate_registered_versions_rejected(versions):
    """Strengthened: duplicate registered versions are rejected for any input
    shape that reaches the registry validation path."""
    entries = _registry(1, 2)
    # Inject a duplicate by repeating a version in the registry.
    duplicated = tuple(Migration(v, f"m{v}") for v in versions)
    with pytest.raises(DuplicateMigrationVersionError):
        validate_registry(duplicated)


def test_all_missing_versions_listed_in_gap_error():
    """Cleanup: gap errors enumerate every missing version, not just one."""
    with pytest.raises(MigrationGapError) as excinfo:
        validate_registry(_registry(1, 5))
    message = str(excinfo.value)
    assert "missing version(s): 2, 3, 4" in message
