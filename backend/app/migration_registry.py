"""Explicit migration registry and version validation for Greywatch.

This module is intentionally limited to *registry* and *ledger consistency*
checks. It does not contain a migration runner, does not create schema
migration files, and is not wired into ``siem.initialize_database()``.

The future runner is expected to:

1. call :func:`backend.app.migration_ledger.create_schema_migrations_table`,
2. validate its explicit registry with :func:`validate_registry`,
3. read applied versions with :func:`read_applied_versions`, and
4. validate the ledger with :func:`validate_applied_versions` (or the combined
   :func:`validate_ledger`) before applying anything.

Keeping these checks separate from the runner makes them testable without
touching application tables or the production database.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from .migration_ledger import SCHEMA_MIGRATIONS_TABLE

__all__ = [
    "MIGRATIONS",
    "Migration",
    "MigrationError",
    "MigrationRegistryError",
    "InvalidMigrationEntryError",
    "InvalidMigrationVersionError",
    "InvalidMigrationNameError",
    "DuplicateMigrationVersionError",
    "DuplicateMigrationNameError",
    "MigrationGapError",
    "MigrationLedgerError",
    "InvalidAppliedVersionError",
    "DuplicateAppliedVersionError",
    "AppliedVersionGapError",
    "UnregisteredMigrationError",
    "FutureMigrationError",
    "IncompatibleLedgerSchemaError",
    "MigrationNameMismatchError",
    "validate_registry",
    "latest_version",
    "current_applied_version",
    "read_applied_versions",
    "validate_applied_versions",
    "validate_ledger",
]


class MigrationError(ValueError):
    """Base class for all migration-registry and ledger validation errors."""


class MigrationRegistryError(MigrationError):
    """The explicit migration registry is malformed or inconsistent."""


class InvalidMigrationEntryError(MigrationRegistryError):
    """A registry entry is not a :class:`Migration`."""


class InvalidMigrationVersionError(MigrationRegistryError):
    """A registry entry has a non-integer or non-positive version."""


class InvalidMigrationNameError(MigrationRegistryError):
    """A registry entry has a missing, non-string, or malformed name."""


class DuplicateMigrationVersionError(MigrationRegistryError):
    """Two registry entries share the same version."""


class DuplicateMigrationNameError(MigrationRegistryError):
    """Two registry entries share the same name."""


class MigrationGapError(MigrationRegistryError):
    """Registered versions are not contiguous starting at 1."""


class MigrationLedgerError(MigrationError):
    """The ``schema_migrations`` ledger cannot be read or is inconsistent."""


class InvalidAppliedVersionError(MigrationLedgerError):
    """A ledger row has a malformed or non-positive version."""


class DuplicateAppliedVersionError(MigrationLedgerError):
    """The ledger contains the same applied version more than once."""


class AppliedVersionGapError(MigrationLedgerError):
    """Applied versions are not contiguous starting at 1."""


class UnregisteredMigrationError(MigrationLedgerError):
    """An applied version does not exist in the migration registry."""


class FutureMigrationError(MigrationLedgerError):
    """The database is newer than the application's highest migration."""


class IncompatibleLedgerSchemaError(MigrationLedgerError):
    """The ``schema_migrations`` ledger exists but has an incompatible schema."""


class MigrationNameMismatchError(MigrationLedgerError):
    """A ledger row's recorded name does not match its registered migration."""


@dataclass(frozen=True, slots=True)
class Migration:
    """A stable, explicit representation of one registered migration.

    ``version`` is the integer ordering key; ``name`` is the human-readable
    identifier recorded in the ledger. Values are validated by
    :func:`validate_registry` rather than at construction time so malformed
    entries can be reported with index/context by the registry validator.
    """

    version: int
    name: str


#: Explicit ordered registry. Keep this empty until real migration modules
#: exist; append ``Migration(version, name)`` entries in the same change that
#: adds the corresponding migration file. The future runner must not infer
#: migrations from filesystem contents.
MIGRATIONS: tuple[Migration, ...] = ()


def _is_int(value: object) -> bool:
    """Return True for real integers, excluding ``bool`` (a subclass of int)."""
    return isinstance(value, int) and not isinstance(value, bool)


def _format_versions(versions: Iterable[int]) -> str:
    """Format a version collection for an actionable error message."""
    ordered = sorted(set(versions))
    return ", ".join(str(version) for version in ordered) or "none"


def validate_registry(entries: Iterable[object]) -> tuple[Migration, ...]:
    """Validate and return a normalized, version-sorted registry.

    Rules:

    * every entry must be a :class:`Migration`;
    * every version must be a positive integer (``bool`` is rejected);
    * every name must be a non-empty string without leading/trailing whitespace;
    * versions and names must be unique;
    * versions must be contiguous and start at 1.

    An empty registry is valid and represents "no migrations registered yet".
    """
    try:
        iterator = iter(entries)
    except TypeError as exc:
        raise InvalidMigrationEntryError(
            "migration registry must be an iterable of Migration entries"
        ) from exc

    try:
        items = tuple(iterator)
    except TypeError:
        # An internal TypeError raised while consuming the iterable is a real
        # problem in the iterator itself, not a non-iterable argument; let it
        # propagate unchanged so callers see the original failure.
        raise

    for index, entry in enumerate(items):
        if not isinstance(entry, Migration):
            raise InvalidMigrationEntryError(
                f"migration registry entry {index} must be a Migration, "
                f"got {type(entry).__name__}"
            )

        version = entry.version
        name = entry.name

        if not _is_int(version):
            raise InvalidMigrationVersionError(
                f"migration registry entry {index} ({name!r}) has invalid "
                f"version {version!r}; versions must be positive integers"
            )
        if version <= 0:
            raise InvalidMigrationVersionError(
                f"migration {name!r} has version {version}; versions must "
                "start at 1"
            )

        if not isinstance(name, str):
            raise InvalidMigrationNameError(
                f"migration version {version} has an invalid name "
                f"{name!r}; names must be non-empty strings"
            )
        if not name.strip():
            raise InvalidMigrationNameError(
                f"migration version {version} has an empty name; names must "
                "be non-empty strings"
            )
        if name != name.strip():
            raise InvalidMigrationNameError(
                f"migration version {version} has a name with leading or "
                f"trailing whitespace: {name!r}"
            )

    by_version: dict[int, Migration] = {}
    by_name: dict[str, Migration] = {}
    for entry in items:
        existing_version = by_version.get(entry.version)
        if existing_version is not None:
            raise DuplicateMigrationVersionError(
                f"duplicate migration version {entry.version}: "
                f"{existing_version.name!r} and {entry.name!r}"
            )
        by_version[entry.version] = entry

        existing_name = by_name.get(entry.name)
        if existing_name is not None:
            raise DuplicateMigrationNameError(
                f"duplicate migration name {entry.name!r} used by versions "
                f"{existing_name.version} and {entry.version}"
            )
        by_name[entry.name] = entry

    ordered = tuple(sorted(items, key=lambda entry: entry.version))
    expected = 1
    for entry in ordered:
        if entry.version != expected:
            missing = sorted(set(range(1, entry.version)) - by_version.keys())
            raise MigrationGapError(
                "migration versions must be contiguous starting at 1; "
                f"missing version(s): {_format_versions(missing)} "
                f"(registered: {_format_versions(by_version)})"
            )
        expected += 1

    return ordered


def latest_version(entries: Iterable[object] = MIGRATIONS) -> int:
    """Return the highest registered version, or ``0`` for an empty registry."""
    ordered = validate_registry(entries)
    return ordered[-1].version if ordered else 0


def _extract_applied_version(row: object, index: int) -> int:
    """Extract one positive integer version from a ledger row-like object.

    Accepts plain integers, ``sqlite3.Row`` objects with a ``version`` column,
    mappings with a ``version`` key, and tuple/list rows whose first element is
    the version. This keeps the helper usable with raw SQL and with test data.
    """
    if _is_int(row):
        value: object = row
    elif isinstance(row, sqlite3.Row):
        try:
            value = row["version"]
        except (IndexError, KeyError) as exc:
            raise InvalidAppliedVersionError(
                f"ledger row {index} has no 'version' column"
            ) from exc
    elif isinstance(row, Mapping):
        if "version" not in row:
            raise InvalidAppliedVersionError(
                f"ledger row {index} has no 'version' key"
            )
        value = row["version"]
    elif isinstance(row, (tuple, list)):
        if not row:
            raise InvalidAppliedVersionError(
                f"ledger row {index} is empty; expected a version as the "
                "first element"
            )
        value = row[0]
    else:
        raise InvalidAppliedVersionError(
            f"ledger row {index} has unsupported type "
            f"{type(row).__name__}; expected an integer or a row with a "
            "'version' field"
        )

    if not _is_int(value):
        raise InvalidAppliedVersionError(
            f"ledger row {index} has invalid version {value!r}; expected a "
            "positive integer"
        )
    if value <= 0:
        raise InvalidAppliedVersionError(
            f"ledger row {index} has non-positive version {value}; applied "
            "versions must start at 1"
        )
    return value


def _extract_applied_name(row: object, index: int) -> str | None:
    """Return the migration name carried by a ledger row, or ``None``.

    Accepts :class:`sqlite3.Row`, mappings, and tuple/list rows whose second
    element is the name. Plain integers and rows without a name field return
    ``None`` so callers can skip name comparison when no name is available.
    """
    try:
        if isinstance(row, sqlite3.Row):
            if "name" in row.keys():
                value: object = row["name"]
            else:
                return None
        elif isinstance(row, Mapping):
            value = row.get("name")
            if value is None:
                return None
        elif isinstance(row, (tuple, list)):
            if len(row) < 2:
                return None
            value = row[1]
        else:
            return None
    except (IndexError, KeyError):
        return None

    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidAppliedVersionError(
            f"ledger row {index} has invalid name {value!r}; expected a string"
        )
    return value


def current_applied_version(rows: Iterable[object]) -> int:
    """Return the highest applied version from ledger rows, or ``0`` if empty.

    This helper only determines the current scalar version. It does not check
    for gaps, unknown versions, or future versions; use
    :func:`validate_applied_versions` or :func:`validate_ledger` for that.
    """
    try:
        iterator = iter(rows)
    except TypeError as exc:
        raise MigrationLedgerError(
            "ledger rows must be an iterable of version values or rows"
        ) from exc

    highest = 0
    for index, row in enumerate(iterator):
        version = _extract_applied_version(row, index)
        highest = max(highest, version)
    return highest


def _validate_ledger_schema(connection: sqlite3.Connection) -> None:
    """Verify ``schema_migrations`` exists with the expected, compatible shape.

    Required columns: ``version`` (INTEGER PRIMARY KEY), ``name`` (NOT NULL),
    ``applied_at`` (NOT NULL). A missing table or an incompatible schema raises
    an actionable :class:`MigrationLedgerError` subclass *before* any data is
    read, so callers never observe a raw ``no such table``/``no such column``
    error.
    """
    try:
        info = connection.execute(
            f"PRAGMA table_info({SCHEMA_MIGRATIONS_TABLE})"
        ).fetchall()
    except sqlite3.OperationalError as exc:
        message = str(exc).lower()
        if "no such table" in message:
            raise MigrationLedgerError(
                f"{SCHEMA_MIGRATIONS_TABLE} table is missing; call "
                "create_schema_migrations_table() before reading the ledger"
            ) from exc
        # locking, I/O, or other OperationalError: preserve the original.
        raise

    if not info:
        raise MigrationLedgerError(
            f"{SCHEMA_MIGRATIONS_TABLE} table is missing; call "
            "create_schema_migrations_table() before reading the ledger"
        )

    # PRAGMA table_info rows are (cid, name, type, notnull, dflt_value, pk).
    # Indexing by position is robust to the connection's row_factory.
    columns: dict[str, tuple[str, bool, bool]] = {
        row[1]: (row[2].upper() if row[2] else "", bool(row[3]), bool(row[5]))
        for row in info
    }
    required = ("version", "name", "applied_at")
    missing = [column for column in required if column not in columns]
    if missing:
        raise IncompatibleLedgerSchemaError(
            f"{SCHEMA_MIGRATIONS_TABLE} table has an incompatible schema; "
            f"missing column(s): {_format_versions(missing)}. Recreate the "
            "ledger with create_schema_migrations_table()."
        )

    version_type, version_notnull, version_pk = columns["version"]
    if not version_pk or "INT" not in version_type:
        raise IncompatibleLedgerSchemaError(
            f"{SCHEMA_MIGRATIONS_TABLE} column 'version' must be an INTEGER "
            "PRIMARY KEY; the ledger schema is incompatible."
        )

    name_type, name_notnull, _ = columns["name"]
    if not name_notnull:
        raise IncompatibleLedgerSchemaError(
            f"{SCHEMA_MIGRATIONS_TABLE} column 'name' must be NOT NULL; the "
            "ledger schema is incompatible."
        )

    applied_type, applied_notnull, _ = columns["applied_at"]
    if not applied_notnull:
        raise IncompatibleLedgerSchemaError(
            f"{SCHEMA_MIGRATIONS_TABLE} column 'applied_at' must be NOT NULL; "
            "the ledger schema is incompatible."
        )


def read_applied_versions(
    connection: sqlite3.Connection,
) -> tuple[tuple[int, str], ...]:
    """Read applied (version, name) pairs from ``schema_migrations``.

    The ledger table must already exist with the expected schema; this function
    deliberately does not create or modify it. Returns rows in ascending version
    order. Raises :class:`MigrationLedgerError` if the table is missing,
    :class:`IncompatibleLedgerSchemaError` if the schema is wrong, and preserves
    the original ``sqlite3`` error (chained) for locking, I/O, or corruption
    failures that are neither.
    """
    _validate_ledger_schema(connection)

    try:
        rows = connection.execute(
            f"SELECT version, name FROM {SCHEMA_MIGRATIONS_TABLE} "
            "ORDER BY version"
        ).fetchall()
    except sqlite3.OperationalError as exc:
        message = str(exc).lower()
        if "no such table" in message:
            raise MigrationLedgerError(
                f"{SCHEMA_MIGRATIONS_TABLE} table is missing; call "
                "create_schema_migrations_table() before reading the ledger"
            ) from exc
        # locking, I/O, or other OperationalError: preserve the original.
        raise
    except sqlite3.DatabaseError:
        # corruption or other database-level failure: preserve the original.
        raise

    return tuple(
        (_extract_applied_version(row, index), _extract_applied_name(row, index))
        for index, row in enumerate(rows)
    )


def _registered_version_set(entries: Iterable[object]) -> tuple[tuple[int, str | None], ...]:
    """Normalize and fully validate registered entries into ``(version, name)`` pairs.

    ``entries`` may be :class:`Migration` objects or bare positive integers.
    This performs the same shape checks as :func:`validate_registry` -- type,
    positivity, duplicate, and gap -- so a caller of
    :func:`validate_applied_versions` cannot bypass registry validation by
    relying on an empty ledger. Bare integers have no name (``None``);
    :class:`Migration` names are validated for type, non-emptiness, and padding.
    """
    try:
        iterator = iter(entries)
    except TypeError as exc:
        raise MigrationRegistryError(
            "registered versions must be an iterable of Migration entries or "
            "positive integers"
        ) from exc

    normalized: list[tuple[int, str | None]] = []
    for index, entry in enumerate(iterator):
        if isinstance(entry, Migration):
            version = entry.version
            name = entry.name
            if not _is_int(version):
                raise InvalidMigrationVersionError(
                    f"registered migration {name!r} has invalid version "
                    f"{version!r}; versions must be positive integers"
                )
            if version <= 0:
                raise MigrationRegistryError(
                    f"registered version {version} is not positive; versions must "
                    "start at 1"
                )
            if not isinstance(name, str):
                raise InvalidMigrationNameError(
                    f"registered migration version {version} has an invalid name "
                    f"{name!r}; names must be non-empty strings"
                )
            if not name.strip():
                raise InvalidMigrationNameError(
                    f"registered migration version {version} has an empty name; "
                    "names must be non-empty strings"
                )
            if name != name.strip():
                raise InvalidMigrationNameError(
                    f"registered migration version {version} has a name with "
                    f"leading or trailing whitespace: {name!r}"
                )
            normalized.append((version, name))
        elif _is_int(entry):
            version = entry
            if version <= 0:
                raise MigrationRegistryError(
                    f"registered version {version} is not positive; versions must "
                    "start at 1"
                )
            normalized.append((version, None))
        else:
            raise MigrationRegistryError(
                f"registered version entry {index} must be a Migration or an "
                f"integer, got {type(entry).__name__}"
            )

    versions = [version for version, _ in normalized]
    duplicates = sorted(
        version for version in set(versions) if versions.count(version) > 1
    )
    if duplicates:
        raise DuplicateMigrationVersionError(
            "registered migration version(s) appear more than once: "
            f"{_format_versions(duplicates)}"
        )

    unique_sorted = sorted(set(versions))
    if unique_sorted:
        if unique_sorted != list(range(1, unique_sorted[-1] + 1)):
            missing = sorted(set(range(1, unique_sorted[-1] + 1)) - set(unique_sorted))
            raise MigrationGapError(
                "registered migration versions must be contiguous starting at "
                f"1; missing version(s): {_format_versions(missing)} "
                f"(registered: {_format_versions(unique_sorted)})"
            )

    return tuple(normalized)


def validate_applied_versions(
    applied_versions: Iterable[object],
    registered_versions: Iterable[object],
) -> int:
    """Validate ledger versions against the registered version set.

    Checks, in order:

    * the registered set is well-formed (positive integers, no duplicate or
      gapped versions, valid :class:`Migration` names);
    * every applied version is a positive integer;
    * no applied version appears twice;
    * no applied version is newer than the highest registered version;
    * every applied version is present in the registered set;
    * a version's recorded name matches its registered name;
    * applied versions are contiguous starting at 1.

    Returns the current applied version (``0`` for an empty ledger).

    ``registered_versions`` may be :class:`Migration` objects or bare integers.
    Registered versions are always validated first, so a caller cannot bypass
    registry validation by calling this function directly with an empty ledger.
    """
    # M1: validate the registered set BEFORE the empty-ledger early return so
    # a direct caller cannot bypass registry validation with an empty ledger.
    registered = _registered_version_set(registered_versions)
    registered_versions_set = {version for version, _ in registered}
    registered_names = {
        version: name for version, name in registered if name is not None
    }
    highest_registered = max(registered_versions_set, default=0)

    # M2: separate the iter() call from consumption. A non-iterable argument
    # raises MigrationLedgerError; a TypeError raised while consuming the
    # iterable (e.g. by a generator) propagates unchanged.
    try:
        iterator = iter(applied_versions)
    except TypeError as exc:
        raise MigrationLedgerError(
            "applied versions must be an iterable of version values or rows"
        ) from exc
    applied_rows = list(iterator)

    applied: list[int] = []
    applied_names: dict[int, str] = {}
    for index, row in enumerate(applied_rows):
        version = _extract_applied_version(row, index)
        applied.append(version)
        name = _extract_applied_name(row, index)
        if name is not None:
            applied_names[version] = name

    if not applied:
        return 0

    duplicates = sorted(
        version for version in set(applied) if applied.count(version) > 1
    )
    if duplicates:
        raise DuplicateAppliedVersionError(
            "applied migration version(s) appear more than once: "
            f"{_format_versions(duplicates)}"
        )

    highest_applied = max(applied)

    if highest_applied > highest_registered:
        raise FutureMigrationError(
            f"applied migration version {highest_applied} is newer than the "
            f"highest registered version {highest_registered}; the database is "
            "from a newer Greywatch version"
        )

    unknown = sorted(set(applied) - registered_versions_set)
    if unknown:
        raise UnregisteredMigrationError(
            "applied migration version(s) are not registered: "
            f"{_format_versions(unknown)} "
            f"(registered: {_format_versions(registered_versions_set)})"
        )

    # M3: a version's recorded name must match its registered name.
    mismatches = sorted(
        version for version, applied_name in applied_names.items()
        if version in registered_names
        and applied_name != registered_names[version]
    )
    if mismatches:
        first = mismatches[0]
        raise MigrationNameMismatchError(
            f"applied migration version {first} name "
            f"{applied_names[first]!r} does not match registered name "
            f"{registered_names[first]!r}"
        )

    ordered = sorted(set(applied))
    expected = list(range(1, highest_applied + 1))
    if ordered != expected:
        missing = sorted(set(expected) - set(ordered))
        raise AppliedVersionGapError(
            "applied migration versions must be contiguous starting at 1; "
            f"missing version(s): {_format_versions(missing)} "
            f"(applied: {_format_versions(ordered)})"
        )

    return highest_applied


def validate_ledger(
    connection: sqlite3.Connection,
    entries: Iterable[object] = MIGRATIONS,
) -> int:
    """Validate the registry and the database ledger together.

    This is the intended high-level check for a future runner. It validates
    the registry first, then reads and validates ``schema_migrations``. It
    never writes to the database.
    """
    ordered = validate_registry(entries)
    return validate_applied_versions(
        read_applied_versions(connection),
        ordered,
    )
