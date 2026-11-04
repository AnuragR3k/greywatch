"""Read-only database lifecycle inspection for Greywatch.

Classifies a SQLite database into a discrete :class:`DatabaseState` by combining
structural schema inspection (:mod:`backend.app.migration_schema`) with the
existing migration ledger/registry validators (:mod:`backend.app.migration_registry`
and :mod:`backend.app.migration_ledger`).

Read-only / side-effect policy
------------------------------

Every public function here is strictly **read-only**:

* no ``CREATE`` / ``ALTER`` / ``DROP`` / ``INSERT`` / ``UPDATE`` / ``DELETE``;
* no ``PRAGMA`` *writes*; only read-only PRAGMAs are used
  (``table_info`` / ``index_list`` / ``index_xinfo`` / ``foreign_key_list``,
  ``schema_version`` / ``user_version`` reads, and ``quick_check``);
* no call to ``create_schema_migrations_table()``.

### WAL handling (``inspect_path``)

Opening a database in WAL journaling mode with ``mode=ro`` can *create*
``-shm`` / ``-wal`` sidecar files beside the original database, which would
violate the read-only guarantee and mutate the original directory. To avoid any
such side effect, :func:`inspect_path` uses this policy:

* if ``{path}-wal`` exists (WAL mode with potentially uncheckpointed data), the
  database and its ``-wal`` / ``-shm`` companions are copied to a private
  temporary directory and the *copy* is opened ``mode=ro``. The original
  database and its directory are never modified and never receive new sidecar
  files. The WAL data is applied to the inspected copy so uncheckpointed
  transactions are not silently dropped.
* otherwise (rollback-journal mode, or a checkpointed WAL with no ``-wal``
  file) the original file is opened directly with ``mode=ro`` and no sidecars
  are ever created.

.. note::

   The WAL-copy policy does **not** provide an atomic snapshot: the database,
   ``-wal``, and ``-shm`` companions are copied in separate ``copy2`` calls
   and another process may append to the WAL between those copies.  This is a
   best-effort consistency window, not a transactional guarantee.  A future
   improvement could use ``sqlite3_backup_step`` (which copies at a single
   read-transaction snapshot) for a stronger consistency promise.

### Path safety (C1)

Filesystem paths are percent-encoded into the SQLite URI (``?``, ``#``, ``%``
and non-ASCII bytes are encoded) so they can never be interpreted as URI
delimiters. ``mode=ro`` is always preserved, guaranteeing we never silently
inspect a different database. Non-existent, directory, FIFO, and permission-
denied targets are reported as distinct states rather than being opened.

### Integrity verification (M3)

By default (``verify=True``) :func:`inspect_path` runs a read-only
``PRAGMA quick_check`` after opening, which catches header-intact corruption
that a plain ``sqlite_master`` read would miss. ``quick_check`` performs a
single read pass over the file (O(file size)); pass ``verify=False`` to skip
it when the caller can guarantee integrity and wants the cheapest possible
inspect.

This is inspection only: it does not run migrations, does not create schema
migration files, and is not wired into ``siem.initialize_database()``.

State semantics
---------------

* :attr:`DatabaseState.CURRENT` -- every application table is present *and* its
  structure matches the expected schema **and** a ledger is present whose
  applied version equals the highest registered version (> 0).
* :attr:`DatabaseState.UNVERSIONED` -- every application table is present and
  matches the expected schema, but there is **no** migration ledger (or an
  empty one) and no migrations are registered. This is the normal freshly
  shipped state and is intentionally distinguished from ``CURRENT`` (M4) so the
  two meanings do not collapse.
* :attr:`DatabaseState.PENDING` -- current schema, ledger applied version is
  behind the registered latest.
* :attr:`DatabaseState.NEWER` -- ledger applied version is ahead of the
  registered latest.
* :attr:`DatabaseState.INCONSISTENT` -- the ledger is present but gapped,
  duplicated, name-mismatched, references unknown migrations, or has an
  incompatible schema; **or** the ledger claims migrations were applied while
  the application schema does not reflect them.

.. note::

   Schema expectations are versioned in :mod:`backend.app.migration_schema`.
   A database whose ledger claims version N is compared against the cumulative
   vN schema, including the v2 agent/API-key/audit tables and the v3
   audit-chain columns/index. A ledger entry is never accepted on its own: any
   missing or incompatible object makes the database INCONSISTENT, and the
   report's ``detail`` names the missing table, column, or index. Legacy
   databases without a ledger (or with an empty ledger) are compared against
   the v1 baseline so they remain migratable.
"""

from __future__ import annotations

import errno
import os
import shutil
import sqlite3
import stat
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .migration_registry import (
    AppliedVersionGapError,
    DuplicateAppliedVersionError,
    FutureMigrationError,
    InvalidAppliedVersionError,
    MIGRATIONS,
    Migration,
    MigrationLedgerError,
    MigrationNameMismatchError,
    MigrationRegistryError,
    UnregisteredMigrationError,
    read_applied_versions,
    validate_applied_versions,
    validate_registry,
)
from .migration_schema import (
    ADDABLE_COLUMNS,
    ADDABLE_INDEXES,
    APP_TABLES,
    EXPECTED_SCHEMA,
    LEDGER_TABLE,
    SchemaDifferences,
    compare_schema,
    describe_differences,
    expected_schema_for_version,
    table_names,
)

__all__ = [
    "DatabaseState",
    "DatabaseReport",
    "inspect_connection",
    "inspect_path",
    "is_greywatch_database",
    "classify_sqlite_error",
    "MigrationStateError",
    "ensure_database_file_exists",
]


class MigrationStateError(RuntimeError):
    """Database state prevents migration or initialization."""
    pass


class DatabaseState(str, Enum):
    """Discrete lifecycle states a Greywatch database can be in."""

    MISSING = "missing"
    EMPTY = "empty"
    FRESH = "fresh"
    UNVERSIONED = "unversioned"
    LEDGER_ONLY = "ledger_only"
    LEGACY_READY = "legacy_ready"
    LEGACY_PARTIAL = "legacy_partial"
    LEGACY_INCOMPATIBLE = "legacy_incompatible"
    CURRENT = "current"
    PENDING = "pending"
    INCONSISTENT = "inconsistent"
    NEWER = "newer"
    UNRELATED = "unrelated"
    CORRUPT = "corrupt"
    LOCKED = "locked"
    PERMISSION_DENIED = "permission_denied"
    UNREADABLE = "unreadable"


@dataclass(slots=True)
class DatabaseReport:
    """Result of inspecting a database."""

    state: DatabaseState | None = None
    path: str | None = None
    tables: list[str] = field(default_factory=list)
    differences: SchemaDifferences | None = None
    applied_version: int | None = None
    latest_version: int = 0
    ledger_present: bool = False
    detail: str | None = None
    error: Exception | None = None


# --------------------------------------------------------------------------- #
# Difference description helpers
# --------------------------------------------------------------------------- #


def _describe_differences(diffs: SchemaDifferences) -> str:
    """Backwards-compatible wrapper around the public formatter."""
    return describe_differences(diffs)


def _material_schema_incompatibility(diffs: SchemaDifferences) -> bool:
    """True when any present table has a structural defect that cannot be
    repaired by adding migration-addable columns/indexes.

    A "material" incompatibility is one that cannot be repaired by adding
    migration-addable columns/indexes: a wrong column type, wrong PK position,
    missing core column, missing/incompatible foreign key, wrong index
    structure (columns / collation / order / uniqueness / partial), or wrong
    table options.
    """
    if (
        diffs.incompatible_columns
        or diffs.incompatible_indexes
        or diffs.missing_foreign_keys
        or diffs.incompatible_foreign_keys
        or diffs.incompatible_table_options
    ):
        return True
    for table, columns in diffs.missing_columns.items():
        if not set(columns).issubset(ADDABLE_COLUMNS.get(table, frozenset())):
            return True
    for table, indexes in diffs.missing_indexes.items():
        if not set(indexes).issubset(ADDABLE_INDEXES.get(table, frozenset())):
            return True
    return False


def _is_legacy_ready(diffs: SchemaDifferences) -> bool:
    """True when differences are limited to migration-addable columns/indexes.

    A database that has every core column/index/foreign key but is missing
    only the columns/indexes introduced by ``_migrate_events_table`` /
    ``_migrate_alerts_table`` can be migrated forward safely (LEGACY_READY).
    Any material incompatibility makes it INCOMPATIBLE.
    """
    return not _material_schema_incompatibility(diffs)


# --------------------------------------------------------------------------- #
# Ledger validation (ledger-first, C3)
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class _LedgerResult:
    applied_rows: tuple[tuple[int, str], ...]
    applied_version: int
    exception: BaseException | None = None
    # Classification hint for the caller:
    # "future" | "lock" | "permission" | "corrupt" | "unreadable" | "ledger" | None
    kind: str | None = None


def _ledger_error(result: _LedgerResult, exc: sqlite3.Error) -> _LedgerResult:
    """Classify a SQLite error raised while reading/validating the ledger."""
    msg = str(exc).lower()
    if "locked" in msg:
        kind: str | None = "lock"
    elif "permission" in msg or "read-only" in msg or "attempt to" in msg:
        kind = "permission"
    elif "malformed" in msg or "file is not a database" in msg or "corrupt" in msg:
        kind = "corrupt"
    else:
        kind = "unreadable"
    result.exception = exc
    result.kind = kind
    return result


def _validate_ledger(
    connection: sqlite3.Connection, ordered: tuple[Migration, ...]
) -> _LedgerResult:
    """Read and validate the ledger, classifying any failure.

    Returns applied ``(version, name)`` rows and the highest applied version.
    On failure, ``exception`` is set with a ``kind`` hint so the caller can map
    it to a precise :class:`DatabaseState` (NEWER, LOCKED, etc.) instead of a
    blanket CORRUPT.
    """
    result = _LedgerResult(applied_rows=(), applied_version=0)
    try:
        rows = read_applied_versions(connection)
    except MigrationLedgerError as exc:
        # IncompatibleLedgerSchemaError, InvalidAppliedVersionError, etc.
        result.exception = exc
        result.kind = "ledger"
        return result
    except sqlite3.Error as exc:
        return _ledger_error(result, exc)

    result.applied_rows = rows
    result.applied_version = max((row[0] for row in rows), default=0)

    try:
        validate_applied_versions(rows, ordered)
    except FutureMigrationError as exc:
        result.exception = exc
        result.kind = "future"
    except (
        AppliedVersionGapError,
        DuplicateAppliedVersionError,
        InvalidAppliedVersionError,
        MigrationNameMismatchError,
        UnregisteredMigrationError,
    ) as exc:
        result.exception = exc
        result.kind = "ledger"
    except sqlite3.Error as exc:  # pragma: no cover - defensive
        return _ledger_error(result, exc)
    return result


# --------------------------------------------------------------------------- #
# Connection / path error classification (M3)
# --------------------------------------------------------------------------- #


def _classify_sqlite_error(exc: BaseException) -> tuple[DatabaseState, str | None]:
    """Map a SQLite/OS error to a precise state and a human reason.

    Used for the connection-level failure path (open / PRAGMA / read errors).
    See :func:`_ledger_error` for the ledger-path mapping.
    """
    msg = str(exc).lower()
    if isinstance(exc, PermissionError):
        return DatabaseState.PERMISSION_DENIED, "file permission denied"
    if isinstance(exc, FileNotFoundError):
        return DatabaseState.MISSING, "database file disappeared between checks"
    if isinstance(exc, sqlite3.OperationalError):
        if "locked" in msg:
            return DatabaseState.LOCKED, "database is locked"
        if "permission" in msg or "read-only" in msg or "attempt to" in msg:
            return DatabaseState.PERMISSION_DENIED, "read-only database or permission denied"
        if "no such" in msg:
            return DatabaseState.MISSING, "database object not found"
    if isinstance(exc, sqlite3.ProgrammingError):
        return DatabaseState.UNREADABLE, f"invalid or closed connection (programming error): {exc}"
    if isinstance(exc, sqlite3.DatabaseError):
        if "malformed" in msg or "file is not a database" in msg or "corrupt" in msg:
            return DatabaseState.CORRUPT, "database image is corrupt"
        return DatabaseState.UNREADABLE, "database is unreadable"
    if isinstance(exc, OSError):
        return DatabaseState.UNREADABLE, "I/O error reading database"
    return DatabaseState.UNREADABLE, type(exc).__name__


def classify_sqlite_error(exc: BaseException) -> DatabaseState:
    """Public helper exposing the M3 error -> state mapping."""
    state, _ = _classify_sqlite_error(exc)
    return state


def _quick_check(connection: sqlite3.Connection) -> str | None:
    """Run a read-only ``PRAGMA quick_check``; return ``None`` if healthy.

    Returns a non-``ok`` string when SQLite reports an integrity problem.
    Lock-related ``OperationalError`` exceptions are *re-raised* so the caller
    can classify them as ``LOCKED`` rather than ``CORRUPT``.
    """
    try:
        row = connection.execute("PRAGMA quick_check").fetchone()
    except sqlite3.OperationalError as exc:
        if "locked" in str(exc).lower():
            raise
        return "quick_check could not run"
    except sqlite3.ProgrammingError:
        raise  # caller misuse (e.g. closed connection) -- do not mask as corruption
    except sqlite3.Error:
        return "quick_check could not run"
    value = row[0] if row else "error"
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    if value.strip().lower() == "ok":
        return None
    return str(value)


# --------------------------------------------------------------------------- #
# Registry materialization (M2) and path safety (C1)
# --------------------------------------------------------------------------- #


def _validate_registry_once(
    entries: Any,
) -> tuple[tuple[Migration, ...], MigrationRegistryError | None]:
    """Materialize and validate the registry *once* (M2).

    Never consumes a generator a second time: ``validate_registry`` consumes
    ``entries`` exactly once into a tuple, which is then reused for every
    classification decision.
    """
    try:
        ordered = validate_registry(entries)
    except MigrationRegistryError as exc:
        return (), exc
    return ordered, None


def _resolve_path_safely(path: str | os.PathLike[str]) -> "DatabaseReport | None":
    """Validate ``path`` is a regular file we may inspect read-only.

    Returns ``None`` if the path is OK to open, otherwise a ready-to-return
    :class:`DatabaseReport` describing why inspection cannot proceed (MISSING,
    EMPTY, PERMISSION_DENIED, UNREADABLE for directories/FIFOs/specials).

    .. note::

       We skip ``Path.exists()`` and go straight to ``Path.stat()``.
       ``exists()`` returns ``False`` when a *parent* directory is unreadable,
       which would misclassify a genuinely-present file as ``MISSING``.
       ``stat()`` raises ``FileNotFoundError`` (file truly absent) or
       ``PermissionError`` (access denied), letting us distinguish the two
       correctly.  TOCTOU safety is preserved: a file deleted between
       ``stat`` and ``open`` is caught by the caller's ``FileNotFoundError``
       handler.
    """
    location = Path(path)
    try:
        st = location.stat()
    except FileNotFoundError:
        return DatabaseReport(path=os.fspath(location), state=DatabaseState.MISSING)
    except PermissionError as exc:
        return DatabaseReport(
            path=os.fspath(location),
            state=DatabaseState.PERMISSION_DENIED,
            error=exc,
            detail=f"permission denied: {exc}",
        )
    except OSError as exc:
        return DatabaseReport(
            path=os.fspath(location),
            state=DatabaseState.UNREADABLE,
            error=exc,
            detail=f"cannot stat database file: {exc}",
        )
    if not stat.S_ISREG(st.st_mode):
        return DatabaseReport(
            path=os.fspath(location),
            state=DatabaseState.UNREADABLE,
            detail="target is not a regular file (directory, FIFO, or special file)",
        )
    if st.st_size == 0:
        return DatabaseReport(path=os.fspath(location), state=DatabaseState.EMPTY)
    if not os.access(location, os.R_OK):
        return DatabaseReport(
            path=os.fspath(location),
            state=DatabaseState.PERMISSION_DENIED,
            detail="file is not readable",
        )
    return None


def _read_only_uri(path: Path) -> str:
    """Build a read-only SQLite URI that escapes path metacharacters (C1).

    ``?``, ``#``, ``%`` and non-ASCII bytes in the path are percent-encoded so
    they are never interpreted as URI delimiters, preserving ``mode=ro`` and
    guaranteeing we never silently open a different database.
    """
    resolved = path.resolve()
    encoded = quote(os.fspath(resolved), safe="")
    return f"file:{encoded}?mode=ro"


def _db_is_wal(path: Path) -> bool:
    """Return True if the database file is in WAL journaling mode.

    Detects WAL mode from database header bytes 18/19 (the file-format write/read
    version; value ``2`` means WAL). This is a pure read of the header and never
    opens the database as a connection, so it has no side effects and works
    even on a WAL database whose ``-wal``/``-shm`` companions have already been
    checkpointed away (a case the ``-wal`` existence check misses but where
    ``mode=ro`` would still *create* sidecar files beside the original).
    """
    try:
        with open(path, "rb") as handle:
            header = handle.read(100)
    except OSError:
        return False
    if len(header) < 20:
        return False
    return header[18] == 2 or header[19] == 2


def _open_readonly_with_wal_copy(path: Path) -> tuple[sqlite3.Connection, str | None]:
    """Open ``path`` read-only, copying to a temp dir if WAL mode is active.

    If the database header indicates WAL journaling mode, the database and any
    present ``-wal`` / ``-shm`` companions are copied to a private temporary
    directory and the *copy* is opened ``mode=ro``. This applies any
    uncheckpointed WAL data to the inspected copy without creating or modifying
    sidecars beside the original database (opening a WAL database directly in
    ``mode=ro`` would create ``-shm``/``-wal`` files next to the original).
    When the database is in rollback-journal mode the original file is opened
    directly with ``mode=ro`` and no sidecars are ever created.

    Returns ``(connection, temp_dir_or_None)``. When ``temp_dir`` is not
    ``None`` the caller must remove it (via :func:`_maybe_cleanup`) after
    closing the connection.
    """
    resolved = path.resolve()
    parent = resolved.parent
    stem = resolved.name
    if _db_is_wal(resolved):
        tmp_dir = tempfile.mkdtemp(prefix="greywatch-inspect-", dir=tempfile.gettempdir())
        try:
            dst = os.path.join(tmp_dir, stem)
            shutil.copy2(resolved, dst)
            for ext in ("-wal", "-shm"):
                side = parent / f"{stem}{ext}"
                if side.exists():
                    shutil.copy2(side, os.path.join(tmp_dir, f"{stem}{ext}"))
            connection = sqlite3.connect(_read_only_uri(Path(dst)), uri=True)
        except BaseException:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise
        return connection, tmp_dir

    return sqlite3.connect(_read_only_uri(resolved), uri=True), None


def _maybe_cleanup(connection: sqlite3.Connection | None, tmp_dir: str | None) -> None:
    if connection is not None:
        connection.close()
    if tmp_dir:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #


def inspect_connection(
    connection: sqlite3.Connection,
    entries: Any = MIGRATIONS,
    verify: bool = True,
) -> DatabaseReport:
    """Classify an already-open database connection.

    Read-only: the connection is not written to, no PRAGMA side effects are
    produced, and the connection is not closed by this function. Pass ``entries``
    to classify against a custom migration registry (iterable / generator,
    consumed exactly once). Pass ``verify=False`` to skip the default
    ``PRAGMA quick_check`` gate.
    """
    report = DatabaseReport()

    # M2: materialize the registry once.
    ordered, reg_error = _validate_registry_once(entries)
    if reg_error is not None:
        report.state = DatabaseState.INCONSISTENT
        report.latest_version = 0
        report.detail = f"inspection registry is invalid: {reg_error}"
        report.error = reg_error
        return report
    latest = ordered[-1].version if ordered else 0
    report.latest_version = latest

    # M3: quick_check gate -- catch header-intact corruption cheaply.
    # Lock-related OperationalErrors and ProgrammingError (closed/invalid
    # connection) from quick_check are re-raised and classified below,
    # not as CORRUPT.
    if verify:
        try:
            problem = _quick_check(connection)
        except (sqlite3.OperationalError, sqlite3.ProgrammingError) as exc:
            state, reason = _classify_sqlite_error(exc)
            report.state = state
            report.error = exc
            report.detail = reason
            return report
        if problem is not None:
            report.state = DatabaseState.CORRUPT
            report.error = sqlite3.DatabaseError(problem)
            report.detail = f"integrity check failed: {problem}"
            return report

    # Read table names (raises on a corrupt schema page).
    try:
        tables = table_names(connection)
    except sqlite3.Error as exc:
        state, reason = _classify_sqlite_error(exc)
        report.state = state
        report.error = exc
        report.detail = reason
        return report

    report.tables = sorted(tables)
    lowered_present = {name.lower() for name in tables}
    app_present = {t for t in APP_TABLES if t.lower() in lowered_present}
    ledger_present = LEDGER_TABLE.lower() in lowered_present
    report.ledger_present = ledger_present

    # ---- Ledger-first validation (C3) ------------------------------------ #
    applied_rows: tuple[tuple[int, str], ...] = ()
    applied_version = 0
    if ledger_present:
        lr = _validate_ledger(connection, ordered)
        if lr.exception is not None:
            report.applied_version = lr.applied_version
            if lr.kind == "future":
                report.state = DatabaseState.NEWER
                report.detail = (
                    f"ledger is ahead of the registered latest version "
                    f"({lr.applied_version} > {latest})"
                )
            elif lr.kind == "lock":
                report.state = DatabaseState.LOCKED
            elif lr.kind == "permission":
                report.state = DatabaseState.PERMISSION_DENIED
            elif lr.kind == "corrupt":
                report.state = DatabaseState.CORRUPT
            else:  # "ledger" or "unreadable"
                report.state = DatabaseState.INCONSISTENT
                report.detail = f"ledger failed validation: {lr.exception}"
            report.error = lr.exception
            return report
        applied_rows = lr.applied_rows
        applied_version = lr.applied_version

    # ---- No Greywatch content at all ------------------------------------- #
    if not app_present and not ledger_present:
        report.state = DatabaseState.FRESH if not tables else DatabaseState.UNRELATED
        report.applied_version = 0
        return report

    # ---- LEDGER_ONLY ----------------------------------------------------- #
    if ledger_present and not app_present:
        # Ledger already validated above; valid here means it parsed+validated.
        report.applied_version = applied_version
        if applied_rows:
            report.state = DatabaseState.INCONSISTENT
            report.detail = (
                "ledger records applied migrations but no application tables exist"
            )
        else:
            report.state = DatabaseState.LEDGER_ONLY
        return report

    # ---- Application tables present (partial or complete) ---------------- #
    report.applied_version = applied_version

    # M3: the expected schema is version-aware. A ledger that claims version N
    # must satisfy the cumulative schema introduced through N. Only the shipped
    # registry has version-specific descriptors; custom registries used by
    # callers/tests fall back to the v1 baseline they are built on.
    comparison_schema = EXPECTED_SCHEMA
    if applied_version >= 1 and tuple(ordered) == MIGRATIONS:
        try:
            comparison_schema = expected_schema_for_version(applied_version)
        except ValueError as exc:
            report.state = DatabaseState.INCONSISTENT
            report.detail = str(exc)
            report.error = exc
            return report

    report.differences = compare_schema(connection, expected=comparison_schema)
    diffs = report.differences

    # A ledger claiming applied migrations that the schema does not satisfy is
    # inconsistent -- never report LEGACY_* when the ledger says otherwise (C3).
    if applied_version >= 1 and not diffs.complete:
        report.state = DatabaseState.INCONSISTENT
        report.detail = (
            f"ledger claims applied version {applied_version} but the schema "
            f"does not match the expected v{applied_version} schema: "
            f"{_describe_differences(diffs)}"
        )
        return report

    partial = app_present != set(APP_TABLES)
    if partial:
        # C3: a partial database with an incompatible *existing* table must not
        # be reported as ordinary LEGACY_PARTIAL.
        if _material_schema_incompatibility(diffs):
            report.state = DatabaseState.LEGACY_INCOMPATIBLE
            report.detail = _describe_differences(diffs)
        else:
            report.state = DatabaseState.LEGACY_PARTIAL
        return report

    # All five application tables present.
    if not diffs.complete:
        if _is_legacy_ready(diffs):
            # applied_version must be 0 here (guarded above).
            report.state = DatabaseState.LEGACY_READY
        else:
            report.state = DatabaseState.LEGACY_INCOMPATIBLE
            report.detail = _describe_differences(diffs)
        return report

    # Schema is current; classify by the validated ledger.
    if applied_version > latest:
        report.state = DatabaseState.NEWER
    elif applied_version < latest:
        report.state = DatabaseState.PENDING
    else:
        # applied == latest
        report.state = DatabaseState.UNVERSIONED if latest == 0 else DatabaseState.CURRENT
    return report


def inspect_path(
    path: str | os.PathLike[str],
    entries: Any = MIGRATIONS,
    verify: bool = True,
) -> DatabaseReport:
    """Classify the database at ``path`` without creating or modifying it.

    A non-existent path is :attr:`DatabaseState.MISSING`; a zero-byte file is
    :attr:`DatabaseState.EMPTY`; directories/FIFOs/specials are
    ``UNREADABLE``; permission errors are ``PERMISSION_DENIED``. Otherwise the
    file is opened read-only (``mode=ro``); if a WAL sidecar exists the
    database and its WAL companions are copied to a temporary directory and
    inspected there (see the module docstring), so the original database and
    directory never receive ``-wal``/``-shm`` files.

    ``verify`` (default ``True``) runs a read-only ``PRAGMA quick_check`` before
    declaring the database healthy; set it to ``False`` to skip that single
    read pass.
    """
    location = Path(path)
    report = DatabaseReport(path=os.fspath(location))

    checked = _resolve_path_safely(location)
    if checked is not None:
        return checked

    try:
        connection, tmp_dir = _open_readonly_with_wal_copy(location)
    except PermissionError as exc:
        report.state = DatabaseState.PERMISSION_DENIED
        report.error = exc
        report.detail = f"permission denied opening database: {exc}"
        return report
    except FileNotFoundError:
        return DatabaseReport(path=os.fspath(location), state=DatabaseState.MISSING)
    except sqlite3.Error as exc:
        state, reason = _classify_sqlite_error(exc)
        report.state = state
        report.error = exc
        report.detail = reason
        return report

    try:
        result = inspect_connection(connection, entries=entries, verify=verify)
        result.path = os.fspath(location)
        return result
    except sqlite3.Error as exc:
        state, reason = _classify_sqlite_error(exc)
        report.state = state
        report.error = exc
        report.detail = reason
        return report
    finally:
        _maybe_cleanup(connection, tmp_dir)


def _is_valid_sqlite_database(path: str) -> bool:
    """
    Verify that `path` is a valid SQLite database with a proper header.

    Returns True if:
    - File exists and is non-zero
    - SQLite can open it and read PRAGMA user_version
    - PRAGMA quick_check returns ok
    """
    try:
        if not os.path.exists(path):
            return False
        if os.path.getsize(path) == 0:
            return False

        conn = sqlite3.connect(path)
        try:
            # Verify we can read the database header
            version = conn.execute("PRAGMA user_version").fetchone()
            if version is None:
                return False
            # Optional: quick integrity check
            integrity = conn.execute("PRAGMA quick_check").fetchone()
            if integrity != ("ok",):
                return False
            return True
        finally:
            conn.close()
    except (sqlite3.Error, OSError):
        return False


def ensure_database_file_exists(db_path: Path) -> None:
    """
    Atomically ensure a valid empty SQLite database exists at db_path.

    Strategy:
    1. If destination exists, return immediately (another process published).
    2. Create temp file in SAME directory.
    3. Initialize temp file as valid SQLite (PRAGMA user_version=0).
    4. CLOSE connection -- this forces SQLite to write the database header/page.
    5. VERIFY the temp file is a valid non-zero SQLite database.
    6. Attempt atomic no-replace publication via os.link().
    7. On FileExistsError (EEXIST): another process won -> use their file.
    8. On other OSError (cross-device, no link support): FAIL CLOSED.
    9. On successful publication: explicitly unlink the temporary pathname.
    10. Clean up temp file on any error.

    Guarantees:
    - Any process inspecting db_path sees either nothing or a fully initialized
      valid SQLite database (FRESH state).
    - No zero-byte window visible to other processes.
    - No replacement of an existing destination.
    - Temporary pathname is removed after successful publication.

    Orphaned temporary files from crashed processes are NOT automatically cleaned.
    They are harmless (small, distinctive names, never published) and can be
    removed manually or on next deployment. Automatic cleanup would risk deleting
    a temp file another active worker is still initializing.
    """
    if db_path.exists():
        return

    tmp_path = None
    try:
        # Create temp file in same directory
        fd, tmp_path = tempfile.mkstemp(
            dir=db_path.parent,
            prefix=f".{db_path.name}.init.",
            suffix=".tmp"
        )
        os.close(fd)

        # Initialize as valid SQLite database
        conn = sqlite3.connect(tmp_path)
        try:
            conn.execute("PRAGMA user_version=0")
            conn.commit()
        finally:
            conn.close()

        # CRITICAL: Verify the temp file is a valid non-zero SQLite database
        # before attempting publication.
        if not _is_valid_sqlite_database(tmp_path):
            raise MigrationStateError(
                f"Failed to initialize valid SQLite database at {tmp_path}"
            )

        # Atomic no-replace publication via hard link
        try:
            os.link(tmp_path, str(db_path))
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                # Another process published first
                return
            elif exc.errno in (errno.EXDEV, errno.EPERM, errno.ENOTSUP):
                raise MigrationStateError(
                    f"Cannot atomically publish database: {exc}. "
                    f"Filesystem must support hard links (no cross-device, no NFS)."
                ) from exc
            else:
                raise MigrationStateError(
                    f"Failed to publish database: {exc}"
                ) from exc
        else:
            # Publication succeeded -- explicitly unlink the temporary pathname
            # The destination now has the same inode; our temp name is no longer needed.
            try:
                os.unlink(tmp_path)
            except OSError:
                # If unlink fails, the file is still published correctly.
                # The temp name is leaked but harmless.
                pass
            tmp_path = None  # Ownership transferred; finally block will not unlink

    finally:
        # Safety net: clean up temp file only if publication failed
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def is_greywatch_database(connection: sqlite3.Connection) -> bool:
    """Return True if the connection has any Greywatch application table."""
    return bool(
        {t for t in APP_TABLES if t.lower() in {name.lower() for name in table_names(connection)}}
    )
