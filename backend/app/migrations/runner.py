"""Transactional migration runner for Greywatch database.

This module orchestrates schema migrations with proper transaction handling,
lock management, and state classification. It is designed to be called by
the ``gw_migrate`` CLI tool.

All write operations happen within a single SQLite transaction that is
committed or rolled back atomically. The runner ensures:

* Path safety: symlinks are resolved, missing files are rejected
* Lock ordering: read-only inspection before acquiring write lock
* Ledger integrity: existing ledgers are validated, never repaired
* Schema consistency: post-migration verification of schema and FKs
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

from ..migration_ledger import SCHEMA_MIGRATIONS_TABLE, create_schema_migrations_table
from ..migration_registry import MIGRATIONS, Migration
from ..migration_schema import compare_schema
from ..migration_state import DatabaseReport, DatabaseState, inspect_path
from .v001_baseline import PartialSchemaError, up as up_migration

if TYPE_CHECKING:
    pass

__all__ = [
    "migrate",
    "status",
    "plan",
    "verify",
    "MigrationError",
    "MigrationStateError",
    "MigrationConflictError",
]


class MigrationError(RuntimeError):
    """Base class for migration runner errors."""


class MigrationStateError(MigrationError):
    """Migration cannot proceed due to database state."""


class MigrationConflictError(MigrationError):
    """Database is locked or another migration is in progress."""


# SQLite connection configuration for Greywatch
WAL_MODE = "WAL"
BUSY_TIMEOUT_MS = 10000
SYNCHRONOUS = "NORMAL"


def _utc_now() -> datetime:
    """Return the current UTC datetime."""
    return datetime.now(timezone.utc)


def _resolve_path_safely(path: str | os.PathLike[str]) -> Path:
    """Resolve a path safely, handling symlinks and validating existence.

    - For existing paths: resolve symlinks with strict=True
    - Does NOT create missing files
    - Returns a Path positioned for URI-mode connection

    Raises MigrationStateError if the path is missing or a broken symlink.
    """
    location = Path(path)

    # Resolve with strict=True to catch broken symlinks
    try:
        resolved = location.resolve(strict=True)
    except FileNotFoundError as exc:
        raise MigrationStateError(
            f"database path does not exist: {path}"
        ) from exc
    except OSError as exc:
        raise MigrationStateError(
            f"cannot resolve path {path}: {exc}"
        ) from exc

    # Verify it's a regular file
    if not resolved.is_file():
        raise MigrationStateError(
            f"path is not a regular file: {path}"
        )

    return resolved


def _build_rw_uri(path: Path) -> str:
    """Build a SQLite read-write URI with mode=rw.

    Uses mode=rw which refuses missing files.
    Path is percent-encoded for URI safety.
    """
    encoded = quote(os.fspath(path), safe="/")
    return f"file:{encoded}?mode=rw"


def _open_write_connection(path: Path) -> sqlite3.Connection:
    """Open a write connection with proper SQLite configuration.

    Configures WAL mode, busy_timeout, and synchronous=NORMAL.
    The caller owns the transaction and must commit or rollback.
    """
    uri = _build_rw_uri(path)
    conn = sqlite3.connect(uri, uri=True, timeout=BUSY_TIMEOUT_MS / 1000)
    conn.row_factory = sqlite3.Row

    # Configure SQLite for Greywatch
    conn.execute(f"PRAGMA journal_mode={WAL_MODE}")
    conn.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
    conn.execute(f"PRAGMA synchronous={SYNCHRONOUS}")

    return conn


def _classify_result(report: DatabaseReport) -> tuple[str, bool]:
    """Classify a database report and determine if it can be migrated.

    Returns (error_type, should_noop) where:
    - error_type: 'refuse', 'missing', 'incompatible', or None
    - should_noop: True if the migration should be a no-op (CURRENT state)
    """
    if report.state == DatabaseState.MISSING:
        return "missing", False

    if report.state == DatabaseState.EMPTY:
        return "empty", False

    if report.state in (
        DatabaseState.UNREADABLE,
        DatabaseState.PERMISSION_DENIED,
        DatabaseState.CORRUPT,
        DatabaseState.LOCKED,
    ):
        return "access", False

    if report.state == DatabaseState.UNRELATED:
        return "unrelated", False

    if report.state in (DatabaseState.NEWER, DatabaseState.INCONSISTENT):
        return "incompatible", False

    if report.state in (DatabaseState.LEGACY_INCOMPATIBLE, DatabaseState.LEGACY_PARTIAL):
        return "partial", False

    if report.state == DatabaseState.CURRENT:
        return None, True  # No-op

    # These are migratable states
    return None, False


def status(path: str | os.PathLike[str]) -> DatabaseReport:
    """Read-only status inspection of a Greywatch database.

    Returns a DatabaseReport with the database state classification.
    Raises MigrationStateError for missing, empty, or inaccessible databases.
    """
    try:
        resolved = _resolve_path_safely(path)
    except MigrationStateError:
        raise

    report = inspect_path(resolved)

    # Refuse empty databases
    if report.state == DatabaseState.EMPTY:
        raise MigrationStateError("database is empty")

    return report


def plan(path: str | os.PathLike[str]) -> list[Migration]:
    """Return the list of pending migrations for a database.

    Returns an empty list if:
    - Database is CURRENT
    - Database is in a refused state (MISSING, CORRUPT, etc.)
    - Database is already up-to-date

    Raises MigrationError for database path issues.
    """
    try:
        resolved = _resolve_path_safely(path)
    except MigrationStateError:
        return []

    report = inspect_path(resolved)

    result: list[Migration] = []

    if report.state == DatabaseState.MISSING:
        return result

    if report.state in (DatabaseState.UNREADABLE, DatabaseState.PERMISSION_DENIED, DatabaseState.CORRUPT):
        return result

    if report.state == DatabaseState.CURRENT:
        return result

    if report.state in (DatabaseState.FRESH, DatabaseState.LEDGER_ONLY, DatabaseState.PENDING, DatabaseState.LEGACY_READY):
        from ..migration_registry import latest_version

        latest = latest_version(MIGRATIONS)
        applied = report.applied_version or 0

        if applied < latest:
            result = [m for m in MIGRATIONS if m.version > applied and m.version <= latest]

    return result


def verify(path: str | os.PathLike[str]) -> bool:
    """Verify a database is in CURRENT state (schema complete, ledger valid).

    Returns True if the database is ready for production use.
    Returns False if the database needs migration.
    Raises MigrationError for fatal issues (missing, corrupt, etc.).
    """
    report = status(path)

    if report.state == DatabaseState.MISSING:
        raise MigrationStateError("database does not exist")

    if report.state in (DatabaseState.UNREADABLE, DatabaseState.PERMISSION_DENIED, DatabaseState.CORRUPT):
        raise MigrationError(f"database unreadable: {report.detail}")

    if report.state == DatabaseState.UNRELATED:
        raise MigrationError("database is not a Greywatch database")

    if report.state in (DatabaseState.LEGACY_INCOMPATIBLE, DatabaseState.LEGACY_PARTIAL):
        raise MigrationError(f"database has incompatible schema: {report.detail}")

    if report.state == DatabaseState.NEWER:
        raise MigrationError(f"database is from a newer Greywatch version (ledger: {report.applied_version})")

    if report.state == DatabaseState.INCONSISTENT:
        raise MigrationError(f"database ledger is inconsistent: {report.detail}")

    # CURRENT means verified and ready
    return report.state == DatabaseState.CURRENT


def migrate(path: str | os.PathLike[str], *, dry_run: bool = False) -> dict[str, int]:
    """Run pending migrations, returning counts of applied migrations.

    Returns a dict with 'applied' count (and 'skipped' for future expansion).
    On success, commits the transaction. On any failure, rolls back.

    Dry run reports what would be done without modifying the database.

    Raises:
        MigrationError: for general migration failures
        MigrationStateError: for database state issues (missing, corrupt, incompatible, etc.)
        MigrationConflictError: if database is locked by another process
    """
    from ..migration_registry import read_applied_versions, validate_ledger

    # Phase 0: Resolve path (rejects missing/broken symlink)
    try:
        resolved = _resolve_path_safely(path)
    except MigrationStateError as exc:
        raise MigrationStateError(f"database does not exist: {path}") from exc

    # Phase 1: Read-only preliminary inspection
    report = inspect_path(resolved)

    # Phase 2: Check for refused states upfront
    error_type, should_noop = _classify_result(report)

    if error_type == "missing":
        raise MigrationStateError(f"database does not exist: {resolved}")

    if error_type == "empty":
        raise MigrationStateError(f"database is empty: {resolved}")

    if error_type == "access":
        raise MigrationError(
            f"cannot access database: {report.detail or report.error}"
        ) from report.error

    if error_type == "unrelated":
        raise MigrationError("database is not a Greywatch database")

    if error_type == "incompatible":
        if report.state == DatabaseState.NEWER:
            raise MigrationError(f"database is from a newer Greywatch version (ledger: {report.applied_version})")
        raise MigrationError(f"database in incompatible state: {report.state.value}")

    if error_type == "partial":
        raise MigrationStateError(
            f"database has incompatible schema: {report.detail}"
        )

    if should_noop:
        if dry_run:
            return {"applied": 0, "skipped": 0}
        return {"applied": 0, "skipped": 0}  # Already current

    if dry_run:
        return {"applied": 1, "skipped": 0}

    # Phase 3: Open write connection and acquire lock
    conn = None
    try:
        conn = _open_write_connection(resolved)
    except sqlite3.Error as exc:
        if "locked" in str(exc).lower():
            raise MigrationConflictError(f"database is locked: {exc}") from exc
        raise MigrationError(f"cannot open database: {exc}") from exc

    try:
        # Phase 4: BEGIN IMMEDIATE (acquires write lock)
        conn.execute("BEGIN IMMEDIATE")

        # Phase 5: Re-inspect under lock (state may have changed)
        locked_report = inspect_path(resolved)

        # Phase 6: Reclassify the locked state
        locked_error_type, locked_should_noop = _classify_result(locked_report)

        # Handle state changes after acquiring lock
        if locked_error_type == "missing":
            conn.rollback()
            raise MigrationStateError(f"database disappeared while acquiring lock: {resolved}")

        if locked_error_type == "empty":
            conn.rollback()
            raise MigrationStateError(f"database is empty: {resolved}")

        if locked_error_type == "access":
            conn.rollback()
            raise MigrationError(
                "cannot access database under lock: "
                f"{locked_report.detail or locked_report.error}"
            ) from locked_report.error

        if locked_error_type == "unrelated":
            conn.rollback()
            raise MigrationError("database is not a Greywatch database")

        if locked_error_type == "incompatible":
            conn.rollback()
            if locked_report.state == DatabaseState.NEWER:
                raise MigrationError(f"database is from a newer Greywatch version under lock (ledger: {locked_report.applied_version})")
            raise MigrationError(f"database in incompatible state under lock: {locked_report.state.value}")

        if locked_error_type == "partial":
            conn.rollback()
            raise MigrationStateError(
                f"database has incompatible schema under lock: {locked_report.detail}"
            )

        if locked_should_noop:
            conn.rollback()
            return {"applied": 0, "skipped": 0}  # Already current

        # Phase 7: Validate ledger if present
        if locked_report.ledger_present:
            try:
                validate_ledger(conn)
            except Exception as exc:
                conn.rollback()
                raise MigrationStateError(f"ledger validation failed: {exc}") from exc
            applied_versions = read_applied_versions(conn)
        else:
            applied_versions = ()

        # Phase 8: Determine action based on locked state
        if locked_report.state == DatabaseState.FRESH:
            # Fresh database - run full migration
            create_schema_migrations_table(conn)

            try:
                up_migration(conn)
            except PartialSchemaError as exc:
                conn.rollback()
                raise MigrationStateError(str(exc)) from exc

            # Post-migration verification
            diffs = compare_schema(conn)
            if not diffs.complete:
                conn.rollback()
                raise MigrationStateError(
                    f"schema incomplete after migration"
                )

            # Foreign key check
            fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()
            if fk_violations:
                conn.rollback()
                raise MigrationError(
                    f"foreign key violations after migration: {len(fk_violations)}"
                )

            # Stamp ledger
            utc_now = _utc_now().isoformat()
            conn.execute(
                f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, name, applied_at) VALUES (?, ?, ?)",
                (MIGRATIONS[0].version, MIGRATIONS[0].name, utc_now)
            )

            conn.commit()
            return {"applied": 1, "skipped": 0}

        elif locked_report.state == DatabaseState.LEDGER_ONLY:
            # Ledger only - run full migration
            create_schema_migrations_table(conn)

            try:
                up_migration(conn)
            except PartialSchemaError as exc:
                conn.rollback()
                raise MigrationStateError(str(exc)) from exc

            # Post-migration verification
            diffs = compare_schema(conn)
            if not diffs.complete:
                conn.rollback()
                raise MigrationStateError(f"schema incomplete after migration")

            # Foreign key check
            fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()
            if fk_violations:
                conn.rollback()
                raise MigrationError(f"foreign key violations after migration: {len(fk_violations)}")

            # Stamp ledger
            utc_now = _utc_now().isoformat()
            conn.execute(
                f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, name, applied_at) VALUES (?, ?, ?)",
                (MIGRATIONS[0].version, MIGRATIONS[0].name, utc_now)
            )

            conn.commit()
            return {"applied": 1, "skipped": 0}

        elif locked_report.state == DatabaseState.LEGACY_READY:
            # Legacy ready - run migration to add missing columns
            create_schema_migrations_table(conn)

            try:
                up_migration(conn)
            except PartialSchemaError as exc:
                conn.rollback()
                raise MigrationStateError(str(exc)) from exc

            # Post-migration verification
            diffs = compare_schema(conn)
            if not diffs.complete:
                conn.rollback()
                raise MigrationStateError(f"schema incomplete after migration")

            # Foreign key check
            fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()
            if fk_violations:
                conn.rollback()
                raise MigrationError(f"foreign key violations after migration: {len(fk_violations)}")

            # Stamp ledger if not already present
            if len(applied_versions) == 0:
                utc_now = _utc_now().isoformat()
                conn.execute(
                    f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, name, applied_at) VALUES (?, ?, ?)",
                    (MIGRATIONS[0].version, MIGRATIONS[0].name, utc_now)
                )

            conn.commit()
            return {"applied": 1, "skipped": 0}

        elif locked_report.state == DatabaseState.PENDING:
            # PENDING - just stamp the ledger, schema is complete
            diffs = compare_schema(conn)
            if not diffs.complete:
                conn.rollback()
                raise MigrationStateError(f"schema incomplete under lock")

            # Foreign key check
            fk_violations = conn.execute("PRAGMA foreign_key_check").fetchall()
            if fk_violations:
                conn.rollback()
                raise MigrationError(f"foreign key violations: {len(fk_violations)}")

            # Create ledger table if it doesn't exist
            if not locked_report.ledger_present:
                create_schema_migrations_table(conn)

            # Stamp ledger
            utc_now = _utc_now().isoformat()
            conn.execute(
                f"INSERT INTO {SCHEMA_MIGRATIONS_TABLE} (version, name, applied_at) VALUES (?, ?, ?)",
                (MIGRATIONS[0].version, MIGRATIONS[0].name, utc_now)
            )

            conn.commit()
            return {"applied": 1, "skipped": 0}

        else:
            conn.rollback()
            return {"applied": 0, "skipped": 0}

    except sqlite3.Error as exc:
        if "locked" in str(exc).lower():
            raise MigrationConflictError(f"database is locked: {exc}") from exc
        # Rollback on any error
        if conn is not None:
            try:
                conn.rollback()
            except sqlite3.Error:
                pass
        raise MigrationError(f"migration failed: {exc}") from exc
    finally:
        if conn is not None:
            conn.close()