"""Backup preflight policy shared by startup and manual migrations.

Both application startup (``backend.app.main.lifespan``) and the manual
``scripts/gw_migrate migrate`` CLI execute migrations through
``backend.app.migrations.runner.migrate``.  The backup gate therefore lives in
the runner and this module, so the two entry points cannot drift apart.

Policy
------
``GREYWATCH_REQUIRE_BACKUP``
    Unset means **required** (fail safe for production).  Explicit
    ``0/false/no/off`` is the intentional development opt-out.  Any other value
    is a configuration error: migrations do not run with an ambiguous policy.

``GREYWATCH_BACKUP_DIR``
    Directory containing ``greywatch.db.*`` backups.  Required whenever the
    backup policy is enabled.  The live database may never be selected as its
    own backup.

``GREYWATCH_MAX_BACKUP_AGE_HOURS``
    Positive integer, default ``24``.  The newest matching backup must be no
    older than this.  Invalid values are configuration errors.

Safety properties
-----------------
* Only the newest matching backup is considered; a stale or invalid newest
  backup fails the preflight instead of silently falling back to an older one.
* The selected backup is verified with
  ``scripts.gw_db_backup.verify_database()`` (regular non-symlink file,
  non-empty, ``PRAGMA integrity_check`` and ``foreign_key_check``) before the
  migration runner opens a write connection.
* The selected backup is compared with the live database using ``samefile``
  (with a resolved-path fallback), so a backup path that is the database, a
  hardlink to it, or a symlink to it is rejected.
* A failed preflight raises before any migration writes occur.
* Backups are never deleted, moved, or overwritten here.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from scripts import gw_db_backup

from .migration_state import MigrationStateError

REQUIRE_BACKUP_ENV = "GREYWATCH_REQUIRE_BACKUP"
BACKUP_DIR_ENV = "GREYWATCH_BACKUP_DIR"
MAX_BACKUP_AGE_ENV = "GREYWATCH_MAX_BACKUP_AGE_HOURS"

DEFAULT_MAX_BACKUP_AGE_HOURS = 24

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})

__all__ = [
    "BackupPolicy",
    "BackupPreflightError",
    "resolve_policy",
    "run_backup_preflight",
]


class BackupPreflightError(MigrationStateError):
    """Raised when the migration backup policy cannot be satisfied."""


@dataclass(frozen=True)
class BackupPolicy:
    """Resolved backup preflight configuration."""

    required: bool
    backup_dir: Path | None
    max_age_hours: int


def _configuration_error(message: str) -> BackupPreflightError:
    """Build an actionable configuration error without echoing secrets."""
    return BackupPreflightError(message)


def _invalid_backup(reason: str) -> BackupPreflightError:
    """Build the shared failure message used for missing/stale/invalid backups."""
    return BackupPreflightError(
        "Backup required but no valid backup found. "
        f"{reason} "
        "Create a fresh backup with 'scripts/gw_db_backup.sh backup', verify it "
        "with 'scripts/gw_db_backup.sh verify <backup>', then retry the "
        "migration. For an intentional development run only, set "
        "GREYWATCH_REQUIRE_BACKUP=0."
    )


def _parse_require_flag(environ: Mapping[str, str]) -> tuple[bool, bool]:
    """Return ``(required, explicitly_set)`` for the backup policy.

    Unset or empty means required.  This is the production-safe default; a
    development machine must opt out explicitly.
    """
    raw = environ.get(REQUIRE_BACKUP_ENV)
    if raw is None or not raw.strip():
        return True, False

    normalized = raw.strip().lower()
    if normalized in _TRUTHY:
        return True, True
    if normalized in _FALSY:
        return False, True

    raise _configuration_error(
        f"Invalid {REQUIRE_BACKUP_ENV}={raw!r}. Use 1/true/yes/on to require a "
        "verified backup before migration, or 0/false/no/off for an "
        "intentional development opt-out. Refusing to migrate with an "
        "ambiguous backup policy."
    )


def _parse_max_age(environ: Mapping[str, str]) -> int:
    """Parse a positive integer backup age limit, failing closed on garbage."""
    raw = environ.get(MAX_BACKUP_AGE_ENV)
    if raw is None:
        return DEFAULT_MAX_BACKUP_AGE_HOURS

    value = raw.strip()
    if not value.isdigit() or int(value) <= 0:
        raise _configuration_error(
            f"Invalid {MAX_BACKUP_AGE_ENV}={raw!r}. Use a positive integer "
            f"number of hours, e.g. {MAX_BACKUP_AGE_ENV}=24."
        )
    return int(value)


def _resolve_backup_dir(environ: Mapping[str, str], *, explicitly_set: bool) -> Path:
    """Validate and return the configured backup directory."""
    raw = environ.get(BACKUP_DIR_ENV, "")
    if not raw.strip():
        if explicitly_set:
            raise _configuration_error(
                f"{REQUIRE_BACKUP_ENV}=1 is set but {BACKUP_DIR_ENV} is not "
                "configured. Set it to a dedicated backup directory, e.g. "
                "'/var/backups/greywatch'."
            )
        raise _configuration_error(
            f"{REQUIRE_BACKUP_ENV} defaults to required (production-safe) but "
            f"{BACKUP_DIR_ENV} is not configured. Set it to a dedicated backup "
            "directory (e.g. '/var/backups/greywatch'), or set "
            f"{REQUIRE_BACKUP_ENV}=0 for an intentional development run."
        )

    path = Path(raw)
    try:
        st = os.stat(path)
    except FileNotFoundError as exc:
        raise _configuration_error(
            f"{BACKUP_DIR_ENV} is set to '{path}' but the directory does not "
            "exist. Create it with mode 0700 or correct the path."
        ) from exc
    except NotADirectoryError as exc:
        raise _configuration_error(
            f"{BACKUP_DIR_ENV} is set to '{path}' but it is not a directory. "
            "Provide a valid directory path."
        ) from exc
    except PermissionError as exc:
        raise _configuration_error(
            f"{BACKUP_DIR_ENV} is set to '{path}' but it is not accessible: "
            f"{exc.strerror or exc}. Fix the directory permissions."
        ) from exc
    except OSError as exc:
        raise _configuration_error(
            f"Cannot inspect {BACKUP_DIR_ENV} '{path}': {exc}"
        ) from exc

    if not stat.S_ISDIR(st.st_mode):
        raise _configuration_error(
            f"{BACKUP_DIR_ENV} is set to '{path}' but it is not a directory. "
            "Provide a valid directory path."
        )

    return path


def resolve_policy(
    environ: Mapping[str, str] | None = None,
) -> BackupPolicy:
    """Resolve backup policy from the environment (or an explicit mapping)."""
    env = os.environ if environ is None else environ

    required, explicitly_set = _parse_require_flag(env)
    if not required:
        # Intentional development opt-out: do not demand backup configuration.
        return BackupPolicy(required=False, backup_dir=None, max_age_hours=0)

    max_age_hours = _parse_max_age(env)
    backup_dir = _resolve_backup_dir(env, explicitly_set=explicitly_set)
    return BackupPolicy(
        required=True,
        backup_dir=backup_dir,
        max_age_hours=max_age_hours,
    )


def _same_file(left: Path, right: Path) -> bool:
    """True when two paths identify the same file (resolved-path fallback)."""
    try:
        return os.path.samefile(left, right)
    except OSError:
        try:
            return left.resolve(strict=False) == right.resolve(strict=False)
        except OSError:
            return False


def _newest_backup(backup_dir: Path) -> Path:
    """Return the newest ``greywatch.db.*`` entry, or raise a clear failure."""
    try:
        names = os.listdir(backup_dir)
    except PermissionError as exc:
        raise _configuration_error(
            f"Cannot read {BACKUP_DIR_ENV} '{backup_dir}': "
            f"{exc.strerror or exc}. Fix the directory permissions."
        ) from exc
    except OSError as exc:
        raise _configuration_error(
            f"Cannot read {BACKUP_DIR_ENV} '{backup_dir}': {exc}"
        ) from exc

    candidates: list[tuple[float, str, Path]] = []
    for name in names:
        if not name.startswith(gw_db_backup.DEFAULT_BACKUP_PREFIX):
            continue
        candidate = backup_dir / name
        try:
            st = os.lstat(candidate)
        except OSError as exc:
            raise _invalid_backup(
                f"Cannot inspect backup candidate '{candidate}': {exc}."
            ) from exc
        candidates.append((st.st_mtime, name, candidate))

    if not candidates:
        raise _invalid_backup(
            f"No backup files matching '{gw_db_backup.DEFAULT_BACKUP_PREFIX}*' were found "
            f"in '{backup_dir}'."
        )

    # Newest first.  A tie is broken by name so selection is deterministic.
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return candidates[0][2]


def run_backup_preflight(
    db_path: str | os.PathLike[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> Path | None:
    """Enforce the configured backup policy before any migration write.

    Returns the verified backup path when backups are required, or ``None``
    when the development opt-out is active.  Raises
    :class:`BackupPreflightError` (a ``MigrationStateError``) when the policy is
    misconfigured or no acceptable backup exists.
    """
    policy = resolve_policy(environ)
    if not policy.required:
        return None

    assert policy.backup_dir is not None  # implied by required=True

    live_db = Path(db_path)
    candidate = _newest_backup(policy.backup_dir)

    # Refuse before verification: a backup must never be the live database
    # itself, including through a hardlink or symlink.
    if _same_file(candidate, live_db):
        raise _configuration_error(
            f"Refusing to migrate: backup candidate '{candidate}' refers to "
            f"the live database '{live_db}'. Store backups in a directory "
            "separate from the database file and retry."
        )

    try:
        st = os.stat(candidate)
    except OSError as exc:
        raise _invalid_backup(
            f"Cannot inspect backup candidate '{candidate}': {exc}."
        ) from exc

    age_seconds = time.time() - st.st_mtime
    max_age_seconds = policy.max_age_hours * 3600
    if age_seconds > max_age_seconds:
        raise _invalid_backup(
            f"Newest backup '{candidate}' is {age_seconds / 3600:.1f}h old, "
            f"which exceeds {MAX_BACKUP_AGE_ENV}={policy.max_age_hours}. "
            "Create a fresh backup immediately before migrating."
        )

    try:
        gw_db_backup.verify_database(str(candidate), what="backup")
    except gw_db_backup.BackupError as exc:
        raise _invalid_backup(f"Verification failed: {exc}") from exc
    except (OSError, ValueError, sqlite3.DatabaseError) as exc:
        raise _invalid_backup(
            f"Cannot verify backup '{candidate}': {exc}."
        ) from exc

    return candidate
