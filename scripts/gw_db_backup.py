#!/usr/bin/env python3
"""Greywatch SQLite backup, verify, restore, and retention tool.

This module is the single implementation used by ``gw_db_backup.sh`` (the
operator-facing wrapper). It uses SQLite's online backup API
(``sqlite3.Connection.backup``) so a live WAL-mode database is captured
consistently without ever copying the file directly.

Subcommands
-----------
    backup  <source_db> <backup_dir> [--prefix P] [--retention-days N]
    verify  <db>
    restore <backup_file> <dest_db> --yes [--owner user[:group]] [--prefix P]
    retain  <backup_dir> <days> [--prefix P]

Safety properties
-----------------
* The source database is opened ``mode=ro``; the live file is never written to.
* A backup is written to a private temp file, verified, then atomically renamed
  into place. Incomplete backups are removed.
* Restore verifies the backup, makes an online safety copy of the current
  database, stages and verifies the replacement in the destination directory,
  moves stale ``-wal``/``-shm`` sidecars aside, and atomically replaces the DB.
* Restore requires ``--yes``; it never stops or starts ``greywatch-api``.
* Ownership is only changed when it can be resolved; an unknown deployment user
  is reported and the existing ownership is preserved.

Restore is NOT atomic across the database and its ``-wal``/``-shm`` sidecars.
The service must be stopped by the operator before restoring.
"""

from __future__ import annotations

import argparse
import grp
import os
import pwd
import shutil
import sqlite3
import stat
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

DEFAULT_BACKUP_PREFIX = "greywatch.db."
BACKUP_FILE_MODE = 0o600
BACKUP_DIR_MODE = 0o700
SIDECAR_SUFFIXES = ("-wal", "-shm")


class BackupError(RuntimeError):
    """Raised for any expected, user-facing failure."""


# --------------------------------------------------------------------------- #
# Small helpers
# --------------------------------------------------------------------------- #


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ro_uri(path: str) -> str:
    """Return a read-only SQLite URI for ``path`` (never creates/writes it)."""
    return "file:" + quote(os.path.abspath(path), safe="/") + "?mode=ro"


def _require_regular_file(path: str, what: str) -> None:
    """Require ``path`` to be an existing regular file (not a symlink/dir)."""
    if not os.path.exists(path):
        raise BackupError(f"{what} not found: {path}")
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode):
        raise BackupError(f"{what} must not be a symlink: {path}")
    if not stat.S_ISREG(st.st_mode):
        raise BackupError(f"{what} is not a regular file: {path}")


def _unique_path(directory: str, prefix: str) -> str:
    """Return a non-existent ``prefix<stamp>`` path, suffixing on collision."""
    base = f"{prefix}{_utc_stamp()}"
    candidate = os.path.join(directory, base)
    counter = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, f"{base}.{counter}")
        counter += 1
    return candidate


def _unlink_quietly(path: str | None) -> None:
    if not path:
        return
    try:
        os.unlink(path)
    except OSError:
        pass


def _open_ro(path: str) -> tuple[sqlite3.Connection, bool]:
    """Open ``path`` read-only, remembering whether a ``-wal`` already existed.

    Opening a WAL database read-only can create ``-wal``/``-shm`` sidecars. If
    those did not exist before, they are ours and must be removed afterwards so
    a root-run backup cannot leave root-owned sidecars next to a database owned
    by the unprivileged service user.
    """
    had_wal = os.path.exists(path + "-wal")
    return sqlite3.connect(_ro_uri(path), uri=True), had_wal


def _close_ro(conn: sqlite3.Connection, path: str, had_wal: bool) -> None:
    conn.close()
    if had_wal:
        return  # pre-existing sidecars belong to another process; never touch
    wal = path + "-wal"
    # A read-only connection can never write WAL frames, so a sidecar we
    # created is empty and safe to remove. A non-empty WAL means another
    # process wrote concurrently; leave it alone.
    if os.path.exists(wal) and os.path.getsize(wal) == 0:
        _unlink_quietly(wal)
        _unlink_quietly(path + "-shm")


# --------------------------------------------------------------------------- #
# Verification
# --------------------------------------------------------------------------- #


def verify_database(path: str, *, what: str = "database") -> None:
    """Verify ``path`` is a non-empty, structurally valid SQLite database.

    Runs ``PRAGMA integrity_check`` and ``PRAGMA foreign_key_check`` on a
    read-only connection. Raises :class:`BackupError` on any failure, including
    files that are not SQLite databases (which SQLite reports by raising).
    """
    _require_regular_file(path, what)
    if os.path.getsize(path) == 0:
        raise BackupError(f"{what} is empty: {path}")

    try:
        conn, had_wal = _open_ro(path)
    except sqlite3.Error as exc:  # pragma: no cover - connect rarely fails
        raise BackupError(f"{what} could not be opened: {path}: {exc}") from exc

    try:
        try:
            integrity = conn.execute("PRAGMA integrity_check").fetchall()
            fk = conn.execute("PRAGMA foreign_key_check").fetchall()
        except sqlite3.DatabaseError as exc:
            raise BackupError(
                f"{what} is not a valid SQLite database: {path}: {exc}"
            ) from exc
    finally:
        _close_ro(conn, path, had_wal)

    if integrity != [("ok",)]:
        detail = "; ".join(str(row[0]) for row in integrity[:5]) or "unknown"
        raise BackupError(f"{what} failed integrity_check: {path}: {detail}")
    if fk:
        raise BackupError(
            f"{what} failed foreign_key_check ({len(fk)} violation(s)): {path}"
        )


# --------------------------------------------------------------------------- #
# Backup
# --------------------------------------------------------------------------- #


def _online_copy(src: str, dst: str) -> None:
    """Copy ``src`` to the new file ``dst`` using SQLite's online backup API.

    The copy is converted to DELETE journal mode so it is a single
    self-contained file with no ``-wal``/``-shm`` sidecars (verifying it later
    then never creates sidecars either).
    """
    src_conn, had_wal = _open_ro(src)
    try:
        dst_conn = sqlite3.connect(dst)
        try:
            src_conn.backup(dst_conn)
            try:
                dst_conn.execute("PRAGMA journal_mode=DELETE")
            except sqlite3.Error:
                pass
            dst_conn.commit()
        finally:
            dst_conn.close()
    finally:
        _close_ro(src_conn, src, had_wal)

    # Defensive cleanup: only remove sidecars that hold no pending frames.
    wal = dst + "-wal"
    if os.path.exists(wal) and os.path.getsize(wal) == 0:
        _unlink_quietly(wal)
        _unlink_quietly(dst + "-shm")


def backup_database(
    source_db: str,
    backup_dir: str,
    *,
    prefix: str = DEFAULT_BACKUP_PREFIX,
    retention_days: int = 0,
) -> str:
    """Create a verified backup of ``source_db`` in ``backup_dir``.

    Returns the path of the created backup. Raises :class:`BackupError` on any
    failure, removing the incomplete backup file.
    """
    _require_regular_file(source_db, "source database")

    if os.path.exists(backup_dir) and not os.path.isdir(backup_dir):
        raise BackupError(f"backup directory is not a directory: {backup_dir}")
    os.makedirs(backup_dir, exist_ok=True)
    try:
        os.chmod(backup_dir, BACKUP_DIR_MODE)
    except OSError as exc:
        print(
            f"WARNING: could not set {BACKUP_DIR_MODE:04o} on {backup_dir}: {exc}",
            file=sys.stderr,
        )

    fd, tmp_path = tempfile.mkstemp(
        dir=backup_dir, prefix=f".{prefix}", suffix=".tmp"
    )
    os.close(fd)
    final_path: str | None = None
    try:
        _online_copy(source_db, tmp_path)
        os.chmod(tmp_path, BACKUP_FILE_MODE)
        verify_database(tmp_path, what="backup")
        final_path = _unique_path(backup_dir, prefix)
        os.replace(tmp_path, final_path)
        tmp_path = None  # ownership transferred to final_path
    finally:
        _unlink_quietly(tmp_path)

    assert final_path is not None
    if retention_days > 0:
        prune_backups(backup_dir, retention_days, prefix=prefix)
    return final_path


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #


def prune_backups(
    backup_dir: str,
    retention_days: int,
    *,
    prefix: str = DEFAULT_BACKUP_PREFIX,
) -> tuple[int, int]:
    """Delete regular backup files older than ``retention_days``.

    Only files whose names start with ``prefix`` are considered, and only
    regular files (``lstat``; symlinks and directories are never followed).
    Returns ``(kept, removed)``.
    """
    if retention_days <= 0:
        raise BackupError("retention days must be a positive integer")
    if not os.path.isdir(backup_dir):
        raise BackupError(f"backup directory not found: {backup_dir}")

    cutoff = _utc_now() - timedelta(days=retention_days)
    kept = 0
    removed = 0
    for entry in sorted(os.listdir(backup_dir)):
        if not entry.startswith(prefix):
            continue
        full_path = os.path.join(backup_dir, entry)
        try:
            st = os.lstat(full_path)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        mtime = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
        if mtime < cutoff:
            os.unlink(full_path)
            removed += 1
        else:
            kept += 1
    return kept, removed


# --------------------------------------------------------------------------- #
# Restore
# --------------------------------------------------------------------------- #


def _resolve_owner(owner: str) -> tuple[int, int] | None:
    """Resolve ``user`` or ``user:group`` to ``(uid, gid)`` or ``None``."""
    user, _, group = owner.partition(":")
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        return None
    if group:
        try:
            return pw.pw_uid, grp.getgrnam(group).gr_gid
        except KeyError:
            return None
    return pw.pw_uid, pw.pw_gid


def _apply_ownership(
    path: str, owner: str | None, prev_stat: os.stat_result | None
) -> None:
    """Set ownership, warning instead of failing when it cannot be resolved."""
    target: tuple[int, int] | None = None
    if owner:
        target = _resolve_owner(owner)
        if target is None:
            print(
                f"WARNING: owner '{owner}' could not be resolved; "
                "preserving existing ownership",
                file=sys.stderr,
            )
    if target is None and prev_stat is not None:
        target = (prev_stat.st_uid, prev_stat.st_gid)
    if target is None:
        return
    try:
        os.chown(path, target[0], target[1])
    except OSError as exc:
        print(f"WARNING: could not set ownership on {path}: {exc}", file=sys.stderr)


def restore_database(
    backup_path: str,
    dest_path: str,
    *,
    confirm: bool = False,
    owner: str | None = None,
    prefix: str = DEFAULT_BACKUP_PREFIX,
) -> dict:
    """Safely restore ``backup_path`` over ``dest_path``.

    Requires ``confirm=True`` (the ``--yes`` flag). Verifies the backup first,
    makes an online safety copy of the current database, stages and verifies the
    replacement in the destination directory, moves stale ``-wal``/``-shm``
    sidecars aside, then atomically replaces the database. On failure the
    original database and sidecars are restored whenever possible.

    The service is never stopped or started; the caller must ensure the
    database is not in use.
    """
    if not confirm:
        raise BackupError(
            "refusing to replace the database without --yes "
            "(stop greywatch-api first, then re-run with --yes)"
        )

    verify_database(backup_path, what="backup")
    backup_real = os.path.realpath(backup_path)
    dest_real = os.path.realpath(dest_path)
    if backup_real == dest_real:
        raise BackupError("backup and destination are the same file")

    dest_dir = os.path.dirname(dest_real) or "."
    if not os.path.isdir(dest_dir):
        raise BackupError(f"destination directory does not exist: {dest_dir}")

    dest_existed = os.path.exists(dest_real)
    prev_stat = os.lstat(dest_real) if dest_existed else None
    if dest_existed:
        _require_regular_file(dest_real, "destination database")

    stamp = _utc_stamp()
    basename = os.path.basename(dest_real)
    pre_copy: str | None = None
    moved_sidecars: list[tuple[str, str]] = []
    stage: str | None = None

    try:
        # 1. Recoverable online copy of the current database (handles WAL).
        if dest_existed:
            pre_copy = _unique_path(dest_dir, f"{basename}.pre-restore.")
            _online_copy(dest_real, pre_copy)
            os.chmod(pre_copy, BACKUP_FILE_MODE)
            verify_database(pre_copy, what="pre-restore copy")

        # 2. Stage the replacement next to the destination, then verify it.
        fd, stage = tempfile.mkstemp(
            dir=dest_dir,
            prefix=f".{basename}.restore.",
            suffix=".tmp",
        )
        os.close(fd)
        shutil.copyfile(backup_real, stage)
        os.chmod(stage, BACKUP_FILE_MODE)
        with open(stage, "rb") as fh:
            os.fsync(fh.fileno())
        verify_database(stage, what="staged database")

        # 3. Move stale WAL/SHM sidecars aside (recoverable, not deleted).
        for suffix in SIDECAR_SUFFIXES:
            sidecar = dest_real + suffix
            if os.path.exists(sidecar):
                saved = os.path.join(
                    dest_dir, f"{basename}.{suffix.lstrip('-')}.pre-restore.{stamp}"
                )
                os.replace(sidecar, saved)
                moved_sidecars.append((sidecar, saved))

        # 4. Atomic replacement of the main database file.
        os.replace(stage, dest_real)
        stage = None
        os.chmod(dest_real, BACKUP_FILE_MODE)

        # 5. Ownership (never fatal).
        _apply_ownership(dest_real, owner, prev_stat)
    except Exception:
        # Best-effort rollback: restore sidecars and the original database.
        for sidecar, saved in moved_sidecars:
            try:
                os.replace(saved, sidecar)
            except OSError:
                pass
        if pre_copy and dest_existed and os.path.exists(pre_copy):
            try:
                os.replace(pre_copy, dest_real)
                _apply_ownership(dest_real, None, prev_stat)
            except OSError:
                pass
        _unlink_quietly(stage)
        raise

    return {
        "destination": dest_real,
        "backup": backup_real,
        "pre_restore_copy": pre_copy,
        "moved_sidecars": [saved for _, saved in moved_sidecars],
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gw_db_backup.py",
        description="Greywatch SQLite backup/restore tool.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_backup = sub.add_parser("backup", help="create a verified online backup")
    p_backup.add_argument("source_db")
    p_backup.add_argument("backup_dir")
    p_backup.add_argument("--prefix", default=DEFAULT_BACKUP_PREFIX)
    p_backup.add_argument("--retention-days", type=int, default=0)

    p_verify = sub.add_parser("verify", help="verify a database file")
    p_verify.add_argument("db")

    p_restore = sub.add_parser("restore", help="restore a backup over a database")
    p_restore.add_argument("backup_file")
    p_restore.add_argument("dest_db")
    p_restore.add_argument(
        "--yes",
        action="store_true",
        help="required confirmation before replacing the database",
    )
    p_restore.add_argument("--owner", default=None)
    p_restore.add_argument("--prefix", default=DEFAULT_BACKUP_PREFIX)

    p_retain = sub.add_parser("retain", help="prune old backups")
    p_retain.add_argument("backup_dir")
    p_retain.add_argument("days", type=int)
    p_retain.add_argument("--prefix", default=DEFAULT_BACKUP_PREFIX)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        if args.command == "backup":
            path = backup_database(
                args.source_db,
                args.backup_dir,
                prefix=args.prefix,
                retention_days=args.retention_days,
            )
            print(f"Backup created: {path}")
        elif args.command == "verify":
            verify_database(args.db)
            print(f"OK: {args.db}")
        elif args.command == "restore":
            summary = restore_database(
                args.backup_file,
                args.dest_db,
                confirm=args.yes,
                owner=args.owner,
                prefix=args.prefix,
            )
            print(f"Restore complete: {summary['destination']}")
            if summary["pre_restore_copy"]:
                print(f"Pre-restore copy: {summary['pre_restore_copy']}")
            for saved in summary["moved_sidecars"]:
                print(f"Sidecar moved aside: {saved}")
        elif args.command == "retain":
            kept, removed = prune_backups(
                args.backup_dir, args.days, prefix=args.prefix
            )
            print(f"Retention: kept={kept}, removed={removed}")
    except (BackupError, sqlite3.Error, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())