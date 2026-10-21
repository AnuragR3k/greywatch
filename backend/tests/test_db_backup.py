"""Tests for the Greywatch SQLite backup/restore tool.

These tests exercise ``scripts/gw_db_backup.py`` (the engine) and
``scripts/gw_db_backup.sh`` (the wrapper) against disposable databases under
``tmp_path`` only. The production database ``data/greywatch.db`` is never
opened, and no system service is touched.
"""

from __future__ import annotations

import importlib.util
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ENGINE_PATH = REPO_ROOT / "scripts" / "gw_db_backup.py"
WRAPPER_PATH = REPO_ROOT / "scripts" / "gw_db_backup.sh"

_spec = importlib.util.spec_from_file_location("gw_db_backup", ENGINE_PATH)
gw = importlib.util.module_from_spec(_spec)
assert _spec and _spec.loader
_spec.loader.exec_module(gw)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _make_db(path: Path, *, value: str = "backup works", wal: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    if wal:
        conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("CREATE TABLE events(id INTEGER PRIMARY KEY, raw TEXT)")
    conn.execute("INSERT INTO events(raw) VALUES (?)", (value,))
    conn.commit()
    conn.close()


def _read_value(path: Path) -> str:
    conn = sqlite3.connect(path)
    try:
        return conn.execute("SELECT raw FROM events").fetchone()[0]
    finally:
        conn.close()


def _sidecars(path: Path) -> list[str]:
    return sorted(
        p.name for p in path.parent.glob(path.name + "-*")
    )


def _run_wrapper(args, env_extra=None):
    env = os.environ.copy()
    env["GREYWATCH_PYTHON"] = sys.executable
    env.update(env_extra or {})
    return subprocess.run(
        ["bash", str(WRAPPER_PATH), *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )


# --------------------------------------------------------------------------- #
# Backup
# --------------------------------------------------------------------------- #


def test_backup_creates_verified_self_contained_file(tmp_path):
    src = tmp_path / "live.db"
    backup_dir = tmp_path / "backups"
    _make_db(src, value="backup works")

    out = gw.backup_database(str(src), str(backup_dir))

    out_path = Path(out)
    assert out_path.is_file()
    assert out_path.stat().st_mode & 0o777 == 0o600
    assert backup_dir.stat().st_mode & 0o777 == 0o700
    # Self-contained: no -wal/-shm sidecars next to the backup.
    assert _sidecars(out_path) == []
    gw.verify_database(str(out_path))
    assert _read_value(out_path) == "backup works"


def test_backup_leaves_no_sidecars_on_idle_wal_database(tmp_path):
    src = tmp_path / "live.db"
    backup_dir = tmp_path / "backups"
    _make_db(src)
    assert _sidecars(src) == []  # idle WAL db is checkpointed

    gw.backup_database(str(src), str(backup_dir))

    # A read-only source open must not leave root/service-owned sidecars behind.
    assert _sidecars(src) == []


def test_backup_does_not_clobber_existing_backups(tmp_path):
    src = tmp_path / "live.db"
    backup_dir = tmp_path / "backups"
    _make_db(src)

    first = gw.backup_database(str(src), str(backup_dir))
    second = gw.backup_database(str(src), str(backup_dir))

    assert first != second
    assert Path(first).is_file() and Path(second).is_file()


def test_backup_missing_source_raises_without_artifacts(tmp_path):
    backup_dir = tmp_path / "backups"
    with pytest.raises(gw.BackupError):
        gw.backup_database(str(tmp_path / "nope.db"), str(backup_dir))
    assert not backup_dir.exists() or list(backup_dir.iterdir()) == []


def test_backup_removes_incomplete_file_on_verify_failure(tmp_path, monkeypatch):
    src = tmp_path / "live.db"
    backup_dir = tmp_path / "backups"
    _make_db(src)

    def _boom(path, *, what="database"):
        raise gw.BackupError("simulated verification failure")

    monkeypatch.setattr(gw, "verify_database", _boom)

    with pytest.raises(gw.BackupError):
        gw.backup_database(str(src), str(backup_dir))

    # No final backup and no leftover temp files.
    assert list(backup_dir.iterdir()) == []


# --------------------------------------------------------------------------- #
# Verify
# --------------------------------------------------------------------------- #


def test_verify_accepts_valid_database(tmp_path):
    db = tmp_path / "ok.db"
    _make_db(db)
    gw.verify_database(str(db))  # must not raise


def test_verify_rejects_missing_file(tmp_path):
    with pytest.raises(gw.BackupError, match="not found"):
        gw.verify_database(str(tmp_path / "missing.db"))


def test_verify_rejects_empty_file(tmp_path):
    empty = tmp_path / "empty.db"
    empty.write_bytes(b"")
    with pytest.raises(gw.BackupError, match="empty"):
        gw.verify_database(str(empty))


def test_verify_rejects_corrupt_file(tmp_path):
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"this is definitely not a sqlite database")
    with pytest.raises(gw.BackupError):
        gw.verify_database(str(bad))


def test_verify_rejects_foreign_key_violation(tmp_path):
    db = tmp_path / "fk.db"
    conn = sqlite3.connect(db)
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("CREATE TABLE parent(id INTEGER PRIMARY KEY)")
    conn.execute(
        "CREATE TABLE child(id INTEGER PRIMARY KEY, pid INTEGER REFERENCES parent(id))"
    )
    conn.execute("INSERT INTO child(id, pid) VALUES (1, 42)")  # no parent 42
    conn.commit()
    conn.close()

    # integrity is fine; only the foreign-key check should fail.
    assert sqlite3.connect(db).execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    with pytest.raises(gw.BackupError, match="foreign_key_check"):
        gw.verify_database(str(db))


def test_verify_rejects_failed_integrity_check(tmp_path, monkeypatch):
    db = tmp_path / "corrupt-page.db"
    _make_db(db)

    class _FakeConn:
        def execute(self, sql, *args):
            class _Cur:
                def fetchall(self_inner):
                    if "integrity_check" in sql:
                        return [("*** in database main ***",)]
                    return []

            return _Cur()

        def close(self):
            pass

    monkeypatch.setattr(gw, "_open_ro", lambda path: (_FakeConn(), False))
    monkeypatch.setattr(gw, "_close_ro", lambda conn, path, had_wal: None)

    with pytest.raises(gw.BackupError, match="integrity_check"):
        gw.verify_database(str(db))


# --------------------------------------------------------------------------- #
# Restore
# --------------------------------------------------------------------------- #


def test_restore_requires_confirmation_and_preserves_destination(tmp_path):
    src = tmp_path / "live.db"
    backup_dir = tmp_path / "backups"
    _make_db(src, value="current")
    backup = gw.backup_database(str(src), str(backup_dir))

    with pytest.raises(gw.BackupError, match="--yes"):
        gw.restore_database(backup, str(src), confirm=False)
    assert _read_value(src) == "current"


def test_restore_preserves_backup_data(tmp_path):
    src = tmp_path / "live.db"
    backup_dir = tmp_path / "backups"
    _make_db(src, value="original")
    backup = gw.backup_database(str(src), str(backup_dir))

    # Mutate the live database, then restore the backup.
    conn = sqlite3.connect(src)
    conn.execute("UPDATE events SET raw='mutated'")
    conn.commit()
    conn.close()

    summary = gw.restore_database(backup, str(src), confirm=True)

    assert _read_value(src) == "original"
    assert Path(summary["pre_restore_copy"]).is_file()
    gw.verify_database(summary["pre_restore_copy"])
    assert _sidecars(src) == []


def test_restore_rejects_corrupt_backup_and_preserves_destination(tmp_path):
    src = tmp_path / "live.db"
    _make_db(src, value="keep me")
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"garbage")

    with pytest.raises(gw.BackupError):
        gw.restore_database(str(bad), str(src), confirm=True)
    assert _read_value(src) == "keep me"


def test_restore_rejects_missing_backup_and_preserves_destination(tmp_path):
    src = tmp_path / "live.db"
    _make_db(src, value="keep me")

    with pytest.raises(gw.BackupError, match="not found"):
        gw.restore_database(str(tmp_path / "missing.db"), str(src), confirm=True)
    assert _read_value(src) == "keep me"


def test_restore_rejects_same_file(tmp_path):
    src = tmp_path / "live.db"
    _make_db(src)
    with pytest.raises(gw.BackupError, match="same file"):
        gw.restore_database(str(src), str(src), confirm=True)


def test_restore_moves_sidecars_aside(tmp_path):
    src = tmp_path / "live.db"
    backup_dir = tmp_path / "backups"
    _make_db(src, value="original")
    backup = gw.backup_database(str(src), str(backup_dir))

    # Simulate an in-use WAL database by holding a connection open so the
    # sidecars persist, then restore.
    holder = sqlite3.connect(src)
    holder.execute("PRAGMA journal_mode=WAL")
    holder.execute("INSERT INTO events(raw) VALUES ('live')")
    holder.commit()
    assert _sidecars(src) != []

    summary = gw.restore_database(backup, str(src), confirm=True)

    assert summary["moved_sidecars"]
    for saved in summary["moved_sidecars"]:
        assert Path(saved).is_file()
    assert not (tmp_path / "live.db-wal").exists()
    assert not (tmp_path / "live.db-shm").exists()
    holder.close()


def test_restore_failure_preserves_original_database(tmp_path, monkeypatch):
    src = tmp_path / "live.db"
    backup_dir = tmp_path / "backups"
    _make_db(src, value="original")
    backup = gw.backup_database(str(src), str(backup_dir))
    conn = sqlite3.connect(src)
    conn.execute("UPDATE events SET raw='mutated'")
    conn.commit()
    conn.close()

    real_replace = gw.os.replace

    def _failing_replace(src_arg, dst_arg, *args, **kwargs):
        if dst_arg == str(src) and ".restore." in os.path.basename(src_arg):
            raise OSError("simulated replace failure")
        return real_replace(src_arg, dst_arg, *args, **kwargs)

    monkeypatch.setattr(gw.os, "replace", _failing_replace)

    with pytest.raises(OSError):
        gw.restore_database(backup, str(src), confirm=True)

    # The atomic replace never happened, so the mutated DB is intact.
    assert _read_value(src) == "mutated"


def test_restore_unknown_owner_preserves_ownership(tmp_path, capsys):
    src = tmp_path / "live.db"
    backup_dir = tmp_path / "backups"
    _make_db(src, value="original")
    backup = gw.backup_database(str(src), str(backup_dir))
    before = os.stat(src).st_uid

    summary = gw.restore_database(
        backup, str(src), confirm=True, owner="definitely-no-such-user-xyz"
    )

    assert os.stat(summary["destination"]).st_uid == before
    assert "could not be resolved" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #


def test_prune_retention_boundaries(tmp_path):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    old = backup_dir / "greywatch.db.old"
    new = backup_dir / "greywatch.db.new"
    unrelated = backup_dir / "notes.txt"
    for f in (old, new, unrelated):
        f.write_bytes(b"x")
    old_time = time.time() - 40 * 86400
    os.utime(old, (old_time, old_time))
    os.utime(unrelated, (old_time, old_time))
    (backup_dir / "greywatch.db.dir").mkdir()

    kept, removed = gw.prune_backups(str(backup_dir), 30)

    assert (kept, removed) == (1, 1)
    assert not old.exists()
    assert new.exists()
    assert unrelated.exists()  # unrelated files are never pruned
    assert (backup_dir / "greywatch.db.dir").exists()  # directories untouched


def test_prune_does_not_follow_symlinks(tmp_path):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    target = tmp_path / "precious.txt"
    target.write_text("do not delete")
    link = backup_dir / "greywatch.db.link"
    link.symlink_to(target)
    old_time = time.time() - 40 * 86400
    os.utime(target, (old_time, old_time))

    kept, removed = gw.prune_backups(str(backup_dir), 30)

    assert (kept, removed) == (0, 0)
    assert target.read_text() == "do not delete"


def test_prune_rejects_non_positive_days(tmp_path):
    with pytest.raises(gw.BackupError):
        gw.prune_backups(str(tmp_path), 0)


# --------------------------------------------------------------------------- #
# Wrapper script
# --------------------------------------------------------------------------- #


def test_wrapper_backup_and_restore_roundtrip(tmp_path):
    src = tmp_path / "live.db"
    backup_dir = tmp_path / "backups"
    _make_db(src, value="wrapper works")
    env = {"GREYWATCH_DB": str(src), "GREYWATCH_BACKUP_DIR": str(backup_dir)}

    backup_run = _run_wrapper(["backup"], env)
    assert backup_run.returncode == 0, backup_run.stderr
    backups = list(backup_dir.glob("greywatch.db.*"))
    assert len(backups) == 1

    # restore without --yes is refused
    refused = _run_wrapper(["restore", str(backups[0])], env)
    assert refused.returncode == 1
    assert "--yes" in refused.stderr

    # mutate then restore with --yes
    conn = sqlite3.connect(src)
    conn.execute("UPDATE events SET raw='mutated'")
    conn.commit()
    conn.close()
    ok = _run_wrapper(["restore", str(backups[0]), "--yes"], env)
    assert ok.returncode == 0, ok.stderr
    assert _read_value(src) == "wrapper works"


def test_wrapper_reports_missing_database(tmp_path):
    run = _run_wrapper(
        ["backup"],
        {
            "GREYWATCH_DB": str(tmp_path / "nope.db"),
            "GREYWATCH_BACKUP_DIR": str(tmp_path / "backups"),
        },
    )
    assert run.returncode == 1
    assert "not found" in run.stderr.lower()


def test_wrapper_never_invokes_systemctl():
    text = WRAPPER_PATH.read_text()
    assert "systemctl" not in text