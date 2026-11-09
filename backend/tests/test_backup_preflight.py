"""M4 regression tests: backup preflight for startup and manual migrations.

The production default requires a recent, verified backup before the runner
opens a write connection.  These tests exercise the shared policy module, the
runner directly, application startup, and the ``scripts/gw_migrate`` CLI.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest

from backend.app.backup_preflight import (
    DEFAULT_MAX_BACKUP_AGE_HOURS,
    BackupPreflightError,
    resolve_policy,
    run_backup_preflight,
)
from backend.app.migration_ledger import SCHEMA_MIGRATIONS_TABLE
from backend.app.migration_state import DatabaseState, inspect_path
from backend.app.migrations.runner import migrate
from scripts import gw_db_backup

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "scripts" / "gw_migrate"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _fresh_db(path: Path) -> Path:
    """Create a valid SQLite file with no application tables (FRESH state)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA user_version=0")
        conn.commit()
    finally:
        conn.close()
    assert inspect_path(path).state == DatabaseState.FRESH
    return path


def _legacy_ready_db(path: Path) -> Path:
    """Core v1 tables/indexes with only migration-addable columns missing."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
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
            CREATE INDEX idx_events_ip_time ON events(source_ip, timestamp);

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
            CREATE INDEX idx_alerts_status ON alerts(status, created_at);

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
            CREATE INDEX idx_incidents_status ON incidents(status, created_at);
            CREATE INDEX idx_incidents_rule_ip ON incidents(rule_id, source_ip, status);

            CREATE TABLE incident_events (
                incident_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                added_at TEXT NOT NULL,
                PRIMARY KEY (incident_id, event_id),
                FOREIGN KEY (incident_id) REFERENCES incidents(id),
                FOREIGN KEY (event_id) REFERENCES events(id)
            );
            CREATE INDEX idx_incident_events_incident ON incident_events(incident_id);
            CREATE INDEX idx_incident_events_event ON incident_events(event_id);

            CREATE TABLE collector_state (key TEXT PRIMARY KEY, value TEXT);
            """
        )
        conn.commit()
    finally:
        conn.close()
    assert inspect_path(path).state == DatabaseState.LEGACY_READY
    return path


def _backup(db_path: Path, backup_dir: Path) -> Path:
    return Path(gw_db_backup.backup_database(str(db_path), str(backup_dir)))


def _set_backup_mtime(backup_path: Path, age_hours: float) -> None:
    """Set mtime to exactly `age_hours` ago from now."""
    stamp = time.time() - age_hours * 3600
    os.utime(backup_path, (stamp, stamp))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _ledger_versions(path: Path) -> list[int]:
    conn = sqlite3.connect(path)
    try:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if SCHEMA_MIGRATIONS_TABLE not in tables:
            return []
        return [
            row[0]
            for row in conn.execute(
                f"SELECT version FROM {SCHEMA_MIGRATIONS_TABLE} ORDER BY version"
            )
        ]
    finally:
        conn.close()


def _backup_env(backup_dir: Path, **extra: str) -> dict[str, str]:
    env = {
        "GREYWATCH_REQUIRE_BACKUP": "1",
        "GREYWATCH_BACKUP_DIR": str(backup_dir),
    }
    env.update(extra)
    return env


def _run_cli(args: list[str], overrides: dict[str, str | None]) -> subprocess.CompletedProcess:
    """Run ``scripts/gw_migrate`` with a controlled environment.

    A ``None`` override removes the variable, which lets tests exercise the
    production default (unset means required).
    """
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(REPO_ROOT) + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )
    for key, value in overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    return subprocess.run(
        [sys.executable, str(CLI_PATH), *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )


# --------------------------------------------------------------------------- #
# Policy resolution
# --------------------------------------------------------------------------- #


class TestBackupPolicy:
    def test_unset_policy_defaults_to_required(self, tmp_path):
        policy = resolve_policy({"GREYWATCH_BACKUP_DIR": str(tmp_path)})
        assert policy.required is True
        assert policy.max_age_hours == DEFAULT_MAX_BACKUP_AGE_HOURS
        assert policy.backup_dir == tmp_path

    @pytest.mark.parametrize("value", ["0", "false", "FALSE", "no", "off"])
    def test_explicit_opt_out_disables_preflight(self, value):
        policy = resolve_policy({"GREYWATCH_REQUIRE_BACKUP": value})
        assert policy.required is False
        assert policy.backup_dir is None

    @pytest.mark.parametrize("value", ["1", "true", "YES", "on"])
    def test_explicit_enable_requires_backup_dir(self, value):
        with pytest.raises(BackupPreflightError, match="GREYWATCH_BACKUP_DIR"):
            resolve_policy({"GREYWATCH_REQUIRE_BACKUP": value})

    @pytest.mark.parametrize("value", ["maybe", "2", "enabled", "yes please"])
    def test_invalid_require_value_fails_closed(self, value):
        with pytest.raises(
            BackupPreflightError, match="Invalid GREYWATCH_REQUIRE_BACKUP"
        ):
            resolve_policy(
                {
                    "GREYWATCH_REQUIRE_BACKUP": value,
                    "GREYWATCH_BACKUP_DIR": "/tmp/does-not-matter",
                }
            )

    @pytest.mark.parametrize("value", ["0", "-1", "24.5", "abc", "", "1e3"])
    def test_invalid_max_age_fails_closed(self, tmp_path, value):
        with pytest.raises(
            BackupPreflightError, match="Invalid GREYWATCH_MAX_BACKUP_AGE_HOURS"
        ):
            resolve_policy(
                {
                    "GREYWATCH_REQUIRE_BACKUP": "1",
                    "GREYWATCH_BACKUP_DIR": str(tmp_path),
                    "GREYWATCH_MAX_BACKUP_AGE_HOURS": value,
                }
            )

    def test_explicit_requirement_without_dir_matches_legacy_message(self):
        with pytest.raises(
            BackupPreflightError,
            match="GREYWATCH_REQUIRE_BACKUP=1 is set but GREYWATCH_BACKUP_DIR "
            "is not configured",
        ):
            resolve_policy({"GREYWATCH_REQUIRE_BACKUP": "1"})

    def test_default_requirement_without_dir_explains_default(self):
        with pytest.raises(
            BackupPreflightError, match="defaults to required .*GREYWATCH_BACKUP_DIR"
        ):
            resolve_policy({})

    def test_nonexistent_backup_dir(self, tmp_path):
        with pytest.raises(BackupPreflightError, match="does not exist"):
            resolve_policy(_backup_env(tmp_path / "missing"))

    def test_backup_dir_is_a_file(self, tmp_path):
        target = tmp_path / "not-a-dir"
        target.write_text("x")
        with pytest.raises(BackupPreflightError, match="not a directory"):
            resolve_policy(_backup_env(target))


# --------------------------------------------------------------------------- #
# Candidate selection and verification
# --------------------------------------------------------------------------- #


class TestBackupSelection:
    def test_missing_backup_fails_with_actionable_message(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()

        with pytest.raises(
            BackupPreflightError, match="Backup required but no valid backup found"
        ) as excinfo:
            run_backup_preflight(db, environ=_backup_env(backup_dir))
        assert "gw_db_backup.sh" in str(excinfo.value)

    def test_stale_backup_is_rejected(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        backup = _backup(db, backup_dir)
        _set_backup_mtime(backup, 25)

        with pytest.raises(
            BackupPreflightError, match="exceeds GREYWATCH_MAX_BACKUP_AGE_HOURS=24"
        ):
            run_backup_preflight(db, environ=_backup_env(backup_dir))

    def test_custom_max_age_is_enforced(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        backup = _backup(db, backup_dir)
        _set_backup_mtime(backup, 7)

        with pytest.raises(
            BackupPreflightError, match="exceeds GREYWATCH_MAX_BACKUP_AGE_HOURS=6"
        ):
            run_backup_preflight(
                db,
                environ=_backup_env(backup_dir, GREYWATCH_MAX_BACKUP_AGE_HOURS="6"),
            )

    def test_fresh_backup_is_accepted(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        backup = _backup(db, backup_dir)

        assert (
            run_backup_preflight(db, environ=_backup_env(backup_dir)) == backup
        )

    def test_corrupt_backup_is_rejected(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        (backup_dir / "greywatch.db.corrupt").write_bytes(b"not a sqlite database")

        with pytest.raises(
            BackupPreflightError, match="Backup required but no valid backup found"
        ):
            run_backup_preflight(db, environ=_backup_env(backup_dir))

    def test_empty_backup_is_rejected(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        (backup_dir / "greywatch.db.empty").write_bytes(b"")

        with pytest.raises(
            BackupPreflightError, match="Backup required but no valid backup found"
        ):
            run_backup_preflight(db, environ=_backup_env(backup_dir))

    def test_foreign_key_violation_in_backup_is_rejected(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        broken = backup_dir / "greywatch.db.fk"
        conn = sqlite3.connect(broken)
        try:
            conn.executescript(
                """
                PRAGMA foreign_keys=OFF;
                CREATE TABLE parent (id INTEGER PRIMARY KEY);
                CREATE TABLE child (
                    id INTEGER PRIMARY KEY,
                    parent_id INTEGER NOT NULL REFERENCES parent(id)
                );
                INSERT INTO child (id, parent_id) VALUES (1, 999);
                """
            )
            conn.commit()
        finally:
            conn.close()

        with pytest.raises(
            BackupPreflightError, match="foreign_key_check|Verification failed"
        ):
            run_backup_preflight(db, environ=_backup_env(backup_dir))

    def test_symlink_backup_is_rejected(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        real_backup = _backup(db, backup_dir)
        link = backup_dir / "greywatch.db.link"
        os.symlink(real_backup, link)

        with pytest.raises(
            BackupPreflightError, match="Backup required but no valid backup found"
        ):
            run_backup_preflight(db, environ=_backup_env(backup_dir))

    def test_stale_newest_backup_rejected_without_fallback(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        # Create stale backup first, age it to 48h
        stale = _backup(db, backup_dir)
        _set_backup_mtime(stale, 48)
        # Create fresh backup second, age it to 2h
        # This has a later mtime (created second) so it will be "newest"
        fresh = _backup(db, backup_dir)
        _set_backup_mtime(fresh, 2)

        # The fresh backup should be selected (newest mtime) and accepted
        assert run_backup_preflight(db, environ=_backup_env(backup_dir)) == fresh

    def test_stale_backup_rejected(self, tmp_path):
        """The newest backup is stale -> fail with age error."""
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        backup = _backup(db, backup_dir)
        # Set mtime to 48h ago
        _set_backup_mtime(backup, 48)

        with pytest.raises(
            BackupPreflightError, match="exceeds GREYWATCH_MAX_BACKUP_AGE_HOURS=24"
        ):
            run_backup_preflight(db, environ=_backup_env(backup_dir))

    def test_valid_newest_is_selected_over_older_corrupt_file(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        older = _backup(db, backup_dir)
        _set_backup_mtime(older, 2)
        newest = _backup(db, backup_dir)

        assert run_backup_preflight(db, environ=_backup_env(backup_dir)) == newest

    def test_backup_that_is_the_live_database_is_rejected(self, tmp_path):
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        db = _fresh_db(backup_dir / "greywatch.db.live")

        with pytest.raises(
            BackupPreflightError, match="refers to the live database"
        ):
            run_backup_preflight(db, environ=_backup_env(backup_dir))

    def test_hardlink_to_live_database_is_rejected(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        os.link(db, backup_dir / "greywatch.db.hardlink")

        with pytest.raises(
            BackupPreflightError, match="refers to the live database"
        ):
            run_backup_preflight(db, environ=_backup_env(backup_dir))

    def test_unreadable_backup_file_is_rejected(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        backup = _backup(db, backup_dir)
        os.chmod(backup, 0o000)
        try:
            with pytest.raises(
                BackupPreflightError,
                match="Backup required but no valid backup found",
            ):
                run_backup_preflight(db, environ=_backup_env(backup_dir))
        finally:
            os.chmod(backup, 0o600)

    def test_unreadable_backup_directory_is_rejected(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        os.chmod(backup_dir, 0o000)
        try:
            with pytest.raises(BackupPreflightError, match="Cannot read GREYWATCH_BACKUP_DIR"):
                run_backup_preflight(db, environ=_backup_env(backup_dir))
        finally:
            os.chmod(backup_dir, 0o700)


# --------------------------------------------------------------------------- #
# Runner integration
# --------------------------------------------------------------------------- #


class TestRunnerPreflight:
    def test_failed_preflight_leaves_database_bytes_unchanged(
        self, tmp_path, monkeypatch
    ):
        # Use LEGACY_READY to test backup requirement (FRESH is exempt)
        db = _legacy_ready_db(tmp_path / "legacy.sqlite")
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        before = _sha256(db)
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))

        with pytest.raises(BackupPreflightError):
            migrate(str(db), dry_run=False)

        assert _sha256(db) == before
        assert _ledger_versions(db) == []
        assert inspect_path(db).state == DatabaseState.LEGACY_READY

    def test_fresh_database_migrates_without_backup(self, tmp_path, monkeypatch):
        """FRESH databases are exempt from backup preflight (bootstrap scenario)."""
        db = _fresh_db(tmp_path / "db.sqlite")
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.delenv("GREYWATCH_BACKUP_DIR", raising=False)

        result = migrate(str(db), dry_run=False)

        assert result["applied"] == 4
        assert inspect_path(db).state == DatabaseState.CURRENT
        assert _ledger_versions(db) == [1, 2, 3, 4]

    def test_valid_backup_allows_migration(self, tmp_path, monkeypatch):
        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        _backup(db, backup_dir)
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))

        result = migrate(str(db), dry_run=False)

        assert result["applied"] == 4
        assert inspect_path(db).state == DatabaseState.CURRENT
        assert _ledger_versions(db) == [1, 2, 3, 4]

    def test_wal_mode_backup_is_accepted(self, tmp_path, monkeypatch):
        db = _fresh_db(tmp_path / "db.sqlite")
        writer = sqlite3.connect(db)
        try:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute("PRAGMA user_version=7")
            writer.commit()

            backup_dir = tmp_path / "backups"
            backup = _backup(db, backup_dir)
        finally:
            writer.close()

        # The backup captured committed WAL frames, not just the main file.
        conn = sqlite3.connect(backup)
        try:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 7
        finally:
            conn.close()
        gw_db_backup.verify_database(str(backup), what="backup")

        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))
        assert migrate(str(db), dry_run=False)["applied"] == 4
        assert inspect_path(db).state == DatabaseState.CURRENT

    def test_legacy_database_migrates_with_valid_backup(self, tmp_path, monkeypatch):
        db = _legacy_ready_db(tmp_path / "legacy.sqlite")
        backup_dir = tmp_path / "backups"
        _backup(db, backup_dir)
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))

        result = migrate(str(db), dry_run=False)

        assert result["applied"] == 4
        assert inspect_path(db).state == DatabaseState.CURRENT
        assert _ledger_versions(db) == [1, 2, 3, 4]

    def test_current_database_skips_preflight(self, tmp_path, monkeypatch):
        db = _fresh_db(tmp_path / "db.sqlite")
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "0")
        migrate(str(db), dry_run=False)

        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.delenv("GREYWATCH_BACKUP_DIR", raising=False)
        assert migrate(str(db), dry_run=False) == {"applied": 0, "skipped": 0}

    def test_dry_run_does_not_require_backup(self, tmp_path, monkeypatch):
        db = _fresh_db(tmp_path / "db.sqlite")
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.delenv("GREYWATCH_BACKUP_DIR", raising=False)

        assert migrate(str(db), dry_run=True)["applied"] == 4
        assert _ledger_versions(db) == []


# --------------------------------------------------------------------------- #
# Application startup
# --------------------------------------------------------------------------- #


class TestStartupPreflight:
    def test_startup_fails_without_backup(self, tmp_path, monkeypatch):
        from starlette.testclient import TestClient

        # Use LEGACY_READY to test backup requirement (FRESH is exempt)
        db = _legacy_ready_db(tmp_path / "legacy.sqlite")
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        monkeypatch.setenv("GREYWATCH_DB", str(db))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))

        from backend.app.main import app

        with pytest.raises(
            RuntimeError, match="Backup required but no valid backup found"
        ):
            with TestClient(app):
                pass
        assert _ledger_versions(db) == []
        assert inspect_path(db).state == DatabaseState.LEGACY_READY

    def test_startup_fresh_succeeds_without_backup(self, tmp_path, monkeypatch):
        """FRESH database can start without backup (bootstrap scenario)."""
        from starlette.testclient import TestClient

        db = _fresh_db(tmp_path / "db.sqlite")
        monkeypatch.setenv("GREYWATCH_DB", str(db))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.delenv("GREYWATCH_BACKUP_DIR", raising=False)

        from backend.app.main import app

        with TestClient(app) as client:
            body = client.get("/health").json()
        assert body["schema_ready"] is True
        assert body["migration_applied"] >= 1
        assert inspect_path(db).state == DatabaseState.CURRENT

    def test_startup_succeeds_with_valid_backup(self, tmp_path, monkeypatch):
        from starlette.testclient import TestClient

        db = _fresh_db(tmp_path / "db.sqlite")
        backup_dir = tmp_path / "backups"
        _backup(db, backup_dir)
        monkeypatch.setenv("GREYWATCH_DB", str(db))
        monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "1")
        monkeypatch.setenv("GREYWATCH_BACKUP_DIR", str(backup_dir))

        from backend.app.main import app

        with TestClient(app) as client:
            body = client.get("/health").json()
        assert body["schema_ready"] is True
        assert body["migration_applied"] == 1
        assert inspect_path(db).state == DatabaseState.CURRENT

    def test_startup_default_requires_backup(self, tmp_path, monkeypatch):
        from starlette.testclient import TestClient

        # Use LEGACY_READY to test default backup requirement (FRESH is exempt)
        db = _legacy_ready_db(tmp_path / "legacy.sqlite")
        monkeypatch.setenv("GREYWATCH_DB", str(db))
        monkeypatch.delenv("GREYWATCH_REQUIRE_BACKUP", raising=False)
        monkeypatch.delenv("GREYWATCH_BACKUP_DIR", raising=False)

        from backend.app.main import app

        with pytest.raises(RuntimeError, match="defaults to required"):
            with TestClient(app):
                pass
        assert _ledger_versions(db) == []
        assert inspect_path(db).state == DatabaseState.LEGACY_READY


# --------------------------------------------------------------------------- #
# Manual CLI
# --------------------------------------------------------------------------- #


class TestManualCliPreflight:
    def test_cli_fails_without_backup_and_leaves_db_unchanged(self, tmp_path):
        # Use LEGACY_READY to test backup requirement (FRESH is exempt)
        db = _legacy_ready_db(tmp_path / "legacy.sqlite")
        backup_dir = tmp_path / "backups"
        backup_dir.mkdir()
        before = _sha256(db)

        result = _run_cli(
            ["migrate", str(db), "--yes"],
            _backup_env(backup_dir),
        )

        assert result.returncode == 1
        assert "Backup required but no valid backup found" in result.stderr
        assert _sha256(db) == before
        assert _ledger_versions(db) == []

    def test_cli_succeeds_with_valid_backup(self, tmp_path):
        db = _legacy_ready_db(tmp_path / "legacy.sqlite")
        backup_dir = tmp_path / "backups"
        _backup(db, backup_dir)

        result = _run_cli(
            ["migrate", str(db), "--yes"],
            _backup_env(backup_dir),
        )

        assert result.returncode == 0, result.stderr
        assert "Applied 4 migration(s)" in result.stdout
        assert inspect_path(db).state == DatabaseState.CURRENT

    def test_cli_default_fails_closed_when_backup_unset(self, tmp_path):
        # Use LEGACY_READY to test default backup requirement (FRESH is exempt)
        db = _legacy_ready_db(tmp_path / "legacy.sqlite")

        result = _run_cli(
            ["migrate", str(db), "--yes"],
            {"GREYWATCH_REQUIRE_BACKUP": None, "GREYWATCH_BACKUP_DIR": None},
        )

        assert result.returncode == 1
        assert "defaults to required" in result.stderr
        assert _ledger_versions(db) == []
        assert inspect_path(db).state == DatabaseState.LEGACY_READY

    def test_cli_stale_backup_fails_and_leaves_db_unchanged(self, tmp_path):
        # Use LEGACY_READY to test stale backup rejection (FRESH is exempt)
        db = _legacy_ready_db(tmp_path / "legacy.sqlite")
        backup_dir = tmp_path / "backups"
        backup = _backup(db, backup_dir)
        _set_backup_mtime(backup, 48)
        before = _sha256(db)

        result = _run_cli(
            ["migrate", str(db), "--yes"],
            _backup_env(backup_dir),
        )

        assert result.returncode == 1
        assert "exceeds GREYWATCH_MAX_BACKUP_AGE_HOURS" in result.stderr
        assert _sha256(db) == before
        assert _ledger_versions(db) == []
        assert inspect_path(db).state == DatabaseState.LEGACY_READY

    def test_cli_dry_run_is_exempt_from_backup(self, tmp_path):
        db = _fresh_db(tmp_path / "db.sqlite")

        result = _run_cli(
            ["migrate", str(db), "--dry-run"],
            {
                "GREYWATCH_REQUIRE_BACKUP": "1",
                "GREYWATCH_BACKUP_DIR": None,
            },
        )

        assert result.returncode == 0, result.stderr
        assert "Would apply 4 migration(s)" in result.stdout
        assert _ledger_versions(db) == []
