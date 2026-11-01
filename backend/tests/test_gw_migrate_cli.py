"""End-to-end tests for the ``scripts/gw_migrate`` CLI entry point.

Every test invokes the real script in a subprocess with an explicit path to a
disposable SQLite database under ``tmp_path``.  The production database
(``data/greywatch.db``) and the configured ``GREYWATCH_DB`` are never used.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from backend.app.migration_ledger import SCHEMA_MIGRATIONS_TABLE
from backend.app.migration_schema import APP_TABLES

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "scripts" / "gw_migrate"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _run_cli(*args: object, input_text: str | None = None):
    """Run the CLI entry point and capture its real exit code and streams.

    ``input_text`` is ``None`` by default, in which case stdin is ``DEVNULL``:
    a command that unexpectedly prompts then hits EOF instead of hanging.
    """
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(REPO_ROOT) + (
        os.pathsep + existing_pythonpath if existing_pythonpath else ""
    )

    kwargs = (
        {"input": input_text}
        if input_text is not None
        else {"stdin": subprocess.DEVNULL}
    )
    return subprocess.run(
        [sys.executable, str(CLI_PATH), *(str(arg) for arg in args)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        env=env,
        timeout=60,
        **kwargs,
    )


def _make_fresh_db(path: Path) -> Path:
    """Create a valid SQLite file with no application tables (FRESH state)."""
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE __placeholder__ (id INTEGER PRIMARY KEY)")
        conn.commit()
        conn.execute("DROP TABLE __placeholder__")
        conn.commit()
    finally:
        conn.close()
    return path


def _tables(path: Path) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        return {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    finally:
        conn.close()


def _ledger_rows(path: Path) -> list[tuple[int, str]]:
    if SCHEMA_MIGRATIONS_TABLE not in _tables(path):
        return []
    conn = sqlite3.connect(path)
    try:
        return conn.execute(
            f"SELECT version, name FROM {SCHEMA_MIGRATIONS_TABLE} "
            "ORDER BY version"
        ).fetchall()
    finally:
        conn.close()


def _assert_migrated(path: Path) -> None:
    assert set(APP_TABLES) <= _tables(path)
    assert _ledger_rows(path) == [(1, "baseline")]


def _assert_unmigrated(path: Path) -> None:
    tables = _tables(path)
    assert not any(table in tables for table in APP_TABLES)
    assert SCHEMA_MIGRATIONS_TABLE not in tables


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def fresh_db(tmp_path: Path) -> Path:
    return _make_fresh_db(tmp_path / "fresh.db")


@pytest.fixture
def current_db(fresh_db: Path) -> Path:
    result = _run_cli("migrate", fresh_db, "--yes")
    assert result.returncode == 0, result.stderr
    _assert_migrated(fresh_db)
    return fresh_db


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #


def test_status_fresh_database(fresh_db: Path):
    result = _run_cli("status", fresh_db)

    assert result.returncode == 0
    assert result.stderr == ""
    assert "State: fresh" in result.stdout
    assert "Applied version: 0" in result.stdout
    assert "Latest version: 1" in result.stdout
    assert "Ledger present: no" in result.stdout


def test_status_current_database(current_db: Path):
    result = _run_cli("status", current_db)

    assert result.returncode == 0
    assert result.stderr == ""
    assert "State: current" in result.stdout
    assert "Applied version: 1" in result.stdout
    assert "Ledger present: yes" in result.stdout


def test_status_missing_database_reports_error(tmp_path: Path):
    missing = tmp_path / "does-not-exist.db"

    result = _run_cli("status", missing)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("ERROR: ")
    assert "does not exist" in result.stderr


# --------------------------------------------------------------------------- #
# plan
# --------------------------------------------------------------------------- #


def test_plan_fresh_database_lists_baseline(fresh_db: Path):
    before = fresh_db.read_bytes()

    result = _run_cli("plan", fresh_db)

    assert result.returncode == 0
    assert result.stderr == ""
    assert "Pending migrations (1):" in result.stdout
    assert "v1: baseline" in result.stdout
    # A plan preview is strictly read-only.
    assert fresh_db.read_bytes() == before
    _assert_unmigrated(fresh_db)


def test_plan_current_database_is_empty(current_db: Path):
    result = _run_cli("plan", current_db)

    assert result.returncode == 0
    assert result.stderr == ""
    assert "No pending migrations" in result.stdout


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #


def test_verify_current_database(current_db: Path):
    result = _run_cli("verify", current_db)

    assert result.returncode == 0
    assert result.stderr == ""
    assert result.stdout.startswith("OK: database at ")
    assert "is current" in result.stdout


def test_verify_not_current_fails(fresh_db: Path):
    result = _run_cli("verify", fresh_db)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("FAILED: ")
    assert "is not current" in result.stderr


def test_verify_missing_database_reports_error(tmp_path: Path):
    missing = tmp_path / "does-not-exist.db"

    result = _run_cli("verify", missing)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("ERROR: ")
    assert "does not exist" in result.stderr


# --------------------------------------------------------------------------- #
# migrate: confirmation, --yes, --dry-run
# --------------------------------------------------------------------------- #


def test_migrate_interactive_confirmation_applies(fresh_db: Path):
    result = _run_cli("migrate", fresh_db, input_text="y\n")

    assert result.returncode == 0
    assert result.stderr == ""
    assert "Apply pending migrations? [y/N]" in result.stdout
    assert "Applied 1 migration(s)" in result.stdout
    _assert_migrated(fresh_db)


def test_migrate_interactive_declined_aborts(fresh_db: Path):
    before = fresh_db.read_bytes()

    result = _run_cli("migrate", fresh_db, input_text="n\n")

    assert result.returncode == 1
    assert "Apply pending migrations? [y/N]" in result.stdout
    assert result.stderr.startswith("Aborted")
    assert "Applied" not in result.stdout
    assert fresh_db.read_bytes() == before
    _assert_unmigrated(fresh_db)


def test_migrate_interactive_eof_aborts(fresh_db: Path):
    before = fresh_db.read_bytes()

    # Empty input closes stdin immediately, so input() raises EOFError.
    result = _run_cli("migrate", fresh_db, input_text="")

    assert result.returncode == 1
    assert "Apply pending migrations? [y/N]" in result.stdout
    assert "Aborted (no confirmation)" in result.stderr
    assert fresh_db.read_bytes() == before
    _assert_unmigrated(fresh_db)


def test_migrate_yes_bypasses_confirmation_and_applies(fresh_db: Path):
    result = _run_cli("migrate", fresh_db, "--yes")

    assert result.returncode == 0
    assert result.stderr == ""
    assert "Apply pending migrations? [y/N]" not in result.stdout
    assert "Applied 1 migration(s)" in result.stdout
    _assert_migrated(fresh_db)


def test_migrate_dry_run_does_not_mutate_or_prompt(fresh_db: Path):
    before = fresh_db.read_bytes()

    result = _run_cli("migrate", fresh_db, "--dry-run")

    assert result.returncode == 0
    assert result.stderr == ""
    assert "Apply pending migrations? [y/N]" not in result.stdout
    assert "Would apply 1 migration(s)" in result.stdout
    assert fresh_db.read_bytes() == before
    _assert_unmigrated(fresh_db)


def test_migrate_yes_on_current_database_is_noop(current_db: Path):
    result = _run_cli("migrate", current_db, "--yes")

    assert result.returncode == 0
    assert result.stderr == ""
    assert "No migrations to apply" in result.stdout
    assert _ledger_rows(current_db) == [(1, "baseline")]


def test_migrate_corrupt_database_reports_error_and_does_not_write(tmp_path: Path):
    corrupt = tmp_path / "corrupt.db"
    corrupt.write_bytes(b"this is not a SQLite database\n")
    before = corrupt.read_bytes()

    result = _run_cli("migrate", corrupt, "--yes")

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.startswith("ERROR: ")
    assert "cannot access database" in result.stderr
    assert corrupt.read_bytes() == before


# --------------------------------------------------------------------------- #
# Argument parsing and invalid arguments
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ((), "the following arguments are required: command"),
        (("frobnicate",), "invalid choice"),
        (("status",), "the following arguments are required: path"),
        (
            ("migrate", "ignored.db", "--bogus"),
            "unrecognized arguments: --bogus",
        ),
    ],
)
def test_invalid_arguments_exit_2(args, expected):
    result = _run_cli(*args)

    assert result.returncode == 2
    assert result.stdout == ""
    assert "usage: gw_migrate" in result.stderr
    assert expected in result.stderr


def test_help_exits_zero():
    result = _run_cli("--help")

    assert result.returncode == 0
    assert result.stderr == ""
    assert "usage: gw_migrate" in result.stdout
    for command in ("status", "plan", "verify", "migrate"):
        assert command in result.stdout
