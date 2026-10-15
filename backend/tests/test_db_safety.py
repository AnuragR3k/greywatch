"""Regression tests for the database-safety guard.

These verify that automated tests can never silently use the production database
``data/greywatch.db``:

* an unset ``GREYWATCH_DB`` is redirected to an isolated temp database; and
* an explicit production path is refused with a clear, loud failure.

They do **not** touch the real production database. See
``backend/tests/conftest.py`` and ``siem.is_production_db_path``.
"""

import os
import subprocess
import sys
from pathlib import Path

from backend.app.siem import DEFAULT_DB_PATH, is_production_db_path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_is_production_db_path_recognises_default(tmp_path):
    """The detector flags the production path (str or Path) and clears a temp path."""
    assert is_production_db_path(DEFAULT_DB_PATH) is True
    assert is_production_db_path(str(DEFAULT_DB_PATH)) is True
    assert is_production_db_path(tmp_path / "test.db") is False
    assert is_production_db_path("/nope/test.db") is False


def test_conftest_redirects_unset_db_to_a_temp_path():
    """A test that does not set GREYWATCH_DB gets an isolated temp database.

    The autouse ``_isolate_test_database`` fixture in conftest.py has already
    set ``GREYWATCH_DB`` (this test does not request the ``_db`` fixture), and
    it must not be the production path.
    """
    env_db = os.environ.get("GREYWATCH_DB")
    assert env_db is not None  # conftest redirected the unset default
    assert not is_production_db_path(env_db)


def test_explicit_production_db_is_refused(tmp_path):
    """A test configured to use the production database must fail loudly, not run.

    Runs a real (existing) test under a subprocess pytest with ``GREYWATCH_DB``
    pointed at the production database, and asserts the safety guard fails it
    with a clear message rather than touching the database.
    """
    target = (
        "backend/tests/test_db_safety.py::"
        "test_is_production_db_path_recognises_default"
    )
    env = dict(os.environ)
    env["GREYWATCH_DB"] = str(DEFAULT_DB_PATH)
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest", target,
            "-q", "--no-header", "-p", "no:cacheprovider", "-o",
            "addopts=",
        ],
        env=env,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    combined = (result.stdout + result.stderr).lower()
    assert result.returncode != 0, f"guard did not refuse prod DB:\n{combined}"
    assert "production database" in combined
