"""Pytest database-safety guard for the Greywatch test suite.

This fixture exists because ``siem._connection()`` falls back to the default
production database (``data/greywatch.db``) when the ``GREYWATCH_DB`` environment
variable is unset. A test that touches the database without setting
``GREYWATCH_DB`` would therefore silently read/write production data — which is
exactly how the Day-5 schema-migration incident on ``data/greywatch.db`` began.

The guard is **test-only** (it lives in the test tree and is inactive for the
running application), so normal local application startup — which intentionally
uses the production database — is unaffected. It implements two policies:

* **Unset ``GREYWATCH_DB`` → redirect to a temp database.** Tests that do not
  set ``GREYWATCH_DB`` themselves get an isolated temp database, so they can
  never fall back to production.
* **Explicit production path → fail loudly.** If ``GREYWATCH_DB`` is pointed at
  the production database, the test fails immediately with a clear message
  instead of using it.

Tests that want a specific database set ``GREYWATCH_DB`` themselves (e.g. the
``_db`` fixture with a path under ``tmp_path``); this guard only handles the
unset and explicit-production cases, so it never fights an intentional
temp-DB override.
"""

from __future__ import annotations

import os

import pytest

from backend.app.siem import DEFAULT_DB_PATH, is_production_db_path


@pytest.fixture(autouse=True)
def _disable_rate_limit_for_global_app(monkeypatch):
    """Disable rate limiting on the shared global app for existing tests.

    The global FastAPI app registers a single ``RateLimitMiddleware`` whose
    bucket store is shared across every ``TestClient(app)`` test in the
    session. Existing tests are not rate-limit tests; disabling here prevents
    cross-test token depletion and order-dependent 429 flakiness. The new
    rate-limiter tests construct fresh middleware instances with explicit
    config and are unaffected (explicit config takes precedence over env).
    """
    monkeypatch.setenv("GREYWATCH_RATE_LIMIT_ENABLED", "0")


@pytest.fixture(autouse=True)
def _disable_preauth_rate_limit_for_global_app(monkeypatch):
    """Disable the shared app's pre-auth agent-key limiter for existing tests.

    ``PreAuthAgentRateLimitMiddleware`` is registered once on the global app
    and keeps process-wide bucket state. Existing tests are not pre-auth
    limiter tests; disabling here prevents cross-test token depletion and
    order-dependent 429 flakiness. The dedicated pre-auth tests construct
    fresh middleware instances (or re-enable the limiter explicitly) and are
    unaffected because an explicit config or test-local env value wins.
    """
    monkeypatch.setenv("GREYWATCH_PREAUTH_RATE_LIMIT_ENABLED", "0")


@pytest.fixture(autouse=True)
def _disable_backup_preflight_for_disposable_databases(monkeypatch):
    """Opt existing tests out of the production backup gate.

    The suite routinely migrates throwaway databases under ``tmp_path`` that
    have no backup directory.  The production default requires a verified
    backup, so tests opt out explicitly here; the M4 backup-preflight tests set
    ``GREYWATCH_REQUIRE_BACKUP=1`` (or delete it to exercise the default) and
    provide their own backups.
    """
    monkeypatch.setenv("GREYWATCH_REQUIRE_BACKUP", "0")


@pytest.fixture(autouse=True)
def _isolate_test_database(tmp_path, monkeypatch):
    """Redirect unset ``GREYWATCH_DB`` to a temp DB; refuse an explicit prod path."""
    env_db = os.environ.get("GREYWATCH_DB")
    if env_db:
        if is_production_db_path(env_db):
            pytest.fail(
                "Refusing to run a test against the production database "
                f"({DEFAULT_DB_PATH}). Set GREYWATCH_DB to a temporary path, "
                "e.g. `GREYWATCH_DB=$(mktemp -u /tmp/test-XXXX.db) pytest`.",
                pytrace=False,
            )
        # Already pointed at a non-production database by the test — leave it.
    else:
        monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "test.db"))


@pytest.fixture(autouse=True)
def isolate_schema_guard(monkeypatch):
    """Isolate the process-wide schema guard for each test.

    The guard in siem._SCHEMA_MANAGED_BY_RUNNER is process-wide and persists
    across TestClient instances. This fixture resets it via monkeypatch so
    each test gets a clean state.
    """
    import backend.app.siem as siem_module
    monkeypatch.setattr(siem_module, "_SCHEMA_MANAGED_BY_RUNNER", False, raising=False)


@pytest.fixture
def api_client(tmp_path):
    """Create a TestClient with an isolated temporary database.

    This fixture sets GREYWATCH_DB to a unique temp path, creates a TestClient
    (which runs the FastAPI lifespan to initialize the schema), and yields it.
    Each test gets a completely isolated database.
    """
    import os
    from backend.app.main import app
    from starlette.testclient import TestClient

    db_path = str(tmp_path / "test.db")
    os.environ["GREYWATCH_DB"] = db_path
    with TestClient(app) as client:
        yield client
