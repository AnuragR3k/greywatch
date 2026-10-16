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
