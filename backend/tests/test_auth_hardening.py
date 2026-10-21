"""Regression tests for authentication hardening (security review F6).

These tests verify that:
* API tokens never leak into API responses, denial log records, or status outputs.
* ``get_api_token()`` provides a single point of truth for the configured token,
  used by both the trust boundary and the rate limiter.
* Edge cases (empty, whitespace-only, missing token) fail safely.

Logs are captured from the ``greywatch.api`` logger via pytest's ``caplog``
fixture, following the convention used by ``test_collector.py`` and
``test_suricata.py`` (``caplog.at_level(level, logger="...")``).
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from backend.app.main import (
    app as base_app,
)
from backend.app.main import (
    get_api_token,
)

logger = logging.getLogger("greywatch.api")

TOKEN = "test-secret-token-123"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def _token_env(monkeypatch):
    """Network-exposed deployment: a shared-secret token is configured."""
    monkeypatch.setenv("GREYWATCH_API_TOKEN", TOKEN)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "1")
    yield


@pytest.fixture
def _no_token_env(monkeypatch):
    """No token configured: loopback mode."""
    monkeypatch.delenv("GREYWATCH_API_TOKEN", raising=False)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "1")
    yield


def _denial_records(caplog):
    """Return captured records that are denial log records."""
    return [r for r in caplog.records if getattr(r, "event", None) == "request_denied"]


# --------------------------------------------------------------------------- #
# get_api_token() centralization
# --------------------------------------------------------------------------- #


def test_get_api_token_returns_configured_token(monkeypatch):
    """get_api_token() returns the raw configured token value."""
    monkeypatch.setenv("GREYWATCH_API_TOKEN", TOKEN)
    assert get_api_token() == TOKEN


def test_get_api_token_returns_none_when_unset(monkeypatch):
    """get_api_token() returns None when the token is unset."""
    monkeypatch.delenv("GREYWATCH_API_TOKEN", raising=False)
    assert get_api_token() is None


def test_get_api_token_returns_none_when_empty(monkeypatch):
    """get_api_token() returns None when the token is an empty string."""
    monkeypatch.setenv("GREYWATCH_API_TOKEN", "")
    assert get_api_token() is None


def test_get_api_token_returns_whitespace_token_as_is(monkeypatch):
    """get_api_token() returns the whitespace-only token as-is (fail-closed).

    A whitespace-only token is truthy and enables token mode; no caller can
    ever authenticate against it because the Bearer path strips whitespace
    from the provided value before comparison. This is the safe outcome.
    """
    monkeypatch.setenv("GREYWATCH_API_TOKEN", "   ")
    assert get_api_token() == "   "


# --------------------------------------------------------------------------- #
# Token non-disclosure in API responses
# --------------------------------------------------------------------------- #


def test_token_not_in_401_error_response(_token_env, caplog):
    """A 401 response body must not contain the configured token."""
    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        client = TestClient(base_app)
        resp = client.get(
            "/api/v1/events",
            headers={"Authorization": f"Bearer {TOKEN}WRONG"},
        )
    assert resp.status_code == 401
    body = resp.json()
    assert TOKEN not in str(body)
    assert TOKEN not in resp.text


def test_token_not_in_401_error_response_api_key(_token_env, caplog):
    """A 401 response body must not contain the token when sent via X-API-Key."""
    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        client = TestClient(base_app)
        resp = client.get("/api/v1/events", headers={"X-API-Key": TOKEN + "wrong"})
    assert resp.status_code == 401
    body = resp.json()
    assert TOKEN not in str(body)
    assert TOKEN not in resp.text


def test_token_not_in_status_response(_token_env, caplog):
    """Collector status responses must not contain the configured token."""
    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        client = TestClient(base_app)
        resp = client.get(
            "/api/v1/suricata/status",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert TOKEN not in str(body)
    assert TOKEN not in resp.text


# --------------------------------------------------------------------------- #
# Token non-disclosure in denial log records
# --------------------------------------------------------------------------- #


def test_token_not_in_denial_log_records(_token_env, caplog):
    """Denial log records must not contain the configured token."""
    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        client = TestClient(base_app)
        # Invalid token value that contains the real token as a substring.
        resp = client.get(
            "/api/v1/events",
            headers={"Authorization": f"Bearer {TOKEN}WRONG"},
        )
    assert resp.status_code == 401
    records = _denial_records(caplog)
    assert records, "expected a denial log record"
    for rec in records:
        combined = " ".join(
            str(getattr(rec, k, ""))
            for k in ("event", "reason", "method", "path", "status", "peer")
        )
        combined += " " + rec.getMessage()
        assert TOKEN not in combined, f"token leaked in denial record: {rec}"


# --------------------------------------------------------------------------- #
# Single point of truth: trust boundary and rate limiter agree
# --------------------------------------------------------------------------- #


def test_trust_boundary_and_rate_limiter_use_same_token(monkeypatch):
    """get_api_token() is the single source for both auth and rate-limit identity.

    When the token is set, both the trust boundary (401 on missing creds) and
    the rate limiter (token-keyed bucket) derive from the same value.
    """
    monkeypatch.setenv("GREYWATCH_API_TOKEN", TOKEN)
    monkeypatch.delenv("GREYWATCH_RATE_LIMIT_ENABLED", raising=False)

    token = get_api_token()
    assert token == TOKEN

    # Trust boundary enforces auth in token mode.
    from backend.app.main import _check_trust_boundary

    class _FakeRequest:
        class _Client:
            host = "testclient"

        def __init__(self):
            self.client = self._Client()
            self.headers = {}
            self.url = type("url", (), {"path": "/api/v1/events"})()

    req = _FakeRequest()
    result = _check_trust_boundary(req)
    assert result == (401, "Authentication required")

    # Rate limiter derives its key from the token value.
    from backend.app.main import RateLimitMiddleware

    middleware = RateLimitMiddleware(lambda s, r, snd: None)
    scope = {"type": "http", "client": ("127.0.0.1", 54321), "headers": []}
    key = middleware._client_key(scope)
    assert key == ("token", TOKEN)


# --------------------------------------------------------------------------- #
# Empty token falls back to loopback (fail-safe configuration)
# --------------------------------------------------------------------------- #


def test_empty_token_falls_back_to_loopback(_no_token_env):
    """With no token configured, the trust boundary applies loopback enforcement."""
    from backend.app.main import _check_trust_boundary

    class _FakeRequest:
        class _Client:
            host = "testclient"

        def __init__(self):
            self.client = self._Client()
            self.headers = {}
            self.url = type("url", (), {"path": "/api/v1/events"})()

    req = _FakeRequest()
    assert _check_trust_boundary(req) is None


def test_get_api_token_none_when_no_token(_no_token_env):
    """get_api_token() returns None when no token is configured."""
    assert get_api_token() is None


# --------------------------------------------------------------------------- #
# Non-ASCII credentials must fail closed (401), never raise (500)
# --------------------------------------------------------------------------- #


def test_non_ascii_bearer_token_returns_401_not_500(_token_env):
    """A non-ASCII Authorization value is denied with 401, not 500.

    Regression guard: ``hmac.compare_digest`` raises ``TypeError`` on
    non-ASCII ``str`` input and HTTP header bytes decode as latin-1, so a
    crafted header previously turned a denied request into an unhandled 500.
    """
    client = TestClient(base_app)
    resp = client.get(
        "/api/v1/events", headers=[(b"authorization", b"Bearer \xe9bad")]
    )
    assert resp.status_code == 401


def test_non_ascii_api_key_returns_401_not_500(_token_env):
    """A non-ASCII X-API-Key value is denied with 401, not 500."""
    client = TestClient(base_app)
    resp = client.get("/api/v1/events", headers=[(b"x-api-key", b"\xe9bad")])
    assert resp.status_code == 401


def test_non_ascii_configured_token_matches_at_boundary(monkeypatch):
    """A non-ASCII configured token still compares correctly at the boundary.

    Exercised directly against ``_check_trust_boundary`` (httpx re-encodes
    non-ASCII byte headers, so the transport layer cannot carry the exact byte
    sequence): a mismatch fails closed, an exact match is allowed, and neither
    raises.
    """
    monkeypatch.setenv("GREYWATCH_API_TOKEN", "s\xe9cret")
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "1")

    from backend.app.main import _check_trust_boundary

    class _FakeRequest:
        class _Client:
            host = "testclient"

        def __init__(self, headers):
            self.client = self._Client()
            self.headers = headers
            self.url = type("url", (), {"path": "/api/v1/events"})()

    # No credentials and a wrong non-ASCII credential both fail closed.
    assert _check_trust_boundary(_FakeRequest({})) == (401, "Authentication required")
    assert _check_trust_boundary(
        _FakeRequest({"Authorization": "Bearer wr\xf6ng"})
    ) == (401, "Authentication required")
    # Exact match is allowed (returns None).
    assert _check_trust_boundary(
        _FakeRequest({"Authorization": "Bearer s\xe9cret"})
    ) is None
    assert _check_trust_boundary(_FakeRequest({"X-API-Key": "s\xe9cret"})) is None
