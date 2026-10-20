"""Regression tests for safe denial audit logging (security review F4).

These tests verify that denied requests (trust-boundary 401/403, rate-limit
429, and body-size 413) emit exactly one structured log record each, that the
record never contains credentials/cookies/bodies/query strings, that client
forwarding headers cannot spoof the logged peer, that successful requests are
silent, and that a logging failure never lets a denied request through.

The implementation lives in ``backend/app/main.py``:
``_log_denied_request`` (best-effort, swallows logging errors) and its call
sites in ``_trust_boundary``, ``RateLimitMiddleware``, and
``MaxBodySizeMiddleware``.

Logs are captured from the ``greywatch.api`` logger via pytest's ``caplog``
fixture, following the convention used by ``test_collector.py`` and
``test_suricata.py`` (``caplog.at_level(level, logger="...")``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import anyio
import pytest
from backend.app import main
from backend.app.collector import CollectResult
from backend.app.main import (
    MaxBodySizeMiddleware,
    RateLimitConfig,
    RateLimitMiddleware,
    _client_peer,
)
from backend.app.main import (
    app as base_app,
)
from fastapi.testclient import TestClient

logger = logging.getLogger("greywatch.api")


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def _local_env(monkeypatch):
    """Default local deployment: no token; loopback enforcement on."""
    monkeypatch.delenv("GREYWATCH_API_TOKEN", raising=False)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "1")
    yield


@pytest.fixture
def _token_env(monkeypatch):
    """Network-exposed deployment: a shared-secret token is configured."""
    TOKEN = "test-secret-token-123"
    monkeypatch.setenv("GREYWATCH_API_TOKEN", TOKEN)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "1")
    yield


@pytest.fixture
def _stub_backends(monkeypatch):
    """Decouple gate tests from collector/journal/insert internals."""
    monkeypatch.setattr(
        main,
        "ingest_lines",
        lambda lines, event_ids=None: {
            "received": len(lines),
            "parsed": 0,
            "ignored": len(lines),
            "events": [],
            "alerts": [],
        },
    )
    monkeypatch.setattr(main.collector, "collect_once", lambda config: CollectResult())
    monkeypatch.setattr(main.suricata, "collect_once", lambda config: CollectResult())
    monkeypatch.setattr(main, "close_alert", lambda alert_id: True)
    monkeypatch.setattr(main, "list_events", lambda limit=100: [{"x": 1}])
    monkeypatch.setattr(
        main, "list_alerts", lambda status="open", limit=100: [{"x": 1}]
    )
    monkeypatch.setattr(
        main, "get_alert_detail", lambda alert_id: {"alert": {"id": alert_id}}
    )
    monkeypatch.setattr(main.collector, "status", lambda: {"enabled": False})
    monkeypatch.setattr(main.suricata, "status", lambda: {"enabled": False})


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _denial_records(caplog):
    """Return captured records that are denial log records."""
    return [r for r in caplog.records if getattr(r, "event", None) == "request_denied"]


@dataclass
class FakeClock:
    """Injectable monotonic clock advanced manually by tests."""

    value: float = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def _run_middleware(middleware, scope, receive):
    """Run an ASGI middleware and return the sent messages."""
    sent = []

    async def send(message):
        sent.append(message)

    async def run():
        await middleware(scope, receive, send)
        return sent

    return anyio.run(run)


def _request_receive(body=b"", more_body=False):
    """Build an ASGI receive callable returning a single http.request message."""

    async def receive():
        return {"type": "http.request", "body": body, "more_body": more_body}

    return receive


def _dummy_app(status=200, body=b'{"ok": true}'):
    """Minimal ASGI app that returns a fixed response."""

    async def app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [[b"content-type", b"application/json"]],
            }
        )
        await send({"type": "http.response.body", "body": body})

    return app


def _http_scope(
    method="GET",
    path="/api/v1/events",
    client=("203.0.113.5", 54321),
    headers=None,
    query_string=b"",
):
    """Build a minimal ASGI http scope with a real remote peer."""
    return {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": query_string,
        "headers": headers or [],
        "client": client,
    }


# --------------------------------------------------------------------------- #
# Trust-boundary denials (global app)
# --------------------------------------------------------------------------- #


def test_remote_trust_boundary_rejection_logged(_local_env, caplog, monkeypatch):
    """A remote peer rejected by the trust boundary produces a log record."""
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: False)
    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        client = TestClient(base_app)
        resp = client.get("/api/v1/events")
    assert resp.status_code == 403
    records = _denial_records(caplog)
    assert len(records) == 1, records
    rec = records[0]
    assert rec.reason == "remote_peer_not_allowed"
    assert rec.status == 403
    assert rec.method == "GET"
    assert rec.path == "/api/v1/events"


def test_missing_or_invalid_token_rejection_logged(_token_env, caplog):
    """Missing/invalid token rejection (401) produces a log record."""
    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        client = TestClient(base_app)
        resp = client.get("/api/v1/events")
    assert resp.status_code == 401
    records = _denial_records(caplog)
    assert len(records) == 1, records
    rec = records[0]
    assert rec.reason == "authentication_required"
    assert rec.status == 401


# --------------------------------------------------------------------------- #
# Rate-limit denials (fresh middleware, injectable clock)
# --------------------------------------------------------------------------- #


def test_rate_limit_429_logged(tmp_path, monkeypatch, caplog):
    """A rate-limited request (HTTP 429) produces a log record."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "ratelog.db"))
    from backend.app.siem import initialize_database

    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(
        ingestion=1, reads=1, collector=1, alert_close=1, burst_multiplier=1
    )
    middleware = RateLimitMiddleware(_dummy_app(), config=cfg, clock=clock)
    scope = _http_scope(method="POST", path="/api/v1/events/ingest")

    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        _run_middleware(middleware, scope, _request_receive())  # consume token
        messages = _run_middleware(middleware, scope, _request_receive())  # denied

    assert messages[0]["status"] == 429
    records = _denial_records(caplog)
    assert len(records) == 1, records
    rec = records[0]
    assert rec.reason == "rate_limit_exceeded"
    assert rec.status == 429
    assert rec.method == "POST"
    assert rec.path == "/api/v1/events/ingest"
    assert rec.peer == "203.0.113.5"


# --------------------------------------------------------------------------- #
# Body-size denials (fresh middleware)
# --------------------------------------------------------------------------- #


def test_body_size_413_logged(tmp_path, monkeypatch, caplog):
    """An oversized request (HTTP 413) produces a log record."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "bodylog.db"))
    from backend.app.siem import initialize_database

    initialize_database()
    middleware = MaxBodySizeMiddleware(_dummy_app(), max_bytes=100)
    scope = _http_scope(method="POST", path="/api/v1/events/ingest")

    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        messages = _run_middleware(
            middleware, scope, _request_receive(body=b"x" * 101, more_body=False)
        )

    assert messages[0]["status"] == 413
    records = _denial_records(caplog)
    assert len(records) == 1, records
    rec = records[0]
    assert rec.reason == "request_body_too_large"
    assert rec.status == 413
    assert rec.method == "POST"
    assert rec.path == "/api/v1/events/ingest"


# --------------------------------------------------------------------------- #
# Credential / sensitive data exclusion
# --------------------------------------------------------------------------- #


def test_denial_record_excludes_credentials_and_body(caplog, monkeypatch):
    """Denial records never log tokens, cookies, bodies, or sensitive headers."""
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: False)
    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        client = TestClient(base_app)
        client.get(
            "/api/v1/events",
            headers={
                "Authorization": "Bearer secret-token-value",
                "X-API-Key": "api-key-value",
                "Cookie": "sessionid=abc123; csrftoken=xyz",
            },
        )
    records = _denial_records(caplog)
    assert len(records) == 1, records
    rec = records[0]
    combined = " ".join(
        str(getattr(rec, k, ""))
        for k in ("event", "reason", "method", "path", "status", "peer")
    )
    combined += " " + rec.getMessage()
    assert "secret-token-value" not in combined
    assert "api-key-value" not in combined
    assert "sessionid" not in combined
    assert "csrftoken" not in combined
    assert "abc123" not in combined
    assert "xyz" not in combined
    assert "Bearer" not in combined


def test_denial_record_excludes_query_string(caplog, monkeypatch):
    """Logged paths never include query strings (they may hold sensitive values)."""
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: False)
    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        client = TestClient(base_app)
        client.get("/api/v1/events?secret=leak-me&token=also-leak")
    records = _denial_records(caplog)
    assert len(records) == 1, records
    rec = records[0]
    assert "?" not in rec.path, rec.path
    assert "secret=leak-me" not in rec.path
    assert "token=also-leak" not in rec.path
    assert rec.path == "/api/v1/events"


# --------------------------------------------------------------------------- #
# Forwarding-header spoofing
# --------------------------------------------------------------------------- #


def test_forwarding_headers_cannot_spoof_logged_peer(caplog, monkeypatch):
    """X-Forwarded-For etc. are never used to identify the logged peer."""
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: False)
    forged = {
        "X-Forwarded-For": "127.0.0.1, 127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "Forwarded": 'for=127.0.0.1:5312, for="[::1]:5312"',
    }
    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        client = TestClient(base_app)
        resp = client.get("/api/v1/events", headers=forged)
    assert resp.status_code == 403
    records = _denial_records(caplog)
    assert len(records) == 1, records
    # The logged peer must not be the forged loopback address.
    rec = records[0]
    assert rec.peer != "127.0.0.1", rec.peer
    # _client_peer never consults forwarding headers.
    scope = _http_scope(
        headers=[(b"x-forwarded-for", b"127.0.0.1"), (b"x-real-ip", b"127.0.0.1")]
    )
    assert _client_peer(scope) == "203.0.113.5"


# --------------------------------------------------------------------------- #
# Successful requests are silent
# --------------------------------------------------------------------------- #


def test_successful_requests_do_not_produce_denial_records(
    _local_env, caplog, _stub_backends, monkeypatch
):
    """Allowed requests never emit denial log records."""
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: True)
    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        client = TestClient(base_app)
        client.get("/api/v1/events")
        client.get("/health")
        client.post("/api/v1/events/ingest", json={"lines": ["x"]})
    assert _denial_records(caplog) == []


# --------------------------------------------------------------------------- #
# Logging failure stays fail-closed
# --------------------------------------------------------------------------- #


def test_logging_failure_does_not_allow_rejected_request(caplog, monkeypatch):
    """A logging failure never turns a denial into an allowed response."""
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: False)

    def _boom(*args, **kwargs):
        raise RuntimeError("logging is broken")

    monkeypatch.setattr(logger, "info", _boom)

    client = TestClient(base_app)
    # The denial must still be enforced even though logging raises internally.
    resp = client.get("/api/v1/events")
    assert resp.status_code == 403
    assert "local host" in resp.json()["detail"]


# --------------------------------------------------------------------------- #
# One record per denial
# --------------------------------------------------------------------------- #


def test_each_denial_logged_exactly_once(caplog, monkeypatch):
    """A single denial produces exactly one log record, not one per layer."""
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: False)
    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        client = TestClient(base_app)
        resp = client.get("/api/v1/events")
    assert resp.status_code == 403
    records = _denial_records(caplog)
    assert len(records) == 1, records


def test_rate_limit_one_record_per_denial(tmp_path, monkeypatch, caplog):
    """A single rate-limit denial produces exactly one log record."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "onerate.db"))
    from backend.app.siem import initialize_database

    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(
        ingestion=1, reads=1, collector=1, alert_close=1, burst_multiplier=1
    )
    middleware = RateLimitMiddleware(_dummy_app(), config=cfg, clock=clock)
    scope = _http_scope(method="GET", path="/api/v1/events")

    with caplog.at_level(logging.INFO, logger="greywatch.api"):
        _run_middleware(middleware, scope, _request_receive())  # consume token
        messages = _run_middleware(middleware, scope, _request_receive())  # denied

    assert messages[0]["status"] == 429
    records = _denial_records(caplog)
    assert len(records) == 1, records


# --------------------------------------------------------------------------- #
# Peer resolution sanity (never forwarding headers)
# --------------------------------------------------------------------------- #


def test_client_peer_uses_asgi_client_not_forwarding_headers():
    """_client_peer reads only the ASGI scope client address."""
    scope = _http_scope(
        headers=[(b"x-forwarded-for", b"10.0.0.1"), (b"x-real-ip", b"10.0.0.1")]
    )
    assert _client_peer(scope) == "203.0.113.5"

    scope_no_client = dict(_http_scope())
    scope_no_client.pop("client")
    assert _client_peer(scope_no_client) == "unknown"
