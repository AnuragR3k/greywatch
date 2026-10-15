"""Regression tests for the Greywatch API trust boundary (PR #3, finding #1).

The ``_trust_boundary`` HTTP middleware in ``backend/app/main.py`` gates
**every endpoint except ``/`` and ``/health``**, uniformly for reads and writes,
in two modes:

  * Default (no ``GREYWATCH_API_TOKEN``): loopback peers allowed; remote or
    unknown peers -> 403. The peer is the ASGI connection
    (``request.client.host``); forwarding headers are NOT consulted, so they
    cannot spoof loopback.
  * Token (``GREYWATCH_API_TOKEN`` set): a valid ``Authorization: Bearer`` or
    ``X-API-Key`` header (constant-time ``hmac.compare_digest``) is required
    for any non-public endpoint; anything else -> 401.

A denied request is short-circuited by the middleware, so failed auth never
invokes a collection / ingest / read backend.

These tests are hermetic: the database is a per-test temp file via the conftest
autouse guard, and env vars are set via ``monkeypatch``. ``data/greywatch.db`` is
never opened (``GREYWATCH_DB`` is left unset so the guard redirects it to a temp
path).
"""

import pytest
from fastapi.testclient import TestClient

from backend.app import main
from backend.app.collector import CollectResult
from backend.app.main import app

client = TestClient(app)

TOKEN = "test-secret-token-123"

# (label, method, path, json_body) for every protected (non-public) endpoint,
# covering writes/mutations AND the read endpoints that expose raw_message /
# alert evidence -- reads must be protected too (PR #3 finding #1).
SENSITIVE = [
    ("events-ingest", "POST", "/api/v1/events/ingest", {"lines": ["x"]}),
    ("journal-collect", "POST", "/api/v1/journal/collect", None),
    ("suricata-collect", "POST", "/api/v1/suricata/collect", None),
    ("alert-close", "POST", "/api/v1/alerts/1/close", None),
    ("events-read", "GET", "/api/v1/events", None),
    ("alerts-read", "GET", "/api/v1/alerts", None),
    ("alert-detail-read", "GET", "/api/v1/alerts/1", None),
    ("journal-status", "GET", "/api/v1/journal/status", None),
    ("suricata-status", "GET", "/api/v1/suricata/status", None),
]

# Exempt (public) paths: never gated, even in token mode.
PUBLIC = ["/", "/health"]


def _request(method, path, body=None, headers=None):
    """Issue a request with the correct verb (some protected endpoints are GET)."""
    headers = headers or {}
    if method == "GET":
        return client.get(path, headers=headers)
    return client.post(path, json=body, headers=headers)


@pytest.fixture
def _stub_backends(monkeypatch):
    """Decouple gate tests from collector/journal/insert internals.

    The gate runs before the handler; stubbing the backends keeps every test
    deterministic (no journalctl / EVE file / DB state in the asserts).
    """
    monkeypatch.setattr(
        main,
        "ingest_lines",
        lambda lines: {
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
    # read backends
    monkeypatch.setattr(main, "list_events", lambda limit=100: [{"x": 1}])
    monkeypatch.setattr(
        main, "list_alerts", lambda status="open", limit=100: [{"x": 1}]
    )
    monkeypatch.setattr(
        main, "get_alert_detail", lambda alert_id: {"alert": {"id": alert_id}}
    )
    monkeypatch.setattr(main.collector, "status", lambda: {"enabled": False})
    monkeypatch.setattr(main.suricata, "status", lambda: {"enabled": False})


@pytest.fixture
def _local_env(monkeypatch):
    """Default local deployment: no token; loopback enforcement on."""
    monkeypatch.delenv("GREYWATCH_API_TOKEN", raising=False)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "1")
    yield


@pytest.fixture
def _token_env(monkeypatch):
    """Network-exposed deployment: a shared-secret token is configured."""
    monkeypatch.setenv("GREYWATCH_API_TOKEN", TOKEN)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "1")
    yield


# --------------------------------------------------------------------------- #
# Public endpoints: never gated (even in token mode)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("path", PUBLIC)
def test_public_endpoints_never_gated(_token_env, path):
    """``/`` and ``/health`` remain reachable without auth (boot checks)."""
    assert client.get(path).status_code == 200, path


# --------------------------------------------------------------------------- #
# Default local mode (no token): loopback-only -- reads included
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("label,method,path,body", SENSITIVE)
def test_local_loopback_peer_allowed(
    _local_env, _stub_backends, label, method, path, body
):
    """A local peer is allowed on every protected endpoint (reads + writes).

    Starlette's TestClient advertises peer host ``"testclient"``, which
    ``_is_loopback_host`` treats as local; so default local access is allowed.
    """
    assert _request(method, path, body).status_code == 200, label


@pytest.mark.parametrize("label,method,path,body", SENSITIVE)
def test_remote_peer_rejected_default_mode(
    _local_env, _stub_backends, monkeypatch, label, method, path, body
):
    """A non-loopback peer (remote) is denied on EVERY protected endpoint.

    This is the core of PR #3 finding #1: reads -- which expose raw_message
    and alert evidence -- are now protected, not just writes.
    """
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: False)
    resp = _request(method, path, body)
    assert resp.status_code == 403, (label, resp.status_code, resp.text)
    assert "local host" in resp.json()["detail"]


def test_loopback_only_disabled_bypasses_gate(_local_env, monkeypatch, _stub_backends):
    """``GREYWATCH_API_LOOPBACK_ONLY=0`` disables the loopback gate for proxied
    deployments; the proxy is then responsible for access control."""
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: False)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "0")
    assert client.post("/api/v1/suricata/collect").status_code == 200


# --------------------------------------------------------------------------- #
# Token mode (network-exposed): all protected endpoints, reads included
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("label,method,path,body", SENSITIVE)
def test_token_mode_missing_or_invalid_rejected(
    _token_env, _stub_backends, label, method, path, body
):
    """With a token configured, missing/invalid credentials -> 401."""
    assert _request(method, path, body).status_code == 401, label
    assert _request(method, path, body, headers={"Authorization": "Bearer wrong"}).status_code == 401, label
    assert _request(method, path, body, headers={"X-API-Key": "wrong"}).status_code == 401, label


@pytest.mark.parametrize("label,method,path,body", SENSITIVE)
def test_token_mode_valid_authenticates(
    _token_env, _stub_backends, label, method, path, body
):
    """A valid bearer token or API key authenticates the request -> 200."""
    assert _request(
        method, path, body, headers={"Authorization": f"Bearer {TOKEN}"}
    ).status_code == 200, label
    assert _request(
        method, path, body, headers={"X-API-Key": TOKEN}
    ).status_code == 200, label


def test_token_mode_backends_not_invoked_on_missing_token(_token_env, monkeypatch):
    """A 401 short-circuits before any collection/ingest/read work runs (no side
    effects on failed auth)."""

    def _explode(*args, **kwargs):
        raise AssertionError("backend must not be invoked when auth fails")

    monkeypatch.setattr(main, "ingest_lines", _explode)
    monkeypatch.setattr(main.collector, "collect_once", _explode)
    monkeypatch.setattr(main.suricata, "collect_once", _explode)
    monkeypatch.setattr(main, "close_alert", _explode)
    monkeypatch.setattr(main, "list_events", _explode)
    monkeypatch.setattr(main, "list_alerts", _explode)
    monkeypatch.setattr(main, "get_alert_detail", _explode)
    monkeypatch.setattr(main.collector, "status", _explode)
    monkeypatch.setattr(main.suricata, "status", _explode)
    resp = client.post("/api/v1/events/ingest", json={"lines": ["x"]})
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# Forwarding-header spoofing cannot bypass the loopback gate
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("label,method,path,body", SENSITIVE)
def test_forwarding_headers_cannot_spoof_loopback(
    _local_env, monkeypatch, label, method, path, body
):
    """``X-Forwarded-For`` / ``X-Real-IP`` / ``Forwarded`` are never read by the
    gate, so a forged loopback address in those headers cannot bypass a real
    remote peer. The peer is simulated as non-loopback by patching the
    peer-check helper (TestClient always advertises a local / "testclient"
    peer, so we cannot forge a remote ASGI client from the test transport)."""
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: False)
    forged = {
        "X-Forwarded-For": "127.0.0.1, 127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "Forwarded": 'for=127.0.0.1:5312, for="[::1]:5312"',
    }
    assert _request(method, path, body, headers=forged).status_code == 403, label


# --------------------------------------------------------------------------- #
# Empty / whitespace token handling (fail-closed)
# --------------------------------------------------------------------------- #


def test_empty_token_falls_back_to_loopback(_local_env, monkeypatch, _stub_backends):
    """``GREYATCH_API_TOKEN=''`` is falsy -> token mode OFF -> loopback applies.
    A remote peer is still rejected (403); a loopback peer is allowed (200)."""
    monkeypatch.setenv("GREYWATCH_API_TOKEN", "")
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: False)
    assert client.post("/api/v1/suricata/collect").status_code == 403
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: True)
    assert client.post("/api/v1/suricata/collect").status_code == 200


def test_whitespace_only_token_is_fail_closed(_local_env, _stub_backends, monkeypatch):
    """A whitespace-only token is truthy -> token mode ON -> unauthenticated
    callers (even a loopback peer) are rejected with 401. This is the operator
    pitfall (an accidental whitespace secret locks out local access) and is the
    safe, fail-closed outcome: no credentials can never authenticate."""
    monkeypatch.setenv("GREYWATCH_API_TOKEN", "   ")
    # loopback peer (TestClient "testclient") but NO credentials -> 401:
    assert client.post("/api/v1/suricata/collect").status_code == 401
    assert client.post(
        "/api/v1/events/ingest", json={"lines": ["x"]}
    ).status_code == 401
    # invalid bearer -> 401:
    assert client.post(
        "/api/v1/suricata/collect",
        headers={"Authorization": "Bearer wrong"},
    ).status_code == 401


# --------------------------------------------------------------------------- #
# _is_loopback_host: peer classification (deployment safety)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "host,expected",
    [
        (None, False),  # unknown peer -> fail-closed (never trusted as local)
        ("testclient", True),  # Starlette TestClient sentinel
        ("127.0.0.1", True),  # IPv4 loopback
        ("::1", True),  # IPv6 loopback
        ("127.255.255.255", True),  # 127.0.0.0/8 is loopback
        ("203.0.113.5", False),  # remote (RFC 5737)
        ("192.0.2.1", False),  # remote (RFC 5737)
        ("8.8.8.8", False),  # remote
        ("not-an-ip", False),  # unparseable -> not loopback
        ("", False),  # empty -> unknown -> fail-closed
    ],
)
def test_is_loopback_host_classification(host, expected):
    from backend.app.main import _is_loopback_host

    assert _is_loopback_host(host) is expected
