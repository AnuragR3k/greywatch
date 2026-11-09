"""Regression tests for pre-authentication agent-key rate limiting (M1).

The trust boundary authenticates ``gw_*`` agent keys and writes an
``auth_failure`` audit row for every failure. It runs before the global rate
limiter, so without a pre-auth limit an unauthenticated client could grow the
audit log/WAL without bound and contend for SQLite's single writer.

``PreAuthAgentRateLimitMiddleware`` runs outermost and rejects excess
agent-key attempts before authentication, audit writes, body buffering, or the
global limiter.

Covered behaviors:
  * Repeated invalid agent-key requests get HTTP 429 with a numeric
    ``Retry-After``.
  * Rejections are logged but never write an ``audit_log`` row; the first
    failing attempt (which does reach authentication) still does.
  * Different client identities have independent buckets.
  * Forwarding headers from untrusted peers cannot reset or bypass a bucket,
    while a configured trusted proxy (loopback by default) may supply the
    client identity.
  * Only the right-most ``X-Forwarded-For`` hop is used, so client-supplied
    left-most values cannot spoof or rotate the bucket.
  * A valid agent authenticates after the bucket refills.
  * Legacy-token traffic is untouched and never consumes pre-auth tokens.
  * The bucket store is bounded and evicts least-recently-used identities.
  * Environment configuration parses safely and can be explicitly disabled.
"""

from __future__ import annotations

import ipaddress
import sqlite3
from dataclasses import dataclass

import anyio
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

from backend.app import main
from backend.app.agents import create_agent, create_api_key
from backend.app.migration_state import ensure_database_file_exists
from backend.app.migrations.runner import migrate
from backend.app.main import (
    PREAUTH_RATE_BURST_MULTIPLIER_DEFAULT,
    PREAUTH_RATE_LIMIT_DEFAULT,
    PREAUTH_RATE_MAX_ENTRIES_DEFAULT,
    PreAuthRateLimitConfig,
    PreAuthAgentRateLimitMiddleware,
    _client_identity,
    _is_trusted_proxy,
    _parse_trusted_proxies,
    _trust_boundary,
    get_preauth_rate_limit_config,
    get_trusted_proxy_networks,
)

INGEST_PATH = "/api/v1/events/ingest"
LEGACY_TOKEN = "legacy-shared-secret"
INVALID_KEY = "gw_this-key-does-not-exist"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


@dataclass
class FrozenClock:
    """Injectable monotonic clock advanced manually by tests."""

    value: float = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


class _OkApp:
    """Minimal downstream ASGI app that records successful calls."""

    def __init__(self) -> None:
        self.calls = 0

    async def __call__(self, scope, receive, send) -> None:
        self.calls += 1
        await send(
            {"type": "http.response.start", "status": 200, "headers": []}
        )
        await send({"type": "http.response.body", "body": b"ok"})


def _scope(
    *,
    client: tuple[str, int] = ("203.0.113.9", 50000),
    headers: dict[str, str] | None = None,
) -> dict:
    raw_headers = [
        (name.lower().encode("latin-1"), value.encode("latin-1"))
        for name, value in (headers or {}).items()
    ]
    return {
        "type": "http",
        "method": "POST",
        "path": INGEST_PATH,
        "query_string": b"",
        "headers": raw_headers,
        "client": client,
    }


def _drive(middleware, scope: dict):
    """Run the middleware for one request and return (status, headers, app)."""
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        sent.append(message)

    anyio.run(middleware, scope, receive, send)

    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    headers = {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in next(
            m["headers"] for m in sent if m["type"] == "http.response.start"
        )
    }
    return status, headers, middleware.app


def _middleware(
    *,
    limit: int = 1,
    burst_multiplier: int = 1,
    max_entries: int = 100,
    clock: FrozenClock | None = None,
    app=None,
) -> PreAuthAgentRateLimitMiddleware:
    return PreAuthAgentRateLimitMiddleware(
        app or _OkApp(),
        config=PreAuthRateLimitConfig(
            enabled=True,
            limit=limit,
            burst_multiplier=burst_multiplier,
            max_entries=max_entries,
        ),
        clock=clock or FrozenClock(),
    )


def _agent_headers(key: str = INVALID_KEY) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


# --------------------------------------------------------------------------- #
# Unit behavior of the middleware
# --------------------------------------------------------------------------- #


def test_repeated_invalid_keys_get_429_with_numeric_retry_after():
    """The request after the burst is rejected with a numeric Retry-After."""
    middleware = _middleware(limit=1, burst_multiplier=1)

    first_status, _, app = _drive(middleware, _scope(headers=_agent_headers()))
    assert first_status == 200
    assert app.calls == 1

    second_status, headers, _ = _drive(
        middleware, _scope(headers=_agent_headers())
    )
    assert second_status == 429
    assert headers["retry-after"].isdigit()
    assert int(headers["retry-after"]) >= 1
    assert app.calls == 1  # rejected before the downstream app

    body = b'{"detail":"Agent authentication rate limit exceeded"}'
    assert body  # documented response shape; asserted via real app below


def test_non_agent_requests_bypass_the_preauth_limiter():
    """Legacy-token and anonymous requests never consume pre-auth tokens."""
    middleware = _middleware(limit=1, burst_multiplier=1)

    for _ in range(10):
        status, _, app = _drive(middleware, _scope())
        assert status == 200
    assert app.calls == 10

    # Legacy credentials are not agent keys either.
    for _ in range(10):
        status, _, app = _drive(
            middleware, _scope(headers={"Authorization": f"Bearer {LEGACY_TOKEN}"})
        )
        assert status == 200
    assert app.calls == 20
    assert len(middleware._buckets) == 0


def test_different_client_identities_have_independent_buckets():
    """Exhausting one identity does not consume another identity's quota."""
    middleware = _middleware(limit=1, burst_multiplier=1)

    assert _drive(
        middleware, _scope(client=("198.51.100.1", 1), headers=_agent_headers())
    )[0] == 200
    assert _drive(
        middleware, _scope(client=("198.51.100.1", 1), headers=_agent_headers())
    )[0] == 429

    assert _drive(
        middleware, _scope(client=("198.51.100.2", 2), headers=_agent_headers())
    )[0] == 200
    assert _drive(
        middleware, _scope(client=("198.51.100.2", 2), headers=_agent_headers())
    )[0] == 429


def test_refill_restores_access():
    """Advancing the clock past the refill interval allows the next attempt."""
    clock = FrozenClock()
    middleware = _middleware(limit=1, burst_multiplier=1, clock=clock)

    assert _drive(middleware, _scope(headers=_agent_headers()))[0] == 200
    assert _drive(middleware, _scope(headers=_agent_headers()))[0] == 429

    clock.advance(61.0)
    assert _drive(middleware, _scope(headers=_agent_headers()))[0] == 200


def test_bucket_store_is_bounded():
    """A flood of distinct identities cannot grow the bucket store forever."""
    middleware = _middleware(limit=1, burst_multiplier=1, max_entries=2)

    for index in range(10):
        _drive(
            middleware,
            _scope(client=(f"198.51.100.{index + 1}", 1), headers=_agent_headers()),
        )

    assert len(middleware._buckets) <= 2


# --------------------------------------------------------------------------- #
# Client identity / spoofing
# --------------------------------------------------------------------------- #


def test_untrusted_peer_cannot_spoof_forwarded_headers():
    """A remote peer's forwarding headers never change the bucket key."""
    middleware = _middleware(limit=1, burst_multiplier=1)
    peer = ("203.0.113.9", 50000)

    first, _, app = _drive(
        middleware,
        _scope(
            client=peer,
            headers={
                **_agent_headers(),
                "X-Greywatch-Client-IP": "198.51.100.10",
                "X-Forwarded-For": "198.51.100.10",
            },
        ),
    )
    assert first == 200

    # Rotate every spoofable header. The untrusted peer still shares a bucket.
    second, _, _ = _drive(
        middleware,
        _scope(
            client=peer,
            headers={
                **_agent_headers(),
                "X-Greywatch-Client-IP": "198.51.100.11",
                "X-Forwarded-For": "198.51.100.11",
            },
        ),
    )
    assert second == 429
    assert app.calls == 1


def test_untrusted_peer_identity_is_the_peer_even_with_headers():
    scope = _scope(
        client=("203.0.113.9", 1),
        headers={
            "X-Greywatch-Client-IP": "198.51.100.10",
            "X-Forwarded-For": "198.51.100.11",
        },
    )
    assert _client_identity(scope) == "203.0.113.9"


def test_trusted_proxy_supplies_client_identity():
    """A configured proxy's X-Greywatch-Client-IP separates real clients."""
    middleware = _middleware(limit=1, burst_multiplier=1)
    proxy = ("127.0.0.1", 50000)

    assert _drive(
        middleware,
        _scope(
            client=proxy,
            headers={
                **_agent_headers(),
                "X-Greywatch-Client-IP": "198.51.100.20",
            },
        ),
    )[0] == 200
    assert _drive(
        middleware,
        _scope(
            client=proxy,
            headers={
                **_agent_headers(),
                "X-Greywatch-Client-IP": "198.51.100.20",
            },
        ),
    )[0] == 429

    # A different real client behind the same proxy is unaffected.
    assert _drive(
        middleware,
        _scope(
            client=proxy,
            headers={
                **_agent_headers(),
                "X-Greywatch-Client-IP": "198.51.100.21",
            },
        ),
    )[0] == 200


def test_trusted_proxy_uses_rightmost_forwarded_for_hop():
    """Only the hop appended by the trusted proxy is authoritative."""
    middleware = _middleware(limit=1, burst_multiplier=1)
    proxy = ("127.0.0.1", 50000)

    def request_with(left: str, actual: str):
        return _scope(
            client=proxy,
            headers={
                **_agent_headers(),
                "X-Forwarded-For": f"{left}, {actual}",
            },
        )

    assert _drive(middleware, request_with("10.0.0.1", "198.51.100.30"))[0] == 200
    # Rotating the client-supplied left-most value must not reset the bucket.
    assert _drive(middleware, request_with("10.0.0.2", "198.51.100.30"))[0] == 429

    assert _drive(middleware, request_with("10.0.0.3", "198.51.100.31"))[0] == 200


def test_forwarded_for_with_port_is_normalized():
    middleware = _middleware(limit=1, burst_multiplier=1)
    proxy = ("127.0.0.1", 50000)

    def request_with(value: str):
        return _scope(
            client=proxy,
            headers={**_agent_headers(), "X-Forwarded-For": value},
        )

    assert _drive(middleware, request_with("198.51.100.40:51234"))[0] == 200
    assert _drive(middleware, request_with("198.51.100.40:60000"))[0] == 429


def test_trusted_proxy_parsing_defaults_and_invalid_entries(monkeypatch):
    monkeypatch.delenv("GREYWATCH_TRUSTED_PROXIES", raising=False)
    networks = get_trusted_proxy_networks()
    assert ipaddress.ip_network("127.0.0.1/32") in networks
    assert ipaddress.ip_network("::1/128") in networks
    assert _is_trusted_proxy("127.0.0.1")
    assert not _is_trusted_proxy("203.0.113.9")

    # Invalid entries are ignored and do not make the peer trusted.
    parsed = _parse_trusted_proxies("not-a-cidr, 10.0.0.0/8")
    assert parsed == (ipaddress.ip_network("10.0.0.0/8"),)


# --------------------------------------------------------------------------- #
# Environment configuration
# --------------------------------------------------------------------------- #


def test_preauth_config_defaults(monkeypatch):
    for name in (
        "GREYWATCH_PREAUTH_RATE_LIMIT_ENABLED",
        "GREYWATCH_PREAUTH_RATE_LIMIT",
        "GREYWATCH_PREAUTH_RATE_BURST_MULTIPLIER",
        "GREYWATCH_PREAUTH_RATE_MAX_ENTRIES",
    ):
        monkeypatch.delenv(name, raising=False)

    cfg = get_preauth_rate_limit_config()
    assert cfg.enabled is True
    assert cfg.limit == PREAUTH_RATE_LIMIT_DEFAULT
    assert cfg.burst_multiplier == PREAUTH_RATE_BURST_MULTIPLIER_DEFAULT
    assert cfg.max_entries == PREAUTH_RATE_MAX_ENTRIES_DEFAULT


def test_preauth_config_invalid_values_fall_back(monkeypatch):
    monkeypatch.setenv("GREYWATCH_PREAUTH_RATE_LIMIT_ENABLED", "1")
    monkeypatch.setenv("GREYWATCH_PREAUTH_RATE_LIMIT", "not-a-number")
    monkeypatch.setenv("GREYWATCH_PREAUTH_RATE_BURST_MULTIPLIER", "-2")
    monkeypatch.setenv("GREYWATCH_PREAUTH_RATE_MAX_ENTRIES", "0")

    cfg = get_preauth_rate_limit_config()
    assert cfg.enabled is True
    assert cfg.limit == PREAUTH_RATE_LIMIT_DEFAULT
    assert cfg.burst_multiplier == PREAUTH_RATE_BURST_MULTIPLIER_DEFAULT
    assert cfg.max_entries == PREAUTH_RATE_MAX_ENTRIES_DEFAULT


def test_preauth_limit_can_be_explicitly_disabled(monkeypatch):
    monkeypatch.setenv("GREYWATCH_PREAUTH_RATE_LIMIT_ENABLED", "0")
    middleware = PreAuthAgentRateLimitMiddleware(_OkApp())

    for _ in range(10):
        status, _, app = _drive(middleware, _scope(headers=_agent_headers()))
        assert status == 200
    assert app.calls == 10


# --------------------------------------------------------------------------- #
# Integration with the real trust boundary and database
# --------------------------------------------------------------------------- #


@pytest.fixture
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "preauth.db"))
    monkeypatch.setenv("GREYWATCH_KEY_HASH_ITERATIONS", "1000")
    monkeypatch.setenv("GREYWATCH_API_TOKEN", LEGACY_TOKEN)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "1")
    db_path = tmp_path / "preauth.db"
    ensure_database_file_exists(db_path)
    migrate(str(db_path), dry_run=False)
    yield str(db_path)


def _build_integration_app(config, clock):
    """Fresh app with the real trust boundary inside the pre-auth limiter."""
    app = FastAPI()
    app.add_middleware(BaseHTTPMiddleware, dispatch=_trust_boundary)
    app.add_middleware(
        PreAuthAgentRateLimitMiddleware, config=config, clock=clock
    )

    @app.post(INGEST_PATH)
    async def ingest(request: Request):
        return {"received": 1}

    return app


def _auth_failure_count(db_path: str) -> int:
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE event_type = 'auth_failure'"
        ).fetchone()
    return int(row[0])


def _make_agent_key(name: str) -> str:
    agent = create_agent(name)
    return create_api_key(agent.id).plaintext_key


def test_rejections_happen_before_audit_writes(isolated_db):
    """The first failure is audited; pre-auth rejections are not."""
    clock = FrozenClock()
    config = PreAuthRateLimitConfig(
        enabled=True, limit=1, burst_multiplier=1, max_entries=100
    )
    app = _build_integration_app(config, clock)
    client = TestClient(app)

    before = _auth_failure_count(isolated_db)

    first = client.post(
        INGEST_PATH,
        json={"lines": ["event"]},
        headers={"Authorization": f"Bearer {INVALID_KEY}"},
    )
    assert first.status_code == 401
    assert _auth_failure_count(isolated_db) == before + 1

    second = client.post(
        INGEST_PATH,
        json={"lines": ["event"]},
        headers={"Authorization": f"Bearer {INVALID_KEY}"},
    )
    assert second.status_code == 429
    assert second.headers["Retry-After"].isdigit()
    # Rejected before authentication: no additional audit row.
    assert _auth_failure_count(isolated_db) == before + 1


def test_valid_agent_authenticates_after_refill(isolated_db):
    """A legitimate agent resumes immediately once its IP bucket refills."""
    clock = FrozenClock()
    config = PreAuthRateLimitConfig(
        enabled=True, limit=1, burst_multiplier=1, max_entries=100
    )
    app = _build_integration_app(config, clock)
    key = _make_agent_key("legit-agent")
    client = TestClient(app)

    assert client.post(
        INGEST_PATH,
        json={"lines": ["event"]},
        headers={"Authorization": f"Bearer {INVALID_KEY}"},
    ).status_code == 401
    assert client.post(
        INGEST_PATH,
        json={"lines": ["event"]},
        headers={"Authorization": f"Bearer {INVALID_KEY}"},
    ).status_code == 429

    clock.advance(61.0)
    response = client.post(
        INGEST_PATH,
        json={"lines": ["event"]},
        headers={"Authorization": f"Bearer {key}"},
    )
    assert response.status_code == 200


def test_valid_agent_behind_caddy_headers_authenticates(isolated_db):
    """The documented Caddy client-IP header does not break agent auth."""
    clock = FrozenClock()
    config = PreAuthRateLimitConfig(
        enabled=True, limit=10, burst_multiplier=1, max_entries=100
    )
    app = _build_integration_app(config, clock)
    key = _make_agent_key("caddy-agent")
    client = TestClient(app)  # peer is "testclient", trusted by default

    for _ in range(3):
        response = client.post(
            INGEST_PATH,
            json={"lines": ["event"]},
            headers={
                "Authorization": f"Bearer {key}",
                "X-Greywatch-Client-IP": "198.51.100.50",
                "X-Forwarded-For": "198.51.100.50",
            },
        )
        assert response.status_code == 200


def test_legacy_token_does_not_consume_preauth_tokens(isolated_db):
    """Shared-token traffic is untouched and cannot fill the agent bucket."""
    clock = FrozenClock()
    config = PreAuthRateLimitConfig(
        enabled=True, limit=1, burst_multiplier=1, max_entries=100
    )
    app = _build_integration_app(config, clock)
    client = TestClient(app)

    for _ in range(5):
        response = client.post(
            INGEST_PATH,
            json={"lines": ["event"]},
            headers={"X-Greywatch-Token": LEGACY_TOKEN},
        )
        assert response.status_code == 200

    assert client.post(
        INGEST_PATH,
        json={"lines": ["event"]},
        headers={"Authorization": f"Bearer {INVALID_KEY}"},
    ).status_code == 401
    assert client.post(
        INGEST_PATH,
        json={"lines": ["event"]},
        headers={"Authorization": f"Bearer {INVALID_KEY}"},
    ).status_code == 429


def test_remote_spoofing_cannot_bypass_through_real_app(isolated_db):
    """A remote peer rotating forwarding headers is still one bucket."""
    clock = FrozenClock()
    config = PreAuthRateLimitConfig(
        enabled=True, limit=1, burst_multiplier=1, max_entries=100
    )
    app = _build_integration_app(config, clock)
    client = TestClient(app, client=("203.0.113.60", 50000))

    first = client.post(
        INGEST_PATH,
        json={"lines": ["event"]},
        headers={
            "Authorization": f"Bearer {INVALID_KEY}",
            "X-Greywatch-Client-IP": "198.51.100.61",
            "X-Forwarded-For": "198.51.100.61",
        },
    )
    assert first.status_code == 401

    second = client.post(
        INGEST_PATH,
        json={"lines": ["event"]},
        headers={
            "Authorization": f"Bearer {INVALID_KEY}",
            "X-Greywatch-Client-IP": "198.51.100.62",
            "X-Forwarded-For": "198.51.100.62",
        },
    )
    assert second.status_code == 429


def test_response_body_is_documented_shape(isolated_db):
    clock = FrozenClock()
    config = PreAuthRateLimitConfig(
        enabled=True, limit=1, burst_multiplier=1, max_entries=100
    )
    app = _build_integration_app(config, clock)
    client = TestClient(app)

    client.post(
        INGEST_PATH,
        json={"lines": ["event"]},
        headers={"Authorization": f"Bearer {INVALID_KEY}"},
    )
    response = client.post(
        INGEST_PATH,
        json={"lines": ["event"]},
        headers={"Authorization": f"Bearer {INVALID_KEY}"},
    )
    assert response.status_code == 429
    assert response.json() == {
        "detail": "Agent authentication rate limit exceeded"
    }


def test_preauth_limiter_thread_safety():
    """Concurrent requests from multiple threads must not corrupt the bucket store.

    This is a regression test for AUTH-001: the pre-auth limiter's
    ``_buckets`` OrderedDict was accessed without a lock in a context that
    could be executed concurrently (e.g. via threadpool or multiple workers).
    """
    import threading

    from backend.app.main import (
        PreAuthAgentRateLimitMiddleware,
        PreAuthRateLimitConfig,
    )

    clock = FrozenClock()
    config = PreAuthRateLimitConfig(
        enabled=True, limit=100, burst_multiplier=1, max_entries=1000
    )

    # Test the middleware directly without the trust boundary
    # (which requires a database). Use the unit-test helper pattern.
    class _OkApp:
        def __init__(self):
            self.calls = 0

        async def __call__(self, scope, receive, send):
            self.calls += 1
            await send(
                {"type": "http.response.start", "status": 200, "headers": []}
            )
            await send({"type": "http.response.body", "body": b"ok"})

    middleware = PreAuthAgentRateLimitMiddleware(
        _OkApp(),
        config=config,
        clock=clock,
    )

    results = {"success": 0, "rate_limited": 0, "errors": 0, "details": []}
    results_lock = threading.Lock()

    def make_request():
        try:
            scope = {
                "type": "http",
                "method": "POST",
                "path": INGEST_PATH,
                "query_string": b"",
                "headers": [(b"authorization", f"Bearer {INVALID_KEY}".encode("latin-1"))],
                "client": ("198.51.100.1", 50000),
            }

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            sent = []

            async def send(message):
                sent.append(message)

            import anyio
            anyio.run(middleware, scope, receive, send)

            status = next(m["status"] for m in sent if m["type"] == "http.response.start")
            with results_lock:
                if status == 200:
                    results["success"] += 1
                elif status == 429:
                    results["rate_limited"] += 1
                else:
                    results["errors"] += 1
                    results["details"].append(f"status={status}")
        except Exception as e:
            with results_lock:
                results["errors"] += 1
                results["details"].append(f"exception={e}")

    # Fire 50 concurrent requests from 5 threads (10 each)
    threads = []
    for _ in range(5):
        t = threading.Thread(target=lambda: [make_request() for _ in range(10)])
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Debug output
    print(f"Results: {results}")

    # All 50 requests should be allowed (limit=100)
    assert results["success"] == 50
    assert results["rate_limited"] == 0
    assert results["errors"] == 0
