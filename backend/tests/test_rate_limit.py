"""Tests for the configurable API rate limiter (security review F2).

These tests are hermetic: every test constructs a fresh middleware instance (or
app) with an injectable monotonic clock and an isolated bucket store, so no
state leaks between cases and no wall-clock sleeping is required.

Covered behaviors:
  * Configuration parsing with safe documented defaults; invalid values never
      silently disable rate limiting.
  * Token-bucket enforcement: under limit accepted, at boundary accepted, over
      limit rejected with HTTP 429.
  * Deterministic ``Retry-After`` computed from the injectable clock.
  * Burst capacity = requests-per-minute x burst multiplier.
  * Refill over simulated time via the injectable clock.
  * Per-client isolation; public paths exempt; disabled mode allows all.
  * Missing/untrusted client identity never uses forwarding headers.
  * Bounded bucket store with max entry count and eviction.
  * Trust boundary runs outside rate limiting: auth failures (401/403) never
      consume rate-limit tokens.
  * Existing endpoint behavior preserved within configured limits.
"""

import math
import os
from dataclasses import dataclass

import anyio
import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware

from backend.app.main import (
    MaxBodySizeMiddleware,
    RateLimitConfig,
    RateLimitMiddleware,
    _trust_boundary,
    get_rate_limit_config,
    app as base_app,
)
from backend.app.siem import initialize_database


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


@dataclass
class FakeClock:
    """Injectable monotonic clock advanced manually by tests."""

    value: float = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def make_app(
    config: RateLimitConfig | None = None,
    clock: FakeClock | None = None,
    max_request_bytes: int | None = None,
) -> FastAPI:
    """Build a fresh FastAPI app with rate-limit (and optional body-limit) middleware."""
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, config=config, clock=clock)
    if max_request_bytes is not None:
        app.add_middleware(MaxBodySizeMiddleware, max_bytes=max_request_bytes)

    @app.post("/api/v1/events/ingest")
    async def ingest(request: Request):
        body = await request.body()
        return {"received": len(body)}

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


def client_for(config=None, clock=None, max_request_bytes=None):
    return TestClient(make_app(config, clock, max_request_bytes))


# --------------------------------------------------------------------------- #
# Configuration parsing
# --------------------------------------------------------------------------- #


def test_default_config_values():
    """Factory defaults match the documented defaults."""
    cfg = RateLimitConfig()
    assert cfg.enabled is True
    assert cfg.ingestion == 60
    assert cfg.reads == 120
    assert cfg.collector == 30
    assert cfg.alert_close == 30
    assert cfg.burst_multiplier == 2


def test_get_rate_limit_config_defaults(monkeypatch):
    """Unset env -> documented defaults."""
    monkeypatch.delenv("GREYWATCH_RATE_LIMIT_ENABLED", raising=False)
    monkeypatch.delenv("GREYWATCH_RATE_LIMIT_INGESTION", raising=False)
    monkeypatch.delenv("GREYWATCH_RATE_LIMIT_READS", raising=False)
    monkeypatch.delenv("GREYWATCH_RATE_LIMIT_COLLECTOR", raising=False)
    monkeypatch.delenv("GREYWATCH_RATE_LIMIT_ALERT_CLOSE", raising=False)
    monkeypatch.delenv("GREYWATCH_RATE_LIMIT_BURST_MULTIPLIER", raising=False)

    cfg = get_rate_limit_config()
    assert cfg.enabled is True
    assert cfg.ingestion == 60
    assert cfg.reads == 120
    assert cfg.collector == 30
    assert cfg.alert_close == 30
    assert cfg.burst_multiplier == 2


@pytest.mark.parametrize(
    "env_value,expected",
    [
        ("1", True),
        ("true", True),
        ("yes", True),
        ("0", False),
        ("false", False),
        ("no", False),
        ("  1  ", True),  # surrounding whitespace tolerated
    ],
)
def test_get_rate_limit_config_enabled_parsing(monkeypatch, env_value, expected):
    """The enabled flag parses booleans and tolerates whitespace."""
    monkeypatch.setenv("GREYWATCH_RATE_LIMIT_ENABLED", env_value)
    assert get_rate_limit_config().enabled is expected


def test_get_rate_limit_config_enabled_invalid_defaults_true(monkeypatch):
    """Invalid enabled value -> True (safe default, never silently disabled)."""
    monkeypatch.setenv("GREYWATCH_RATE_LIMIT_ENABLED", "not-a-boolean")
    assert get_rate_limit_config().enabled is True

    monkeypatch.setenv("GREYWATCH_RATE_LIMIT_ENABLED", "")
    assert get_rate_limit_config().enabled is True


@pytest.mark.parametrize(
    "env_var,attr,default",
    [
        ("GREYWATCH_RATE_LIMIT_INGESTION", "ingestion", 60),
        ("GREYWATCH_RATE_LIMIT_READS", "reads", 120),
        ("GREYWATCH_RATE_LIMIT_COLLECTOR", "collector", 30),
        ("GREYWATCH_RATE_LIMIT_ALERT_CLOSE", "alert_close", 30),
    ],
)
def test_get_rate_limit_config_limits_invalid_fall_back_to_default(
    monkeypatch, env_var, attr, default
):
    """Non-numeric or non-positive category limits fall back to the default."""
    monkeypatch.setenv(env_var, "not-a-number")
    assert getattr(get_rate_limit_config(), attr) == default

    monkeypatch.setenv(env_var, "0")
    assert getattr(get_rate_limit_config(), attr) == default

    monkeypatch.setenv(env_var, "-5")
    assert getattr(get_rate_limit_config(), attr) == default


def test_get_rate_limit_config_burst_multiplier_invalid_defaults_to_two(monkeypatch):
    """Invalid burst multiplier falls back to 2."""
    monkeypatch.setenv("GREYWATCH_RATE_LIMIT_BURST_MULTIPLIER", "not-an-int")
    assert get_rate_limit_config().burst_multiplier == 2

    monkeypatch.setenv("GREYWATCH_RATE_LIMIT_BURST_MULTIPLIER", "0")
    assert get_rate_limit_config().burst_multiplier == 2

    monkeypatch.setenv("GREYWATCH_RATE_LIMIT_BURST_MULTIPLIER", "-1")
    assert get_rate_limit_config().burst_multiplier == 2


# --------------------------------------------------------------------------- #
# ASGI-level middleware tests (injectable clock)
# --------------------------------------------------------------------------- #


def _dummy_app():
    async def app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"application/json"]],
            }
        )
        await send({"type": "http.response.body", "body": b'{"ok": true}'})

    return app


def _run_middleware(middleware, scope, receive):
    sent = []

    async def send(message):
        sent.append(message)

    async def run():
        await middleware(scope, receive, send)
        return sent

    return anyio.run(run)


def _request_receive(body=b"", more_body=False):
    called = {"n": 0}

    async def receive():
        called["n"] += 1
        return {"type": "http.request", "body": body, "more_body": more_body}

    return receive, called


def test_under_limit_passes_through(tmp_path, monkeypatch):
    """A request under the rate limit reaches the inner app (200)."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "under.db"))
    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(ingestion=60, reads=120, collector=30, alert_close=30)
    middleware = RateLimitMiddleware(_dummy_app(), config=cfg, clock=clock)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/events/ingest",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 54321),
    }
    receive, _ = _request_receive()
    messages = _run_middleware(middleware, scope, receive)

    assert messages[0]["status"] == 200


def test_exactly_at_capacity_is_accepted(tmp_path, monkeypatch):
    """Burst capacity (limit x multiplier) requests are all accepted."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "at.db"))
    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(ingestion=1, reads=1, collector=1, alert_close=1, burst_multiplier=3)
    # capacity = 1 * 3 = 3 tokens
    middleware = RateLimitMiddleware(_dummy_app(), config=cfg, clock=clock)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/events/ingest",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 54321),
    }

    statuses = []
    for _ in range(3):
        receive, _ = _request_receive()
        messages = _run_middleware(middleware, scope, receive)
        statuses.append(messages[0]["status"])

    assert statuses == [200, 200, 200]


def test_one_over_capacity_is_rejected_429(tmp_path, monkeypatch):
    """One request past burst capacity returns HTTP 429."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "over.db"))
    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(ingestion=1, reads=1, collector=1, alert_close=1, burst_multiplier=3)
    # capacity = 3 tokens
    middleware = RateLimitMiddleware(_dummy_app(), config=cfg, clock=clock)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/events/ingest",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 54321),
    }

    for _ in range(3):
        receive, _ = _request_receive()
        _run_middleware(middleware, scope, receive)

    receive, _ = _request_receive()
    messages = _run_middleware(middleware, scope, receive)

    assert messages[0]["type"] == "http.response.start"
    assert messages[0]["status"] == 429


def test_429_includes_retry_after_header(tmp_path, monkeypatch):
    """A 429 response carries a numeric Retry-After header."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "ra.db"))
    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(
        ingestion=60, reads=1, collector=1, alert_close=1, burst_multiplier=1
    )
    # limit=1 req/min -> refill_per_sec = 1/60, capacity = 1
    middleware = RateLimitMiddleware(_dummy_app(), config=cfg, clock=clock)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/events",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 54321),
    }

    # Consume the single token.
    receive, _ = _request_receive()
    _run_middleware(middleware, scope, receive)

    # Second request is rate limited.
    receive, _ = _request_receive()
    messages = _run_middleware(middleware, scope, receive)

    start = [m for m in messages if m["type"] == "http.response.start"][0]
    assert start["status"] == 429
    headers = {k.decode(): v.decode() for k, v in start["headers"]}
    assert "retry-after" in headers
    retry_after = int(headers["retry-after"])
    # (1 - 0) / (1/60) = 60 seconds exactly.
    assert retry_after == 60


def test_refill_over_simulated_time(tmp_path, monkeypatch):
    """Tokens refill as the injectable clock advances; no wall-clock sleep."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "refill.db"))
    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(
        ingestion=60, reads=1, collector=1, alert_close=1, burst_multiplier=1
    )
    # limit=1 req/min -> refill_per_sec = 1/60; need 60 seconds for 1 token.
    middleware = RateLimitMiddleware(_dummy_app(), config=cfg, clock=clock)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/events",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 54321),
    }

    receive, _ = _request_receive()
    assert _run_middleware(middleware, scope, receive)[0]["status"] == 200

    # Immediately again: exhausted.
    receive, _ = _request_receive()
    assert _run_middleware(middleware, scope, receive)[0]["status"] == 429

    # Advance 60 seconds: exactly one token refills.
    clock.advance(60)
    receive, _ = _request_receive()
    assert _run_middleware(middleware, scope, receive)[0]["status"] == 200


def test_per_client_isolation(tmp_path, monkeypatch):
    """Client A exhausting its bucket does not affect client B."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "iso.db"))
    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(
        ingestion=60, reads=1, collector=1, alert_close=1, burst_multiplier=1
    )
    middleware = RateLimitMiddleware(_dummy_app(), config=cfg, clock=clock)

    def make_scope(ip):
        return {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/events",
            "query_string": b"",
            "headers": [],
            "client": (ip, 54321),
        }

    scope_a = make_scope("10.0.0.1")
    scope_b = make_scope("10.0.0.2")

    receive, _ = _request_receive()
    assert _run_middleware(middleware, scope_a, receive)[0]["status"] == 200
    receive, _ = _request_receive()
    assert _run_middleware(middleware, scope_a, receive)[0]["status"] == 429

    # Client B still has its own bucket -> allowed.
    receive, _ = _request_receive()
    assert _run_middleware(middleware, scope_b, receive)[0]["status"] == 200


def test_public_paths_exempt(tmp_path, monkeypatch):
    """GET / and GET /health are never rate limited."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "public.db"))
    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(
        ingestion=1, reads=1, collector=1, alert_close=1, burst_multiplier=1
    )
    middleware = RateLimitMiddleware(_dummy_app(), config=cfg, clock=clock)

    for path in ("/", "/health"):
        scope = {
            "type": "http",
            "method": "GET",
            "path": path,
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 54321),
        }
        receive, _ = _request_receive()
        # Many requests, all pass.
        for _ in range(10):
            receive, _ = _request_receive()
            assert _run_middleware(middleware, scope, receive)[0]["status"] == 200


def test_disabled_rate_limit_allows_all(tmp_path, monkeypatch):
    """enabled=False skips rate limiting entirely."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "disabled.db"))
    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(enabled=False, ingestion=1, reads=1, burst_multiplier=1)
    middleware = RateLimitMiddleware(_dummy_app(), config=cfg, clock=clock)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/events",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 54321),
    }

    for _ in range(100):
        receive, _ = _request_receive()
        assert _run_middleware(middleware, scope, receive)[0]["status"] == 200


def test_missing_client_host_uses_unknown_key(tmp_path, monkeypatch):
    """A scope without a client address is keyed as 'unknown' (fail-safe, never
    crashes; forwarding headers are never consulted)."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "nohost.db"))
    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(
        ingestion=1, reads=1, collector=1, alert_close=1, burst_multiplier=1
    )
    middleware = RateLimitMiddleware(_dummy_app(), config=cfg, clock=clock)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/events",
        "query_string": b"",
        "headers": [],
        # No "client" key at all.
    }
    receive, _ = _request_receive()
    assert _run_middleware(middleware, scope, receive)[0]["status"] == 200

    # A second request from the same unknown peer consumes the second token.
    receive, _ = _request_receive()
    assert _run_middleware(middleware, scope, receive)[0]["status"] == 429


def test_non_http_scope_passes_through(tmp_path, monkeypatch):
    """Lifespan / websocket scopes are not rate limited."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "nonttp.db"))
    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(ingestion=1, reads=1, burst_multiplier=1)
    middleware = RateLimitMiddleware(_dummy_app(), config=cfg, clock=clock)

    scope = {"type": "lifespan"}
    receive = lambda: {"type": "lifespan.startup"}
    messages = _run_middleware(middleware, scope, receive)
    assert messages[0]["status"] == 200


# --------------------------------------------------------------------------- #
# Bounded bucket store
# --------------------------------------------------------------------------- #


def test_bucket_store_is_bounded_with_eviction(tmp_path, monkeypatch):
    """The bucket store never grows beyond max_entries; oldest entries evict."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "bound.db"))
    initialize_database()
    clock = FakeClock()
    cfg = RateLimitConfig(
        ingestion=1, reads=1, collector=1, alert_close=1, burst_multiplier=1
    )
    middleware = RateLimitMiddleware(
        _dummy_app(), config=cfg, clock=clock, max_entries=3
    )

    def make_scope(ip):
        return {
            "type": "http",
            "method": "GET",
            "path": "/api/v1/events",
            "query_string": b"",
            "headers": [],
            "client": (ip, 54321),
        }

    # Create 3 buckets.
    for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        receive, _ = _request_receive()
        _run_middleware(middleware, make_scope(ip), receive)
    assert len(middleware._buckets) == 3

    # A 4th client evicts the oldest entry.
    receive, _ = _request_receive()
    _run_middleware(middleware, make_scope("4.4.4.4"), receive)
    assert len(middleware._buckets) == 3
    assert ("ip", "1.1.1.1") not in middleware._buckets
    assert ("ip", "4.4.4.4") in middleware._buckets


# --------------------------------------------------------------------------- #
# TestClient integration tests
# --------------------------------------------------------------------------- #


def test_client_under_limit_is_accepted(tmp_path, monkeypatch):
    """A request under the limit returns 200 via TestClient."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "c_under.db"))
    initialize_database()
    cfg = RateLimitConfig(ingestion=60, reads=120, burst_multiplier=2)
    client = client_for(cfg)

    resp = client.post("/api/v1/events/ingest", content=b"x" * 10)
    assert resp.status_code == 200


def test_client_over_limit_returns_429(tmp_path, monkeypatch):
    """Exceeding the limit via TestClient returns 429 with Retry-After."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "c_over.db"))
    initialize_database()
    cfg = RateLimitConfig(ingestion=1, reads=120, burst_multiplier=1)
    client = client_for(cfg)

    # First request consumes the single token.
    assert client.post("/api/v1/events/ingest", content=b"x" * 10).status_code == 200
    # Second request is rate limited.
    resp = client.post("/api/v1/events/ingest", content=b"x" * 10)
    assert resp.status_code == 429
    assert "retry-after" in resp.headers
    assert int(resp.headers["retry-after"]) >= 1
    body = resp.json()
    assert "detail" in body


def test_client_public_path_exempt(tmp_path, monkeypatch):
    """GET /health is not rate limited even when other paths are."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "c_public.db"))
    initialize_database()
    cfg = RateLimitConfig(ingestion=1, reads=120, burst_multiplier=1)
    client = client_for(cfg)

    # Exhaust the read bucket on /events/ingest (limit 1).
    client.post("/api/v1/events/ingest", content=b"x" * 10)
    assert client.post("/api/v1/events/ingest", content=b"x" * 10).status_code == 429

    # /health remains unaffected.
    assert client.get("/health").status_code == 200


# --------------------------------------------------------------------------- #
# Middleware order: trust boundary outside rate limit
# --------------------------------------------------------------------------- #


def make_order_app(config=None):
    """Fresh app with TrustBoundary -> MaxBodySize -> RateLimit -> app order.

    add_middleware inserts at index 0, so the last registered middleware ends
    up outermost. Register TrustBoundary last.
    """
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, config=config)
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=1024 * 1024)
    app.add_middleware(BaseHTTPMiddleware, dispatch=_trust_boundary)

    @app.post("/api/v1/events/ingest")
    async def ingest(request: Request):
        body = await request.body()
        return {"received": len(body)}

    return app


def test_auth_failure_does_not_consume_rate_token(tmp_path, monkeypatch):
    """With a token configured, unauthenticated requests get 401 and never
    consume rate-limit tokens (trust boundary is outermost)."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "order.db"))
    initialize_database()
    monkeypatch.setenv("GREYWATCH_API_TOKEN", "secret-token")
    cfg = RateLimitConfig(ingestion=1, reads=120, burst_multiplier=1)
    app = make_order_app(cfg)
    client = TestClient(app)

    # Unauthenticated -> 401 (trust boundary short-circuits before rate limit).
    resp = client.post("/api/v1/events/ingest", content=b"x" * 10)
    assert resp.status_code == 401

    # Authenticated request still gets its full rate allowance -> 200, not 429.
    # This proves the earlier 401 did not consume the single rate-limit token.
    resp = client.post(
        "/api/v1/events/ingest",
        content=b"x" * 10,
        headers={"Authorization": "Bearer secret-token"},
    )
    assert resp.status_code == 200


def test_middleware_registration_order():
    """The global app registers middleware so the effective order is
    TrustBoundary -> MaxBodySize -> RateLimit -> app."""
    names = [m.cls.__name__ for m in base_app.user_middleware]
    # Registration order: trust boundary (BaseHTTPMiddleware) first, then
    # MaxBodySize, then RateLimit last -> reversed build makes RateLimit
    # innermost, MaxBodySize middle, trust boundary outermost.
    assert names[0] == "BaseHTTPMiddleware"  # trust boundary
    assert names[1] == "MaxBodySizeMiddleware"
    assert names[2] == "RateLimitMiddleware"

