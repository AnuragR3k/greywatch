"""Tests for the configurable API request-body size limit (security review F1).

These tests are hermetic: each test builds a fresh FastAPI app with the
``MaxBodySizeMiddleware`` configured via ``GREYWATCH_MAX_REQUEST_BYTES`` and a
temp database, so no production data is touched and tests run deterministically
in CI.

Covered behaviors:
  * Requests under the limit are accepted (200).
  * Requests exactly at the limit are accepted (200).
  * Requests exceeding the limit are rejected (413 Payload Too Large).
  * Enforcement is against actual bytes received, not the Content-Length header:
    missing, malformed, or misleading length headers are handled safely.
  * Chunked / streamed bodies that exceed the limit are rejected.
  * Configuration overrides (custom max bytes) work.
  * Invalid configuration values fall back to the safe default (1 MiB) and never
      silently disable the protection.
  * Setting the limit to 0 disables it (explicit operator choice).
  * GET /health and other public endpoints are unaffected.
  * Trust-boundary interaction: body limit applies to protected endpoints too.
"""

import os
from dataclasses import dataclass

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from backend.app.main import MaxBodySizeMiddleware, app as base_app
from backend.app.siem import initialize_database


DEFAULT_MAX_BYTES = 1024 * 1024  # 1 MiB


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


@dataclass
class AppConfig:
    max_request_bytes: int | None = None


def make_app(
    max_request_bytes: int | None = None, db_path: str | None = None
) -> FastAPI:
    """Build a fresh FastAPI app with MaxBodySizeMiddleware and test routes."""
    if db_path:
        os.environ["GREYWATCH_DB"] = db_path
    app = FastAPI()
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=max_request_bytes)

    @app.post("/api/v1/events/ingest")
    async def ingest(request: Request):
        body = await request.body()
        return {"received": len(body), "parsed": len(body)}

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


def client_for(max_request_bytes: int | None = None, db_path: str | None = None):
    """Return a TestClient for an app configured with the given limit."""
    return TestClient(make_app(max_request_bytes, db_path))


# --------------------------------------------------------------------------- #
# Config function (get_max_request_bytes)
# --------------------------------------------------------------------------- #


def test_get_max_request_bytes_default_is_one_mebibyte(monkeypatch):
    """Unset env -> default 1 MiB (1,048,576 bytes)."""
    monkeypatch.delenv("GREYWATCH_MAX_REQUEST_BYTES", raising=False)
    from backend.app.main import get_max_request_bytes

    assert get_max_request_bytes() == DEFAULT_MAX_BYTES


@pytest.mark.parametrize(
    "env_value,expected",
    [
        ("1048576", 1024 * 1024),
        ("1000", 1000),
        ("1", 1),
        ("0", None),  # 0 = disabled
        ("-1", None),  # negative = disabled
        ("  2048  ", 2048),  # surrounding whitespace tolerated
    ],
)
def test_get_max_request_bytes_parses_values(
    monkeypatch, env_value, expected
):
    """Valid numeric env values are parsed; 0/negative disables."""
    monkeypatch.setenv("GREYWATCH_MAX_REQUEST_BYTES", env_value)
    from backend.app.main import get_max_request_bytes

    assert get_max_request_bytes() == expected


def test_get_max_request_bytes_invalid_falls_back_to_default(monkeypatch):
    """Non-numeric env value -> safe default (1 MiB), never silently disabled."""
    monkeypatch.setenv("GREYWATCH_MAX_REQUEST_BYTES", "not-a-number")
    from backend.app.main import get_max_request_bytes

    assert get_max_request_bytes() == DEFAULT_MAX_BYTES


def test_get_max_request_bytes_invalid_empty_falls_back_to_default(monkeypatch):
    """Empty string env value -> safe default (1 MiB)."""
    monkeypatch.setenv("GREYWATCH_MAX_REQUEST_BYTES", "")
    from backend.app.main import get_max_request_bytes

    assert get_max_request_bytes() == DEFAULT_MAX_BYTES


# --------------------------------------------------------------------------- #
# Under / at / over the limit (via TestClient)
# --------------------------------------------------------------------------- #


def test_under_limit_is_accepted(tmp_path, monkeypatch):
    """A body smaller than the limit is processed normally."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "under.db"))
    initialize_database()
    client = client_for(DEFAULT_MAX_BYTES, str(tmp_path / "under.db"))

    small_body = b"x" * 100  # 100 bytes << 1 MiB
    resp = client.post(
        "/api/v1/events/ingest",
        content=small_body,
        headers={"content-type": "application/json"},
    )
    # Invalid JSON body is fine for this test; we only check size enforcement.
    assert resp.status_code in (200, 422)  # 422 = JSON parse error, not size


def test_at_limit_is_accepted(tmp_path, monkeypatch):
    """A body exactly equal to the limit is accepted (boundary, not off-by-one)."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "at.db"))
    initialize_database()
    client = client_for(100, str(tmp_path / "at.db"))

    body = b"x" * 100  # exactly 100 bytes == limit
    resp = client.post(
        "/api/v1/events/ingest", content=body, headers={"content-type": "text/plain"}
    )
    assert resp.status_code == 200


def test_over_limit_is_rejected(tmp_path, monkeypatch):
    """A body larger than the limit returns HTTP 413."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "over.db"))
    initialize_database()
    client = client_for(100, str(tmp_path / "over.db"))

    body = b"x" * 101  # 101 bytes > 100 limit
    resp = client.post(
        "/api/v1/events/ingest", content=body, headers={"content-type": "text/plain"}
    )
    assert resp.status_code == 413
    body_json = resp.json()
    assert "detail" in body_json
    assert "too large" in body_json["detail"].lower()


def test_over_limit_by_a_lot_is_rejected(tmp_path, monkeypatch):
    """A body far exceeding the limit returns 413 (not 500 or hang)."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "over_lot.db"))
    initialize_database()
    client = client_for(DEFAULT_MAX_BYTES, str(tmp_path / "over_lot.db"))

    body = b"x" * (DEFAULT_MAX_BYTES + 1)
    resp = client.post(
        "/api/v1/events/ingest", content=body, headers={"content-type": "text/plain"}
    )
    assert resp.status_code == 413


# --------------------------------------------------------------------------- #
# Missing / inaccurate Content-Length (actual bytes enforced)
# --------------------------------------------------------------------------- #


def test_actual_bytes_enforced_not_content_length(tmp_path, monkeypatch):
    """The limit is enforced on actual bytes received, not Content-Length.

    A client that claims Content-Length: 10 but sends 101 bytes is rejected
    because we count real bytes as they stream in.
    """
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "cl.db"))
    initialize_database()
    client = client_for(100, str(tmp_path / "cl.db"))

    # TestClient sets Content-Length automatically; to test misleading headers
    # we exercise the middleware directly via ASGI (see test_*_asgi below).
    # Through TestClient, simply confirm an oversized body is rejected.
    body = b"x" * 101
    resp = client.post(
        "/api/v1/events/ingest", content=body, headers={"content-type": "text/plain"}
    )
    assert resp.status_code == 413


# --------------------------------------------------------------------------- #
# Chunked / streamed bodies
# --------------------------------------------------------------------------- #


def test_streamed_body_over_limit_is_rejected(tmp_path, monkeypatch):
    """A chunked/streamed body whose cumulative size exceeds the limit is 413.

    We drive the middleware ASGI interface directly so we control chunking.
    """
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "stream.db"))
    initialize_database()

    from backend.app.main import MaxBodySizeMiddleware

    async def dummy_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"application/json"]],
            }
        )
        await send(
            {"type": "http.response.body", 'body': b'{"ok": true}'.encode()}
        )

    middleware = MaxBodySizeMiddleware(dummy_app, max_bytes=100)

    import anyio

    async def run():
        received = []
        sent = []

        async def receive():
            if not received:
                received.append(True)
                return {
                    "type": "http.request",
                    "body": b"x" * 60,
                    "more_body": True,
                }
            return {
                "type": "http.request",
                "body": b"x" * 60,  # cumulative 120 > 100
                "more_body": False,
            }

        async def send(message):
            sent.append(message)

        await middleware(
            {"type": "http", "method": "POST", "path": "/ingest", "query_string": b""},
            receive,
            send,
        )
        return sent

    messages = anyio.run(run)

    assert messages[0]["type"] == "http.response.start"
    assert messages[0]["status"] == 413


def test_streamed_body_under_limit_passes_through(tmp_path, monkeypatch):
    """A chunked/streamed body under the limit reaches the inner app."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "stream_ok.db"))
    initialize_database()

    from backend.app.main import MaxBodySizeMiddleware

    inner_called = {"n": 0}

    async def dummy_app(scope, receive, send):
        inner_called["n"] += 1
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        assert body == b"x" * 60
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"application/json"]],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = MaxBodySizeMiddleware(dummy_app, max_bytes=100)

    import anyio

    async def run():
        sent = []

        async def receive():
            return {
                "type": "http.request",
                "body": b"x" * 60,
                "more_body": False,
            }

        async def send(message):
            sent.append(message)

        await middleware(
            {"type": "http", "method": "POST", "path": "/ingest", "query_string": b""},
            receive,
            send,
        )
        return sent

    messages = anyio.run(run)

    assert inner_called["n"] == 1
    assert messages[0]["status"] == 200


# --------------------------------------------------------------------------- #
# Configuration overrides
# --------------------------------------------------------------------------- #


def test_custom_max_bytes_override(tmp_path, monkeypatch):
    """GREYWATCH_MAX_REQUEST_BYTES sets a custom limit."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "custom.db"))
    initialize_database()
    client = client_for(50, str(tmp_path / "custom.db"))

    assert client.post(
        "/api/v1/events/ingest", content=b"x" * 50, headers={"content-type": "text/plain"}
    ).status_code == 200
    assert client.post(
        "/api/v1/events/ingest", content=b"x" * 51, headers={"content-type": "text/plain"}
    ).status_code == 413


def test_limit_zero_disables_protection(tmp_path, monkeypatch):
    """GREYWATCH_MAX_REQUEST_BYTES=0 disables the limit (explicit operator choice)."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "zero.db"))
    initialize_database()
    client = client_for(0, str(tmp_path / "zero.db"))

    # 10 MiB body is accepted when the limit is disabled.
    body = b"x" * (10 * 1024 * 1024)
    resp = client.post(
        "/api/v1/events/ingest",
        content=body,
        headers={"content-type": "text/plain"},
    )
    assert resp.status_code == 200


# --------------------------------------------------------------------------- #
# Public endpoints unaffected
# --------------------------------------------------------------------------- #


def test_public_endpoints_unaffected_by_body_limit(tmp_path, monkeypatch):
    """GET /health works regardless of body-limit configuration."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "public.db"))
    initialize_database()
    client = client_for(100, str(tmp_path / "public.db"))

    assert client.get("/health").status_code == 200


# --------------------------------------------------------------------------- #
# Trust-boundary interaction
# --------------------------------------------------------------------------- #


def test_body_limit_applies_to_protected_endpoints(tmp_path, monkeypatch):
    """The body limit is enforced even on protected ingestion endpoints.

    A large body to /api/v1/events/ingest is rejected with 413 regardless of
    trust-boundary mode (loopback / TestClient peer is local).
    """
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "protected.db"))
    initialize_database()
    client = client_for(50, str(tmp_path / "protected.db"))

    resp = client.post(
        "/api/v1/events/ingest",
        content=b"x" * 51,
        headers={"content-type": "text/plain"},
    )
    assert resp.status_code == 413


# --------------------------------------------------------------------------- #
# ASGI-level edge cases: missing / misleading headers
# --------------------------------------------------------------------------- #


def test_asgi_missing_content_length_oversized_rejected(tmp_path, monkeypatch):
    """ASGI scope with no Content-Length header: actual bytes are still counted.

    The middleware never inspects Content-Length, so its absence is irrelevant.
    """
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "no_cl.db"))
    initialize_database()

    from backend.app.main import MaxBodySizeMiddleware

    async def dummy_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"application/json"]],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = MaxBodySizeMiddleware(dummy_app, max_bytes=100)

    import anyio

    async def run():
        sent = []

        async def receive():
            return {
                "type": "http.request",
                "body": b"x" * 150,  # no Content-Length header in scope
                "more_body": False,
            }

        async def send(message):
            sent.append(message)

        await middleware(
            {
                "type": "http",
                "method": "POST",
                "path": "/ingest",
                "query_string": b"",
                "headers": [],  # no Content-Length header
            },
            receive,
            send,
        )
        return sent

    messages = anyio.run(run)

    assert messages[0]["status"] == 413


def test_asgi_misleading_content_length_actual_bytes_enforced(
    tmp_path, monkeypatch
):
    """A scope claiming Content-Length: 10 but sending 150 bytes -> 413.

    The middleware counts real bytes, so the misleading header is irrelevant.
    """
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "mislead.db"))
    initialize_database()

    from backend.app.main import MaxBodySizeMiddleware

    async def dummy_app(scope, receive, send):
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [[b"content-type", b"application/json"]],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = MaxBodySizeMiddleware(dummy_app, max_bytes=100)

    import anyio

    async def run():
        sent = []

        async def receive():
            return {
                "type": "http.request",
                "body": b"x" * 150,
                "more_body": False,
            }

        async def send(message):
            sent.append(message)

        await middleware(
            {
                "type": "http",
                "method": "POST",
                "path": "/ingest",
                "query_string": b"",
                "headers": [[b"content-length", b"10"]],  # lies!
            },
            receive,
            send,
        )
        return sent

    messages = anyio.run(run)

    assert messages[0]["status"] == 413

