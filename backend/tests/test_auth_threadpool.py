"""Regression tests for moving PBKDF2 verification off the event loop (M2).

``authenticate_api_key()`` performs PBKDF2-HMAC-SHA256 with 600,000
iterations. The trust boundary used to call it synchronously inside the async
middleware, blocking the event loop (and therefore ``/health`` and dashboard
requests) for the duration of every agent-key authentication.

The fix runs the synchronous trust-boundary check in Starlette's threadpool
(``run_in_threadpool``). These tests prove that:

  * the expensive verification executes on a worker thread, not the event
    loop thread;
  * an unrelated coroutine keeps progressing while verification is blocked;
  * concurrent authentications run in parallel without serializing the loop;
  * authentication semantics are unchanged (valid key succeeds, invalid key
    fails, constant-time comparison and stored iteration count are preserved).
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import threading
import time

import anyio
import httpx
import pytest
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware

from backend.app import agents as agents_module
from backend.app.agents import create_agent, create_api_key
from backend.app.main import _trust_boundary
from backend.app.migration_state import ensure_database_file_exists
from backend.app.migrations.runner import migrate

INGEST_PATH = "/api/v1/events/ingest"


# --------------------------------------------------------------------------- #
# Fixtures and helpers
# --------------------------------------------------------------------------- #


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Fresh app with the real trust boundary and an isolated database."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "threadpool.db"))
    # Keep key creation cheap; the tests below inject their own verification
    # delay, so the real hash cost would only make the suite slower.
    monkeypatch.setenv("GREYWATCH_KEY_HASH_ITERATIONS", "1000")
    monkeypatch.delenv("GREYWATCH_API_TOKEN", raising=False)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "1")
    db_path = tmp_path / "threadpool.db"
    ensure_database_file_exists(db_path)
    migrate(str(db_path), dry_run=False)

    app = FastAPI()
    app.add_middleware(BaseHTTPMiddleware, dispatch=_trust_boundary)

    @app.post(INGEST_PATH)
    async def ingest(request: Request):
        return {"received": 1}

    return app


def _make_agent_key(name: str) -> str:
    agent = create_agent(name)
    return create_api_key(agent.id).plaintext_key


async def _post(app: FastAPI, key: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        return await client.post(
            INGEST_PATH,
            json={"lines": ["event"]},
            headers={"Authorization": f"Bearer {key}"},
        )


# --------------------------------------------------------------------------- #
# Threadpool execution
# --------------------------------------------------------------------------- #


def test_verify_key_runs_on_worker_thread(app, monkeypatch):
    """The synchronous PBKDF2 path must not execute on the event-loop thread."""
    key = _make_agent_key("worker-thread")
    real_verify = agents_module._verify_key
    verification_threads: list[int] = []

    def recording_verify(plaintext_key, stored_hash):
        verification_threads.append(threading.get_ident())
        return real_verify(plaintext_key, stored_hash)

    monkeypatch.setattr(agents_module, "_verify_key", recording_verify)

    response = anyio.run(_post, app, key)

    assert response.status_code == 200
    assert verification_threads, "PBKDF2 verification was never invoked"
    assert verification_threads[0] != threading.main_thread().ident


def test_blocked_verification_does_not_stall_the_event_loop(app, monkeypatch):
    """An ``asyncio.sleep`` ticker keeps running during a blocked hash."""
    key = _make_agent_key("responsive-loop")
    real_verify = agents_module._verify_key
    ticks = 0

    def slow_verify(plaintext_key, stored_hash):
        # Simulate the 600k-iteration PBKDF2 cost deterministically.
        time.sleep(0.35)
        return real_verify(plaintext_key, stored_hash)

    monkeypatch.setattr(agents_module, "_verify_key", slow_verify)

    async def scenario() -> tuple[httpx.Response, int]:
        nonlocal ticks

        async def ticker() -> None:
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        task = asyncio.create_task(ticker())
        try:
            response = await _post(app, key)
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        return response, ticks

    response, observed_ticks = anyio.run(scenario)

    assert response.status_code == 200
    # Without the threadpool the loop is frozen for the whole 0.35 s sleep and
    # the ticker cannot advance at all. Require a clear margin below that.
    assert observed_ticks >= 5


def test_concurrent_authentications_run_in_parallel(app, monkeypatch):
    """Two blocked verifications overlap instead of serializing the loop."""
    key_a = _make_agent_key("parallel-a")
    key_b = _make_agent_key("parallel-b")
    real_verify = agents_module._verify_key

    state = {"current": 0, "max": 0}
    lock = threading.Lock()

    def slow_verify(plaintext_key, stored_hash):
        with lock:
            state["current"] += 1
            state["max"] = max(state["max"], state["current"])
        try:
            time.sleep(0.25)
            return real_verify(plaintext_key, stored_hash)
        finally:
            with lock:
                state["current"] -= 1

    monkeypatch.setattr(agents_module, "_verify_key", slow_verify)

    async def scenario() -> tuple[httpx.Response, httpx.Response, int]:
        ticks = 0

        async def ticker() -> None:
            nonlocal ticks
            while True:
                await asyncio.sleep(0.01)
                ticks += 1

        task = asyncio.create_task(ticker())
        try:
            responses = await asyncio.gather(_post(app, key_a), _post(app, key_b))
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
        return responses[0], responses[1], ticks

    first, second, observed_ticks = anyio.run(scenario)

    assert first.status_code == 200
    assert second.status_code == 200
    assert state["max"] >= 2, "verifications did not overlap"
    assert observed_ticks >= 5


# --------------------------------------------------------------------------- #
# Authentication semantics preserved
# --------------------------------------------------------------------------- #


def test_invalid_agent_key_is_still_rejected(app):
    response = anyio.run(_post, app, "gw_this-key-does-not-exist")
    assert response.status_code == 401


def test_verify_key_still_uses_stored_iterations_and_constant_time_compare():
    """The real verifier keeps the stored iteration count and hmac.compare_digest."""
    plaintext = "gw_semantics-check"
    salt = b"0123456789abcdef"
    iterations = 1234
    digest = hashlib.pbkdf2_hmac("sha256", plaintext.encode(), salt, iterations)
    stored = f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"

    verified, stored_iterations = agents_module._verify_key(plaintext, stored)
    assert verified is True
    assert stored_iterations == iterations

    # A wrong key must fail for the same hash.
    wrong, _ = agents_module._verify_key("gw_wrong", stored)
    assert wrong is False

    # Guard against a future "optimization" that replaces the constant-time
    # comparison with a plain equality check.
    source = agents_module._verify_key.__code__.co_names
    assert "compare_digest" in source
    assert hmac.compare_digest(digest, digest)


def test_default_iteration_count_is_not_weakened(monkeypatch):
    monkeypatch.delenv("GREYWATCH_KEY_HASH_ITERATIONS", raising=False)
    assert agents_module.DEFAULT_KEY_HASH_ITERATIONS == 600_000
    generated = agents_module._hash_key("gw_iterations")
    assert generated.split("$")[1] == "600000"
