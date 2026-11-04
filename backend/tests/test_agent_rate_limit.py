"""Regression tests for per-agent API rate limiting.

The per-agent limiter is enforced by the ``_trust_boundary`` middleware, after
a valid agent API key has been authenticated and before the ingestion handler
runs. These tests exercise the real application middleware stack while
stubbing the ingestion backend so the assertions are deterministic and focus on
rate-limit behavior.

Determinism:
  * ``agents.time`` is replaced with a frozen monotonic clock, so token-bucket
    refill never races the test.
  * The agent bucket store and its asyncio lock are reset for every test.
  * Each test uses its own temporary database and agent/key fixtures.

Covered behaviors:
  * A valid agent request within quota succeeds.
  * Exceeding the agent quota returns HTTP 429 and never invokes the endpoint.
  * The 429 response carries a numeric ``Retry-After`` header.
  * Buckets are independent per agent.
  * ``GREYWATCH_AGENT_RATE_LIMIT_ENABLED=0`` disables per-agent enforcement.
  * Failed agent authentication does not consume agent quota.
  * Legacy-token requests are not subject to per-agent limits.
  * The dual-credential request shape produced by Caddy (X-API-Key agent key
    plus shared Authorization) is still limited per agent.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.app import agents as agents_module
from backend.app import main
from backend.app.agents import create_agent, create_api_key
from backend.app.main import app as base_app

INGEST_PATH = "/api/v1/events/ingest"
LEGACY_TOKEN = "legacy-shared-secret"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


class FrozenClock:
    """Deterministic stand-in for the ``time`` module's monotonic clock."""

    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture(autouse=True)
def _deterministic_agent_rate_limit_state(monkeypatch):
    """Freeze the clock and reset the process-wide agent bucket store.

    The bucket store and lock are module globals in ``backend.app.agents``.
    Replacing them per test prevents state (and event-loop affinity) from
    leaking across tests.
    """
    clock = FrozenClock()
    monkeypatch.setattr(agents_module, "time", clock)
    monkeypatch.setattr(agents_module, "_agent_buckets", {})
    monkeypatch.setattr(agents_module, "_agent_buckets_lock", None)
    yield clock


@pytest.fixture
def agent_limits(monkeypatch):
    """Configure per-agent limits on demand (resolved on every request)."""

    def configure(ingestion: int = 1, burst: float = 1.0, enabled: bool = True) -> None:
        monkeypatch.setenv(
            "GREYWATCH_AGENT_RATE_LIMIT_ENABLED", "1" if enabled else "0"
        )
        monkeypatch.setenv("GREYWATCH_AGENT_RATE_INGESTION", str(ingestion))
        monkeypatch.setenv("GREYWATCH_AGENT_RATE_BURST", str(burst))

    return configure


@pytest.fixture
def ingest_calls(monkeypatch):
    """Stub the ingestion backend and record successful downstream calls."""
    calls: list[dict] = []

    def fake_ingest(lines, event_ids=None, agent_id=None):
        calls.append({"lines": lines, "agent_id": agent_id})
        return {
            "received": len(lines),
            "parsed": 0,
            "ignored": len(lines),
            "events": [],
            "alerts": [],
        }

    monkeypatch.setattr(main, "ingest_lines", fake_ingest)
    return calls


@pytest.fixture
def agent_client(tmp_path, monkeypatch, ingest_calls):
    """Real app with an isolated migrated database and stubbed ingestion."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "agent-rate-limit.db"))
    # Keep PBKDF2 cheap in tests; authentication resolves this consistently.
    monkeypatch.setenv("GREYWATCH_KEY_HASH_ITERATIONS", "1000")
    # Exercise the agent-auth path, not legacy-token or loopback-only paths.
    monkeypatch.delenv("GREYWATCH_API_TOKEN", raising=False)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "1")
    # Global limiting is out of scope here; the conftest autouse fixture also
    # disables it for the shared app.
    monkeypatch.setenv("GREYWATCH_RATE_LIMIT_ENABLED", "0")

    with TestClient(base_app) as client:
        yield client


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _make_agent_key(name: str) -> tuple[int, str]:
    agent = create_agent(name)
    key = create_api_key(agent.id)
    return agent.id, key.plaintext_key


def _post_ingest(client: TestClient, key: str):
    return client.post(
        INGEST_PATH,
        json={"lines": ["test event"]},
        headers={"Authorization": f"Bearer {key}"},
    )


# --------------------------------------------------------------------------- #
# Quota enforcement
# --------------------------------------------------------------------------- #


def test_agent_request_within_quota_succeeds(
    agent_client, agent_limits, ingest_calls
):
    """Requests within the configured agent quota reach the endpoint."""
    agent_limits(ingestion=2)
    _, key = _make_agent_key("within-quota")

    first = _post_ingest(agent_client, key)
    second = _post_ingest(agent_client, key)

    assert first.status_code == 200
    assert second.status_code == 200
    assert len(ingest_calls) == 2


def test_agent_exceeding_quota_returns_429(
    agent_client, agent_limits, ingest_calls
):
    """The request after the agent's quota is exhausted gets HTTP 429."""
    agent_limits(ingestion=1)
    _, key = _make_agent_key("over-quota")

    assert _post_ingest(agent_client, key).status_code == 200
    response = _post_ingest(agent_client, key)

    assert response.status_code == 429
    assert response.json() == {"detail": "Agent rate limit exceeded"}
    # The denied request must not reach the downstream endpoint.
    assert len(ingest_calls) == 1


def test_agent_429_includes_numeric_retry_after(agent_client, agent_limits):
    """A per-agent 429 response advertises a positive integer Retry-After."""
    agent_limits(ingestion=1)
    _, key = _make_agent_key("retry-after")

    assert _post_ingest(agent_client, key).status_code == 200
    response = _post_ingest(agent_client, key)

    assert response.status_code == 429
    retry_after = response.headers.get("Retry-After")
    assert retry_after is not None
    assert retry_after.isdigit()
    assert int(retry_after) >= 1


def test_different_agents_have_independent_buckets(
    agent_client, agent_limits, ingest_calls
):
    """Exhausting one agent's bucket does not consume another agent's quota."""
    agent_limits(ingestion=1)
    _, key_a = _make_agent_key("agent-a")
    _, key_b = _make_agent_key("agent-b")

    assert _post_ingest(agent_client, key_a).status_code == 200
    assert _post_ingest(agent_client, key_a).status_code == 429
    assert _post_ingest(agent_client, key_b).status_code == 200
    assert _post_ingest(agent_client, key_b).status_code == 429
    assert len(ingest_calls) == 2


def test_failed_agent_auth_does_not_consume_agent_quota(
    agent_client, agent_limits, ingest_calls
):
    """Authentication runs before enforcement: a 401 must not use a token."""
    agent_limits(ingestion=1)
    _, key = _make_agent_key("auth-before-limit")

    invalid = _post_ingest(agent_client, "gw_this-key-does-not-exist")
    assert invalid.status_code == 401

    assert _post_ingest(agent_client, key).status_code == 200
    assert len(ingest_calls) == 1


# --------------------------------------------------------------------------- #
# Configuration and non-agent callers
# --------------------------------------------------------------------------- #


def test_disabling_agent_rate_limit_allows_all(
    agent_client, agent_limits, ingest_calls
):
    """GREYWATCH_AGENT_RATE_LIMIT_ENABLED=0 disables per-agent enforcement."""
    agent_limits(ingestion=1, enabled=False)
    _, key = _make_agent_key("disabled-limit")

    for _ in range(5):
        assert _post_ingest(agent_client, key).status_code == 200
    assert len(ingest_calls) == 5


def test_legacy_token_requests_are_not_agent_rate_limited(
    agent_client, agent_limits, ingest_calls, monkeypatch
):
    """Legacy-token callers bypass per-agent buckets, even when one is full."""
    agent_limits(ingestion=1)
    monkeypatch.setenv("GREYWATCH_API_TOKEN", LEGACY_TOKEN)
    _, agent_key = _make_agent_key("legacy-bypass")

    # Exhaust the agent's bucket to prove enforcement is active in this env.
    assert _post_ingest(agent_client, agent_key).status_code == 200
    assert _post_ingest(agent_client, agent_key).status_code == 429

    # The legacy shared token has no per-agent identity, so every request is
    # allowed as far as the agent limiter is concerned.
    for _ in range(5):
        assert _post_ingest(agent_client, LEGACY_TOKEN).status_code == 200
    assert len(ingest_calls) == 6


def test_caddy_dual_header_request_is_rate_limited_per_agent(
    agent_client, agent_limits, ingest_calls, monkeypatch
):
    """Agent-key + shared-Authorization requests consume the agent's bucket.

    The agent key must be authenticated (not the shared token), so exhausting
    the agent quota yields 429 even though every request also carries a valid
    legacy credential. A legacy-only request still bypasses the agent bucket.
    """
    agent_limits(ingestion=1)
    monkeypatch.setenv("GREYWATCH_API_TOKEN", LEGACY_TOKEN)
    agent_id, key = _make_agent_key("caddy-dual-header-limit")

    dual_headers = {
        "Authorization": f"Bearer {LEGACY_TOKEN}",
        "X-API-Key": key,
    }

    first = agent_client.post(
        INGEST_PATH, json={"lines": ["test event"]}, headers=dual_headers
    )
    second = agent_client.post(
        INGEST_PATH, json={"lines": ["test event"]}, headers=dual_headers
    )

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json() == {"detail": "Agent rate limit exceeded"}
    assert len(ingest_calls) == 1
    assert ingest_calls[0]["agent_id"] == agent_id

    # Legacy-only traffic is governed by the global limiter, not this bucket.
    legacy = agent_client.post(
        INGEST_PATH,
        json={"lines": ["legacy event"]},
        headers={"X-Greywatch-Token": LEGACY_TOKEN},
    )
    assert legacy.status_code == 200
    assert len(ingest_calls) == 2
    assert ingest_calls[1]["agent_id"] is None
