"""HTTP-level regression tests for the agent/API-key administration API (H3).

The admin routes are ordinary FastAPI handlers protected centrally by the
``_trust_boundary`` middleware. These tests deliberately exercise the whole
stack -- test client, middleware, routing, Pydantic validation, handlers,
transactions, migrations, and the audit chain -- rather than calling the
``backend.app.agents`` functions directly.

Coverage:
  * every admin endpoint with missing, invalid, valid, and agent credentials;
  * loopback and token trust-boundary modes, including a genuine remote peer;
  * request validation, unknown identifiers, duplicate/conflicting operations;
  * successful lifecycle behavior and exact audit events;
  * audit-persistence failure with rollback at the HTTP boundary;
  * list/audit pagination, filtering, and ordering;
  * one-time plaintext handling and non-exposure of hashes/secrets;
  * revoked and time-expired key behavior.

The test database is isolated per test by the ``admin_client`` fixture. PBKDF2
iterations are reduced only for test speed; production defaults are unchanged.
"""

from __future__ import annotations

import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from backend.app import agents as agents_module
from backend.app.audit_chain import verify_chain
from backend.app.main import app

TOKEN = "test-admin-shared-token-not-for-production"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
INGEST_PATH = "/api/v1/events/ingest"

# Every admin route, with a syntactically valid path. Authentication and
# authorization are evaluated before routing/validation, so these are safe for
# denial tests without seeding data.
ENDPOINTS = [
    ("GET", "/api/v1/admin/agents", None),
    ("GET", "/api/v1/admin/agents/1", None),
    ("POST", "/api/v1/admin/agents", {"name": "auth-probe"}),
    ("PATCH", "/api/v1/admin/agents/1", {"display_name": "probe"}),
    ("POST", "/api/v1/admin/agents/1/deactivate", {"reason": "probe"}),
    ("GET", "/api/v1/admin/agents/1/keys", None),
    ("POST", "/api/v1/admin/agents/1/keys", {"name": "probe"}),
    ("POST", "/api/v1/admin/keys/1/revoke", {"reason": "probe"}),
    ("POST", "/api/v1/admin/keys/1/rotate", None),
    ("GET", "/api/v1/admin/audit-log", None),
]


# --------------------------------------------------------------------------- #
# Fixtures and helpers
# --------------------------------------------------------------------------- #


def _make_client(tmp_path, monkeypatch, *, peer=("testclient", 50000)) -> TestClient:
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "admin-api.db"))
    monkeypatch.setenv("GREYWATCH_API_TOKEN", TOKEN)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "1")
    monkeypatch.setenv("GREYWATCH_KEY_HASH_ITERATIONS", "1000")
    monkeypatch.setenv("GREYWATCH_RATE_LIMIT_ENABLED", "0")
    monkeypatch.setenv("GREYWATCH_PREAUTH_RATE_LIMIT_ENABLED", "0")
    return TestClient(app, raise_server_exceptions=False, client=peer)


@pytest.fixture
def admin_client(tmp_path, monkeypatch):
    """Local loopback client with the shared admin token configured."""
    with _make_client(tmp_path, monkeypatch) as client:
        yield client


@pytest.fixture
def remote_client(tmp_path, monkeypatch):
    """A genuinely non-loopback peer (ASGI client address is not testclient)."""
    with _make_client(
        tmp_path, monkeypatch, peer=("203.0.113.7", 51234)
    ) as client:
        yield client


@pytest.fixture
def admin_state(admin_client):
    """One active agent and one active key created through the HTTP API."""
    agent = _create_agent(admin_client, "state-agent")
    key = _create_key(admin_client, agent["id"], name="state-key")
    return agent, key


@pytest.fixture
def step_clock(monkeypatch):
    """Monotonic UTC clock so list/audit ordering is deterministic.

    Production truncates timestamps to whole seconds, which makes records
    created in the same second tie. The endpoint's documented order is
    ``timestamp DESC``; feeding distinct timestamps lets the tests assert it
    without relying on SQLite tie-breaking.
    """

    class Clock:
        def __init__(self) -> None:
            self.value = datetime(2026, 1, 1, tzinfo=timezone.utc)

        def __call__(self) -> str:
            current = self.value
            self.value += timedelta(seconds=1)
            return current.isoformat()

    monkeypatch.setattr(agents_module, "_utc_now", Clock())


def _request(client, method, path, body=None, headers=None, params=None):
    """Issue an HTTP request; ``headers=None`` means use the admin token."""
    return client.request(
        method,
        path,
        json=body,
        headers=AUTH if headers is None else headers,
        params=params,
    )


def _create_agent(client, name="test-agent", **fields):
    response = client.post(
        "/api/v1/admin/agents", json={"name": name, **fields}, headers=AUTH
    )
    assert response.status_code == 200, response.text
    return response.json()


def _create_key(client, agent_id, **fields):
    response = client.post(
        f"/api/v1/admin/agents/{agent_id}/keys", json=fields, headers=AUTH
    )
    assert response.status_code == 200, response.text
    return response.json()


def _audit_entries(client, **params):
    response = client.get(
        "/api/v1/admin/audit-log", headers=AUTH, params=params
    )
    assert response.status_code == 200, response.text
    return response.json()["entries"]


def _db() -> sqlite3.Connection:
    connection = sqlite3.connect(os.environ["GREYWATCH_DB"])
    connection.row_factory = sqlite3.Row
    return connection


def _verify_chain():
    connection = _db()
    try:
        return verify_chain(connection)
    finally:
        connection.close()


def _stored_key_hash(key_id: int) -> str:
    connection = _db()
    try:
        row = connection.execute(
            "SELECT key_hash FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()
    finally:
        connection.close()
    assert row is not None
    return row["key_hash"]


@contextmanager
def _audit_insert_failure() -> Iterator[None]:
    """Make every audit INSERT abort, simulating audit storage failure."""
    connection = sqlite3.connect(os.environ["GREYWATCH_DB"])
    try:
        connection.execute(
            """
            CREATE TRIGGER fail_audit_insert
            BEFORE INSERT ON audit_log
            BEGIN
                SELECT RAISE(ABORT, 'simulated audit persistence failure');
            END
            """
        )
        connection.commit()
    finally:
        connection.close()
    try:
        yield
    finally:
        connection = sqlite3.connect(os.environ["GREYWATCH_DB"])
        try:
            connection.execute("DROP TRIGGER IF EXISTS fail_audit_insert")
            connection.commit()
        finally:
            connection.close()


# --------------------------------------------------------------------------- #
# Authentication and trust boundary
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer wrong-token"},
        {"X-API-Key": "wrong-token"},
        {"X-Greywatch-Token": "wrong-token"},
    ],
    ids=["missing", "wrong-bearer", "wrong-api-key", "wrong-proxy-token"],
)
def test_admin_endpoints_require_valid_shared_token(admin_client, headers):
    """Every admin endpoint rejects missing/invalid shared credentials with 401."""
    for method, path, body in ENDPOINTS:
        response = _request(admin_client, method, path, body, headers=headers)
        assert response.status_code == 401, (method, path, response.text)


def test_all_shared_token_header_forms_authorize_admin_api(admin_client):
    """Bearer, X-API-Key, and proxy-injected X-Greywatch-Token are equivalent."""
    for headers in (
        {"Authorization": f"Bearer {TOKEN}"},
        {"X-API-Key": TOKEN},
        {"X-Greywatch-Token": TOKEN},
    ):
        response = admin_client.get("/api/v1/admin/agents", headers=headers)
        assert response.status_code == 200, response.text


def test_loopback_without_token_can_use_admin_api(admin_client, monkeypatch):
    """Default local deployment: a loopback peer needs no shared token."""
    monkeypatch.delenv("GREYWATCH_API_TOKEN", raising=False)
    response = admin_client.get("/api/v1/admin/agents")
    assert response.status_code == 200, response.text


def test_remote_peer_rejected_in_loopback_mode(remote_client, monkeypatch):
    """A non-loopback peer is denied when no token is configured."""
    monkeypatch.delenv("GREYWATCH_API_TOKEN", raising=False)
    response = remote_client.get("/api/v1/admin/agents")
    assert response.status_code == 403
    assert "local host" in response.json()["detail"]


def test_remote_peer_with_valid_token_is_allowed(remote_client):
    """Token mode authenticates remote administrators through the boundary."""
    response = remote_client.get("/api/v1/admin/agents", headers=AUTH)
    assert response.status_code == 200, response.text


def test_remote_peer_allowed_when_loopback_only_is_disabled(
    remote_client, monkeypatch
):
    """``GREYWATCH_API_LOOPBACK_ONLY=0`` trusts a peer-authenticating proxy."""
    monkeypatch.delenv("GREYWATCH_API_TOKEN", raising=False)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "0")
    response = remote_client.get("/api/v1/admin/agents")
    assert response.status_code == 200, response.text


def test_valid_agent_key_forbidden_on_every_admin_endpoint(admin_client, admin_state):
    """A valid agent key is an ingestion credential, never an admin credential."""
    agent, key = admin_state
    paths = [
        ("GET", "/api/v1/admin/agents", None),
        ("GET", f"/api/v1/admin/agents/{agent['id']}", None),
        ("POST", "/api/v1/admin/agents", {"name": "agent-key-must-not-create"}),
        ("PATCH", f"/api/v1/admin/agents/{agent['id']}", {"display_name": "x"}),
        (
            "POST",
            f"/api/v1/admin/agents/{agent['id']}/deactivate",
            {"reason": "x"},
        ),
        ("GET", f"/api/v1/admin/agents/{agent['id']}/keys", None),
        ("POST", f"/api/v1/admin/agents/{agent['id']}/keys", {"name": "x"}),
        ("POST", f"/api/v1/admin/keys/{key['id']}/revoke", {"reason": "x"}),
        ("POST", f"/api/v1/admin/keys/{key['id']}/rotate", None),
        ("GET", "/api/v1/admin/audit-log", None),
    ]
    agent_headers = {"X-API-Key": key["plaintext_key"]}
    for method, path, body in paths:
        response = _request(admin_client, method, path, body, headers=agent_headers)
        assert response.status_code == 403, (method, path, response.text)
        assert "restricted to ingestion" in response.json()["detail"]

    # Dual credentials must not downgrade the agent key to shared-token auth.
    dual = admin_client.get(
        "/api/v1/admin/agents",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "X-API-Key": key["plaintext_key"],
        },
    )
    assert dual.status_code == 403

    # None of the denied mutation attempts may have taken effect.
    listed = admin_client.get("/api/v1/admin/agents", headers=AUTH).json()
    assert [row["name"] for row in listed["agents"]] == ["state-agent"]
    assert admin_client.get(
        f"/api/v1/admin/agents/{agent['id']}/keys", headers=AUTH
    ).json()["keys"][0]["status"] == "active"


def test_invalid_agent_key_is_not_downgraded_to_shared_token(admin_client):
    """A ``gw_*`` credential is exclusive even when a valid token is present."""
    response = admin_client.get(
        "/api/v1/admin/agents",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "X-API-Key": "gw_this-key-does-not-exist",
        },
    )
    assert response.status_code == 401
    assert "agent API key" in response.json()["detail"]


def test_revoked_agent_key_is_not_downgraded_to_shared_token(
    admin_client, admin_state
):
    """A revoked agent key never falls back to the shared admin token."""
    _, key = admin_state
    revoked = admin_client.post(
        f"/api/v1/admin/keys/{key['id']}/revoke",
        json={"reason": "test"},
        headers=AUTH,
    )
    assert revoked.status_code == 200

    response = admin_client.get(
        "/api/v1/admin/agents",
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "X-API-Key": key["plaintext_key"],
        },
    )
    assert response.status_code == 401


@pytest.mark.parametrize(
    "case",
    [
        "list-agents",
        "get-agent",
        "create-agent",
        "update-agent",
        "deactivate-agent",
        "list-keys",
        "create-key",
        "revoke-key",
        "rotate-key",
        "audit-log",
    ],
)
def test_valid_admin_credentials_authorize_each_endpoint(
    admin_client, admin_state, case
):
    """Every endpoint succeeds with a valid shared token (fresh state per case)."""
    agent, key = admin_state
    cases = {
        "list-agents": ("GET", "/api/v1/admin/agents", None),
        "get-agent": ("GET", f"/api/v1/admin/agents/{agent['id']}", None),
        "create-agent": (
            "POST",
            "/api/v1/admin/agents",
            {"name": "created-through-endpoint"},
        ),
        "update-agent": (
            "PATCH",
            f"/api/v1/admin/agents/{agent['id']}",
            {"display_name": "Updated"},
        ),
        "deactivate-agent": (
            "POST",
            f"/api/v1/admin/agents/{agent['id']}/deactivate",
            {"reason": "test deactivation"},
        ),
        "list-keys": (
            "GET",
            f"/api/v1/admin/agents/{agent['id']}/keys",
            None,
        ),
        "create-key": (
            "POST",
            f"/api/v1/admin/agents/{agent['id']}/keys",
            {"name": "created-through-endpoint"},
        ),
        "revoke-key": (
            "POST",
            f"/api/v1/admin/keys/{key['id']}/revoke",
            {"reason": "test revocation"},
        ),
        "rotate-key": (
            "POST",
            f"/api/v1/admin/keys/{key['id']}/rotate",
            None,
        ),
        "audit-log": ("GET", "/api/v1/admin/audit-log", None),
    }
    method, path, body = cases[case]
    response = _request(admin_client, method, path, body)
    assert response.status_code == 200, response.text


# --------------------------------------------------------------------------- #
# Request validation, unknown identifiers, and conflicts
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"name": ""},
        {"name": "bad name!"},
        {"name": "x" * 129},
        {"name": "ok", "display_name": "x" * 257},
        {"name": "ok", "description": "x" * 1025},
    ],
)
def test_create_agent_rejects_malformed_payload(admin_client, payload):
    response = admin_client.post(
        "/api/v1/admin/agents", json=payload, headers=AUTH
    )
    assert response.status_code == 422, response.text


@pytest.mark.parametrize(
    "payload",
    [
        {"display_name": "x" * 257},
        {"description": "x" * 1025},
    ],
)
def test_update_agent_rejects_malformed_payload(admin_client, admin_state, payload):
    agent, _ = admin_state
    response = admin_client.patch(
        f"/api/v1/admin/agents/{agent['id']}", json=payload, headers=AUTH
    )
    assert response.status_code == 422, response.text


@pytest.mark.parametrize("payload", [{}, {"reason": ""}, {"reason": "x" * 513}])
def test_deactivate_rejects_malformed_payload(admin_client, admin_state, payload):
    agent, _ = admin_state
    response = admin_client.post(
        f"/api/v1/admin/agents/{agent['id']}/deactivate",
        json=payload,
        headers=AUTH,
    )
    assert response.status_code == 422, response.text


@pytest.mark.parametrize(
    "payload",
    [
        {"expires_at": "not-a-timestamp"},
        {"expires_at": "2026-01-01"},
        # A timezone is optional in the schema pattern; naive values are
        # interpreted as UTC by the authentication path.
        {"name": "x" * 129},
    ],
)
def test_create_key_rejects_malformed_payload(admin_client, admin_state, payload):
    agent, _ = admin_state
    response = admin_client.post(
        f"/api/v1/admin/agents/{agent['id']}/keys",
        json=payload,
        headers=AUTH,
    )
    assert response.status_code == 422, response.text


@pytest.mark.parametrize("payload", [{}, {"reason": ""}, {"reason": "x" * 513}])
def test_revoke_key_rejects_malformed_payload(admin_client, admin_state, payload):
    _, key = admin_state
    response = admin_client.post(
        f"/api/v1/admin/keys/{key['id']}/revoke",
        json=payload,
        headers=AUTH,
    )
    assert response.status_code == 422, response.text


def test_unknown_agent_identifiers_return_404(admin_client):
    assert admin_client.get(
        "/api/v1/admin/agents/999999", headers=AUTH
    ).status_code == 404
    assert admin_client.patch(
        "/api/v1/admin/agents/999999",
        json={"display_name": "x"},
        headers=AUTH,
    ).status_code == 404
    assert admin_client.post(
        "/api/v1/admin/agents/999999/deactivate",
        json={"reason": "x"},
        headers=AUTH,
    ).status_code == 404
    assert admin_client.get(
        "/api/v1/admin/agents/999999/keys", headers=AUTH
    ).status_code == 404
    assert admin_client.post(
        "/api/v1/admin/agents/999999/keys",
        json={"name": "x"},
        headers=AUTH,
    ).status_code == 404


def test_unknown_key_identifiers_use_documented_statuses(admin_client):
    """Unknown revoke is 404; unknown rotate is 409 (ValueError mapping)."""
    assert admin_client.post(
        "/api/v1/admin/keys/999999/revoke",
        json={"reason": "x"},
        headers=AUTH,
    ).status_code == 404
    assert admin_client.post(
        "/api/v1/admin/keys/999999/rotate", headers=AUTH
    ).status_code == 409


def test_malformed_path_identifiers_return_422(admin_client):
    assert admin_client.get(
        "/api/v1/admin/agents/not-an-int", headers=AUTH
    ).status_code == 422
    assert admin_client.post(
        "/api/v1/admin/keys/not-an-int/revoke",
        json={"reason": "x"},
        headers=AUTH,
    ).status_code == 422


def test_duplicate_agent_name_is_conflict(admin_client):
    _create_agent(admin_client, "duplicate-agent")
    response = admin_client.post(
        "/api/v1/admin/agents", json={"name": "duplicate-agent"}, headers=AUTH
    )
    assert response.status_code == 409
    assert "already exists" in response.json()["detail"]
    assert len(_audit_entries(admin_client, event_type="agent_created")) == 1


def test_repeated_deactivation_is_conflict(admin_client, admin_state):
    agent, _ = admin_state
    first = admin_client.post(
        f"/api/v1/admin/agents/{agent['id']}/deactivate",
        json={"reason": "first"},
        headers=AUTH,
    )
    assert first.status_code == 200
    second = admin_client.post(
        f"/api/v1/admin/agents/{agent['id']}/deactivate",
        json={"reason": "second"},
        headers=AUTH,
    )
    assert second.status_code == 409


def test_key_creation_and_rotation_on_inactive_agent_conflict(
    admin_client, admin_state
):
    agent, key = admin_state
    assert admin_client.post(
        f"/api/v1/admin/agents/{agent['id']}/deactivate",
        json={"reason": "test"},
        headers=AUTH,
    ).status_code == 200

    create = admin_client.post(
        f"/api/v1/admin/agents/{agent['id']}/keys",
        json={"name": "too-late"},
        headers=AUTH,
    )
    assert create.status_code == 409
    rotate = admin_client.post(
        f"/api/v1/admin/keys/{key['id']}/rotate", headers=AUTH
    )
    assert rotate.status_code == 409


def test_repeated_revocation_and_rotation_of_revoked_key_conflict(
    admin_client, admin_state
):
    _, key = admin_state
    assert admin_client.post(
        f"/api/v1/admin/keys/{key['id']}/revoke",
        json={"reason": "first"},
        headers=AUTH,
    ).status_code == 200

    second = admin_client.post(
        f"/api/v1/admin/keys/{key['id']}/revoke",
        json={"reason": "second"},
        headers=AUTH,
    )
    assert second.status_code == 409
    rotate = admin_client.post(
        f"/api/v1/admin/keys/{key['id']}/rotate", headers=AUTH
    )
    assert rotate.status_code == 409


@pytest.mark.parametrize(
    "path,params",
    [
        ("/api/v1/admin/agents", {"status": "bogus"}),
        ("/api/v1/admin/agents", {"limit": 0}),
        ("/api/v1/admin/agents", {"limit": 501}),
        ("/api/v1/admin/agents", {"offset": -1}),
        ("/api/v1/admin/agents/1/keys", {"status": "bogus"}),
        ("/api/v1/admin/audit-log", {"limit": 0}),
        ("/api/v1/admin/audit-log", {"limit": 501}),
        ("/api/v1/admin/audit-log", {"offset": -1}),
        ("/api/v1/admin/audit-log", {"agent_id": "not-an-int"}),
    ],
)
def test_list_query_validation(admin_client, path, params):
    response = admin_client.get(path, headers=AUTH, params=params)
    assert response.status_code == 422, response.text


# --------------------------------------------------------------------------- #
# Successful lifecycle, audit events, and secret handling
# --------------------------------------------------------------------------- #


def test_full_lifecycle_emits_expected_audit_events(admin_client, step_clock):
    created = _create_agent(
        admin_client, "lifecycle-agent", display_name="Initial", description="Before"
    )
    agent_id = created["id"]

    listed = admin_client.get("/api/v1/admin/agents", headers=AUTH).json()
    assert [row["name"] for row in listed["agents"]] == ["lifecycle-agent"]

    detail = admin_client.get(
        f"/api/v1/admin/agents/{agent_id}", headers=AUTH
    ).json()
    assert detail["display_name"] == "Initial"
    assert detail["status"] == "active"

    updated = admin_client.patch(
        f"/api/v1/admin/agents/{agent_id}",
        json={"display_name": "Renamed", "description": "After"},
        headers=AUTH,
    )
    assert updated.status_code == 200
    assert updated.json()["display_name"] == "Renamed"
    assert updated.json()["description"] == "After"

    key = _create_key(admin_client, agent_id, name="primary")
    assert re.fullmatch(r"gw_[A-Za-z0-9_-]{43}", key["plaintext_key"])
    assert key["key_prefix"] == key["plaintext_key"][:8]

    listed_keys = admin_client.get(
        f"/api/v1/admin/agents/{agent_id}/keys", headers=AUTH
    ).json()
    assert [row["id"] for row in listed_keys["keys"]] == [key["id"]]
    assert listed_keys["keys"][0]["status"] == "active"

    rotated = admin_client.post(
        f"/api/v1/admin/keys/{key['id']}/rotate", headers=AUTH
    )
    assert rotated.status_code == 200
    new_key = rotated.json()
    assert new_key["id"] != key["id"]
    assert new_key["plaintext_key"] != key["plaintext_key"]

    keys_after_rotation = admin_client.get(
        f"/api/v1/admin/agents/{agent_id}/keys", headers=AUTH
    ).json()["keys"]
    by_id = {row["id"]: row for row in keys_after_rotation}
    assert by_id[key["id"]]["status"] == "revoked"
    assert by_id[key["id"]]["revoked_reason"] == "Rotated by admin_api"
    assert by_id[new_key["id"]]["status"] == "active"

    revoked = admin_client.post(
        f"/api/v1/admin/keys/{new_key['id']}/revoke",
        json={"reason": "end of test"},
        headers=AUTH,
    )
    assert revoked.status_code == 200

    deactivated = admin_client.post(
        f"/api/v1/admin/agents/{agent_id}/deactivate",
        json={"reason": "finished"},
        headers=AUTH,
    )
    assert deactivated.status_code == 200
    final_agent = admin_client.get(
        f"/api/v1/admin/agents/{agent_id}", headers=AUTH
    ).json()
    assert final_agent["status"] == "inactive"
    assert final_agent["deactivated_reason"] == "finished"

    entries = _audit_entries(admin_client, agent_id=agent_id, limit=500)
    assert [entry["event_type"] for entry in reversed(entries)] == [
        "agent_created",
        "agent_updated",
        "key_generated",
        "key_rotated",
        "key_revoked",
        "agent_deactivated",
    ]
    assert all(entry["actor"] == "admin_api" for entry in entries)
    assert _verify_chain() == (True, [])

    # Read/audit responses must never expose the one-time plaintext or hash.
    stored_hash = _stored_key_hash(key["id"])
    for response_text in (
        admin_client.get("/api/v1/admin/agents", headers=AUTH).text,
        admin_client.get(f"/api/v1/admin/agents/{agent_id}", headers=AUTH).text,
        admin_client.get(
            f"/api/v1/admin/agents/{agent_id}/keys", headers=AUTH
        ).text,
        admin_client.get("/api/v1/admin/audit-log", headers=AUTH).text,
    ):
        assert key["plaintext_key"] not in response_text
        assert new_key["plaintext_key"] not in response_text
        assert stored_hash not in response_text
        assert "key_hash" not in response_text
        assert "plaintext_key" not in response_text


def test_key_creation_response_shows_plaintext_once_but_never_the_hash(
    admin_client, admin_state
):
    agent, _ = admin_state
    response = admin_client.post(
        f"/api/v1/admin/agents/{agent['id']}/keys",
        json={"name": "one-time"},
        headers=AUTH,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["plaintext_key"].startswith("gw_")
    assert "key_hash" not in response.text

    stored_hash = _stored_key_hash(body["id"])
    assert stored_hash not in response.text
    listed = admin_client.get(
        f"/api/v1/admin/agents/{agent['id']}/keys", headers=AUTH
    )
    assert body["plaintext_key"] not in listed.text
    assert stored_hash not in listed.text


def test_deactivation_bulk_revokes_keys_with_one_audit_event(
    admin_client, step_clock
):
    agent = _create_agent(admin_client, "bulk-revoke")
    first = _create_key(admin_client, agent["id"], name="first")
    second = _create_key(admin_client, agent["id"], name="second")

    assert admin_client.post(
        f"/api/v1/admin/agents/{agent['id']}/deactivate",
        json={"reason": "bulk"},
        headers=AUTH,
    ).status_code == 200

    keys = admin_client.get(
        f"/api/v1/admin/agents/{agent['id']}/keys", headers=AUTH
    ).json()["keys"]
    assert {row["id"] for row in keys} == {first["id"], second["id"]}
    assert all(row["status"] == "revoked" for row in keys)
    assert all(row["revoked_reason"] == "Agent deactivated: bulk" for row in keys)

    events = [
        entry["event_type"]
        for entry in reversed(_audit_entries(admin_client, agent_id=agent["id"]))
    ]
    assert events == [
        "agent_created",
        "key_generated",
        "key_generated",
        "agent_deactivated",
    ]


def test_noop_agent_update_emits_no_audit_event(admin_client):
    agent = _create_agent(admin_client, "noop-update")
    response = admin_client.patch(
        f"/api/v1/admin/agents/{agent['id']}", json={}, headers=AUTH
    )
    assert response.status_code == 200
    assert response.json()["display_name"] is None
    assert [
        entry["event_type"]
        for entry in _audit_entries(admin_client, agent_id=agent["id"])
    ] == ["agent_created"]


# --------------------------------------------------------------------------- #
# Pagination, filtering, ordering
# --------------------------------------------------------------------------- #


def test_agent_list_pagination_filtering_and_ordering(admin_client, step_clock):
    for index in range(5):
        _create_agent(admin_client, f"page-agent-{index}")

    first = admin_client.get(
        "/api/v1/admin/agents",
        headers=AUTH,
        params={"limit": 2, "offset": 0},
    ).json()
    second = admin_client.get(
        "/api/v1/admin/agents",
        headers=AUTH,
        params={"limit": 2, "offset": 2},
    ).json()
    last = admin_client.get(
        "/api/v1/admin/agents",
        headers=AUTH,
        params={"limit": 2, "offset": 4},
    ).json()

    assert [row["name"] for row in first["agents"]] == [
        "page-agent-4",
        "page-agent-3",
    ]
    assert [row["name"] for row in second["agents"]] == [
        "page-agent-2",
        "page-agent-1",
    ]
    assert [row["name"] for row in last["agents"]] == ["page-agent-0"]
    assert first["count"] == 2  # count is the page size, not a total.

    # Status filtering.
    newest_id = first["agents"][0]["id"]
    assert admin_client.post(
        f"/api/v1/admin/agents/{newest_id}/deactivate",
        json={"reason": "filter test"},
        headers=AUTH,
    ).status_code == 200
    inactive = admin_client.get(
        "/api/v1/admin/agents", headers=AUTH, params={"status": "inactive"}
    ).json()
    active = admin_client.get(
        "/api/v1/admin/agents", headers=AUTH, params={"status": "active"}
    ).json()
    revoked = admin_client.get(
        "/api/v1/admin/agents", headers=AUTH, params={"status": "revoked"}
    ).json()
    assert [row["name"] for row in inactive["agents"]] == ["page-agent-4"]
    assert len(active["agents"]) == 4
    assert revoked["count"] == 0


def test_key_list_filtering_and_ordering(admin_client, step_clock):
    agent = _create_agent(admin_client, "key-list")
    keys = [
        _create_key(admin_client, agent["id"], name=f"key-{index}")
        for index in range(3)
    ]
    assert admin_client.post(
        f"/api/v1/admin/keys/{keys[1]['id']}/revoke",
        json={"reason": "filter test"},
        headers=AUTH,
    ).status_code == 200

    all_keys = admin_client.get(
        f"/api/v1/admin/agents/{agent['id']}/keys", headers=AUTH
    ).json()["keys"]
    assert [row["id"] for row in all_keys] == [
        keys[2]["id"],
        keys[1]["id"],
        keys[0]["id"],
    ]

    active = admin_client.get(
        f"/api/v1/admin/agents/{agent['id']}/keys",
        headers=AUTH,
        params={"status": "active"},
    ).json()["keys"]
    revoked = admin_client.get(
        f"/api/v1/admin/agents/{agent['id']}/keys",
        headers=AUTH,
        params={"status": "revoked"},
    ).json()["keys"]
    assert [row["id"] for row in active] == [keys[2]["id"], keys[0]["id"]]
    assert [row["id"] for row in revoked] == [keys[1]["id"]]


def test_audit_log_pagination_filtering_and_ordering(admin_client, step_clock):
    first = _create_agent(admin_client, "audit-page-0")
    second = _create_agent(admin_client, "audit-page-1")
    _create_key(admin_client, second["id"], name="audit-key")
    assert admin_client.patch(
        f"/api/v1/admin/agents/{second['id']}",
        json={"display_name": "Audited"},
        headers=AUTH,
    ).status_code == 200

    page_one = _audit_entries(
        admin_client, agent_id=second["id"], limit=2, offset=0
    )
    page_two = _audit_entries(
        admin_client, agent_id=second["id"], limit=2, offset=2
    )
    assert [entry["event_type"] for entry in page_one] == [
        "agent_updated",
        "key_generated",
    ]
    assert [entry["event_type"] for entry in page_two] == ["agent_created"]
    assert page_one[0]["timestamp"] >= page_one[1]["timestamp"]

    generated = _audit_entries(admin_client, event_type="key_generated")
    assert len(generated) == 1
    assert generated[0]["agent_id"] == second["id"]

    created = _audit_entries(admin_client, event_type="agent_created", limit=500)
    assert [entry["agent_id"] for entry in created] == [
        second["id"],
        first["id"],
    ]

    filtered = _audit_entries(
        admin_client,
        agent_id=second["id"],
        event_type="agent_updated",
    )
    assert len(filtered) == 1
    assert filtered[0]["actor"] == "admin_api"


# --------------------------------------------------------------------------- #
# Revoked and expired key behavior
# --------------------------------------------------------------------------- #


def test_revoked_key_is_rejected_for_ingestion_and_listed_as_revoked(
    admin_client, admin_state
):
    agent, key = admin_state
    assert admin_client.post(
        f"/api/v1/admin/keys/{key['id']}/revoke",
        json={"reason": "compromised"},
        headers=AUTH,
    ).status_code == 200

    ingest = admin_client.post(
        INGEST_PATH,
        json={"lines": ["test"]},
        headers={"X-API-Key": key["plaintext_key"]},
    )
    assert ingest.status_code == 401

    listed = admin_client.get(
        f"/api/v1/admin/agents/{agent['id']}/keys",
        headers=AUTH,
        params={"status": "revoked"},
    ).json()["keys"]
    assert len(listed) == 1
    assert listed[0]["revoked_reason"] == "compromised"


def test_expired_key_is_rejected_but_remains_status_active(
    admin_client, admin_state
):
    """Document current expiry semantics: auth enforces expires_at; status stays active.

    There is no background job that flips ``api_keys.status`` to ``expired``,
    so the ``status=expired`` admin filter does not currently match a key whose
    ``expires_at`` has passed. This test pins that behavior so a future change
    is deliberate and documented.
    """
    agent, _ = admin_state
    agent_id = agent["id"]
    expired = _create_key(
        admin_client,
        agent_id,
        name="expired-key",
        expires_at="2000-01-01T00:00:00Z",
    )

    ingest = admin_client.post(
        INGEST_PATH,
        json={"lines": ["test"]},
        headers={"X-API-Key": expired["plaintext_key"]},
    )
    assert ingest.status_code == 401

    all_keys = admin_client.get(
        f"/api/v1/admin/agents/{agent_id}/keys", headers=AUTH
    ).json()["keys"]
    row = next(item for item in all_keys if item["id"] == expired["id"])
    assert row["status"] == "active"
    assert row["expires_at"] == "2000-01-01T00:00:00Z"

    expired_filter = admin_client.get(
        f"/api/v1/admin/agents/{agent_id}/keys",
        headers=AUTH,
        params={"status": "expired"},
    ).json()
    assert expired_filter["count"] == 0

    failures = _audit_entries(
        admin_client, event_type="auth_failure", agent_id=agent_id
    )
    assert any("key_expired" in (entry["detail"] or "") for entry in failures)


# --------------------------------------------------------------------------- #
# Audit persistence failure and rollback
# --------------------------------------------------------------------------- #


def test_audit_failure_returns_500_and_rolls_back_every_lifecycle_mutation(
    admin_client,
):
    agent = _create_agent(admin_client, "audit-failure-target")
    agent_id = agent["id"]
    key = _create_key(admin_client, agent_id, name="audit-failure-key")
    key_id = key["id"]
    assert _verify_chain() == (True, [])

    with _audit_insert_failure():
        create = admin_client.post(
            "/api/v1/admin/agents",
            json={"name": "unaudited-agent"},
            headers=AUTH,
        )
        assert create.status_code == 500

        update = admin_client.patch(
            f"/api/v1/admin/agents/{agent_id}",
            json={"display_name": "unaudited"},
            headers=AUTH,
        )
        assert update.status_code == 500

        create_key = admin_client.post(
            f"/api/v1/admin/agents/{agent_id}/keys",
            json={"name": "unaudited-key"},
            headers=AUTH,
        )
        assert create_key.status_code == 500
        # The failed response must not leak the generated one-time key or the
        # simulated storage error details.
        assert "gw_" not in create_key.text
        assert "simulated audit" not in create_key.text

        rotate = admin_client.post(
            f"/api/v1/admin/keys/{key_id}/rotate", headers=AUTH
        )
        assert rotate.status_code == 500

        revoke = admin_client.post(
            f"/api/v1/admin/keys/{key_id}/revoke",
            json={"reason": "unaudited"},
            headers=AUTH,
        )
        assert revoke.status_code == 500

        deactivate = admin_client.post(
            f"/api/v1/admin/agents/{agent_id}/deactivate",
            json={"reason": "unaudited"},
            headers=AUTH,
        )
        assert deactivate.status_code == 500

        # All state must be exactly as it was before the failed attempts.
        listed = admin_client.get("/api/v1/admin/agents", headers=AUTH).json()
        assert [row["name"] for row in listed["agents"]] == [
            "audit-failure-target"
        ]
        unchanged = admin_client.get(
            f"/api/v1/admin/agents/{agent_id}", headers=AUTH
        ).json()
        assert unchanged["display_name"] is None
        assert unchanged["status"] == "active"

        keys = admin_client.get(
            f"/api/v1/admin/agents/{agent_id}/keys", headers=AUTH
        ).json()["keys"]
        assert [row["id"] for row in keys] == [key_id]
        assert keys[0]["status"] == "active"

        assert len(_audit_entries(admin_client)) == 2
        assert _verify_chain() == (True, [])

    # Once audit storage is healthy, the API recovers and the chain continues.
    recovered = admin_client.post(
        "/api/v1/admin/agents",
        json={"name": "recovered-after-audit-failure"},
        headers=AUTH,
    )
    assert recovered.status_code == 200, recovered.text
    assert len(_audit_entries(admin_client)) == 3
    assert _verify_chain() == (True, [])
