"""Tests for the cross-event correlation engine (Milestone 2).

Covers the ``SSH_BRUTE_FORCE_THEN_SUCCESS`` rule, the incidents schema and
CRUD/status transitions, the incident API (incl. auth gating), transaction
rollback/retry, and regression guards for the existing SSH and Suricata
detections.

Tests are hermetic: each sets ``GREYWATCH_DB`` to a temp path so the conftest
database-safety guard never touches ``data/greywatch.db``.
"""

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app import main
from backend.app.siem import (
    SSH_BRUTE_FORCE_THEN_SUCCESS_RULE,
    count_incidents,
    get_incident,
    ingest_events,
    initialize_database,
    list_incidents,
)

client = TestClient(main.app)

TOKEN = "test-secret-token-correlation"

ATTACK_IP = "203.0.113.10"
OTHER_IP = "198.51.100.7"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def _window_env(monkeypatch):
    """A 60-minute correlation window so tests control the time bounds."""
    monkeypatch.setenv("GREYWATCH_CORRELATION_WINDOW_MINUTES", "60")


@pytest.fixture
def _token_env(monkeypatch):
    """Network-exposed deployment: a shared-secret token is configured."""
    monkeypatch.setenv("GREYWATCH_API_TOKEN", TOKEN)
    monkeypatch.setenv("GREYWATCH_API_LOOPBACK_ONLY", "1")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _iso(minutes_offset: float) -> str:
    """ISO-8601 UTC timestamp ``minutes_offset`` from now."""
    return (
        datetime.now(timezone.utc) + timedelta(minutes=minutes_offset)
    ).isoformat(timespec="seconds")


def _ssh_event(
    event_type: str,
    source_ip: str,
    minutes_offset: float,
    username: str = "user",
) -> dict:
    """A normalized SSH event at a controlled timestamp."""
    return {
        "timestamp": _iso(minutes_offset),
        "host": "lab-host",
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "severity": "medium" if "failed" in event_type else "low",
        "raw_message": f"sshd[1]: {event_type} for {username} from {source_ip}",
        "source": "test",
    }


def _failures(count: int, source_ip: str, start_minutes_ago: float = 20) -> list[dict]:
    """``count`` failed logins spaced one minute apart ending ``start_minutes_ago``."""
    return [
        _ssh_event("ssh_login_failed", source_ip, -start_minutes_ago + i)
        for i in range(count)
    ]


def _ingest(events: list[dict], *, db_path) -> dict:
    import os

    os.environ["GREYWATCH_DB"] = str(db_path)
    initialize_database()
    return ingest_events(events)


# --------------------------------------------------------------------------- #
# Correlation rule
# --------------------------------------------------------------------------- #


def test_valid_correlation_creates_incident(tmp_path, _window_env, monkeypatch):
    """Five failures plus a same-IP success within the window -> one incident."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "valid.db"))
    events = [
        *_failures(5, ATTACK_IP, start_minutes_ago=20),
        _ssh_event("ssh_login_success", ATTACK_IP, -14),
    ]
    result = ingest_events(events)

    assert result["incidents"] is not None
    assert len(result["incidents"]) == 1
    incident = result["incidents"][0]
    assert incident["rule_id"] == SSH_BRUTE_FORCE_THEN_SUCCESS_RULE
    assert incident["title"] == "SSH brute force followed by successful login"
    assert incident["severity"] == "critical"
    assert incident["status"] == "open"
    assert incident["source_ip"] == ATTACK_IP
    assert incident["event_count"] == 5

    # Related events: 5 failures then the success, in chronological order.
    related = incident["related_event_ids"]
    assert len(related) == 6
    detail = get_incident(incident["id"])
    assert len(detail["related_events"]) == 6
    assert [e["event_type"] for e in detail["related_events"]] == [
        "ssh_login_failed",
    ] * 5 + ["ssh_login_success"]
    assert all(e["source_ip"] == ATTACK_IP for e in detail["related_events"])


def test_nonmatching_ip_no_incident(tmp_path, _window_env, monkeypatch):
    """A success from a different source IP must not correlate."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "nomatch.db"))
    events = [
        *_failures(5, ATTACK_IP, start_minutes_ago=20),
        _ssh_event("ssh_login_success", OTHER_IP, -14),
    ]
    result = ingest_events(events)

    assert result["incidents"] == []
    assert list_incidents(status="all") == []


def test_success_outside_window_no_incident(tmp_path, monkeypatch):
    """A success outside the correlation window must not correlate."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "oow.db"))
    monkeypatch.setenv("GREYWATCH_CORRELATION_WINDOW_MINUTES", "60")
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=60)
    # Failures and a success that all predate the window cutoff.
    events = [
        {
            **_ssh_event("ssh_login_failed", ATTACK_IP, 0),
            "timestamp": (cutoff - timedelta(minutes=10)).isoformat(timespec="seconds"),
        }
        for _ in range(5)
    ] + [
        {
            **_ssh_event("ssh_login_success", ATTACK_IP, 0),
            "timestamp": (cutoff - timedelta(minutes=5)).isoformat(timespec="seconds"),
        }
    ]
    result = ingest_events(events)

    assert result["incidents"] == []
    assert list_incidents(status="all") == []


def test_failures_without_success_no_incident(tmp_path, _window_env, monkeypatch):
    """Threshold failures alone produce an alert but no correlation incident.

    The successful-login signal is genuinely absent; the framework is in place
    but the complete attack pattern is not claimed.
    """
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "nosuccess.db"))
    # Failures inside the 5-minute brute-force window but with no success.
    result = ingest_events(_failures(5, ATTACK_IP, start_minutes_ago=4))

    assert result["incidents"] == []
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["rule_id"] == "SSH_BRUTE_FORCE"
    assert list_incidents(status="all") == []


def test_missing_source_ip_or_timestamp_skipped(tmp_path, _window_env, monkeypatch):
    """Events lacking a usable source IP or timestamp are skipped, not crashed."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "missing.db"))
    events = [
        *_failures(5, ATTACK_IP, start_minutes_ago=20),
        # Success with no source IP.
        {**_ssh_event("ssh_login_success", "", -14), "source_ip": None},
        # Success with an unusable timestamp.
        {**_ssh_event("ssh_login_success", ATTACK_IP, 0), "timestamp": "not-a-time"},
    ]
    result = ingest_events(events)

    assert result["incidents"] == []
    assert list_incidents(status="all") == []


def test_duplicate_evaluation_no_duplicate_incident(tmp_path, _window_env, monkeypatch):
    """Re-ingesting the same pattern creates exactly one incident."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "dup.db"))
    events = [
        *_failures(5, ATTACK_IP, start_minutes_ago=20),
        _ssh_event("ssh_login_success", ATTACK_IP, -14),
    ]
    first = ingest_events(events)
    second = ingest_events(events)

    assert len(first["incidents"]) == 1
    assert len(second["incidents"]) == 1
    assert first["incidents"][0]["id"] == second["incidents"][0]["id"]
    assert len(list_incidents(status="all")) == 1


# --------------------------------------------------------------------------- #
# Incident storage and status transitions
# --------------------------------------------------------------------------- #


def test_incident_status_transitions_via_api(tmp_path, monkeypatch):
    """Acknowledge and resolve transitions, including validation."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "transitions.db"))
    events = [
        *_failures(5, ATTACK_IP, start_minutes_ago=20),
        _ssh_event("ssh_login_success", ATTACK_IP, -14),
    ]
    ingest_events(events)
    incident_id = list_incidents(status="all")[0]["id"]

    # open -> acknowledged
    resp = client.post(f"/api/v1/incidents/{incident_id}/acknowledge")
    assert resp.status_code == 200
    assert resp.json()["status"] == "acknowledged"

    # acknowledged -> resolved
    resp = client.post(f"/api/v1/incidents/{incident_id}/resolve")
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"

    # resolved -> acknowledge is an invalid transition (409)
    resp = client.post(f"/api/v1/incidents/{incident_id}/acknowledge")
    assert resp.status_code == 409

    # resolve on an already-resolved incident is idempotent (200)
    resp = client.post(f"/api/v1/incidents/{incident_id}/resolve")
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"

    # unknown incident -> 404
    resp = client.post("/api/v1/incidents/999999/resolve")
    assert resp.status_code == 404

    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["status"] == "resolved"
    assert detail["closed_at"] is not None


def test_open_incident_can_resolve_directly(tmp_path, monkeypatch):
    """An open incident may resolve without acknowledging first."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "direct.db"))
    events = [
        *_failures(5, ATTACK_IP, start_minutes_ago=20),
        _ssh_event("ssh_login_success", ATTACK_IP, -14),
    ]
    ingest_events(events)
    incident_id = list_incidents(status="all")[0]["id"]

    resp = client.post(f"/api/v1/incidents/{incident_id}/resolve")
    assert resp.status_code == 200
    assert resp.json()["status"] == "resolved"


def test_incident_list_and_detail(tmp_path, _window_env, monkeypatch):
    """Incidents are listable and addressable with related events."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "detail.db"))
    events = [
        *_failures(5, ATTACK_IP, start_minutes_ago=20),
        _ssh_event("ssh_login_success", ATTACK_IP, -14),
    ]
    ingest_events(events)

    listed = client.get("/api/v1/incidents").json()
    assert listed["count"] == 1
    assert listed["incidents"][0]["rule_id"] == SSH_BRUTE_FORCE_THEN_SUCCESS_RULE

    incident_id = listed["incidents"][0]["id"]
    detail = client.get(f"/api/v1/incidents/{incident_id}").json()
    assert detail["id"] == incident_id
    assert detail["status"] == "open"
    assert len(detail["related_events"]) == 6
    # Chronological order: failures ascending, then the success.
    timestamps = [e["timestamp"] for e in detail["related_events"]]
    assert timestamps == sorted(timestamps)

    # Unknown incident -> 404
    assert client.get("/api/v1/incidents/999999").status_code == 404


# --------------------------------------------------------------------------- #
# Authentication gating (trust boundary preserved for incident endpoints)
# --------------------------------------------------------------------------- #


def test_incident_endpoints_require_auth_in_token_mode(
    tmp_path, _token_env, monkeypatch
):
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "auth.db"))
    events = [
        *_failures(5, ATTACK_IP, start_minutes_ago=20),
        _ssh_event("ssh_login_success", ATTACK_IP, -14),
    ]
    ingest_events(events)
    incident_id = list_incidents(status="all")[0]["id"]

    for method, path in [
        ("get", "/api/v1/incidents"),
        ("get", f"/api/v1/incidents/{incident_id}"),
        ("post", f"/api/v1/incidents/{incident_id}/acknowledge"),
        ("post", f"/api/v1/incidents/{incident_id}/resolve"),
    ]:
        assert getattr(client, method)(path).status_code == 401, path
        assert (
            getattr(client, method)(
                path, headers={"Authorization": f"Bearer {TOKEN}"}
            ).status_code
            == 200
        ), path
        assert (
            getattr(client, method)(
                path, headers={"X-API-Key": TOKEN}
            ).status_code
            == 200
        ), path


def test_incident_endpoints_remote_peer_rejected_default_mode(
    tmp_path, monkeypatch
):
    """Without a token, a non-loopback peer is rejected on incident endpoints."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "remote.db"))
    monkeypatch.setattr(main, "_is_loopback_host", lambda host: False)
    events = [
        *_failures(5, ATTACK_IP, start_minutes_ago=20),
        _ssh_event("ssh_login_success", ATTACK_IP, -14),
    ]
    ingest_events(events)
    incident_id = list_incidents(status="all")[0]["id"]

    assert client.get("/api/v1/incidents").status_code == 403
    assert client.get(f"/api/v1/incidents/{incident_id}").status_code == 403
    assert client.post(f"/api/v1/incidents/{incident_id}/resolve").status_code == 403


# --------------------------------------------------------------------------- #
# Transaction rollback and retry
# --------------------------------------------------------------------------- #


class _FailingConnection:
    """Wraps a real connection but fails INSERTs into ``incidents``.

    Used to simulate a mid-transation failure; the caller's ``_connection()``
    context manager must roll the whole batch back.
    """

    def __init__(self, connection: sqlite3.Connection):
        self._connection = connection

    def execute(self, sql, params=()):
        upper = sql.upper()
        if "INSERT" in upper and "INCIDENTS" in upper:
            raise sqlite3.OperationalError("simulated incident insert failure")
        return self._connection.execute(sql, params)

    def __getattr__(self, name):
        return getattr(self._connection, name)


def test_correlation_rollback_and_retry(tmp_path, monkeypatch):
    """A failed incident write rolls back; a retry succeeds (idempotent)."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "rollback.db"))
    initialize_database()
    events = [
        *_failures(5, ATTACK_IP, start_minutes_ago=20),
        _ssh_event("ssh_login_success", ATTACK_IP, -14),
    ]

    # First cycle: inject a failure into the correlation write path.
    from backend.app import siem

    real_connection = siem._connection
    try:

        @contextmanager
        def failing_connection():
            with real_connection() as conn:
                yield _FailingConnection(conn)

        siem._connection = failing_connection
        with pytest.raises(sqlite3.OperationalError):
            ingest_events(events)
    finally:
        siem._connection = real_connection

    # Rolled back: no incident is visible.
    assert list_incidents(status="all") == []

    # Retry with the real pipeline: the incident is created exactly once.
    result = ingest_events(events)
    assert len(result["incidents"]) == 1
    assert len(list_incidents(status="all")) == 1


# --------------------------------------------------------------------------- #
# Regression guards: Suricata must not trigger SSH correlation
# --------------------------------------------------------------------------- #


def test_suricata_events_do_not_trigger_ssh_correlation(
    tmp_path, _window_env, monkeypatch
):
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "suri.db"))
    suricata_event = {
        "timestamp": _iso(-14),
        "host": "sensor",
        "event_type": "suricata_alert",
        "username": None,
        "source_ip": ATTACK_IP,
        "severity": "high",
        "raw_message": '{"event_type":"alert","alert":{"signature":"ET TEST"}}',
        "source": "suricata",
        "signature": "ET TEST",
        "signature_id": "2001219",
        "category": "attempted-recon",
        "proto": "tcp",
        "src_port": 54321,
        "dest_port": 22,
        "dest_ip": "203.0.113.5",
    }
    result = ingest_events([suricata_event])

    assert result["incidents"] == []
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["rule_id"] == "SURICATA_ALERT"
    assert list_incidents(status="all") == []


def test_ssh_brute_force_alert_regression(tmp_path, _window_env, monkeypatch):
    """Existing SSH brute-force detection still produces one alert."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "regression.db"))
    # Failures inside the 5-minute brute-force window.
    result = ingest_events(_failures(5, ATTACK_IP, start_minutes_ago=4))

    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["rule_id"] == "SSH_BRUTE_FORCE"
    assert result["alerts"][0]["severity"] == "high"
    assert result["alerts"][0]["status"] == "open"


def _make_incident(db_path, ip, monkeypatch):
    """Create one ``SSH_BRUTE_FORCE_THEN_SUCCESS`` incident for ``ip``."""
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    initialize_database()
    events = [
        *_failures(5, ip, start_minutes_ago=20),
        _ssh_event("ssh_login_success", ip, -14),
    ]
    return ingest_events(events)["incidents"][0]


def test_list_incidents_offset_pagination(tmp_path, _window_env, monkeypatch):
    """list_incidents honors limit/offset and count_incidents reports the total."""
    db_path = tmp_path / "paginate.db"
    ips = [f"203.0.113.{10 + i}" for i in range(7)]
    for ip in ips:
        _make_incident(db_path, ip, monkeypatch)

    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    initialize_database()

    assert count_incidents(status="all") == 7

    first = list_incidents(status="all", limit=3, offset=0)
    assert len(first) == 3

    second = list_incidents(status="all", limit=3, offset=3)
    assert len(second) == 3
    assert {i["id"] for i in second}.isdisjoint({i["id"] for i in first})

    third = list_incidents(status="all", limit=3, offset=6)
    assert len(third) == 1

    fourth = list_incidents(status="all", limit=3, offset=9)
    assert fourth == []


def test_list_incidents_offset_clamps_negative(tmp_path, _window_env, monkeypatch):
    """A negative offset is treated as zero rather than erroring."""
    db_path = tmp_path / "clamp.db"
    _make_incident(db_path, ATTACK_IP, monkeypatch)

    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    initialize_database()

    assert len(list_incidents(status="all", limit=5, offset=-5)) == 1


def test_incidents_api_pagination_returns_total_and_offset(
    tmp_path, _window_env, monkeypatch
):
    """GET /api/v1/incidents supports limit/offset and returns total count."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "api_paginate.db"))
    initialize_database()

    ips = [f"203.0.113.{20 + i}" for i in range(5)]
    for ip in ips:
        events = [
            *_failures(5, ip, start_minutes_ago=20),
            _ssh_event("ssh_login_success", ip, -14),
        ]
        ingest_events(events)

    # Page 1: limit 2, offset 0.
    r1 = client.get("/api/v1/incidents?status=all&limit=2&offset=0")
    assert r1.status_code == 200
    b1 = r1.json()
    assert b1["total"] == 5
    assert b1["count"] == 2
    assert len(b1["incidents"]) == 2

    # Page 2: limit 2, offset 2 — no overlap with page 1.
    r2 = client.get("/api/v1/incidents?status=all&limit=2&offset=2")
    assert r2.status_code == 200
    b2 = r2.json()
    assert b2["total"] == 5
    assert b2["count"] == 2
    assert len(b2["incidents"]) == 2
    assert {i["id"] for i in b2["incidents"]}.isdisjoint(
        {i["id"] for i in b1["incidents"]}
    )

    # Page 3: offset 4 -> single remaining item.
    r3 = client.get("/api/v1/incidents?status=all&limit=2&offset=4")
    assert r3.status_code == 200
    b3 = r3.json()
    assert b3["total"] == 5
    assert b3["count"] == 1
    assert len(b3["incidents"]) == 1

    # Beyond range: empty page, total still reported.
    r4 = client.get("/api/v1/incidents?status=all&limit=2&offset=10")
    assert r4.status_code == 200
    b4 = r4.json()
    assert b4["total"] == 5
    assert b4["count"] == 0
    assert b4["incidents"] == []
