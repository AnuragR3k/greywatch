from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.siem import (
    _connection,
    initialize_database,
    parse_auth_line,
)

client = TestClient(app)


def create_brute_force_alert(source_ip="203.0.113.10", count=5):
    """Ingest failed SSH logins and return the created alert dict."""
    lines = [
        f"sshd[410{i}]: Failed password for user{i} "
        f"from {source_ip} port {54000 + i} ssh2"
        for i in range(count)
    ]
    response = client.post("/api/v1/events/ingest", json={"lines": lines})
    assert response.status_code == 200
    payload = response.json()
    assert len(payload["alerts"]) == 1
    return payload["alerts"][0]


def test_parse_failed_ssh_login():
    line = (
        "Oct 12 19:41:23 lab-host sshd[1234]: "
        "Failed password for invalid user admin "
        "from 203.0.113.10 port 54001 ssh2"
    )

    event = parse_auth_line(line)

    assert event is not None
    assert event["host"] == "lab-host"
    assert event["event_type"] == "ssh_login_failed"
    assert event["username"] == "admin"
    assert event["source_ip"] == "203.0.113.10"
    assert event["severity"] == "medium"


def test_parse_successful_ssh_login():
    line = (
        "Oct 12 19:41:23 lab-host sshd[1234]: "
        "Accepted publickey for demo "
        "from 192.0.2.20 port 54006 ssh2"
    )

    event = parse_auth_line(line)

    assert event is not None
    assert event["event_type"] == "ssh_login_success"
    assert event["username"] == "demo"
    assert event["source_ip"] == "192.0.2.20"


def test_unrecognized_line_is_ignored():
    assert parse_auth_line("kernel: device initialized") is None


def test_repeated_failures_create_alert(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "test.db"))

    lines = [
        (
            f"sshd[410{i}]: Failed password for user{i} "
            f"from 203.0.113.10 port {54000 + i} ssh2"
        )
        for i in range(5)
    ]

    response = client.post(
        "/api/v1/events/ingest",
        json={"lines": lines},
    )

    assert response.status_code == 200
    payload = response.json()

    assert payload["received"] == 5
    assert payload["parsed"] == 5
    assert payload["ignored"] == 0
    assert len(payload["alerts"]) == 1
    assert payload["alerts"][0]["rule_id"] == "SSH_BRUTE_FORCE"
    assert payload["alerts"][0]["severity"] == "high"

    event_response = client.get("/api/v1/events")
    assert event_response.status_code == 200
    assert event_response.json()["count"] == 5

    alert_response = client.get("/api/v1/alerts")
    assert alert_response.status_code == 200
    assert alert_response.json()["count"] == 1


def test_alert_detail_returns_details_and_evidence(tmp_path, monkeypatch):
    """An existing brute-force alert returns its details and evidence events."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "test.db"))
    alert = create_brute_force_alert()

    response = client.get(f"/api/v1/alerts/{alert['id']}")
    assert response.status_code == 200

    payload = response.json()

    # Alert details
    assert payload["alert"]["id"] == alert["id"]
    assert payload["alert"]["rule_id"] == "SSH_BRUTE_FORCE"
    assert payload["alert"]["title"] == "Repeated SSH authentication failures"
    assert payload["alert"]["severity"] == "high"
    assert payload["alert"]["status"] == "open"
    assert payload["alert"]["source_ip"] == "203.0.113.10"
    assert payload["alert"]["event_count"] == 5
    assert "created_at" in payload["alert"]

    # Evidence time window
    assert "evidence_window_start" in payload
    assert "evidence_window_end" in payload
    assert payload["evidence_window_start"] <= payload["evidence_window_end"]

    # Evidence events
    assert len(payload["evidence_events"]) == 5
    assert payload["evidence_events"][0]["event_type"] == "ssh_login_failed"


def test_evidence_events_include_raw_messages(tmp_path, monkeypatch):
    """Evidence events include their original raw log messages and all fields."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "test.db"))
    alert = create_brute_force_alert()

    response = client.get(f"/api/v1/alerts/{alert['id']}")
    assert response.status_code == 200

    events = response.json()["evidence_events"]
    assert len(events) == 5

    required_fields = {
        "id", "timestamp", "host", "event_type",
        "username", "source_ip", "severity", "raw_message",
    }
    for event in events:
        assert required_fields <= set(event.keys())
        assert event["raw_message"]
        assert "Failed password" in event["raw_message"]
        assert event["source_ip"] == "203.0.113.10"
        assert event["event_type"] == "ssh_login_failed"


def test_unknown_alert_returns_404(tmp_path, monkeypatch):
    """An unknown alert ID returns HTTP 404."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "test.db"))

    response = client.get("/api/v1/alerts/9999")
    assert response.status_code == 404
    assert "detail" in response.json()


def test_alert_no_matching_evidence(tmp_path, monkeypatch):
    """An alert with no matching evidence events is handled without crashing."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "test.db"))
    alert = create_brute_force_alert()

    # Remove all events to simulate purged evidence while the alert persists.
    initialize_database()
    with _connection() as conn:
        conn.execute("DELETE FROM events")

    response = client.get(f"/api/v1/alerts/{alert['id']}")
    assert response.status_code == 200

    payload = response.json()
    assert payload["alert"]["id"] == alert["id"]
    assert payload["evidence_events"] == []
    assert "evidence_window_start" in payload
    assert "evidence_window_end" in payload


def test_events_outside_evidence_window_excluded(tmp_path, monkeypatch):
    """Events outside the defined evidence time window are excluded."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "test.db"))
    alert = create_brute_force_alert()

    # Fetch the alert to obtain the evidence window boundaries.
    detail = client.get(f"/api/v1/alerts/{alert['id']}").json()
    created_at = datetime.fromisoformat(detail["alert"]["created_at"])
    window_start = datetime.fromisoformat(detail["evidence_window_start"])
    window_end = datetime.fromisoformat(detail["evidence_window_end"])

    # An event well before the window start — same source IP and type, so it
    # would only be filtered out by the time-window boundary.
    before_time = (
        created_at
        - timedelta(minutes=10)
    ).astimezone(timezone.utc).isoformat(timespec="seconds")
    before_msg = f"BEFORE_WINDOW_{before_time}"

    # An event well after the window end.
    after_time = (
        created_at
        + timedelta(minutes=10)
    ).astimezone(timezone.utc).isoformat(timespec="seconds")
    after_msg = f"AFTER_WINDOW_{after_time}"

    initialize_database()
    with _connection() as conn:
        conn.execute(
            """
            INSERT INTO events
                (timestamp, host, event_type, username, source_ip, severity, raw_message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                before_time,
                "old-host",
                "ssh_login_failed",
                "olduser",
                "203.0.113.10",
                "medium",
                before_msg,
            ),
        )
        conn.execute(
            """
            INSERT INTO events
                (timestamp, host, event_type, username, source_ip, severity, raw_message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                after_time,
                "future-host",
                "ssh_login_failed",
                "futuser",
                "203.0.113.10",
                "medium",
                after_msg,
            ),
        )

    response = client.get(f"/api/v1/alerts/{alert['id']}")
    assert response.status_code == 200

    events = response.json()["evidence_events"]

    # Only the five original in-window events should be returned.
    assert len(events) == 5

    # Every returned event must fall inside the evidence window.
    for event in events:
        ts = datetime.fromisoformat(event["timestamp"])
        assert window_start <= ts <= window_end

    # Events outside the window must not appear.
    raw_messages = [event["raw_message"] for event in events]
    assert before_msg not in raw_messages
    assert after_msg not in raw_messages
