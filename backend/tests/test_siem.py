from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.siem import parse_auth_line

client = TestClient(app)


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
