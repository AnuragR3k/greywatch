import sqlite3
import time
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

def test_timestamped_failed_ssh_events_create_alert(tmp_path, monkeypatch):
    """Five timestamped failures within five minutes trigger an alert."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "timestamped.db"))

    # Traditional syslog timestamps are interpreted in the system's local timezone.
    now = datetime.now().astimezone().replace(microsecond=0)
    lines = [
        (
            f"{(now - timedelta(seconds=40 * (4 - i))).strftime('%b %d %H:%M:%S')} "
            f"lab-host sshd[510{i}]: Failed password for testuser "
            f"from 198.51.100.77 port {52000 + i} ssh2"
        )
        for i in range(5)
    ]

    response = client.post("/api/v1/events/ingest", json={"lines": lines})

    assert response.status_code == 200
    payload = response.json()
    assert payload["parsed"] == 5
    assert len(payload["alerts"]) == 1
    assert payload["alerts"][0]["rule_id"] == "SSH_BRUTE_FORCE"
    assert payload["alerts"][0]["event_count"] == 5


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


def test_evidence_matches_updated_event_count(tmp_path, monkeypatch):
    """After more failures arrive, event_count and evidence must agree.

    Regression test: the evidence window used to end at created_at, so
    failures ingested after the alert was created were counted on the alert
    but never returned as evidence.
    """
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "test.db"))
    alert = create_brute_force_alert()
    assert alert["event_count"] == 5

    # Cross a second boundary so created_at and last_triggered_at differ;
    # otherwise the old window end (created_at) would coincide with the new
    # one and mask the bug.
    time.sleep(1.1)

    # Two more failures from the same IP while the alert is still open.
    extra = [
        f"sshd[420{i}]: Failed password for later{i} "
        f"from 203.0.113.10 port {56000 + i} ssh2"
        for i in range(2)
    ]
    response = client.post("/api/v1/events/ingest", json={"lines": extra})
    assert response.status_code == 200
    payload = response.json()

    # The existing alert was updated, not duplicated.
    assert payload["alerts"] == []
    assert payload["parsed"] == 2

    detail = client.get(f"/api/v1/alerts/{alert['id']}")
    assert detail.status_code == 200
    body = detail.json()

    # The alert now reports 7 failed logins...
    assert body["alert"]["event_count"] == 7

    # ...and the evidence window ends at the last trigger, not created_at,
    # so the returned evidence agrees with the displayed count.
    last_triggered = body["alert"]["last_triggered_at"]
    assert last_triggered > body["alert"]["created_at"]
    assert body["evidence_window_end"] == last_triggered
    assert len(body["evidence_events"]) == body["alert"]["event_count"] == 7

    # Every returned event falls inside the window that produced the count.
    window_start = datetime.fromisoformat(body["evidence_window_start"])
    window_end = datetime.fromisoformat(body["evidence_window_end"])
    for event in body["evidence_events"]:
        timestamp = datetime.fromisoformat(event["timestamp"])
        assert window_start <= timestamp <= window_end
        assert event["source_ip"] == "203.0.113.10"
        assert event["event_type"] == "ssh_login_failed"

    # Both ingestion batches are represented in the evidence.
    raw_messages = "\n".join(
        event["raw_message"] for event in body["evidence_events"]
    )
    assert "Failed password for user0" in raw_messages
    assert "Failed password for later0" in raw_messages

def test_iso_timestamp_is_normalized_to_utc():
    line = (
        "2026-10-13T12:00:00+05:30 lab-host "
        "sshd[1234]: Failed password for demo "
        "from 198.51.100.20 port 54001 ssh2"
    )

    event = parse_auth_line(line)

    assert event is not None
    assert event["timestamp"] == "2026-10-13T06:30:00+00:00"

def test_migration_backfills_last_triggered_at(tmp_path, monkeypatch):
    """A database created before the column existed gains it safely."""
    db_path = tmp_path / "legacy.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))

    legacy = sqlite3.connect(db_path)
    legacy.executescript(
        """
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            description TEXT NOT NULL,
            event_count INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'open',
            closed_at TEXT
        );
        """
    )
    legacy.execute(
        """
        INSERT INTO alerts (
            created_at, rule_id, title, severity,
            source_ip, description, event_count, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
        """,
        (
            "2026-10-12T10:00:00+00:00",
            "SSH_BRUTE_FORCE",
            "Repeated SSH authentication failures",
            "high",
            "203.0.113.10",
            "Legacy alert",
            5,
        ),
    )
    legacy.commit()
    legacy.close()

    initialize_database()

    with _connection() as conn:
        row = conn.execute(
            "SELECT created_at, last_triggered_at FROM alerts WHERE id = 1"
        ).fetchone()

    # Backfilled from created_at so the window behaves as before the change.
    assert row["last_triggered_at"] == row["created_at"]

    # And the migrated alert serves evidence without errors.
    response = client.get("/api/v1/alerts/1")
    assert response.status_code == 200
    body = response.json()
    assert body["evidence_window_end"] == "2026-10-12T10:00:00+00:00"
    assert body["evidence_events"] == []


# --------------------------------------------------------------------------- #
# End-to-end: HTTP ingestion -> SSH_BRUTE_FORCE -> evidence
# --------------------------------------------------------------------------- #


def _failed_login_line(idx: int, source_ip: str, port: int = 54000) -> str:
    """A syslog-style sshd failed-password line.

    Lines intentionally omit a timestamp so ``parse_auth_line`` assigns the
    current time, guaranteeing the events land inside the detection window
    (``[now-5min, now]``) regardless of when the test runs.
    """
    return (
        f"sshd[60{idx}]: Failed password for attacker{idx} "
        f"from {source_ip} port {port + idx} ssh2"
    )


def test_end_to_end_http_detection_flow(tmp_path, monkeypatch):
    """Deterministic full-stack flow: HTTP ingest -> alert -> evidence.

    Exercises the real FastAPI ingestion endpoint, the shared detection engine,
    the alert-listing API, and the alert-detail/evidence API against an
    isolated temp database. No production data is touched and no real SSH
    activity occurs; everything is synthetic.

    Maps to the 9 end-to-end acceptance points:
      1. synthetic SSH failures sent via the ingestion API
      2. actual request schema + existing (5-in-5-min) threshold
      3. events accepted and stored
      4. SSH_BRUTE_FORCE fires at the threshold
      5. alert retrieved through the real alert API
      6. alert details + evidence retrieved through the detail API
      7. evidence consistent (timestamps, IP, usernames, count, raw messages)
      8. unrelated events + out-of-window events excluded from evidence
      9. repeated ingestion does not duplicate the alert
    """
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "e2e.db"))
    attack_ip = "203.0.113.10"

    # 1, 2, 3, 4: Ingest exactly the threshold (5) of failed logins.
    failed_lines = [_failed_login_line(i, attack_ip) for i in range(5)]
    ingest = client.post("/api/v1/events/ingest", json={"lines": failed_lines})
    assert ingest.status_code == 200
    body = ingest.json()

    assert body["received"] == 5
    assert body["parsed"] == 5
    assert body["ignored"] == 0
    assert len(body["alerts"]) == 1

    alert = body["alerts"][0]
    assert alert["rule_id"] == "SSH_BRUTE_FORCE"
    assert alert["severity"] == "high"
    assert alert["status"] == "open"
    assert alert["source_ip"] == attack_ip
    assert alert["event_count"] == 5

    # 3 (cont.): events persisted and retrievable from the event API.
    stored = client.get("/api/v1/events").json()
    assert stored["count"] == 5
    stored_raws = {e["raw_message"] for e in stored["events"]}
    for line in failed_lines:
        assert line in stored_raws
    assert all(e["source_ip"] == attack_ip for e in stored["events"])
    assert all(e["event_type"] == "ssh_login_failed" for e in stored["events"])

    # 5: the alert is retrievable through the real alert-listing API.
    alerts = client.get("/api/v1/alerts?status=all&limit=100").json()
    assert alerts["count"] == 1
    assert alerts["alerts"][0]["id"] == alert["id"]

    # 8 (unrelated events): a wrong-IP failure, a success, and an invalid-user
    # message from the target IP are all parsed and stored, but none may spawn a
    # new alert or pollute the target-IP alert.
    unrelated = [
        _failed_login_line(0, "198.51.100.99", port=56000),  # wrong source IP
        f"sshd[6100]: Accepted password for bystander from {attack_ip} port 56001 ssh2",
        f"sshd[6101]: Invalid user bystander from {attack_ip}",
    ]
    extra = client.post("/api/v1/events/ingest", json={"lines": unrelated})
    assert extra.status_code == 200
    extra_body = extra.json()
    assert extra_body["parsed"] == 3
    # No new alert: wrong-IP line is below threshold; target-IP failed count
    # is unchanged (the success/invalid_user lines are not counted).
    assert extra_body["alerts"] == []
    assert client.get("/api/v1/alerts?status=all&limit=100").json()["count"] == 1

    # 8 (out-of-window event): a failed login from the target IP whose
    # timestamp predates the evidence window must not be returned as evidence.
    # Inserted directly so it cannot influence the detection count.
    detail_before = client.get(f"/api/v1/alerts/{alert['id']}").json()
    window_start = datetime.fromisoformat(detail_before["evidence_window_start"])
    oow_ts = (window_start - timedelta(minutes=10)).astimezone(timezone.utc).isoformat(
        timespec="seconds"
    )
    with _connection() as conn:
        conn.execute(
            "INSERT INTO events (timestamp, host, event_type, username, "
            "source_ip, severity, raw_message, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                oow_ts,
                "old-host",
                "ssh_login_failed",
                "olduser",
                attack_ip,
                "medium",
                "OOW_" + oow_ts,
                "test",
            ),
        )

    # 9, 6, 7: Re-ingesting two more failures from the target IP updates the
    # existing alert (no duplicate) and the evidence grows to match.
    more_lines = [_failed_login_line(i, attack_ip, port=54100) for i in range(5, 7)]
    again = client.post("/api/v1/events/ingest", json={"lines": more_lines})
    assert again.status_code == 200
    again_body = again.json()
    assert again_body["parsed"] == 2
    assert again_body["alerts"] == []  # 9: no duplicate alert created

    assert client.get("/api/v1/alerts?status=open&limit=100").json()["count"] == 1
    assert client.get("/api/v1/alerts?status=all&limit=100").json()["count"] == 1

    detail = client.get(f"/api/v1/alerts/{alert['id']}").json()
    evidence = detail["evidence_events"]

    # 7: evidence is consistent with the stored in-window failed logins.
    assert detail["alert"]["event_count"] == 7
    assert len(evidence) == 7
    assert detail["evidence_window_start"] <= min(
        e["timestamp"] for e in evidence
    )
    assert detail["evidence_window_end"] >= max(
        e["timestamp"] for e in evidence
    )
    assert {e["source_ip"] for e in evidence} == {attack_ip}
    assert all(e["event_type"] == "ssh_login_failed" for e in evidence)
    assert all("OOW_" not in e["raw_message"] for e in evidence)  # 8: excluded
    assert not any(e["username"] == "bystander" for e in evidence)  # 8: excluded
    expected_users = {f"attacker{i}" for i in range(7)}
    assert {e["username"] for e in evidence} == expected_users
    expected_raws = {
        _failed_login_line(i, attack_ip) for i in range(5)
    } | {_failed_login_line(i, attack_ip, port=54100) for i in range(5, 7)}
    assert {e["raw_message"] for e in evidence} == expected_raws
    # Every evidence timestamp is within its claimed window.
    ws = datetime.fromisoformat(detail["evidence_window_start"])
    we = datetime.fromisoformat(detail["evidence_window_end"])
    for e in evidence:
        ts = datetime.fromisoformat(e["timestamp"])
        assert ws <= ts <= we


def test_below_threshold_does_not_create_alert(tmp_path, monkeypatch):
    """Below-threshold scenario: 4 failures (< 5) store events but raise no alert."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "below.db"))
    attack_ip = "203.0.113.10"
    lines = [_failed_login_line(i, attack_ip) for i in range(4)]

    res = client.post("/api/v1/events/ingest", json={"lines": lines})
    body = res.json()

    assert body["received"] == 4
    assert body["parsed"] == 4
    assert body["alerts"] == []

    events = client.get("/api/v1/events").json()
    assert events["count"] == 4
    assert client.get("/api/v1/alerts?status=all&limit=100").json()["count"] == 0


def test_brute_force_threshold_is_per_source_ip(tmp_path, monkeypatch):
    """At-threshold scenario: two IPs each at 5 failures yield two alerts."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "perip.db"))
    ip_a, ip_b = "203.0.113.10", "198.51.100.7"
    lines = [_failed_login_line(i, ip_a) for i in range(5)] + [
        _failed_login_line(i, ip_b, port=55000) for i in range(5)
    ]

    res = client.post("/api/v1/events/ingest", json={"lines": lines})
    body = res.json()

    assert body["parsed"] == 10
    assert len(body["alerts"]) == 2
    assert {a["source_ip"] for a in body["alerts"]} == {ip_a, ip_b}
    assert client.get("/api/v1/alerts?status=all&limit=100").json()["count"] == 2
