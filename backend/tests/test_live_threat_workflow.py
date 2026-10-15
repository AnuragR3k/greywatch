"""Automated verification of Greywatch's live SSH brute-force detection workflow.

These tests are the executable, hermetic counterpart to
``scripts/live_ssh_brute_force_test.sh``. They exercise the *real* FastAPI
router (via ``TestClient``) plus the real detection engine against a temporary,
per-test SQLite database, using synthetic data and reserved documentation IPs
(RFC 5737: 203.0.113.0/24, 192.0.2.0/24, 198.51.100.0/24).

They deliberately complement (not duplicate) the deeper scenario coverage in
``test_siem.py`` (which already covers below-threshold, per-source-IP, and
out-of-window exclusion). These two tests pin the *live workflow contract* and
the *provenance distinction* that the dashboard relies on to tell synthetic
HTTP-ingested events apart from genuine journal / Suricata telemetry.
"""

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.siem import ingest_events, ingest_lines

client = TestClient(app)

# Reserved documentation IPs — never routable, never target external systems.
ATTACK_IP = "203.0.113.10"
JOURNAL_IP = "192.0.2.5"
SURICATA_IP = "198.51.100.7"


def _failed_login_line(idx: int, source_ip: str, port: int = 54000) -> str:
    """A syslog-style sshd failed-password line.

    No timestamp is embedded so ``parse_auth_line`` assigns the current time,
    guaranteeing the event lands inside the detection window
    (``[now-5min, now]``) regardless of when the test runs.
    """
    return (
        f"sshd[600{idx}]: Failed password for attacker{idx} "
        f"from {source_ip} port {port + idx} ssh2"
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def test_ssh_brute_force_live_detection_contract(tmp_path, monkeypatch):
    """Acceptance contract for the live SSH brute-force workflow.

    Mirrors docs/LIVE_THREAT_TEST.md: 5 synthetic failed logins via the real
    HTTP ingestion endpoint on an isolated DB must produce exactly one
    SSH_BRUTE_FORCE alert whose evidence window contains all 5 events.
    """
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "live.db"))

    # 1, 2, 3: five failed SSH logins from one reserved source IP.
    lines = [_failed_login_line(i, ATTACK_IP) for i in range(5)]
    resp = client.post("/api/v1/events/ingest", json={"lines": lines})
    assert resp.status_code == 200
    body = resp.json()
    assert body["received"] == 5
    assert body["parsed"] == 5
    assert body["ignored"] == 0
    assert len(body["events"]) == 5
    assert len(body["alerts"]) == 1

    # 3 (cont.): events are persisted and retrievable through the events API.
    events = client.get("/api/v1/events?limit=100").json()
    assert events["count"] == 5
    assert all(e["event_type"] == "ssh_login_failed" for e in events["events"])
    assert all(e["source_ip"] == ATTACK_IP for e in events["events"])

    # 4: the alert is persisted with the expected rule, severity, IP, count.
    alert = body["alerts"][0]
    assert alert["rule_id"] == "SSH_BRUTE_FORCE"
    assert alert["severity"] == "high"
    assert alert["status"] == "open"
    assert alert["source_ip"] == ATTACK_IP
    assert alert["event_count"] == 5

    # 5, 6: the alert is retrievable through the alerting API with evidence.
    alerts = client.get("/api/v1/alerts?status=all&limit=100").json()
    assert alerts["count"] == 1
    assert alerts["alerts"][0]["id"] == alert["id"]

    detail = client.get(f"/api/v1/alerts/{alert['id']}").json()
    assert detail["alert"]["event_count"] == 5
    assert len(detail["evidence_events"]) == 5
    assert {e["source_ip"] for e in detail["evidence_events"]} == {ATTACK_IP}
    assert all(
        e["event_type"] == "ssh_login_failed"
        for e in detail["evidence_events"]
    )


def test_synthetic_events_are_distinguished_from_journal_and_suricata(
    tmp_path, monkeypatch
):
    """Provenance distinction (dashboard §4).

    HTTP-ingested events carry ``source=NULL`` (rendered as 'HTTP ingest'),
    journal events carry ``source='journal'`` ('systemd journal'), and Suricata
    EVE events carry ``source='suricata'`` ('Suricata'). The dashboard's
    ``eventSourceLabel``/``eventSourceTone`` derive their badges from this field,
    so the distinction is observable in the data contract consumed by the UI.
    """
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "prov.db"))

    # Synthetic SSH failures via the HTTP path -> source is NULL.
    lines = [_failed_login_line(i, ATTACK_IP) for i in range(5)]
    http = client.post("/api/v1/events/ingest", json={"lines": lines}).json()
    assert http["parsed"] == 5
    assert all(e.get("source") is None for e in http["events"])

    # A genuine-looking journal event, tagged source='journal'.
    journal_event = {
        "timestamp": _now_iso(),
        "host": "lab-host",
        "event_type": "ssh_login_failed",
        "username": "juser",
        "source_ip": JOURNAL_IP,
        "severity": "medium",
        "raw_message": "journalctl: Failed password for juser from 192.0.2.5",
        "source": "journal",
    }
    # A genuine-looking Suricata EVE event, tagged source='suricata'.
    suricata_event = {
        "timestamp": _now_iso(),
        "host": "lab-host",
        "event_type": "suricata_alert",
        "username": None,
        "source_ip": SURICATA_IP,
        "severity": "high",
        "raw_message": "suricata: ET SCAN Potential SSH Scan",
        "source": "suricata",
        "signature": "ET SCAN Potential SSH Scan",
        "signature_id": "2001219",
        "category": "attempted-recon",
        "proto": "tcp",
        "src_port": 54321,
        "dest_port": 22,
        "dest_ip": "203.0.113.5",
    }
    ingest_events([journal_event, suricata_event])

    # 7 events total: 5 HTTP-sourced + 1 journal + 1 suricata.
    events = client.get("/api/v1/events?limit=100").json()
    assert events["count"] == 7
    sources = {e.get("source") for e in events["events"]}
    assert sources == {None, "journal", "suricata"}  # NULL, journal, suricata
    assert (
        sum(1 for e in events["events"] if e.get("source") is None) == 5
    )
    assert sum(1 for e in events["events"] if e.get("source") == "journal") == 1
    assert sum(1 for e in events["events"] if e.get("source") == "suricata") == 1

    # Unlike journal/HTTP events (which only become SSH_BRUTE_FORCE alerts), a
    # Suricata ``alert`` raises its own Greywatch alert (SURICATA_ALERT). The
    # two incident sources are still distinguished by the event ``source``
    # column, so the SSH and Suricata alerts never collide.
    alerts = client.get("/api/v1/alerts?status=all&limit=100").json()
    assert alerts["count"] == 2
    by_rule = {a["rule_id"] for a in alerts["alerts"]}
    assert by_rule == {"SSH_BRUTE_FORCE", "SURICATA_ALERT"}
    ssh = next(a for a in alerts["alerts"] if a["rule_id"] == "SSH_BRUTE_FORCE")
    suri = next(a for a in alerts["alerts"] if a["rule_id"] == "SURICATA_ALERT")
    assert ssh["source_ip"] == ATTACK_IP
    assert suri["source_ip"] == SURICATA_IP
    assert suri["signature"] == "ET SCAN Potential SSH Scan"
    assert suri["severity"] == "high"


def test_ingest_lines_api_still_accepts_mixed_lines(tmp_path, monkeypatch):
    """Regression guard: the HTTP ingestion path remains backward compatible.

    A mix of a failed login, a successful login, an invalid user, and an
    unrecognized line must parse the auth-related ones and ignore the rest,
    without changing the detection contract.
    """
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "mixed.db"))
    mixed = [
        _failed_login_line(0, ATTACK_IP),
        "sshd[6100]: Accepted publickey for bystander from 203.0.113.10 port 56001 ssh2",
        "sshd[6101]: Invalid user bystander from 203.0.113.10",
        "this line is not an auth event and should be ignored",
    ]
    body = ingest_lines(mixed)
    assert body["received"] == 4
    assert body["parsed"] == 3
    assert body["ignored"] == 1
    types = {e["event_type"] for e in body["events"]}
    assert types == {
        "ssh_login_failed",
        "ssh_login_success",
        "ssh_invalid_user",
    }
    # Single failure is below the threshold -> no alert.
    assert body["alerts"] == []
