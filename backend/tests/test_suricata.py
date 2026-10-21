"""Tests for the Suricata EVE JSON integration.

These tests are hermetic and require no Suricata installation: EVE JSON records
are written to temp files and ingested in-process through the real FastAPI
stack. The live ``data/greywatch.db`` is never touched (each test gets a fresh
temp database via ``GREYWATCH_DB``).

Coverage targets from the task:
* field normalization (alert/dns/tls/http/flow + severity + timestamp)
* malformed-record robustness (non-JSON, blank, unknown event types)
* successful ingestion + storage with ``source="suricata"``
* duplicate handling (within a batch, across cycles via offset, and on
  rotation reset via content de-duplication)
* collector progress (offset advance + idle cycle + append resume)
* missing-file resilience (no crash; error reported)
* the existing SSH brute-force rule is unaffected
* API status/collect endpoints + dashboard field compatibility
"""

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.app import siem, suricata as suricata_mod
from backend.app.suricata import (
    SuricataConfig,
    collect_once,
    parse_eve_record,
    status,
)
from backend.app.main import app
from backend.app.siem import (
    _connection,
    get_collector_setting,
    initialize_database,
    list_events,
)

client = TestClient(app)


# --------------------------------------------------------------------------- #
# Helpers / fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture
def _db(tmp_path, monkeypatch):
    """Point the collector + API at a fresh temp database for the test."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "test.db"))
    initialize_database()
    yield tmp_path


def _write_eve(path, records):
    """Write EVE JSON lines (dict or raw str) to ``path``, one per line."""
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(rec if isinstance(rec, str) else json.dumps(rec))
            fh.write("\n")
    return path


def _alert_line(i, src="203.0.113.66", ts=None):
    """Build a realistic, sanitized Suricata EVE alert record (as a JSON str)."""
    if ts is None:
        ts = f"2024-10-12T08:00:0{i}.220741Z"
    record = {
        "timestamp": ts,
        "event_type": "alert",
        "src_ip": src,
        "dest_ip": "198.51.100.7",
        "src_port": 51022,
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "signature_id": 2023000 + i,
            "signature": f"ET SCAN test signature {i}",
            "severity": 1,
            "category": "attempted-recon",
        },
    }
    return json.dumps(record)


def _network_line(event_type, ts=None):
    """Build a sanitized EVE record of a non-alert network event type."""
    if ts is None:
        ts = "2024-10-12T08:00:09.000000Z"
    record = {
        "timestamp": ts,
        "event_type": event_type,
        "src_ip": "203.0.113.66",
        "dest_ip": "198.51.100.7",
        "src_port": 54128,
        "dest_port": 53,
        "proto": "UDP",
        event_type: {"note": "context preserved in raw_message"},
    }
    return json.dumps(record)


def _event_rows():
    with _connection() as conn:
        rows = conn.execute("SELECT * FROM events").fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------- #
# Parsing / field normalization
# --------------------------------------------------------------------------- #


def test_parse_eve_alert_record():
    raw = _alert_line(0)
    record = json.loads(raw)
    event = parse_eve_record(record, raw_line=raw)
    assert event is not None
    # Canonical 8-key event shape + extended network/IDS fields.
    assert event["timestamp"] == "2024-10-12T08:00:00+00:00"
    assert event["host"] == "unknown"
    assert event["event_type"] == "suricata_alert"
    assert event["username"] is None
    assert event["source_ip"] == "203.0.113.66"
    assert event["severity"] == "high"  # Suricata severity 1 -> high
    assert event["raw_message"] == raw  # verbatim provenance
    assert event["source"] == "suricata"
    assert event["dest_ip"] == "198.51.100.7"
    assert event["src_port"] == 51022
    assert event["dest_port"] == 22
    assert event["proto"] == "TCP"
    assert event["signature"] == "ET SCAN test signature 0"
    assert event["signature_id"] == 2023000
    assert event["category"] == "attempted-recon"


@pytest.mark.parametrize("event_type", ["dns", "tls", "http", "flow"])
def test_parse_eve_network_types_extract_common_fields(event_type):
    raw = _network_line(event_type)
    event = parse_eve_record(json.loads(raw), raw_line=raw)
    assert event is not None
    assert event["event_type"] == f"suricata_{event_type}"
    # Network fields from the existing schema are populated for all types.
    assert event["source_ip"] == "203.0.113.66"
    assert event["dest_ip"] == "198.51.100.7"
    assert event["src_port"] == 54128
    assert event["dest_port"] == 53
    assert event["proto"] == "UDP"
    assert event["source"] == "suricata"
    assert event["severity"] == "low"  # non-alert events are contextual
    # Non-alert types carry no signature/alert metadata.
    assert event["signature"] is None
    assert event["signature_id"] is None
    assert event["category"] is None


@pytest.mark.parametrize(
    "record, raw",
    [
        (None, "null"),
        ("not-a-record", "string"),
        (42, "number"),
        ({}, "empty"),
        ({"event_type": "stats"}, "unknown-type"),
        ({"event_type": "alert"}, "no-timestamp"),
        ({"event_type": "alert", "timestamp": "not-a-real-timestamp"}, "bad-timestamp"),
        ({"event_type": "dns"}, "dns-no-timestamp"),
    ],
)
def test_parse_skips_invalid_records(record, raw):
    assert parse_eve_record(record, raw_line=raw) is None


def test_parse_eve_severity_mapping():
    for sev_in, sev_out in [
        (0, "high"),
        (1, "high"),
        (2, "medium"),
        (3, "low"),
        (4, "low"),
        (9, "low"),  # unknown severity floors to low
    ]:
        raw = json.dumps(
            {
                "timestamp": "2024-10-12T08:00:00Z",
                "event_type": "alert",
                "src_ip": "203.0.113.66",
                "alert": {"signature_id": 1, "severity": sev_in},
            }
        )
        ev = parse_eve_record(json.loads(raw), raw_line=raw)
        assert ev["severity"] == sev_out, f"severity {sev_in} -> {sev_out}"
    # Missing severity on the alert object defaults to low.
    raw = json.dumps(
        {"timestamp": "2024-10-12T08:00:00Z", "event_type": "alert"}
    )
    assert parse_eve_record(json.loads(raw), raw_line=raw)["severity"] == "low"


def test_parse_eve_timestamp_normalization():
    # Microsecond precision with Z suffix -> UTC ISO seconds.
    raw = json.dumps(
        {"timestamp": "2024-10-12T13:30:45.678901Z", "event_type": "alert",
         "src_ip": "203.0.113.66", "alert": {"signature_id": 1}}
    )
    ev = parse_eve_record(json.loads(raw), raw_line=raw)
    assert ev["timestamp"] == "2024-10-12T13:30:45+00:00"

    # Non-UTC offset is converted to UTC.
    raw = json.dumps(
        {"timestamp": "2024-10-12T13:30:45+05:30", "event_type": "alert",
         "src_ip": "203.0.113.66", "alert": {"signature_id": 1}}
    )
    ev = parse_eve_record(json.loads(raw), raw_line=raw)
    assert ev["timestamp"] == "2024-10-12T08:00:45+00:00"


def test_parse_eve_uses_host_field_when_present():
    raw = json.dumps(
        {"timestamp": "2024-10-12T08:00:00Z", "event_type": "alert",
         "host": "sensor-01", "src_ip": "203.0.113.66", "alert": {"signature_id": 1}}
    )
    ev = parse_eve_record(json.loads(raw), raw_line=raw)
    assert ev["host"] == "sensor-01"


# --------------------------------------------------------------------------- #
# Collection: successful ingestion + storage
# --------------------------------------------------------------------------- #


def test_collect_ingests_alert_records(_db, tmp_path):
    path = _write_eve(tmp_path / "eve.json", [_alert_line(i) for i in range(3)])
    result = collect_once(SuricataConfig(eve_path=str(path)))

    assert result.records_seen == 3
    assert result.events_ingested == 3
    assert result.errors == []
    # Each distinct Suricata signature raises its own Greywatch alert (rule_id
    # SURICATA_ALERT) in the shared alerts table -- not SSH_BRUTE_FORCE.
    assert len(result.new_alerts) == 3
    assert all(a["rule_id"] == "SURICATA_ALERT" for a in result.new_alerts)
    assert all(a["status"] == "open" for a in result.new_alerts)
    assert all(a["severity"] == "high" for a in result.new_alerts)  # sig sev 1 -> high
    assert all(a["source_ip"] == "203.0.113.66" for a in result.new_alerts)
    assert all(a["dest_ip"] == "198.51.100.7" for a in result.new_alerts)
    assert all(a["proto"] == "TCP" for a in result.new_alerts)
    assert all(a["dest_port"] == 22 for a in result.new_alerts)
    assert {a["signature_id"] for a in result.new_alerts} == {
        2023000,
        2023001,
        2023002,
    }
    assert {a["signature"] for a in result.new_alerts} == {
        "ET SCAN test signature 0",
        "ET SCAN test signature 1",
        "ET SCAN test signature 2",
    }
    # SSH_BRUTE_FORCE is untouched -- Suricata events never fire it.
    assert not any(a["rule_id"] == "SSH_BRUTE_FORCE" for a in result.new_alerts)

    rows = _event_rows()
    assert len(rows) == 3
    assert all(r["source"] == "suricata" for r in rows)
    assert all(r["event_type"] == "suricata_alert" for r in rows)
    assert all(r["dest_ip"] == "198.51.100.7" for r in rows)
    assert all(r["proto"] == "TCP" for r in rows)
    # Signatures survive verbatim (unordered storage -> compare as a set).
    assert {r["signature"] for r in rows} == {
        "ET SCAN test signature 0",
        "ET SCAN test signature 1",
        "ET SCAN test signature 2",
    }
    assert {r["signature_id"] for r in rows} == {2023000, 2023001, 2023002}


def test_collected_events_visible_via_events_api(_db, tmp_path, monkeypatch):
    path = _write_eve(tmp_path / "eve.json", [_alert_line(i) for i in range(3)])
    monkeypatch.setenv("GREYWATCH_SURICATA_EVE_PATH", str(path))

    resp = client.post("/api/v1/suricata/collect")
    assert resp.status_code == 200
    body = resp.json()
    assert body["events_ingested"] == 3
    assert body["errors"] == []

    events = client.get("/api/v1/events").json()["events"]
    assert len(events) == 3
    assert all(e["source"] == "suricata" for e in events)
    suricata_event = events[0]  # most recent
    assert suricata_event["event_type"] == "suricata_alert"
    assert suricata_event["dest_ip"] == "198.51.100.7"
    assert suricata_event["signature_id"] == 2023002
    # Dashboard fields used by the events list are all populated.
    for field in ("event_type", "source_ip", "severity", "raw_message"):
        assert suricata_event[field]


def test_collected_events_visible_via_api_raw_json_field(_db, tmp_path, monkeypatch):
    """The raw_message stored verbatim lets the dashboard render any field."""
    path = _write_eve(tmp_path / "eve.json", [_alert_line(0)])
    monkeypatch.setenv("GREYWATCH_SURICATA_EVE_PATH", str(path))
    client.post("/api/v1/suricata/collect")
    ev = client.get("/api/v1/events").json()["events"][0]
    # raw_message is the original EVE JSON line -> recoverable verbatim.
    assert json.loads(ev["raw_message"])["alert"]["signature"] == "ET SCAN test signature 0"


# --------------------------------------------------------------------------- #
# Collector progress + cross-run dedup
# --------------------------------------------------------------------------- #


def test_collect_progress_advances_offset_and_idle_resumes(_db, tmp_path):
    path = _write_eve(tmp_path / "eve.json", [_alert_line(i) for i in range(3)])
    cfg = SuricataConfig(eve_path=str(path))

    first = collect_once(cfg)
    assert first.events_ingested == 3
    size = path.stat().st_size
    assert get_collector_setting("suricata_last_offset") == str(size)
    assert get_collector_setting("suricata_events_ingested") == "3"

    # Second cycle: offset sits at EOF -> nothing new, no duplicates.
    second = collect_once(cfg)
    assert second.records_seen == 0
    assert second.events_ingested == 0
    assert len(_event_rows()) == 3

    # Append two new records and a third cycle resumes exactly where it left off.
    with path.open("a", encoding="utf-8") as fh:
        fh.write(_alert_line(3))
        fh.write("\n")
        fh.write(_alert_line(4))
        fh.write("\n")
    third = collect_once(cfg)
    assert third.records_seen == 2
    assert third.events_ingested == 2
    assert len(_event_rows()) == 5


def test_collect_within_batch_dedup_by_raw_line(_db, tmp_path):
    """Identical EVE lines within a single read are ingested once."""
    line = _alert_line(0)
    path = _write_eve(tmp_path / "eve.json", [line, line, line])
    result = collect_once(SuricataConfig(eve_path=str(path)))
    assert result.records_seen == 3
    assert result.events_ingested == 1
    assert len(_event_rows()) == 1


# --------------------------------------------------------------------------- #
# Malformed records + large-file cap
# --------------------------------------------------------------------------- #


def test_collect_skips_malformed_lines(_db, tmp_path):
    """A corrupt line never aborts the batch; valid records around it are kept."""
    records = [
        _alert_line(0),
        "this-line-is-not-json",
        "",
        json.dumps({"event_type": "stats"}),  # valid EVE, but not a security event
        _alert_line(1),
    ]
    path = _write_eve(tmp_path / "eve.json", records)
    result = collect_once(SuricataConfig(eve_path=str(path)))

    # records_seen counts valid JSON EVE records (stats included); the malformed
    # and blank lines are skipped at the reader level, exactly like journalctl.
    assert result.records_seen == 3  # 2 alerts + 1 stats
    assert result.events_ingested == 2  # stats is not a recognized event type
    assert result.errors == []
    assert len(_event_rows()) == 2


def test_collect_respects_max_records_cap(_db, tmp_path):
    """A very large EVE file is processed in bounded chunks (no OOM)."""
    path = _write_eve(tmp_path / "eve.json", [_alert_line(i) for i in range(5)])
    cfg = SuricataConfig(eve_path=str(path), max_records=2)

    first = collect_once(cfg)
    assert first.records_seen == 2
    assert first.events_ingested == 2
    assert len(_event_rows()) == 2

    # Remaining bytes are not committed past the 2 processed lines, so the
    # next cycle picks up the rest ("no loss, just latency").
    second = collect_once(cfg)
    assert second.events_ingested == 2
    assert len(_event_rows()) == 4

    third = collect_once(cfg)
    assert third.events_ingested == 1
    assert len(_event_rows()) == 5


# --------------------------------------------------------------------------- #
# Rotation / truncation
# --------------------------------------------------------------------------- #


def test_collect_rotation_resets_offset_and_dedups(_db, tmp_path):
    """If the EVE file shrinks below the stored offset, the collector resets
    and re-reads from 0, de-duplicating records already ingested."""
    path = _write_eve(tmp_path / "eve.json", [_alert_line(i) for i in range(4)])
    cfg = SuricataConfig(eve_path=str(path))

    first = collect_once(cfg)
    assert first.events_ingested == 4
    size_before = path.stat().st_size
    assert get_collector_setting("suricata_last_offset") == str(size_before)

    # Rotation: replace the (larger) file with a smaller one containing a mix
    # of already-stored and new records.
    rotated = [_alert_line(0), _alert_line(4)]  # record 0 was stored, 4 is new
    path.write_text("\n".join(rotated) + "\n", encoding="utf-8")

    second = collect_once(cfg)
    assert second.fallback_used is True  # rotation reset
    assert second.records_seen == 2
    assert second.events_ingested == 1  # record 0 deduped, record 4 stored
    assert len(_event_rows()) == 5  # 4 + 1 new
    assert get_collector_setting("suricata_last_offset") == str(path.stat().st_size)


def test_collect_handles_missing_file(_db, tmp_path):
    """A missing/unreadable EVE file is reported, not raised."""
    cfg = SuricataConfig(eve_path=str(tmp_path / "does-not-exist.json"))
    result = collect_once(cfg)
    assert result.events_ingested == 0
    assert result.records_seen == 0
    assert result.errors
    assert "EVE file not found" in result.errors[0]
    assert len(_event_rows()) == 0


# --------------------------------------------------------------------------- #
# SSH brute-force detection is unaffected
# --------------------------------------------------------------------------- #


def test_suricata_alerts_do_not_trigger_ssh_brute_force(_db, tmp_path, monkeypatch):
    """Suricata ``alert`` events become ``suricata_alert`` events (not
    ``ssh_login_failed``), so they raise ``SURICATA_ALERT`` alerts and never
    fire ``SSH_BRUTE_FORCE``. The SSH rule still works independently via the
    HTTP ingestion path."""
    path = _write_eve(tmp_path / "eve.json", [_alert_line(i) for i in range(5)])
    result = collect_once(SuricataConfig(eve_path=str(path)))
    assert result.events_ingested == 5
    # Suricata alerts raise Greywatch alerts, but of the Suricata rule only --
    # never SSH_BRUTE_FORCE. The 5 records differ by signature_id, so 5
    # distinct alerts (no uncontrolled duplication of distinct attacks).
    assert len(result.new_alerts) == 5
    assert all(a["rule_id"] == "SURICATA_ALERT" for a in result.new_alerts)
    assert all(a["status"] == "open" for a in result.new_alerts)
    assert not any(a["rule_id"] == "SSH_BRUTE_FORCE" for a in result.new_alerts)

    persisted = client.get("/api/v1/alerts?status=all&limit=100").json()
    assert len(persisted["alerts"]) == 5
    assert all(a["rule_id"] == "SURICATA_ALERT" for a in persisted["alerts"])
    assert not any(
        a["rule_id"] == "SSH_BRUTE_FORCE" for a in persisted["alerts"]
    )

    # The SSH rule still works independently via the HTTP ingestion path and
    # raises exactly one SSH_BRUTE_FORCE alert (the suricata events above, which
    # use a different source_ip, never contribute SSH failures).
    lines = [
        f"sshd[600{i}]: Failed password for invalid user u{i} "
        f"from 203.0.113.10 port 5400{i} ssh2"
        for i in range(5)
    ]
    resp = client.post("/api/v1/events/ingest", json={"lines": lines})
    ssh_alerts = resp.json()["alerts"]
    assert len(ssh_alerts) == 1
    assert ssh_alerts[0]["rule_id"] == "SSH_BRUTE_FORCE"
    assert len(_event_rows()) == 10  # 5 suricata + 5 ssh


# --------------------------------------------------------------------------- #
# Status + CLI + run_loop
# --------------------------------------------------------------------------- #


def test_status_reports_checkpoint(_db, tmp_path, monkeypatch):
    path = _write_eve(tmp_path / "eve.json", [_alert_line(i) for i in range(2)])
    monkeypatch.setenv("GREYWATCH_SURICATA_EVE_PATH", str(path))
    collect_once(SuricataConfig(eve_path=str(path)))

    st = status()
    assert st["enabled"] is False
    assert st["eve_path"] == str(path)
    assert st["events_ingested"] == 2
    assert st["last_offset"] == str(path.stat().st_size)
    assert st["last_event_ts"] is not None
    assert st["last_run_at"] is not None


def test_status_endpoint(_db, tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_SURICATA_EVE_PATH", str(tmp_path / "eve.json"))
    resp = client.get("/api/v1/suricata/status")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body) == {
        "enabled",
        "eve_path",
        "last_offset",
        "last_event_ts",
        "events_ingested",
        "last_run_at",
        "attempts",
        "successful_runs",
        "failed_runs",
        "last_attempt_at",
        "last_successful_run_at",
        "records_seen",
        "deduplicated",
        "last_error",
        "last_error_at",
    }
    assert body["enabled"] is False
    assert body["events_ingested"] == 0


# --------------------------------------------------------------------------- #
# Suricata collector health / observability
# --------------------------------------------------------------------------- #


def test_suricata_status_health_fields_after_successful_run(_db, tmp_path, monkeypatch):
    """A successful collection cycle records attempts, successful_runs,
    last_successful_run_at, records_seen and deduplicated."""
    monkeypatch.setenv("GREYWATCH_DB", str(_db / "health.db"))
    path = _write_eve(tmp_path / "eve.json", [_alert_line(0)])
    cfg = SuricataConfig(eve_path=str(path))
    collect_once(cfg)

    body = client.get("/api/v1/suricata/status").json()
    assert body["attempts"] == 1
    assert body["successful_runs"] == 1
    assert body["failed_runs"] == 0
    assert body["records_seen"] == 1
    assert body["deduplicated"] == 0
    assert body["last_error"] is None
    assert body["last_attempt_at"] is not None
    assert body["last_successful_run_at"] is not None
    assert body["last_attempt_at"] == body["last_successful_run_at"]


def test_suricata_failed_run_records_error_not_success(_db, tmp_path, monkeypatch):
    """A failed cycle (missing EVE file) advances attempts/failed_runs and
    last_error, but does NOT advance last_successful_run_at."""
    monkeypatch.setenv("GREYWATCH_DB", str(_db / "fail.db"))
    # First: a successful run to establish a baseline.
    path = _write_eve(tmp_path / "eve.json", [_alert_line(0)])
    cfg = SuricataConfig(eve_path=str(path))
    collect_once(cfg)
    before = client.get("/api/v1/suricata/status").json()
    assert before["successful_runs"] == 1
    assert before["failed_runs"] == 0
    successful_run_at = before["last_successful_run_at"]

    # Second: missing EVE file -> a genuinely failed cycle.
    bad_cfg = SuricataConfig(eve_path=str(tmp_path / "does-not-exist.json"))
    second = collect_once(bad_cfg)
    assert second.errors

    body = client.get("/api/v1/suricata/status").json()
    assert body["attempts"] == 2
    assert body["failed_runs"] == 1
    assert body["successful_runs"] == 1  # unchanged by the failed cycle
    assert body["last_error"] is not None
    assert "EVE file not found" in body["last_error"]
    assert body["last_error_at"] is not None
    # last_successful_run_at must reflect the FIRST (successful) cycle only.
    assert body["last_successful_run_at"] == successful_run_at


def test_suricata_idle_run_is_successful(_db, tmp_path, monkeypatch):
    """A cycle that finds nothing new is still a successful run (idle, not
    failed): last_successful_run_at advances, failed_runs stays 0."""
    monkeypatch.setenv("GREYWATCH_DB", str(_db / "idle.db"))
    path = _write_eve(tmp_path / "eve.json", [_alert_line(0)])
    cfg = SuricataConfig(eve_path=str(path))
    first = collect_once(cfg)
    assert first.events_ingested == 1

    # Second cycle: offset at EOF -> nothing new, still successful.
    second = collect_once(cfg)
    assert second.events_ingested == 0
    assert second.errors == []

    body = client.get("/api/v1/suricata/status").json()
    assert body["attempts"] == 2
    assert body["successful_runs"] == 2
    assert body["failed_runs"] == 0
    assert body["last_successful_run_at"] == body["last_attempt_at"]


def test_suricata_dedup_tracked_on_identical_replay(_db, tmp_path, monkeypatch):
    """records_seen and deduplicated are tracked when the same EVE line is
    replayed at a new byte offset (within-batch raw-line dedup)."""
    monkeypatch.setenv("GREYWATCH_DB", str(_db / "dedup.db"))
    line = _alert_line(0)
    path = tmp_path / "eve.json"
    path.write_text(line + "\n" + line + "\n", encoding="utf-8")
    cfg = SuricataConfig(eve_path=str(path))

    result = collect_once(cfg)
    # Two identical lines in one batch: within-batch dedup stores one.
    assert result.records_seen == 2
    assert result.events_ingested == 1

    body = client.get("/api/v1/suricata/status").json()
    assert body["records_seen"] == 2
    assert body["deduplicated"] == 1
    assert body["attempts"] == 1
    assert body["successful_runs"] == 1


def test_suricata_disabled_collector_status(_db, monkeypatch):
    """A disabled collector reports enabled=false without collecting."""
    monkeypatch.setenv("GREYWATCH_DB", str(_db / "disabled.db"))
    monkeypatch.setenv("GREYWATCH_SURICATA_ENABLED", "0")
    assert suricata_mod.get_config().enabled is False

    body = client.get("/api/v1/suricata/status").json()
    assert body["enabled"] is False


def test_collect_endpoint_missing_file_reports_error(_db, tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_SURICATA_EVE_PATH", str(tmp_path / "nope.json"))
    resp = client.post("/api/v1/suricata/collect")
    assert resp.status_code == 200  # error is reported, not raised
    body = resp.json()
    assert body["events_ingested"] == 0
    assert body["records_seen"] == 0
    assert body["errors"]


def test_collect_endpoint_missing_file_sanitizes_path(_db, tmp_path, monkeypatch):
    """Missing EVE file error must not expose the configured filesystem path
    in the API response. Full details remain in server-side logs."""
    eve_path = str(tmp_path / "deep" / "nested" / "eve.json")
    monkeypatch.setenv("GREYWATCH_SURICATA_EVE_PATH", eve_path)
    resp = client.post("/api/v1/suricata/collect")
    assert resp.status_code == 200  # error is reported, not raised
    body = resp.json()
    assert body["events_ingested"] == 0
    assert body["records_seen"] == 0
    assert body["errors"], "expected failure to be reported"
    for err in body["errors"]:
        assert eve_path not in err, f"filesystem path leaked in error: {err}"
        assert "/deep/" not in err, f"raw path segment not sanitized: {err}"


def test_run_loop_no_op_when_disabled(_db, tmp_path, monkeypatch):
    """An enabled=False config never collects (no EVE file even required)."""
    monkeypatch.setenv("GREYWATCH_SURICATA_EVE_PATH", str(tmp_path / "eve.json"))
    cfg = SuricataConfig(enabled=False, eve_path=str(tmp_path / "nonexistent.json"))
    # Returns immediately without raising or ingesting.
    suricata_mod.run_loop(cfg)
    assert len(_event_rows()) == 0


def test_cli_once_reports_missing_file(_db, monkeypatch):
    """`python -m backend.app.suricata --once` degrades gracefully."""
    monkeypatch.setenv(
        "GREYWATCH_SURICATA_EVE_PATH", str(_db / "nope.json")
    )
    rc = suricata_mod.main(["--once"])
    assert rc == 1  # errors present -> non-zero, but no crash


# --------------------------------------------------------------------------- #
# Suricata alert creation, severity mapping, field preservation
# (Phase 3: a Suricata alert becomes a Greywatch alert)
# --------------------------------------------------------------------------- #


def _eve_alert(
    sig_id=2023001,
    signature="ET SCAN test signature",
    src="203.0.113.66",
    dst="198.51.100.7",
    sport=51022,
    dport=22,
    proto="TCP",
    ts="2024-10-12T08:00:00.000000Z",
    severity=1,
    category="attempted-recon",
    host="sensor-01",
):
    """Build a single, fully-controlled Suricata EVE alert record (as a dict)."""
    return {
        "timestamp": ts,
        "event_type": "alert",
        "src_ip": src,
        "dest_ip": dst,
        "src_port": sport,
        "dest_port": dport,
        "proto": proto,
        "host": host,
        "alert": {
            "signature_id": sig_id,
            "signature": signature,
            "severity": severity,
            "category": category,
        },
    }


def _alert_rows():
    with _connection() as conn:
        rows = conn.execute("SELECT * FROM alerts").fetchall()
    return [dict(r) for r in rows]


@pytest.mark.parametrize(
    "severity_in, expected",
    [(0, "high"), (1, "high"), (2, "medium"), (3, "low"), (4, "low"), (9, "low")],
)
def test_suricata_alert_severity_mapping(_db, severity_in, expected):
    """Suricata severity 0/1 -> high, 2 -> medium, 3/4 -> low, unknown -> low.

    The mapping is applied both on the stored event and on the raised alert,
    and the *original* numeric severity is preserved in the alert description
    and in the evidence events' raw_message (never silently inverted).
    """
    rec = _eve_alert(severity=severity_in, sig_id=2023001)
    event = parse_eve_record(rec, raw_line=json.dumps(rec))
    assert event["severity"] == expected
    assert event["raw_severity"] == severity_in

    result = siem.ingest_events([event])
    assert len(result["alerts"]) == 1
    alert = result["alerts"][0]
    assert alert["rule_id"] == "SURICATA_ALERT"
    assert alert["severity"] == expected
    # Original numeric Suricata severity survives on the alert.
    assert f"Suricata severity {severity_in}" in alert["description"]
    assert "Greywatch:" in alert["description"]

    # ...and lives verbatim in the evidence events' raw_message.
    evidence = siem.list_events()
    assert len(evidence) == 1
    assert evidence[0]["event_type"] == "suricata_alert"
    orig = json.loads(evidence[0]["raw_message"])["alert"]["severity"]
    assert orig == severity_in


def test_suricata_alert_creation_preserves_fields(_db):
    """A Suricata alert raises a Greywatch alert carrying all signature,
    network, category and severity fields, plus source provenance."""
    rec = _eve_alert(
        sig_id=2023010,
        signature="ET SCAN real-sig",
        severity=1,
        category="attempted-recon",
    )
    event = parse_eve_record(rec, raw_line=json.dumps(rec))
    result = siem.ingest_events([event])

    assert len(result["alerts"]) == 1
    alert = result["alerts"][0]
    assert alert["rule_id"] == "SURICATA_ALERT"
    assert alert["status"] == "open"
    assert alert["source_ip"] == "203.0.113.66"
    assert alert["dest_ip"] == "198.51.100.7"
    assert alert["src_port"] == 51022
    assert alert["dest_port"] == 22
    assert alert["proto"] == "TCP"
    assert alert["signature"] == "ET SCAN real-sig"
    assert alert["signature_id"] == 2023010
    assert alert["category"] == "attempted-recon"
    assert alert["severity"] == "high"
    assert alert["event_count"] == 1
    assert "Suricata severity 1" in alert["description"]

    # The persisted row carries the same fields (and SSH columns are untouched).
    rows = _alert_rows()
    assert len(rows) == 1
    row = rows[0]
    assert row["rule_id"] == "SURICATA_ALERT"
    assert row["signature_id"] == 2023010
    assert row["category"] == "attempted-recon"
    assert row["src_port"] == 51022
    assert row["dest_port"] == 22
    assert row["proto"] == "TCP"


def test_suricata_alert_invalid_field_types_degrade_safely(_db):
    """Malformed IDS field types never crash ingestion: a non-integer
    severity floors to 'low', non-integer ports/ids become NULL, yet an alert
    is still raised."""
    rec = {
        "timestamp": "2024-10-12T08:00:00Z",
        "event_type": "alert",
        "src_ip": "203.0.113.66",
        "dest_ip": "198.51.100.7",
        "src_port": "not-a-port",
        "dest_port": "also-not-a-port",
        "proto": "TCP",
        "alert": {
            "signature_id": "not-an-int",
            "signature": "BAD SIG",
            "severity": "high",  # string, not 0-4 -> floors to low
        },
    }
    event = parse_eve_record(rec, raw_line=json.dumps(rec))
    assert event["severity"] == "low"
    assert event["signature_id"] is None
    assert event["src_port"] is None
    assert event["dest_port"] is None

    result = siem.ingest_events([event])
    assert len(result["alerts"]) == 1
    alert = result["alerts"][0]
    assert alert["rule_id"] == "SURICATA_ALERT"
    assert alert["severity"] == "low"
    assert alert["signature_id"] is None
    assert alert["src_port"] is None


def test_suricata_alert_missing_optional_fields(_db):
    """An alert record missing optional fields (category, ports, proto,
    severity) still raises a well-formed alert with NULLs preserved, not a
    crash — missing severity floors to 'low', missing proto to 'unknown'."""
    rec = {
        "timestamp": "2024-10-12T08:00:00Z",
        "event_type": "alert",
        "src_ip": "203.0.113.66",
        "dest_ip": "198.51.100.7",
        "alert": {"signature_id": 2023001, "signature": "ET SCAN minimal"},
        # no src_port / dest_port / proto / category / severity present
    }
    event = parse_eve_record(rec, raw_line=json.dumps(rec))
    result = siem.ingest_events([event])
    assert len(result["alerts"]) == 1
    alert = result["alerts"][0]
    assert alert["rule_id"] == "SURICATA_ALERT"
    assert alert["signature_id"] == 2023001
    assert alert["signature"] == "ET SCAN minimal"
    assert alert["dest_ip"] == "198.51.100.7"
    assert alert["src_port"] is None
    assert alert["dest_port"] is None
    assert alert["proto"] == "unknown"
    assert alert["category"] is None
    assert alert["severity"] == "low"  # missing severity -> conservative low
    # Original record (w/o severity/proto) is still recoverable verbatim.
    assert json.loads(siem.list_events()[0]["raw_message"])["alert"]["signature_id"] == 2023001


# --------------------------------------------------------------------------- #
# Phase 4: deduplication & aggregation
# --------------------------------------------------------------------------- #


def test_suricata_alert_dedup_aggregates_repeated_events(_db):
    """Same signature + 5-tuple repeated in one batch -> one aggregated alert;
    the individual events are still stored (no evidence loss)."""
    recs = [_eve_alert(ts=f"2024-10-12T08:00:0{i}.000000Z") for i in range(3)]
    events = [parse_eve_record(r, raw_line=json.dumps(r)) for r in recs]
    result = siem.ingest_events(events)

    assert len(result["alerts"]) == 1  # aggregation, not duplication
    assert result["alerts"][0]["event_count"] == 3
    # Both the alert and every source event survive.
    assert len(_alert_rows()) == 1
    assert len(siem.list_events()) == 3


def test_suricata_distinct_alerts_remain_distinguishable(_db):
    """Same signature but different dest_port, and a different signature, yield
    distinct alerts (the 5-tuple + signature identity disambiguates them)."""
    recs = [
        _eve_alert(dport=22, sig_id=2023001, signature="sig A"),
        _eve_alert(dport=80, sig_id=2023001, signature="sig A"),  # different dport
        _eve_alert(dport=22, sig_id=2023002, signature="sig B"),  # different sig
    ]
    events = [parse_eve_record(r, raw_line=json.dumps(r)) for r in recs]
    result = siem.ingest_events(events)

    assert len(result["alerts"]) == 3
    assert len({a["signature_id"] for a in result["alerts"]}) == 2
    assert {a["dest_port"] for a in result["alerts"]} == {22, 80}


def test_suricata_alert_outside_window_starts_new_alert(_db):
    """Same signature + endpoints more than the aggregation window apart raise
    a NEW alert, so recurring incidents stay distinguishable in time."""
    window = siem.SURICATA_ALERT_WINDOW_MINUTES
    later = (
        datetime(2024, 10, 12, 8, 0, 0, tzinfo=timezone.utc)
        + timedelta(minutes=window + 1)
    ).isoformat(timespec="seconds")
    recs = [
        _eve_alert(ts="2024-10-12T08:00:00.000000Z"),
        _eve_alert(ts=later),
    ]
    events = [parse_eve_record(r, raw_line=json.dumps(r)) for r in recs]
    result = siem.ingest_events(events)

    assert len(result["alerts"]) == 2  # outside the 60-minute window
    assert all(a["signature_id"] == 2023001 for a in result["alerts"])
    assert {a["event_count"] for a in result["alerts"]} == {1}


def test_suricata_alert_dedup_across_collection_cycles(_db, tmp_path):
    """Aggregation works across collector cycles: later identical-key events
    fold into the existing open alert instead of opening duplicates."""
    path = tmp_path / "eve.json"
    # Cycle 1: two identical-key events -> one aggregated alert (count 2).
    with path.open("w", encoding="utf-8") as fh:
        for i in range(2):
            fh.write(json.dumps(_eve_alert(ts=f"2024-10-12T08:00:0{i}.000000Z")))
            fh.write("\n")
    first = collect_once(SuricataConfig(eve_path=str(path)))
    assert len(first.new_alerts) == 1
    assert _alert_rows()[0]["event_count"] == 2

    # Cycle 2: append two more identical-key events -> aggregate into the same.
    with path.open("a", encoding="utf-8") as fh:
        for i in range(2, 4):
            fh.write(json.dumps(_eve_alert(ts=f"2024-10-12T08:00:0{i}.000000Z")))
            fh.write("\n")
    second = collect_once(SuricataConfig(eve_path=str(path)))
    assert second.events_ingested == 2
    assert len(second.new_alerts) == 0  # aggregated, not a new alert
    assert len(_alert_rows()) == 1
    assert _alert_rows()[0]["event_count"] == 4
    assert len(siem.list_events()) == 4  # evidence grew, not lost


# --------------------------------------------------------------------------- #
# Suricata record identity & replay safety
# --------------------------------------------------------------------------- #


def test_suricata_events_store_source_record_id(_db, tmp_path):
    """Each ingested Suricata event carries a stable ``source_record_id``
    derived from (generation, inode, device, byte_offset)."""
    path = _write_eve(tmp_path / "eve.json", [_alert_line(0), _alert_line(1)])
    result = collect_once(SuricataConfig(eve_path=str(path)))

    assert result.events_ingested == 2
    rows = _event_rows()
    assert len(rows) == 2
    assert all(r["source_record_id"] is not None for r in rows)
    assert all(r["source"] == "suricata" for r in rows)
    # Distinct byte offsets -> distinct record ids.
    assert len({r["source_record_id"] for r in rows}) == 2
    # Generation persisted.
    gen = get_collector_setting("suricata_file_generation")
    assert gen is not None
    assert int(gen) >= 0


def test_suricata_distinct_identical_payloads_preserved(_db, tmp_path):
    """The same Suricata payload ingested at a later byte offset (new cycle)
    is stored as a distinct event: identity is offset-based, not content-based,
    so legitimate repeated events are never collapsed."""
    path = tmp_path / "eve.json"
    line = json.dumps(_eve_alert(sig_id=2023001, signature="identical-payload"))
    path.write_text(line + "\n", encoding="utf-8")
    cfg = SuricataConfig(eve_path=str(path))

    first = collect_once(cfg)
    assert first.events_ingested == 1

    # Append the identical payload again at a new offset.
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line + "\n")
    second = collect_once(cfg)
    assert second.records_seen == 1
    assert second.events_ingested == 1  # stored despite identical payload
    assert len(_event_rows()) == 2
    rows = _event_rows()
    assert len({r["source_record_id"] for r in rows}) == 2


def test_suricata_replay_identifiable_record_skipped(_db):
    """Re-ingesting the same Suricata source_record_id is skipped at the
    storage layer (belt-and-suspenders beyond byte-offset checkpointing)."""
    rec = _eve_alert(sig_id=2023001, signature="replay-test")
    raw_line = json.dumps(rec)
    event = parse_eve_record(rec, raw_line=raw_line)
    event["source"] = "suricata"
    event["source_record_id"] = "5:12345:678:1024"

    first = siem.ingest_events([event])
    assert first["parsed"] == 1
    assert len(first["alerts"]) == 1

    second = siem.ingest_events([event])  # exact replay of same record id
    assert second["parsed"] == 0  # skipped as duplicate
    assert second["alerts"] == []  # no new alert, count not inflated
    assert len(siem.list_events()) == 1  # one logical event


def test_suricata_generation_increments_on_truncation(_db, tmp_path):
    """Truncating the EVE file bumps the file generation so new content at a
    previously-used byte offset is not wrongly treated as a duplicate."""
    path = tmp_path / "eve.json"
    _write_eve(path, [_alert_line(0), _alert_line(1)])
    cfg = SuricataConfig(eve_path=str(path))

    first = collect_once(cfg)
    assert first.events_ingested == 2
    gen_before = int(get_collector_setting("suricata_file_generation"))

    # Truncate and write fresh content at offset 0.
    path.write_text(_alert_line(2) + "\n", encoding="utf-8")
    resumed = collect_once(cfg)
    gen_after = int(get_collector_setting("suricata_file_generation"))

    assert gen_after == gen_before + 1  # generation bumped on truncation
    assert resumed.events_ingested == 1  # new content stored (no offset collision)
    assert len(_event_rows()) == 3  # 2 old + 1 new


def test_suricata_repeated_collection_no_duplicates(_db, tmp_path):
    """Repeated collection cycles with no new data ingest nothing and store
    no duplicates."""
    path = _write_eve(tmp_path / "eve.json", [_alert_line(0)])
    cfg = SuricataConfig(eve_path=str(path))

    first = collect_once(cfg)
    assert first.events_ingested == 1

    second = collect_once(cfg)  # idle: offset at EOF
    assert second.records_seen == 0
    assert second.events_ingested == 0
    assert len(_event_rows()) == 1

    third = collect_once(cfg)  # again
    assert third.events_ingested == 0
    assert len(_event_rows()) == 1


def test_suricata_alert_no_signature_id_still_alerts(_db):
    """An alert record lacking signature_id/signature still raises an alert
    (keyed on the network tuple), with a safe generated title."""
    rec = {
        "timestamp": "2024-10-12T08:00:00Z",
        "event_type": "alert",
        "src_ip": "203.0.113.66",
        "dest_ip": "198.51.100.7",
        "src_port": 51022,
        "dest_port": 22,
        "proto": "TCP",
        "alert": {"signature": None, "signature_id": None, "severity": 1},
    }
    event = parse_eve_record(rec, raw_line=json.dumps(rec))
    result = siem.ingest_events([event])
    assert len(result["alerts"]) == 1
    alert = result["alerts"][0]
    assert alert["rule_id"] == "SURICATA_ALERT"
    assert alert["signature_id"] is None
    assert alert["signature"] is None
    assert alert["title"] == "Suricata alert"


def test_suricata_alert_evidence_and_investigation(_db):
    """GET /alerts/{id} returns the alert's signature/network metadata plus the
    stored suricata_alert events (raw_message preserves the original severity)."""
    rec = _eve_alert(severity=1, sig_id=2023010, signature="ET SCAN real-sig")
    event = parse_eve_record(rec, raw_line=json.dumps(rec))
    siem.ingest_events([event])
    created = _alert_rows()[0]

    detail = siem.get_alert_detail(created["id"])
    assert detail is not None
    alert = detail["alert"]
    assert alert["rule_id"] == "SURICATA_ALERT"
    assert alert["signature"] == "ET SCAN real-sig"
    assert alert["signature_id"] == 2023010
    assert alert["category"] == "attempted-recon"
    assert alert["src_port"] == 51022
    assert alert["dest_port"] == 22
    assert alert["dest_ip"] == "198.51.100.7"
    assert alert["proto"] == "TCP"

    evidence = detail["evidence_events"]
    assert len(evidence) == 1
    assert evidence[0]["event_type"] == "suricata_alert"
    assert evidence[0]["source"] == "suricata"
    # Original record (incl. original alert.severity) is recoverable verbatim.
    raw = json.loads(evidence[0]["raw_message"])
    assert raw["alert"]["severity"] == 1
    assert raw["alert"]["signature_id"] == 2023010
    assert detail["evidence_window_start"] == alert["created_at"]
    assert detail["evidence_window_end"] == alert["last_triggered_at"]


def test_sample_eve_produces_four_distinct_suricata_alerts(_db, tmp_path):
    """The bundled sample-logs/eve.json yields 4 distinct SURICATA_ALERT alerts
    (distinct signatures/endpoints -> no spurious dedup)."""
    sample = Path("sample-logs/eve.json")
    if not sample.exists():
        pytest.skip("sample-logs/eve.json not present")
    result = collect_once(SuricataConfig(eve_path=str(sample)))
    assert result.errors == []
    suri = [a for a in result.new_alerts if a["rule_id"] == "SURICATA_ALERT"]
    assert len(suri) == 4
    assert len({a["signature_id"] for a in suri}) == 4
    # Severity mapping is applied on the raised alerts (e.g. a sev-2 sig -> medium).
    assert {a["severity"] for a in suri} == {"high", "medium"}
    assert len(_alert_rows()) == 4


def test_suricata_alert_does_not_create_duplicate_api_alerts(_db, tmp_path, monkeypatch):
    """End-to-end via the HTTP collect endpoint: suricata alerts surface in
    /api/v1/alerts as SURICATA_ALERT, and a second collect cycle (idle) does
    not duplicate them."""
    path = tmp_path / "eve.json"
    monkeypatch.setenv("GREYWATCH_SURICATA_EVE_PATH", str(path))
    collect_once(SuricataConfig(eve_path=str(path)))  # initialize state cursor

    # Write 3 identical-key alerts and collect via the API.
    with path.open("a", encoding="utf-8") as fh:
        for i in range(3):
            fh.write(json.dumps(_eve_alert(ts=f"2024-10-12T08:00:0{i}.000000Z")))
            fh.write("\n")
    resp = client.post("/api/v1/suricata/collect")
    assert resp.status_code == 200
    body = resp.json()
    assert body["events_ingested"] == 3
    assert len([a for a in body["alerts"] if a["rule_id"] == "SURICATA_ALERT"]) == 1

    # Idle cycle: no new alerts, no duplicates.
    resp2 = client.post("/api/v1/suricata/collect")
    assert resp2.json()["events_ingested"] == 0
    assert resp2.json()["alerts"] == []
    rows = client.get("/api/v1/alerts?status=all&limit=100").json()["alerts"]
    assert len(rows) == 1


# --------------------------------------------------------------------------- #
# Phase 5 (operational hardening): reliability, recovery and operational edges
#
# Every test below is hermetic: EVE data is written into ``tmp_path`` and the
# database is a per-test temp file via the ``_db`` fixture, so the developer
# database (``data/greywatch.db``) is never opened.
# --------------------------------------------------------------------------- #


def test_collect_handles_initially_empty_file_then_appends(_db, tmp_path):
    """An EVE file that exists but holds no records is a clean no-op.

    Expectation: no error, no events, the checkpoint is recorded at byte 0 and
    a poll timestamp is stored (so status shows a live collector); the first
    appended record is then picked up normally.
    """
    path = tmp_path / "eve.json"
    path.write_text("", encoding="utf-8")
    cfg = SuricataConfig(eve_path=str(path))

    result = collect_once(cfg)
    assert result.errors == []
    assert result.records_seen == 0
    assert result.events_ingested == 0
    assert result.new_alerts == []
    assert get_collector_setting("suricata_last_offset") == "0"
    assert get_collector_setting("suricata_last_run_at") is not None
    assert get_collector_setting("suricata_events_ingested") == "0"

    with path.open("a", encoding="utf-8") as fh:
        fh.write(_alert_line(0))
        fh.write("\n")
    second = collect_once(cfg)
    assert second.records_seen == 1
    assert second.events_ingested == 1
    assert len(_event_rows()) == 1


def test_collect_holds_back_partial_line_until_newline(_db, tmp_path):
    """A record Suricata is mid-write is never half-parsed.

    Expectation: the incomplete trailing line is withheld and the committed
    offset does not advance past it; once the newline arrives the record is
    ingested exactly once (no duplicate on the following cycle).
    """
    line = _alert_line(0, ts="2024-10-12T08:00:01.220741Z")
    path = tmp_path / "eve.json"
    path.write_text(line[:60], encoding="utf-8")  # mid-write, no newline
    cfg = SuricataConfig(eve_path=str(path))

    partial = collect_once(cfg)
    assert partial.records_seen == 0
    assert partial.events_ingested == 0
    assert partial.errors == []
    assert get_collector_setting("suricata_last_offset") == "0"
    assert _event_rows() == []

    with path.open("a", encoding="utf-8") as fh:
        fh.write(line[60:] + "\n")
    completed = collect_once(cfg)
    assert completed.records_seen == 1
    assert completed.events_ingested == 1
    assert len(_alert_rows()) == 1

    idle = collect_once(cfg)
    assert idle.records_seen == 0
    assert idle.events_ingested == 0
    assert len(_event_rows()) == 1  # no duplicate from re-reading the tail


def test_collect_reports_unreadable_file(_db, tmp_path):
    """A permission-denied EVE file is reported, never raised.

    Skipped when running as root: root bypasses filesystem permissions, so the
    unreadable condition cannot be reproduced.
    """
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("cannot make a file unreadable as root")

    path = tmp_path / "eve.json"
    path.write_text(_alert_line(0) + "\n", encoding="utf-8")
    os.chmod(path, 0o000)
    try:
        result = collect_once(SuricataConfig(eve_path=str(path)))
        assert result.events_ingested == 0
        assert result.records_seen == 0
        assert result.errors, "an unreadable EVE file must be reported"
        assert "Permission denied" in result.errors[0]
        assert _event_rows() == []
    finally:
        os.chmod(path, 0o600)


def test_collect_truncation_to_zero_resets_checkpoint(_db, tmp_path):
    """Truncating the EVE file to 0 bytes resets the offset and keeps working.

    Expectation: the shrink is detected (``fallback_used``), the offset returns
    to 0 without error, and records written afterwards are ingested.
    """
    path = tmp_path / "eve.json"
    _write_eve(path, [_alert_line(0), _alert_line(1)])
    cfg = SuricataConfig(eve_path=str(path))

    first = collect_once(cfg)
    assert first.events_ingested == 2
    assert first.fallback_used is False

    path.write_text("", encoding="utf-8")
    truncated = collect_once(cfg)
    assert truncated.errors == []
    assert truncated.records_seen == 0
    assert truncated.fallback_used is True
    assert get_collector_setting("suricata_last_offset") == "0"
    assert len(_event_rows()) == 2  # nothing lost, nothing duplicated

    _write_eve(path, [_alert_line(2)])
    resumed = collect_once(cfg)
    assert resumed.records_seen == 1
    assert resumed.events_ingested == 1
    assert resumed.fallback_used is False
    assert len(_event_rows()) == 3


def test_collect_restart_resumes_from_persisted_checkpoint(_db, tmp_path):
    """A restarted collector resumes from the checkpoint stored in the database.

    The checkpoint lives in ``collector_state`` (not in process memory), so a
    fresh configuration object -- the "restarted process" -- must not re-ingest
    already-collected records.
    """
    path = tmp_path / "eve.json"
    _write_eve(path, [_alert_line(i) for i in range(3)])

    before = collect_once(SuricataConfig(eve_path=str(path)))
    assert before.events_ingested == 3
    checkpoint = get_collector_setting("suricata_last_offset")
    assert checkpoint == str(path.stat().st_size)

    # "Restart": brand-new config object, same database.
    after_restart = collect_once(SuricataConfig(eve_path=str(path)))
    assert after_restart.records_seen == 0
    assert after_restart.events_ingested == 0
    assert len(_event_rows()) == 3
    assert get_collector_setting("suricata_last_offset") == checkpoint

    # Only genuinely new bytes are collected after the restart.
    with path.open("a", encoding="utf-8") as fh:
        fh.write(_alert_line(3) + "\n")
    resumed = collect_once(SuricataConfig(eve_path=str(path)))
    assert resumed.events_ingested == 1
    assert len(_event_rows()) == 4


# --------------------------------------------------------------------------- #
# Suricata rotation & crash-recovery hardening
# --------------------------------------------------------------------------- #


def test_collect_restart_after_partial_line_then_complete(_db, tmp_path):
    """A collector restart after holding back an incomplete final line must
    ingest that line exactly once once the newline arrives."""
    path = tmp_path / "eve.json"
    line = _alert_line(0, ts="2024-10-12T08:00:01.220741Z")
    path.write_text(line[:60], encoding="utf-8")  # mid-write, no newline
    cfg = SuricataConfig(eve_path=str(path))

    # First "cycle": partial line held back, nothing ingested, offset at 0.
    partial = collect_once(cfg)
    assert partial.events_ingested == 0
    assert get_collector_setting("suricata_last_offset") == "0"
    assert _event_rows() == []

    # Simulate a restart: brand-new config object, same database + file.
    with path.open("a", encoding="utf-8") as fh:
        fh.write(line[60:] + "\n")  # complete the line
    restarted = collect_once(SuricataConfig(eve_path=str(path)))
    assert restarted.events_ingested == 1
    assert len(_event_rows()) == 1
    # Offset must have advanced past the now-complete line.
    assert get_collector_setting("suricata_last_offset") == str(path.stat().st_size)

    # Idle cycle: no duplicates from re-reading the tail.
    idle = collect_once(SuricataConfig(eve_path=str(path)))
    assert idle.events_ingested == 0
    assert len(_event_rows()) == 1


def test_collect_rename_rotation_detected_via_inode(_db, tmp_path):
    """Rename-based rotation (new inode) whose replacement file has already
    grown past the old offset must still be detected as rotation.

    Rotation detection that relies only on ``offset > size`` misses this case:
    the new file is larger than the old offset, so ``offset > size`` is false,
    no generation bump occurs, and the collector seeks into the middle of the
    new file -- skipping records at offsets [0, old_offset).
    """
    path = tmp_path / "eve.json"
    _write_eve(path, [_alert_line(0)])
    cfg = SuricataConfig(eve_path=str(path))

    first = collect_once(cfg)
    assert first.events_ingested == 1
    old_offset = int(get_collector_setting("suricata_last_offset"))

    # Rotate: rename the current file away (its inode), then write a larger
    # replacement file at the same path (a new inode).
    rotated = tmp_path / "eve.json.old"
    os.rename(path, rotated)
    _write_eve(path, [_alert_line(i) for i in range(1, 6)])  # 5 records

    second = collect_once(cfg)
    # All 5 new records must be ingested; none may be skipped.
    assert second.events_ingested == 5, second
    assert len(_event_rows()) == 6  # 1 old + 5 new
    # The replacement file has a new inode; generation must have been bumped.
    gen = get_collector_setting("suricata_file_generation")
    assert gen is not None and int(gen) >= 1
    new_offset = get_collector_setting("suricata_last_offset")
    assert new_offset == str(path.stat().st_size)


def test_collect_copytruncate_rotation(_db, tmp_path):
    """Copy-truncate rotation: same inode, file truncated then rewritten.

    The shrink below the stored offset is detected via ``offset > size``,
    the generation is bumped, and new content written after the truncate is
    ingested without colliding with the pre-truncate records' offsets.
    """
    path = tmp_path / "eve.json"
    _write_eve(path, [_alert_line(0), _alert_line(1)])
    cfg = SuricataConfig(eve_path=str(path))

    first = collect_once(cfg)
    assert first.events_ingested == 2
    old_offset = int(get_collector_setting("suricata_last_offset"))
    assert old_offset > 0

    # Copy-truncate: truncate the same file (same inode) to 0, then rewrite.
    path.write_text("", encoding="utf-8")
    truncated = collect_once(cfg)
    assert truncated.fallback_used is True
    assert get_collector_setting("suricata_last_offset") == "0"
    gen_after_truncate = int(get_collector_setting("suricata_file_generation"))

    # Write fresh content (same inode, new generation).
    _write_eve(path, [_alert_line(2), _alert_line(3)])
    resumed = collect_once(cfg)
    assert resumed.events_ingested == 2
    assert resumed.fallback_used is False
    assert len(_event_rows()) == 4  # 2 pre-truncate + 2 post-truncate
    # Generation was already bumped by the truncation; a normal append from
    # offset 0 does not re-bump it.
    assert int(get_collector_setting("suricata_file_generation")) == gen_after_truncate
    assert get_collector_setting("suricata_last_offset") == str(path.stat().st_size)


def test_collect_malformed_then_valid_lines(_db, tmp_path):
    """Malformed lines are skipped without aborting the batch; valid lines
    around them are ingested and the offset advances past the garbage."""
    path = tmp_path / "eve.json"
    with path.open("w", encoding="utf-8") as fh:
        fh.write("this is not json\n")
        fh.write(_alert_line(0))
        fh.write("\n")
        fh.write("{not valid json either\n")
        fh.write(_alert_line(1))
        fh.write("\n")
    cfg = SuricataConfig(eve_path=str(path))

    result = collect_once(cfg)
    assert result.errors == []
    assert result.events_ingested == 2
    assert len(_event_rows()) == 2
    assert get_collector_setting("suricata_last_offset") == str(path.stat().st_size)


def test_collect_concurrent_calls_do_not_duplicate(_db, tmp_path):
    """Concurrent collection calls on the same file/database must not store
    duplicate events: the (source, source_record_id) unique index lets exactly
    one insert win per identifiable record."""
    path = _write_eve(tmp_path / "eve.json", [_alert_line(i) for i in range(5)])
    cfg = SuricataConfig(eve_path=str(path))

    # Prime: one cycle stores all 5 and advances the offset to EOF.
    first = collect_once(cfg)
    assert first.events_ingested == 5

    errors: list[BaseException] = []
    results: list[dict] = []
    lock = threading.Lock()

    def worker(_tag: int) -> None:
        try:
            results.append(collect_once(cfg))
        except BaseException as exc:  # noqa: BLE001 - collect failures
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert all(not t.is_alive() for t in threads), "a collector thread hung"
    assert not errors, f"concurrent collect raised: {errors}"
    # Offset already at EOF: every concurrent call finds nothing new.
    assert all(r.events_ingested == 0 for r in results)
    assert len(_event_rows()) == 5  # no duplicates


def test_collect_concurrent_insert_race_dedupes(_db, tmp_path):
    """Concurrent calls that read the same uncollected records: exactly one
    insert wins per record (source_record_id uniqueness), no duplicates."""
    import threading

    path = tmp_path / "eve.json"
    _write_eve(path, [_alert_line(i) for i in range(4)])
    cfg = SuricataConfig(eve_path=str(path))

    errors: list[BaseException] = []
    lock = threading.Lock()

    def worker(_tag: int) -> None:
        try:
            collect_once(cfg)
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert all(not t.is_alive() for t in threads), "a collector thread hung"
    assert not errors, f"concurrent collect raised: {errors}"
    # Exactly 4 events stored, no duplicates, despite 6 overlapping readers.
    assert len(_event_rows()) == 4
    rows = _event_rows()
    assert len({r["source_record_id"] for r in rows}) == 4
    assert all(r["source"] == "suricata" for r in rows)


def test_http_and_journal_idempotency_unchanged(_db, monkeypatch):
    """Regression guard: HTTP and journal idempotency from the prior milestone
    still work alongside Suricata changes (shared dedup storage unaffected)."""
    from backend.app.siem import ingest_lines

    monkeypatch.setenv("GREYWATCH_DB", str(_db / "cross.db"))
    initialize_database()
    ip = "203.0.113.10"
    lines = [
        f"sshd[700]: Failed password for attacker from {ip} port 54000 ssh2"
    ]
    ids = ["http-shared-id"]

    first = ingest_lines(lines, ids)
    second = ingest_lines(lines, ids)  # replay

    assert first["parsed"] == 1
    assert second["parsed"] == 1
    assert second["duplicates"] == 1  # replay skipped
    assert second["alerts"] == []  # no new alert, count not inflated
    assert len(list_events()) == 1  # one logical event


# --------------------------------------------------------------------------- #
# Suricata alert creation, severity mapping, field preservation
# --------------------------------------------------------------------------- #


def test_collect_db_failure_rolls_back_and_preserves_checkpoint(
    _db, tmp_path, monkeypatch
):
    """A database failure mid-cycle must never advance the checkpoint.

    The optimistic offset, the inserted events and the raised alerts are
    committed in ONE transaction, so a failure during ingestion (e.g. a
    transient ``database is locked`` from the concurrent API) rolls the whole
    cycle back. The checkpoint therefore still points at the unprocessed
    record: the detection is not silently lost, and the retry ingests it
    exactly once (no duplicate).
    """
    import sqlite3

    path = _write_eve(tmp_path / "eve.json", [_alert_line(0)])
    cfg = SuricataConfig(eve_path=str(path))

    real = siem._store_events_and_detect
    calls = {"n": 0}

    def flaky(events, connection):
        # Run the real work first (events + alert written inside the caller's
        # transaction), then fail before the caller commits -- simulating a DB
        # error late in the cycle.
        real(events, connection)
        calls["n"] += 1
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(siem, "_store_events_and_detect", flaky)

    with pytest.raises(sqlite3.OperationalError):
        collect_once(cfg)

    assert calls["n"] == 1
    # Nothing from the failed cycle is visible, and the checkpoint is untouched.
    assert _event_rows() == []
    assert _alert_rows() == []
    assert get_collector_setting("suricata_last_offset") is None
    assert get_collector_setting("suricata_last_run_at") is None

    # Retry with the real pipeline resumes from the same record (no loss) and
    # ingests it exactly once (no duplicate).
    monkeypatch.setattr(siem, "_store_events_and_detect", real)
    result = collect_once(cfg)
    assert result.errors == []
    assert result.events_ingested == 1
    assert len(_alert_rows()) == 1
    assert _alert_rows()[0]["rule_id"] == "SURICATA_ALERT"
    assert len(_event_rows()) == 1
    assert get_collector_setting("suricata_last_offset") == str(path.stat().st_size)


def test_evaluate_detections_dispatches_all_rules(_db):
    """The shared pipeline runs every rule over one normalized batch.

    A batch mixing a threshold-reaching burst of SSH failures and a Suricata
    alert yields both ``SSH_BRUTE_FORCE`` and ``SURICATA_ALERT`` new alerts, in
    that stable order, from the single dispatch point -- proving the two
    telemetry sources share one detection path.
    """
    from backend.app.siem import parse_auth_line

    ssh_events = [
        parse_auth_line(
            f"dispatch-host sshd[1]: Failed password for root "
            f"from 203.0.113.9 port {40000 + i} ssh2"
        )
        for i in range(siem.BRUTE_FORCE_THRESHOLD)
    ]
    assert all(event is not None for event in ssh_events)
    assert {event["event_type"] for event in ssh_events} == {"ssh_login_failed"}

    rec = _eve_alert(sig_id=2023999, signature="ET TEST dispatch")
    suri_event = parse_eve_record(rec, raw_line=json.dumps(rec))

    with _connection() as connection:
        inserted, alerts, incidents = siem._store_events_and_detect(
            [*ssh_events, suri_event], connection
        )

    assert [a["rule_id"] for a in alerts] == ["SSH_BRUTE_FORCE", "SURICATA_ALERT"]
    # No ``ssh_login_success`` event, so the correlation rule fires no incident.
    assert incidents == []
    assert len(inserted) == len(ssh_events) + 1
    assert {a["rule_id"] for a in _alert_rows()} == {
        "SSH_BRUTE_FORCE",
        "SURICATA_ALERT",
    }


def test_collect_skips_invalid_records_but_keeps_valid_neighbours(_db, tmp_path):
    """Non-object JSON, bad timestamps and unknown types never abort a batch.

    Two distinct filtering layers, both intentional:
    * the file reader counts only **valid JSON objects** (non-JSON text and
      JSON scalars/arrays such as ``42`` or ``[1, 2, 3]`` are dropped), so
      ``records_seen`` is 3 here;
    * the classifier then drops records it cannot place in the event store
      (no usable timestamp, unrecognized ``event_type``), leaving exactly one
      ingestible alert -- and the valid record after them is still stored.
    """
    records = [
        "not-json-at-all",
        json.dumps([1, 2, 3]),          # valid JSON, not an EVE object
        json.dumps("just-a-string"),    # valid JSON, not an EVE object
        json.dumps(42),                 # valid JSON, not an EVE object
        json.dumps({"event_type": "alert", "timestamp": "not-a-timestamp"}),
        json.dumps({"timestamp": "2024-10-12T08:00:00Z", "event_type": "stats"}),
        _alert_line(0),
    ]
    path = _write_eve(tmp_path / "eve.json", records)
    result = collect_once(SuricataConfig(eve_path=str(path)))

    assert result.errors == []
    assert result.records_seen == 3  # the three valid JSON objects
    assert result.events_ingested == 1  # only the usable alert record
    assert len(_event_rows()) == 1
    assert _event_rows()[0]["event_type"] == "suricata_alert"


def test_disabled_collector_needs_an_explicit_manual_run(_db, tmp_path, monkeypatch):
    """Continuous collection is never silently enabled.

    Expectation: with ``GREYWATCH_SURICATA_ENABLED`` unset, ``get_config()``
    reports ``enabled=False`` and the CLI without ``--once`` refuses to
    collect (exit code 2) while still ingesting nothing; an explicit
    ``--once`` performs exactly one cycle.
    """
    monkeypatch.delenv("GREYWATCH_SURICATA_ENABLED", raising=False)
    path = _write_eve(tmp_path / "eve.json", [_alert_line(0)])
    monkeypatch.setenv("GREYWATCH_SURICATA_EVE_PATH", str(path))

    assert suricata_mod.get_config().enabled is False

    rc_disabled = suricata_mod.main([])  # no --once, not enabled
    assert rc_disabled == 2
    assert _event_rows() == []

    rc_once = suricata_mod.main(["--once"])
    assert rc_once == 0
    assert len(_event_rows()) == 1


# --------------------------------------------------------------------------- #
# Phase 4: unknown-signature incident keying
#
# A record with no rule identity (no signature AND no signature_id) keys on its
# category in addition to the network 5-tuple, so unrelated detections cannot
# collapse into one alert. Signature-bearing records are unchanged.
# --------------------------------------------------------------------------- #


def test_unknown_signature_distinct_categories_do_not_collapse(_db):
    """Two unknown-signature detections with different categories -> two alerts.

    Before the fix both collapsed into one alert whose stored severity/category
    came from the first event while its description came from the last, i.e. a
    self-contradicting alert. Each alert must now describe its own event.
    """
    recs = [
        _eve_alert(
            sig_id=None, signature=None, category="attempted-recon",
            severity=1, ts="2024-10-12T08:00:00.000000Z",
        ),
        _eve_alert(
            sig_id=None, signature=None, category="attempted-admin",
            severity=3, ts="2024-10-12T08:05:00.000000Z",
        ),
    ]
    events = [parse_eve_record(r, raw_line=json.dumps(r)) for r in recs]
    result = siem.ingest_events(events)

    assert len(result["alerts"]) == 2
    rows = sorted(_alert_rows(), key=lambda r: r["id"])
    assert [r["category"] for r in rows] == ["attempted-recon", "attempted-admin"]
    assert [r["event_count"] for r in rows] == [1, 1]
    # Stored severity agrees with each alert's own description (no mixing).
    assert rows[0]["severity"] == "high"
    assert "Suricata severity 1" in rows[0]["description"]
    assert rows[1]["severity"] == "low"
    assert "Suricata severity 3" in rows[1]["description"]
    # Every event is still stored.
    assert len(siem.list_events()) == 2


def test_unknown_signature_evidence_scoped_to_its_own_category(_db):
    """Evidence for an unknown-signature alert contains only its own detections."""
    recs = [
        _eve_alert(sig_id=None, signature=None, category="attempted-recon",
                   ts="2024-10-12T08:00:00.000000Z"),
        _eve_alert(sig_id=None, signature=None, category="attempted-admin",
                   ts="2024-10-12T08:05:00.000000Z"),
    ]
    siem.ingest_events([parse_eve_record(r, raw_line=json.dumps(r)) for r in recs])
    rows = sorted(_alert_rows(), key=lambda r: r["id"])

    for row in rows:
        detail = siem.get_alert_detail(row["id"])
        assert [e["event_type"] for e in detail["evidence_events"]] == ["suricata_alert"]
        assert len(detail["evidence_events"]) == row["event_count"]
        raw = json.loads(detail["evidence_events"][0]["raw_message"])
        assert raw["alert"]["category"] == row["category"]


def test_unknown_signature_same_category_still_aggregates(_db):
    """Identical unknown-signature detections still aggregate (dedup preserved).

    The category discriminator must not turn a sustained stream of the same
    exposure into unbounded alert creation.
    """
    recs = [
        _eve_alert(sig_id=None, signature=None, category="misc-activity",
                   ts=f"2024-10-12T08:00:0{i}.000000Z")
        for i in range(3)
    ]
    result = siem.ingest_events(
        [parse_eve_record(r, raw_line=json.dumps(r)) for r in recs]
    )
    assert len(result["alerts"]) == 1
    assert _alert_rows()[0]["event_count"] == 3
    assert len(siem.list_events()) == 3  # evidence retained


def test_unknown_signature_aggregates_across_collect_cycles(_db, tmp_path):
    """The unknown-signature key is stable across collector cycles."""
    path = tmp_path / "eve.json"
    _write_eve(path, [
        _eve_alert(sig_id=None, signature=None, category="misc-activity",
                   ts="2024-10-12T08:00:00.000000Z"),
    ])
    first = collect_once(SuricataConfig(eve_path=str(path)))
    assert len(first.new_alerts) == 1
    assert _alert_rows()[0]["event_count"] == 1

    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(_eve_alert(
            sig_id=None, signature=None, category="misc-activity",
            ts="2024-10-12T08:01:00.000000Z",
        )) + "\n")
    second = collect_once(SuricataConfig(eve_path=str(path)))
    assert second.events_ingested == 1
    assert second.new_alerts == []  # aggregated, not duplicated
    assert len(_alert_rows()) == 1
    assert _alert_rows()[0]["event_count"] == 2


def test_unknown_signature_outside_window_starts_new_alert(_db):
    """The aggregation window still applies to unknown-signature incidents."""
    window = siem.SURICATA_ALERT_WINDOW_MINUTES
    later = (
        datetime(2024, 10, 12, 8, 0, 0, tzinfo=timezone.utc) + timedelta(minutes=window + 1)
    ).isoformat(timespec="seconds")
    recs = [
        _eve_alert(sig_id=None, signature=None, category="misc-activity",
                   ts="2024-10-12T08:00:00.000000Z"),
        _eve_alert(sig_id=None, signature=None, category="misc-activity", ts=later),
    ]
    result = siem.ingest_events(
        [parse_eve_record(r, raw_line=json.dumps(r)) for r in recs]
    )
    assert len(result["alerts"]) == 2
    assert {a["event_count"] for a in result["alerts"]} == {1}


def test_signature_bearing_dedup_ignores_category(_db):
    """Backward compatibility: with a rule identity present, category is NOT
    part of the key, so a signature whose category text differs (rule updates,
    re-categorised signatures) still aggregates as before."""
    recs = [
        _eve_alert(sig_id=2023001, signature="ET SCAN sig", category="cat-a",
                   ts="2024-10-12T08:00:00.000000Z"),
        _eve_alert(sig_id=2023001, signature="ET SCAN sig", category="cat-b",
                   ts="2024-10-12T08:05:00.000000Z"),
    ]
    result = siem.ingest_events(
        [parse_eve_record(r, raw_line=json.dumps(r)) for r in recs]
    )
    assert len(result["alerts"]) == 1
    assert _alert_rows()[0]["event_count"] == 2
    detail = siem.get_alert_detail(_alert_rows()[0]["id"])
    assert len(detail["evidence_events"]) == 2


# --------------------------------------------------------------------------- #
# Operational logging: run_loop() observability (PR #3 review, finding #2)
# --------------------------------------------------------------------------- #


def test_run_cycle_logs_errors_for_missing_eve_file(_db, tmp_path, caplog):
    """A missing/unreadable EVE file is logged at ERROR by ``_run_cycle`` so a
    misconfigured continuous collector is visible without querying /status."""
    cfg = SuricataConfig(eve_path=str(tmp_path / "does-not-exist.json"))
    with caplog.at_level("ERROR", logger="greywatch.suricata"):
        result = suricata_mod._run_cycle(cfg)
    assert result is not None
    assert result.errors  # "EVE file not found: ..."
    assert "collection cycle reported errors" in caplog.text
    assert "EVE file not found" in caplog.text


def test_run_cycle_is_silent_on_clean_idle_cycle(_db, tmp_path, caplog):
    """An idle cycle with no records and no errors must not write to the log
    (no flood on every poll)."""
    eve = tmp_path / "eve.json"
    eve.write_text("", encoding="utf-8")
    cfg = SuricataConfig(eve_path=str(eve))
    with caplog.at_level("ERROR", logger="greywatch.suricata"):
        result = suricata_mod._run_cycle(cfg)
    assert result.errors == []
    assert "collection cycle reported errors" not in caplog.text
    assert "collection cycle failed" not in caplog.text


def test_run_cycle_swallows_and_logs_unexpected_exceptions(_db, monkeypatch, caplog):
    """``collect_once`` reports file/IO errors via ``result.errors``; anything
    unexpected still kills only the cycle (logged), not the daemon."""
    def boom(config):
        raise RuntimeError("simulated disk corruption")

    monkeypatch.setattr(suricata_mod, "collect_once", boom)
    with caplog.at_level("ERROR", logger="greywatch.suricata"):
        result = suricata_mod._run_cycle(SuricataConfig())
    assert result is None
    assert "collection cycle failed" in caplog.text
    assert "simulated disk corruption" in caplog.text
