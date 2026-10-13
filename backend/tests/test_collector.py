"""Tests for the native systemd-journal authentication collector.

These tests are hermetic: the real ``journalctl`` is never invoked. The
collect* tests monkeypatch ``backend.app.collector.run_journalctl`` with a
deterministic fake that returns canned JSON records, so they run in CI (where
there may be no readable system journal) exactly as on a Fedora host.

The real-journal acceptance verification (injecting events with ``logger`` and
collecting them) is documented in ``docs/JOURNAL_COLLECTOR.md`` and performed
manually against the host journal — see the verification steps at the end of
this file's module docstring.
"""

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app import collector as collector_mod
from backend.app.collector import (
    CollectResult,
    JournalctlError,
    collect_once,
    parse_journal_record,
    run_journalctl,
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
# Helpers
# --------------------------------------------------------------------------- #


def _us(iso: str) -> str:
    """Convert an ISO-8601 timestamp to journalctl's µs-since-epoch form."""
    return str(int(datetime.fromisoformat(iso).timestamp() * 1_000_000))


def _iso_from_us(us: str) -> str:
    """Inverse of :func:`_us`: µs-since-epoch -> normalized UTC ISO 8601."""
    return (
        datetime.fromtimestamp(int(us) / 1_000_000, tz=timezone.utc)
        .astimezone(timezone.utc)
        .isoformat(timespec="seconds")
    )


def rec(
    cursor: str,
    iso: str,
    message: str,
    host: str = "fedora",
    ident: str = "sudo",
    cursor_present: bool = True,
) -> dict:
    """Build a journal JSON record (same shape ``journalctl --output=json``)."""
    record = {
        "__REALTIME_TIMESTAMP": _us(iso),
        "_HOSTNAME": host,
        "SYSLOG_IDENTIFIER": ident,
        "MESSAGE": message,
    }
    if cursor_present:
        record["__CURSOR"] = cursor
    return record


class FakeJournal:
    """A controllable stand-in for :func:`run_journalctl`.

    * ``initial`` is returned when no cursor is available (``--since`` path).
    * ``after`` is returned for ``--after-cursor`` reads. Set to the sentinel
      ``"RAISE"`` to simulate an invalid cursor (journal rotation).
    * Every call's args are recorded in ``self.calls`` for assertions.
    """

    RAISE = "RAISE"

    def __init__(self, initial=None, after=None):
        self.initial = list(initial or [])
        self.after = after
        self.calls = []

    def __call__(self, args, *, command=collector_mod.DEFAULT_JOURNALCTL):
        self.calls.append(list(args))
        if "--after-cursor" in args:
            if self.after == self.RAISE:
                raise JournalctlError(
                    "Failed to seek to cursor: Invalid argument"
                )
            return list(self.after or [])
        # bootstrap / fallback (--since) path
        return list(self.initial or [])


@pytest.fixture
def _db(tmp_path, monkeypatch):
    """Point the collector + API at a fresh temp database for the test."""
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "test.db"))
    initialize_database()
    yield tmp_path


@pytest.fixture
def patch_journal(monkeypatch):
    """Patch ``run_journalctl`` and yield a fresh :class:`FakeJournal`."""
    fake = FakeJournal()
    monkeypatch.setattr(collector_mod, "run_journalctl", fake)
    return fake


def _event_rows():
    with _connection() as conn:
        rows = conn.execute("SELECT * FROM events").fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------- #
# Parsing: PAM / sudo / SSH classification
# --------------------------------------------------------------------------- #


def test_parse_sudo_session_opened():
    event = parse_journal_record(
        rec(
            "c1",
            "2026-10-13T10:00:00+00:00",
            "pam_unix(sudo:session): session opened for user root(uid=0) "
            "by ry3k(uid=1000)",
            ident="sudo",
        )
    )
    assert event is not None
    assert event["event_type"] == "sudo_session_opened"
    assert event["username"] == "root"
    assert event["severity"] == "info"


def test_parse_sudo_session_closed():
    event = parse_journal_record(
        rec(
            "c2",
            "2026-10-13T10:00:01+00:00",
            "pam_unix(sudo:session): session closed for user root",
            ident="sudo",
        )
    )
    assert event is not None
    assert event["event_type"] == "sudo_session_closed"
    assert event["username"] == "root"


def test_parse_sudo_command_preserves_target_user():
    event = parse_journal_record(
        rec(
            "c3",
            "2026-10-13T10:00:02+00:00",
            "    ry3k : TTY=pts/0 ; PWD=/home/ry3k ; USER=root "
            "; COMMAND=/usr/bin/journalctl -b",
            ident="sudo",
        )
    )
    assert event is not None
    assert event["event_type"] == "sudo_command"
    assert event["username"] == "root"
    assert event["severity"] == "low"


def test_parse_pam_auth_failure():
    event = parse_journal_record(
        rec(
            "c4",
            "2026-10-13T10:00:03+00:00",
            "sudo: pam_unix(sudo:auth): authentication failure; "
            "logname= uid=1000 ... user=root ...",
            ident="sudo",
        )
    )
    assert event is not None
    assert event["event_type"] == "pam_auth_failed"
    assert event["username"] == "root"
    assert event["severity"] == "high"


def test_parse_journal_sshd_failed_login_feeds_ssh_rule():
    """A journal-sourced sshd failure must still map to ssh_login_failed so the
    existing SSH_BRUTE_FORCE rule fires identically to line-based ingestion."""
    event = parse_journal_record(
        rec(
            "c5",
            "2026-10-13T10:00:04+00:00",
            "Failed password for invalid user admin from 203.0.113.10 "
            "port 54001 ssh2",
            ident="sshd",
        )
    )
    assert event is not None
    assert event["event_type"] == "ssh_login_failed"
    assert event["username"] == "admin"
    assert event["source_ip"] == "203.0.113.10"
    assert event["severity"] == "medium"


def test_parse_journal_sshd_accepted_and_invalid_user():
    accepted = parse_journal_record(
        rec(
            "c6",
            "2026-10-13T10:00:05+00:00",
            "Accepted publickey for demo from 192.0.2.20 port 54006 ssh2",
            ident="sshd",
        )
    )
    assert accepted["event_type"] == "ssh_login_success"
    assert accepted["username"] == "demo"
    assert accepted["source_ip"] == "192.0.2.20"

    invalid = parse_journal_record(
        rec(
            "c7",
            "2026-10-13T10:00:06+00:00",
            "Invalid user ghost from 203.0.113.10",
            ident="sshd",
        )
    )
    assert invalid["event_type"] == "ssh_invalid_user"
    assert invalid["username"] == "ghost"
    assert invalid["source_ip"] == "203.0.113.10"


def test_unrecognized_journal_record_ignored():
    # An sshd record whose MESSAGE is unrelated to auth is not an event.
    event = parse_journal_record(
        rec(
            "c8",
            "2026-10-13T10:00:07+00:00",
            "Connection closed by 192.0.2.5 port 54000",
            ident="sshd",
        )
    )
    assert event is None


# --------------------------------------------------------------------------- #
# Parsing: timestamp / hostname / provenance preservation
# --------------------------------------------------------------------------- #


def test_timestamp_and_hostname_preserved():
    event = parse_journal_record(
        rec(
            "c9",
            "2026-10-13T10:00:00+00:00",
            "pam_unix(sudo:session): session opened for user root "
            "by ry3k(uid=1000)",
            host="fedora",
        )
    )
    assert event["timestamp"] == "2026-10-13T10:00:00+00:00"
    assert event["host"] == "fedora"


def test_raw_message_preserved_verbatim():
    message = "pam_unix(sudo:session): session opened for user root(uid=0) by ry3k(uid=1000)"
    event = parse_journal_record(rec("c9b", "2026-10-13T10:00:00+00:00", message))
    assert event["raw_message"] == message


def test_genuine_journal_events_distinguished_from_synthetic():
    """`__CURSOR` presence is the line between real and synthetic records."""
    genuine = parse_journal_record(
        rec("g1", "2026-10-13T10:00:00+00:00",
            "pam_unix(sudo:session): session opened for user root by u(uid=1000)")
    )
    assert genuine is not None
    assert genuine["source"] == "journal"

    synthetic = parse_journal_record(
        rec("g1", "2026-10-13T10:00:00+00:00",
            "pam_unix(sudo:session): session opened for user root by u(uid=1000)",
            cursor_present=False)
    )
    assert synthetic is not None
    assert synthetic["source"] == "test"
    # Same message -> only the provenance marker differs.
    assert genuine["raw_message"] == synthetic["raw_message"]


def test_journal_timestamp_microseconds_converted():
    # 2026-10-13T05:06:58Z == 1791868618s -> µs
    rec_us = rec(
        "c10",
        "2026-10-13T05:06:58+00:00",
        "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)",
    )
    expected = _iso_from_us(rec_us["__REALTIME_TIMESTAMP"])
    assert parse_journal_record(rec_us)["timestamp"] == expected


# --------------------------------------------------------------------------- #
# Parsing: malformed records
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "record",
    [
        None,                                   # not a dict
        "not-a-record",                         # not a dict
        {},                                     # empty dict
        {"__CURSOR": "x"},                      # no MESSAGE, no timestamp
        {"MESSAGE": "pam_unix(sudo:session): session opened for user root"},  # no timestamp
        {"__REALTIME_TIMESTAMP": "not-a-number", "MESSAGE": "x", "_HOSTNAME": "h"},
        {"__REALTIME_TIMESTAMP": "", "MESSAGE": "x", "_HOSTNAME": "h"},
        {"__CURSOR": "x", "__REALTIME_TIMESTAMP": _us("2026-10-13T10:00:00+00:00"), "_HOSTNAME": "h", "MESSAGE": ""},
        {"__CURSOR": "x", "__REALTIME_TIMESTAMP": _us("2026-10-13T10:00:00+00:00"), "_HOSTNAME": "h", "MESSAGE": "unrelated kernel noise"},
    ],
)
def test_malformed_records_are_skipped(record):
    assert parse_journal_record(record) is None


def test_malformed_json_line_in_run_journalctl_is_skipped(tmp_path):
    """A corrupt JSON line emitted by journalctl must not abort parsing."""
    fake = tmp_path / "fake-journalctl"
    fake.write_text("#!/bin/sh\n")
    fake.chmod(0o755)
    import subprocess

    good = json.dumps(
        rec("c", "2026-10-13T10:00:00+00:00",
            "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)")
    )
    mixed = good + "\nnot json at all\n\n" + good

    original_run = subprocess.run

    def fake_run(cmd, **kwargs):
        if cmd and cmd[0] == str(fake):
            return subprocess.CompletedProcess(cmd, 0, stdout=mixed, stderr="")
        return original_run(cmd, **kwargs)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("subprocess.run", fake_run)
    try:
        records = run_journalctl([], command=str(fake))
    finally:
        monkeypatch.undo()
    # The two valid JSON objects survive; the corrupt line is skipped.
    assert len(records) == 2


# --------------------------------------------------------------------------- #
# Collection: ingestion + detection
# --------------------------------------------------------------------------- #


def test_collect_ingests_journal_events(_db, patch_journal):
    patch_journal.initial = [
        rec("c1", "2026-10-13T10:00:00+00:00",
            "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)",
            ident="sudo"),
        rec("c2", "2026-10-13T10:00:01+00:00",
            "pam_unix(sudo:session): session closed for user root",
            ident="sudo"),
        rec("c3", "2026-10-13T10:00:02+00:00",
            "Failed password for invalid user admin from 203.0.113.10 "
            "port 54001 ssh2", ident="sshd"),
    ]
    result = collect_once(collector_mod.CollectorConfig())

    assert result.records_seen == 3
    assert result.events_ingested == 3
    rows = _event_rows()
    assert len(rows) == 3
    assert {r["event_type"] for r in rows} == {
        "sudo_session_opened", "sudo_session_closed", "ssh_login_failed"
    }
    assert all(r["source"] == "journal" for r in rows)
    assert rows[0]["host"] == "fedora"
    assert rows[2]["source_ip"] == "203.0.113.10"


def test_collect_preserves_timestamp_hostname_and_raw(_db, patch_journal):
    patch_journal.initial = [
        rec("c1", "2026-10-13T10:00:00+00:00",
            "pam_unix(sudo:session): session opened for user root "
            "by ry3k(uid=1000)", host="myhost", ident="sudo"),
    ]
    collect_once(collector_mod.CollectorConfig())
    rows = _event_rows()
    assert len(rows) == 1
    assert rows[0]["timestamp"] == "2026-10-13T10:00:00+00:00"
    assert rows[0]["host"] == "myhost"
    assert (
        rows[0]["raw_message"]
        == "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)"
    )
    assert rows[0]["source"] == "journal"


def test_collect_advances_checkpoint(_db, patch_journal):
    patch_journal.initial = [
        rec("c1", "2026-10-13T10:00:00+00:00",
            "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)"),
        rec("c2", "2026-10-13T10:00:01+00:00",
            "pam_unix(sudo:session): session closed for user root"),
    ]
    collect_once(collector_mod.CollectorConfig())
    assert get_collector_setting("journal_last_cursor") == "c2"
    assert get_collector_setting("journal_last_event_ts") == "2026-10-13T10:00:01+00:00"
    assert get_collector_setting("journal_events_ingested") == "2"
    assert get_collector_setting("journal_last_run_at") is not None


def test_collect_restart_does_not_duplicate(_db, patch_journal):
    """Checkpoint recovery: a second cycle must not re-ingest already-stored."""
    patch_journal.initial = [
        rec("c1", "2026-10-13T10:00:00+00:00",
            "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)"),
    ]
    # First run: ingests via the --since (no-cursor) path.
    first = collect_once(collector_mod.CollectorConfig())
    assert first.events_ingested == 1

    # Second run: cursor is stored, after-cursor returns nothing new.
    patch_journal.after = []
    second = collect_once(collector_mod.CollectorConfig())
    assert second.records_seen == 0
    assert second.events_ingested == 0

    assert len(_event_rows()) == 1
    # Cursor unchanged when there was nothing new.
    assert get_collector_setting("journal_last_cursor") == "c1"


def test_collect_within_batch_dedup_by_cursor(_db, patch_journal):
    """Two identical records (same cursor) in one batch must yield one event."""
    dup = rec("cDUP", "2026-10-13T10:00:00+00:00",
              "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)")
    other = rec("cOTHER", "2026-10-13T10:00:01+00:00",
                "pam_unix(sudo:session): session closed for user root")
    patch_journal.initial = [dup, dup, other]

    result = collect_once(collector_mod.CollectorConfig())
    assert result.events_ingested == 2
    assert len(_event_rows()) == 2


def test_collect_fallback_on_invalid_cursor(_db, patch_journal):
    """When the cursor is invalid, fall back to --since and still advance."""
    patch_journal.initial = [
        rec("cB1", "2026-10-13T10:00:00+00:00",
            "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)"),
        rec("cB2", "2026-10-13T10:00:01+00:00",
            "pam_unix(sudo:session): session closed for user root"),
    ]
    first = collect_once(collector_mod.CollectorConfig())
    assert first.events_ingested == 2
    assert get_collector_setting("journal_last_cursor") == "cB2"

    # Now simulate cursor invalidation on the next incremental read.
    patch_journal.after = FakeJournal.RAISE
    # Fallback (--since) returns one brand-new record.
    patch_journal.initial = [
        rec("cF3", "2026-10-13T10:05:00+00:00",
            "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)"),
    ]

    second = collect_once(collector_mod.CollectorConfig())
    assert second.fallback_used is True
    assert second.events_ingested == 1
    assert get_collector_setting("journal_last_cursor") == "cF3"
    assert len(_event_rows()) == 3


def test_collect_fallback_no_duplicates_on_overlap(_db, patch_journal):
    """A --since fallback that re-reads already-ingested records must not
    create duplicates (deduplication against recently-stored events)."""
    patch_journal.initial = [
        rec("cD1", "2026-10-13T10:00:00+00:00",
            "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)"),
        rec("cD2", "2026-10-13T10:00:01+00:00",
            "pam_unix(sudo:session): session closed for user root"),
    ]
    collect_once(collector_mod.CollectorConfig())
    assert len(_event_rows()) == 2

    # Cursor invalidated; fallback re-reads cD1+cD2 (overlap) plus a new cD4.
    patch_journal.after = FakeJournal.RAISE
    patch_journal.initial = [
        rec("cD1", "2026-10-13T10:00:00+00:00",
            "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)"),
        rec("cD2", "2026-10-13T10:00:01+00:00",
            "pam_unix(sudo:session): session closed for user root"),
        rec("cD4", "2026-10-13T10:05:00+00:00",
            "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)"),
    ]

    result = collect_once(collector_mod.CollectorConfig())
    # Only the genuinely new record is ingested.
    assert result.events_ingested == 1
    assert len(_event_rows()) == 3


def test_journal_sshd_events_trigger_brute_force(_db, patch_journal):
    """Regression: journal-sourced sshd failures still raise SSH_BRUTE_FORCE."""
    ip = "203.0.113.10"
    patch_journal.initial = [
        rec(
            f"c{i}",
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            f"Failed password for user{i} from {ip} port {54000+i} ssh2",
            ident="sshd",
        )
        for i in range(5)
    ]
    result = collect_once(collector_mod.CollectorConfig())

    assert result.events_ingested == 5
    assert len(result.new_alerts) == 1
    assert result.new_alerts[0]["rule_id"] == "SSH_BRUTE_FORCE"
    assert result.new_alerts[0]["severity"] == "high"

    # Verify end-to-end via the API as well.
    resp = client.get("/api/v1/alerts")
    assert resp.status_code == 200
    alerts = resp.json()["alerts"]
    assert any(a["rule_id"] == "SSH_BRUTE_FORCE" for a in alerts)


def test_ingest_events_runs_detection_and_preserves_source(_db):
    """The structured-events path stores provenance and runs detection."""
    from backend.app.siem import ingest_events

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ip = "198.51.100.7"
    events = [
        {
            "timestamp": now,
            "host": "fedora",
            "event_type": "ssh_login_failed",
            "username": f"u{i}",
            "source_ip": ip,
            "severity": "medium",
            "raw_message": f"Failed password for u{i} from {ip} port {40000+i} ssh2",
            "source": "journal",
        }
        for i in range(5)
    ]
    payload = ingest_events(events)
    assert payload["parsed"] == 5
    assert len(payload["alerts"]) == 1
    assert payload["alerts"][0]["rule_id"] == "SSH_BRUTE_FORCE"

    rows = _event_rows()
    assert len(rows) == 5
    assert all(r["source"] == "journal" for r in rows)


# --------------------------------------------------------------------------- #
# API: journal status + collect endpoints
# --------------------------------------------------------------------------- #


def test_journal_status_endpoint(_db):
    resp = client.get("/api/v1/journal/status")
    assert resp.status_code == 200
    body = resp.json()
    assert "enabled" in body and "last_cursor" in body
    assert "events_ingested" in body


def test_journal_collect_endpoint_uses_collector(_db, monkeypatch):
    payload = {
        "__CURSOR": "ep1",
        "__REALTIME_TIMESTAMP": _us("2026-10-13T10:00:00+00:00"),
        "_HOSTNAME": "fedora",
        "SYSLOG_IDENTIFIER": "sudo",
        "MESSAGE": "pam_unix(sudo:session): session opened for user root by ry3k(uid=1000)",
    }
    monkeypatch.setattr(
        collector_mod, "run_journalctl", lambda args, **kw: [payload]
    )
    monkeypatch.setattr(collector_mod, "get_config", lambda: collector_mod.CollectorConfig())

    resp = client.post("/api/v1/journal/collect")
    assert resp.status_code == 200
    body = resp.json()
    assert body["events_ingested"] == 1

    resp = client.get("/api/v1/events?limit=10")
    assert resp.status_code == 200
    events = resp.json()["events"]
    assert any(e["source"] == "journal" for e in events)


def test_journal_collect_falls_back_when_journalctl_missing(_db, monkeypatch):
    """If journalctl is unavailable the API reports the error, not a 500."""

    def _raise_missing(args, **kwargs):
        raise JournalctlError("journalctl binary not found: journalctl")

    monkeypatch.setattr(collector_mod, "get_config", lambda: collector_mod.CollectorConfig())
    monkeypatch.setattr(collector_mod, "run_journalctl", _raise_missing)

    resp = client.post("/api/v1/journal/collect")
    assert resp.status_code == 200
    body = resp.json()
    assert body["events_ingested"] == 0
    assert body["errors"]


# --------------------------------------------------------------------------- #
# Migration: legacy events table gains the source column
# --------------------------------------------------------------------------- #


def test_events_source_column_added_to_legacy_db(tmp_path, monkeypatch):
    monkeypatch.setenv("GREYWATCH_DB", str(tmp_path / "legacy.db"))
    legacy = _open_legacy_db(tmp_path / "legacy.db")
    legacy.close()

    initialize_database()

    with _connection() as conn:
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
    assert "source" in cols
    # collector_state table is created too.
    with _connection() as conn:
        tables = {row["name"] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()}
    assert "collector_state" in tables


def _open_legacy_db(path):
    import sqlite3
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            host TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT,
            source_ip TEXT,
            severity TEXT NOT NULL,
            raw_message TEXT NOT NULL
        );
        """
    )
    conn.commit()
    return conn
