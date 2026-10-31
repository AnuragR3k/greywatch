"""Tests for the Greywatch event-retention system (backend/app/siem.py + retention.py).

All tests use isolated temporary databases via ``monkeypatch.setenv("GREYWATCH_DB", ...)``
so the production database ``data/greywatch.db`` is never touched.  The conftest
autouse fixture additionally redirects an unset ``GREYWATCH_DB`` to a temp path.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.app.siem import (
    BRUTE_FORCE_WINDOW_MINUTES,
    DEFAULT_RETENTION_BATCH_SIZE,
    RETENTION_BATCH_SIZE_ENV,
    RETENTION_DAYS_ENV,
    SURICATA_ALERT_RULE,
    RetentionSummary,
    _connection,
    _offset_iso,
    _protected_event_ids,
    compute_retention_summary,
    get_retention_batch_size,
    get_retention_config,
    initialize_database,
    ingest_lines,
    prune_events,
    vacuum_database,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _iso_offset(days: int = 0, hours: int = 0, minutes: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp at ``now + offset``."""
    dt = datetime.now(timezone.utc) + timedelta(days=days, hours=hours, minutes=minutes)
    return dt.isoformat(timespec="seconds")


def _old_timestamp(days_ago: int) -> str:
    """Return an ISO-8601 timestamp ``days_ago`` days before now."""
    dt = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return dt.isoformat(timespec="seconds")


def _insert_event(
    connection: sqlite3.Connection,
    *,
    timestamp: str | None = None,
    event_type: str = "ssh_login_failed",
    source_ip: str = "203.0.113.10",
    severity: str = "medium",
    source: str | None = None,
    source_record_id: str | None = None,
    signature: str | None = None,
    signature_id: int | None = None,
    dest_ip: str | None = None,
    src_port: int | None = None,
    dest_port: int | None = None,
    proto: str | None = None,
    category: str | None = None,
    raw_message: str | None = None,
) -> int:
    """Insert a single event row and return its id."""
    if timestamp is None:
        timestamp = _iso_offset(minutes=1)
    if raw_message is None:
        raw_message = f"test event {event_type} {source_ip}"
    cursor = connection.execute(
        """
        INSERT INTO events (
            timestamp, host, event_type, username, source_ip, severity,
            raw_message, source, source_record_id, signature, signature_id,
            dest_ip, src_port, dest_port, proto, category
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            "lab-host",
            event_type,
            "testuser",
            source_ip,
            severity,
            raw_message,
            source,
            source_record_id,
            signature,
            signature_id,
            dest_ip,
            src_port,
            dest_port,
            proto,
            category,
        ),
    )
    return cursor.lastrowid


def _insert_alert(
    connection: sqlite3.Connection,
    *,
    rule_id: str = "SSH_BRUTE_FORCE",
    status: str = "open",
    created_at: str | None = None,
    last_triggered_at: str | None = None,
    source_ip: str = "203.0.113.10",
    signature: str | None = None,
    signature_id: int | None = None,
    dest_ip: str | None = None,
    src_port: int | None = None,
    dest_port: int | None = None,
    proto: str | None = None,
    category: str | None = None,
) -> int:
    """Insert an alert row and return its id."""
    if created_at is None:
        created_at = _iso_offset(minutes=1)
    if last_triggered_at is None:
        last_triggered_at = created_at
    cursor = connection.execute(
        """
        INSERT INTO alerts (
            created_at, rule_id, title, severity, source_ip, description,
            event_count, status, last_triggered_at,
            dest_ip, src_port, dest_port, proto, signature, signature_id, category
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            created_at,
            rule_id,
            "Test alert",
            "high",
            source_ip,
            "test description",
            5,
            status,
            last_triggered_at,
            dest_ip,
            src_port,
            dest_port,
            proto,
            signature,
            signature_id,
            category,
        ),
    )
    return cursor.lastrowid


def _insert_incident(
    connection: sqlite3.Connection,
    *,
    status: str = "open",
    created_at: str | None = None,
    first_seen_at: str | None = None,
    last_seen_at: str | None = None,
    rule_id: str = "SSH_BRUTE_FORCE_THEN_SUCCESS",
    source_ip: str = "203.0.113.10",
) -> int:
    """Insert an incident row and return its id."""
    if created_at is None:
        created_at = _iso_offset(minutes=1)
    if first_seen_at is None:
        first_seen_at = created_at
    if last_seen_at is None:
        last_seen_at = created_at
    cursor = connection.execute(
        """
        INSERT INTO incidents (
            created_at, updated_at, rule_id, title, severity, status,
            source_ip, description, event_count, first_seen_at, last_seen_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            created_at,
            created_at,
            rule_id,
            "Test incident",
            "critical",
            status,
            source_ip,
            "test description",
            5,
            first_seen_at,
            last_seen_at,
        ),
    )
    return cursor.lastrowid


def _link_event_to_incident(
    connection: sqlite3.Connection, incident_id: int, event_id: int
) -> None:
    """Insert a row into incident_events."""
    connection.execute(
        """
        INSERT INTO incident_events (incident_id, event_id, added_at)
        VALUES (?, ?, ?)
        """,
        (incident_id, event_id, _iso_offset(minutes=1)),
    )


# --------------------------------------------------------------------------- #
# Retention configuration
# --------------------------------------------------------------------------- #


def test_retention_disabled_by_default(tmp_path, monkeypatch):
    """When GREYWATCH_EVENT_RETENTION_DAYS is unset, retention is disabled."""
    monkeypatch.delenv(RETENTION_DAYS_ENV, raising=False)
    config = get_retention_config()
    assert config.retention_days is None


def test_invalid_retention_zero_rejected(tmp_path, monkeypatch):
    """A retention value of 0 is invalid and disables retention."""
    monkeypatch.setenv(RETENTION_DAYS_ENV, "0")
    config = get_retention_config()
    assert config.retention_days is None


def test_invalid_retention_negative_rejected(tmp_path, monkeypatch):
    """A negative retention value is invalid and disables retention."""
    monkeypatch.setenv(RETENTION_DAYS_ENV, "-5")
    config = get_retention_config()
    assert config.retention_days is None


def test_invalid_retention_non_numeric_rejected(tmp_path, monkeypatch):
    """A non-numeric retention value is invalid and disables retention."""
    monkeypatch.setenv(RETENTION_DAYS_ENV, "abc")
    config = get_retention_config()
    assert config.retention_days is None


def test_valid_retention_accepted(tmp_path, monkeypatch):
    """A positive integer retention value is accepted."""
    monkeypatch.setenv(RETENTION_DAYS_ENV, "90")
    config = get_retention_config()
    assert config.retention_days == 90


# --------------------------------------------------------------------------- #
# Dry-run behaviour
# --------------------------------------------------------------------------- #


def test_dry_run_does_not_modify_database(tmp_path, monkeypatch):
    """Dry-run mode reports counts but deletes nothing."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        _insert_event(conn, timestamp=_old_timestamp(10))
        _insert_event(conn, timestamp=_old_timestamp(5))
        _insert_event(conn, timestamp=_iso_offset(hours=1))

    with _connection() as conn:
        before = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    summary = prune_events(dry_run=True)

    with _connection() as conn:
        after = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    assert summary.dry_run is True
    assert before == 3
    assert after == 3  # unchanged
    assert summary.deleted_events == 0


def test_execute_removes_eligible_events(tmp_path, monkeypatch):
    """Execute mode deletes events older than the retention period."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        old_id = _insert_event(conn, timestamp=_old_timestamp(10))
        recent_id = _insert_event(conn, timestamp=_iso_offset(hours=1))
        conn.commit()

    summary = prune_events(dry_run=False, batch_size=DEFAULT_RETENTION_BATCH_SIZE)

    assert summary.dry_run is False
    assert summary.deleted_events == 1
    assert summary.batches_run == 1

    with _connection() as conn:
        ids = [r[0] for r in conn.execute("SELECT id FROM events").fetchall()]
    assert old_id not in ids
    assert recent_id in ids


def test_retention_disabled_is_noop(tmp_path, monkeypatch):
    """When retention is disabled, prune_events is a no-op."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.delenv(RETENTION_DAYS_ENV, raising=False)
    initialize_database()

    with _connection() as conn:
        _insert_event(conn, timestamp=_old_timestamp(365))
        conn.commit()

    summary = prune_events(dry_run=False)

    assert summary.disabled is True
    assert summary.deleted_events == 0

    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 1


# --------------------------------------------------------------------------- #
# Retention period boundaries
# --------------------------------------------------------------------------- #


def test_events_inside_retention_period_preserved(tmp_path, monkeypatch):
    """Events within the retention period are never deleted."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        # 2 days ago — within 3-day retention period.
        _insert_event(conn, timestamp=_old_timestamp(2))
        # Just now — definitely within retention.
        _insert_event(conn, timestamp=_iso_offset(hours=1))
        conn.commit()

    summary = prune_events(dry_run=False)

    assert summary.eligible_events == 0
    assert summary.deleted_events == 0

    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 2


def test_events_outside_retention_period_deleted(tmp_path, monkeypatch):
    """Events older than the retention period are eligible for deletion."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        _insert_event(conn, timestamp=_old_timestamp(5))
        _insert_event(conn, timestamp=_old_timestamp(10))
        _insert_event(conn, timestamp=_old_timestamp(60))
        conn.commit()

    summary = prune_events(dry_run=False)

    assert summary.eligible_events == 3
    assert summary.deletable_events == 3
    assert summary.deleted_events == 3

    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 0


def test_retention_boundary_exact_cutoff(tmp_path, monkeypatch):
    """Events exactly at the retention boundary are handled correctly.

    Events with ``timestamp == cutoff`` are NOT eligible (the comparison is
    strictly ``< cutoff``).  Events a fraction of a second older ARE eligible.
    """
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "7")
    initialize_database()

    cutoff = datetime.now(timezone.utc) - timedelta(days=7)

    with _connection() as conn:
        # Exactly at the cutoff — NOT eligible (strict <).
        _insert_event(conn, timestamp=cutoff.isoformat(timespec="seconds"))
        # One second before the cutoff — eligible.
        _insert_event(
            conn,
            timestamp=(cutoff - timedelta(seconds=1)).isoformat(timespec="seconds"),
        )
        conn.commit()

    summary = prune_events(dry_run=False)

    assert summary.eligible_events == 1
    assert summary.deleted_events == 1

    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 1  # the exact-cutoff event remains


# --------------------------------------------------------------------------- #
# Incident protection
# --------------------------------------------------------------------------- #


def test_events_referenced_by_incidents_preserved(tmp_path, monkeypatch):
    """Events linked to incidents (via incident_events) are never deleted."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        old_event = _insert_event(conn, timestamp=_old_timestamp(100))
        incident_id = _insert_incident(conn, status="resolved")
        _link_event_to_incident(conn, incident_id, old_event)
        # Also a non-incident event that is old — should be deleted.
        stray = _insert_event(conn, timestamp=_old_timestamp(100), source_ip="10.0.0.1")
        conn.commit()

    summary = prune_events(dry_run=False)

    assert summary.eligible_events == 2
    assert summary.protected_events == 1  # the incident-referenced event
    assert summary.deletable_events == 1  # the stray event
    assert summary.deleted_events == 1

    with _connection() as conn:
        ids = {r[0] for r in conn.execute("SELECT id FROM events").fetchall()}
    assert old_event in ids  # incident event preserved
    assert stray not in ids  # stray event deleted


def test_events_belonging_to_unresolved_incidents_preserved(tmp_path, monkeypatch):
    """Events linked to unresolved (open) incidents are preserved."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "5")
    initialize_database()

    with _connection() as conn:
        old_event = _insert_event(conn, timestamp=_old_timestamp(50))
        incident_id = _insert_incident(conn, status="open")
        _link_event_to_incident(conn, incident_id, old_event)
        conn.commit()

    summary = prune_events(dry_run=False)

    assert summary.protected_events == 1
    assert summary.deleted_events == 0

    with _connection() as conn:
        ids = {r[0] for r in conn.execute("SELECT id FROM events").fetchall()}
    assert old_event in ids


def test_events_belonging_to_acknowledged_incidents_preserved(tmp_path, monkeypatch):
    """Events linked to acknowledged incidents are preserved (not just open)."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "5")
    initialize_database()

    with _connection() as conn:
        old_event = _insert_event(conn, timestamp=_old_timestamp(50))
        incident_id = _insert_incident(conn, status="acknowledged")
        _link_event_to_incident(conn, incident_id, old_event)
        conn.commit()

    summary = prune_events(dry_run=False)

    assert summary.deleted_events == 0
    with _connection() as conn:
        ids = {r[0] for r in conn.execute("SELECT id FROM events").fetchall()}
    assert old_event in ids


# --------------------------------------------------------------------------- #
# Open alert evidence protection
# --------------------------------------------------------------------------- #


def test_ssh_brute_force_open_alert_evidence_preserved(tmp_path, monkeypatch):
    """Events in an open SSH_BRUTE_FORCE alert's evidence window are protected."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    # Alert was last triggered 4 days ago (beyond 3-day retention, so the
    # evidence window overlaps the deletion zone).
    triggered = _old_timestamp(4)

    with _connection() as conn:
        # Evidence event: ssh_login_failed from the alert's source_ip,
        # within [triggered - 5min, triggered].
        evidence_ts = _offset_iso(triggered, -2)  # 2 minutes before trigger
        evidence_id = _insert_event(
            conn,
            timestamp=evidence_ts,
            event_type="ssh_login_failed",
            source_ip="203.0.113.10",
        )
        # Stray event: very old, different IP — should be deleted.
        stray = _insert_event(
            conn,
            timestamp=_old_timestamp(100),
            event_type="ssh_login_failed",
            source_ip="10.0.0.99",
        )
        # An event in the window but WRONG event_type — not evidence, can delete.
        not_evidence = _insert_event(
            conn,
            timestamp=evidence_ts,
            event_type="ssh_login_success",
            source_ip="203.0.113.10",
        )
        _insert_alert(
            conn,
            rule_id="SSH_BRUTE_FORCE",
            status="open",
            created_at=triggered,
            last_triggered_at=triggered,
            source_ip="203.0.113.10",
        )
        conn.commit()

    summary = prune_events(dry_run=False)

    with _connection() as conn:
        ids = {r[0] for r in conn.execute("SELECT id FROM events").fetchall()}

    assert evidence_id in ids  # protected: open alert evidence
    assert not_evidence not in ids  # deleted: wrong event_type
    assert stray not in ids  # deleted: old + wrong IP


def test_closed_alert_evidence_not_protected(tmp_path, monkeypatch):
    """Events in a closed alert's evidence window are NOT protected."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    triggered = _old_timestamp(100)

    with _connection() as conn:
        evidence_id = _insert_event(
            conn,
            timestamp=triggered,
            event_type="ssh_login_failed",
            source_ip="203.0.113.10",
        )
        _insert_alert(
            conn,
            rule_id="SSH_BRUTE_FORCE",
            status="closed",
            created_at=triggered,
            last_triggered_at=triggered,
            source_ip="203.0.113.10",
        )
        conn.commit()

    summary = prune_events(dry_run=False)

    assert summary.protected_events == 0  # closed alert doesn't protect
    assert summary.deleted_events == 1

    with _connection() as conn:
        ids = {r[0] for r in conn.execute("SELECT id FROM events").fetchall()}
    assert evidence_id not in ids


def test_suricata_open_alert_evidence_preserved(tmp_path, monkeypatch):
    """Suricata alert evidence within the time window is protected."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    # Alert created 2 days ago, last triggered 2 days ago.
    now_str = _old_timestamp(2)

    with _connection() as conn:
        # Suricata alert event within the evidence window and matching the key.
        sig_event_id = _insert_event(
            conn,
            timestamp=now_str,
            event_type="suricata_alert",
            source_ip="203.0.113.10",
            signature="ET TEST ALERT",
            signature_id=2001219,
            dest_ip="192.0.2.1",
            src_port=54321,
            dest_port=22,
            proto="tcp",
            category="attempted-recon",
        )
        # Old stray suricata event — same IP but different signature, should delete.
        stray = _insert_event(
            conn,
            timestamp=_old_timestamp(100),
            event_type="suricata_alert",
            source_ip="203.0.113.10",
            signature="ET OTHER",
            signature_id=2009999,
            dest_ip="192.0.2.1",
            src_port=54321,
            dest_port=22,
            proto="tcp",
            category="attempted-recon",
        )
        _insert_alert(
            conn,
            rule_id="SURICATA_ALERT",
            status="open",
            created_at=now_str,
            last_triggered_at=now_str,
            source_ip="203.0.113.10",
            dest_ip="192.0.2.1",
            src_port=54321,
            dest_port=22,
            proto="tcp",
            signature="ET TEST ALERT",
            signature_id=2001219,
            category="attempted-recon",
        )
        conn.commit()

    summary = prune_events(dry_run=False)

    with _connection() as conn:
        ids = {r[0] for r in conn.execute("SELECT id FROM events").fetchall()}

    assert sig_event_id in ids  # protected: open suricata alert evidence
    assert stray not in ids  # deleted: different signature


def test_unknown_rule_open_alert_protects_window(tmp_path, monkeypatch):
    """An open alert with an unknown rule_id protects its lifetime window."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    created = _old_timestamp(10)
    last_triggered = _old_timestamp(5)

    with _connection() as conn:
        old_in_window = _insert_event(conn, timestamp=_old_timestamp(7))
        old_outside = _insert_event(conn, timestamp=_old_timestamp(100))
        _insert_alert(
            conn,
            rule_id="FUTURE_RULE",
            status="open",
            created_at=created,
            last_triggered_at=last_triggered,
            source_ip="203.0.113.10",
        )
        conn.commit()

    summary = prune_events(dry_run=False)

    with _connection() as conn:
        ids = {r[0] for r in conn.execute("SELECT id FROM events").fetchall()}

    assert old_in_window in ids  # within lifetime window — protected
    assert old_outside not in ids  # outside window — deleted


# --------------------------------------------------------------------------- #
# Edge cases
# --------------------------------------------------------------------------- #


def test_empty_database(tmp_path, monkeypatch):
    """Retention on an empty database reports zero counts and deletes nothing."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    summary = prune_events(dry_run=True)

    assert summary.eligible_events == 0
    assert summary.protected_events == 0
    assert summary.deletable_events == 0
    assert summary.deleted_events == 0


def test_no_eligible_events(tmp_path, monkeypatch):
    """All events within retention period — nothing to delete."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        for _ in range(5):
            _insert_event(conn, timestamp=_iso_offset(hours=1))
        conn.commit()

    summary = prune_events(dry_run=False)

    assert summary.eligible_events == 0
    assert summary.deleted_events == 0


def test_all_events_protected_no_deletions(tmp_path, monkeypatch):
    """All eligible events are protected — nothing deleted."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        old_event = _insert_event(conn, timestamp=_old_timestamp(100))
        incident_id = _insert_incident(conn, status="open")
        _link_event_to_incident(conn, incident_id, old_event)
        conn.commit()

    summary = prune_events(dry_run=False)

    assert summary.eligible_events == 1
    assert summary.protected_events == 1
    assert summary.deletable_events == 0
    assert summary.deleted_events == 0

    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 1


# --------------------------------------------------------------------------- #
# Batch deletion
# --------------------------------------------------------------------------- #


def test_batch_deletion_multiple_batches(tmp_path, monkeypatch):
    """Batch deletion processes all eligible events across multiple batches."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        for _ in range(25):
            _insert_event(conn, timestamp=_old_timestamp(100))
        conn.commit()

    summary = prune_events(dry_run=False, batch_size=10)

    assert summary.eligible_events == 25
    assert summary.deleted_events == 25
    assert summary.batches_run == 3  # ceil(25/10) = 3

    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 0


def test_batch_size_default(tmp_path, monkeypatch):
    """Default batch size is 1000."""
    assert DEFAULT_RETENTION_BATCH_SIZE == 1000


def test_batch_deletion_preserves_protected_across_batches(tmp_path, monkeypatch):
    """Protected events survive even when they appear in a deletion batch's ID
    range."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        old_ids = []
        for _ in range(20):
            old_ids.append(_insert_event(conn, timestamp=_old_timestamp(100)))
        # Protect the first and last old events.
        incident_id = _insert_incident(conn, status="resolved")
        _link_event_to_incident(conn, incident_id, old_ids[0])
        _link_event_to_incident(conn, incident_id, old_ids[-1])
        conn.commit()

    summary = prune_events(dry_run=False, batch_size=5)

    assert summary.deleted_events == 18  # 20 old - 2 protected
    assert summary.protected_events == 2

    with _connection() as conn:
        remaining = {r[0] for r in conn.execute("SELECT id FROM events").fetchall()}
    assert old_ids[0] in remaining  # protected
    assert old_ids[-1] in remaining  # protected
    # 18 non-protected old events were deleted.
    assert remaining == {old_ids[0], old_ids[-1]}


# --------------------------------------------------------------------------- #
# Foreign-key integrity
# --------------------------------------------------------------------------- #


def test_foreign_key_integrity_after_cleanup(tmp_path, monkeypatch):
    """After retention, no orphaned incident_events rows remain."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        # An incident event that's old — but protected, so still linked.
        old = _insert_event(conn, timestamp=_old_timestamp(100))
        inc_id = _insert_incident(conn, status="resolved")
        _link_event_to_incident(conn, inc_id, old)
        # A stray old event with no incident link.
        _insert_event(conn, timestamp=_old_timestamp(100), source_ip="10.0.0.1")
        conn.commit()

    summary = prune_events(dry_run=False)

    assert summary.fk_violations == 0

    # Verify no orphaned incident_events.
    with _connection() as conn:
        orphans = conn.execute(
            """
            SELECT ie.event_id
            FROM incident_events ie
            LEFT JOIN events e ON e.id = ie.event_id
            WHERE e.id IS NULL
            """
        ).fetchall()
    assert orphans == []


def test_foreign_key_enforcement_prevents_orphaned_deletes(tmp_path, monkeypatch):
    """The FK safety net on the retention connection prevents deleting an
    event still referenced by incident_events."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        old = _insert_event(conn, timestamp=_old_timestamp(100))
        inc_id = _insert_incident(conn, status="open")
        _link_event_to_incident(conn, inc_id, old)
        conn.commit()

    # Dry-run should report the event as protected and not deleted.
    summary = prune_events(dry_run=True)
    assert summary.protected_events == 1
    assert summary.deletable_events == 0

    # Verify the FK constraint is active on the retention connection by
    # attempting a direct delete of the protected event.
    from backend.app.siem import _safe_retention_connection

    conn = _safe_retention_connection(str(db_path))
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("DELETE FROM events WHERE id = ?", (old,))
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# Rollback after failure
# --------------------------------------------------------------------------- #


def test_rollback_on_protection_computation_failure(tmp_path, monkeypatch):
    """If the protected-set computation fails, no deletion occurs (no partial
    state)."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        for _ in range(10):
            _insert_event(conn, timestamp=_old_timestamp(100))
        conn.commit()

    # Simulate a failure in the protection computation.
    from backend.app import siem

    def _boom(connection):
        raise RuntimeError("simulated protection computation failure")

    monkeypatch.setattr(siem, "_protected_event_ids", _boom)

    with pytest.raises(RuntimeError, match="simulated"):
        prune_events(dry_run=False)

    # Nothing deleted — the failure happened before any DELETE.
    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 10


# --------------------------------------------------------------------------- #
# Summary / compute
# --------------------------------------------------------------------------- #


def test_compute_retention_summary_dry_run(tmp_path, monkeypatch):
    """compute_retention_summary returns a dry-run summary without deleting."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    initialize_database()

    with _connection() as conn:
        _insert_event(conn, timestamp=_old_timestamp(100))
        _insert_event(conn, timestamp=_iso_offset(hours=1))
        conn.commit()

    summary = compute_retention_summary(3)

    assert summary.dry_run is True
    assert summary.eligible_events == 1
    assert summary.deleted_events == 0

    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 2  # nothing deleted


def test_compute_retention_summary_disabled(tmp_path, monkeypatch):
    """compute_retention_summary with None returns a disabled summary."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    initialize_database()

    summary = compute_retention_summary(None)
    assert summary.disabled is True
    assert summary.retention_days is None


# --------------------------------------------------------------------------- #
# End-to-end: ingest -> detect -> protect
# --------------------------------------------------------------------------- #


def test_ingested_events_old_enough_are_purged(tmp_path, monkeypatch):
    """Events ingested via the normal pipeline and left old enough get pruned
    when they are not evidence for any open alert or incident."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "1")
    initialize_database()

    old_ts = _old_timestamp(5)
    line = (
        f"{old_ts} lab-host sshd[8000]: Failed password for olduser "
        f"from 203.0.113.10 port 54001 ssh2"
    )
    result = ingest_lines([line])
    assert result["parsed"] == 1

    summary = prune_events(dry_run=False)

    assert summary.eligible_events == 1
    assert summary.deleted_events == 1

    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 0


def test_retention_does_not_affect_recent_detection(tmp_path, monkeypatch):
    """Recent events that would trigger detection are preserved."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    # Ingest recent failures — within retention period.
    attack_ip = "203.0.113.10"
    lines = [
        f"sshd[410{i}]: Failed password for user{i} "
        f"from {attack_ip} port {54000 + i} ssh2"
        for i in range(5)
    ]
    result = ingest_lines(lines)
    assert len(result["alerts"]) == 1  # SSH_BRUTE_FORCE alert created

    # Run retention — nothing should be deleted (all events are recent).
    summary = prune_events(dry_run=False)
    assert summary.deleted_events == 0

    # The alert still exists.
    with _connection() as conn:
        alert_count = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE status = 'open'"
        ).fetchone()[0]
    assert alert_count == 1


def test_retention_summary_reports_counts(tmp_path, monkeypatch):
    """The retention summary accurately reports eligible, protected, and
    deletable event counts."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        # 2 old events — eligible
        e1 = _insert_event(conn, timestamp=_old_timestamp(100))
        e2 = _insert_event(conn, timestamp=_old_timestamp(100))
        # 1 old event protected by incident
        e3 = _insert_event(conn, timestamp=_old_timestamp(100))
        inc_id = _insert_incident(conn, status="resolved")
        _link_event_to_incident(conn, inc_id, e3)
        # 1 recent event — not eligible
        _insert_event(conn, timestamp=_iso_offset(hours=1))
        conn.commit()

    summary = prune_events(dry_run=True)

    assert summary.eligible_events == 3  # e1, e2, e3
    assert summary.protected_events == 1  # e3
    assert summary.deletable_events == 2  # e1, e2


# --------------------------------------------------------------------------- #
# Concurrent access
# --------------------------------------------------------------------------- #


def test_concurrent_ingest_during_retention(tmp_path, monkeypatch):
    """Retention and ingestion can run concurrently without deadlocks.

    In WAL mode, readers and one writer proceed concurrently.  The retention
    connection uses a 30 s ``busy_timeout`` to wait for the lock; ingestion
    uses the default 5 s timeout.  This test verifies both complete without
    error and that recent events ingested concurrently are preserved.
    """
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "1")
    initialize_database()

    # Seed old events to be pruned.
    with _connection() as conn:
        for _ in range(20):
            _insert_event(conn, timestamp=_old_timestamp(5))
        conn.commit()

    errors: list[BaseException] = []
    results: list = []
    lock = threading.Lock()

    def run_retention():
        try:
            summary = prune_events(dry_run=False, batch_size=5)
            with lock:
                results.append(summary)
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)

    def run_ingest():
        try:
            lines = [
                f"sshd[900{i}]: Failed password for newuser{i} "
                f"from 198.51.100.{i} port 55000 ssh2"
                for i in range(5)
            ]
            result = ingest_lines(lines)
            with lock:
                results.append(result)
        except BaseException as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)

    t_retention = threading.Thread(target=run_retention)
    t_ingest = threading.Thread(target=run_ingest)

    t_retention.start()
    t_ingest.start()

    t_retention.join(timeout=30)
    t_ingest.join(timeout=30)

    assert not t_retention.is_alive(), "retention thread hung"
    assert not t_ingest.is_alive(), "ingestion thread hung"
    assert not errors, f"concurrent operation failed: {errors}"

    # All 20 old events should be deleted, and 5 new events should remain.
    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 5  # only the concurrent ingestion results remain


# --------------------------------------------------------------------------- #
# CLI / module interface
# --------------------------------------------------------------------------- #


def test_retention_module_main_dry_run(tmp_path, monkeypatch):
    """The retention CLI main() defaults to dry-run and prints a summary."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        _insert_event(conn, timestamp=_old_timestamp(10))
        conn.commit()

    from backend.app.retention import main as retention_main

    rc = retention_main(["--dry-run"])

    assert rc == 0
    # Dry run: nothing deleted.
    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 1


def test_retention_module_main_execute(tmp_path, monkeypatch):
    """The retention CLI main() with --execute deletes eligible events."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        _insert_event(conn, timestamp=_old_timestamp(10))
        _insert_event(conn, timestamp=_iso_offset(hours=1))
        conn.commit()

    from backend.app.retention import main as retention_main

    rc = retention_main(["--execute"])

    assert rc == 0
    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 1


def test_retention_module_main_no_retention_var(tmp_path, monkeypatch):
    """Without GREYWATCH_EVENT_RETENTION_DAYS, the CLI reports disabled."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.delenv(RETENTION_DAYS_ENV, raising=False)
    initialize_database()

    from backend.app.retention import main as retention_main

    rc = retention_main(["--dry-run"])
    assert rc == 0


def test_retention_module_vacuum_refused_without_confirmation(tmp_path, monkeypatch):
    """--vacuum requires interactive confirmation."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    initialize_database()

    from backend.app.retention import main as retention_main

    # Simulate "N" input via stdin.
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO("n\n"))
    rc = retention_main(["--vacuum"])
    assert rc == 2  # aborted


# --------------------------------------------------------------------------- #
# Repeated execution (idempotency)
# --------------------------------------------------------------------------- #


def test_repeated_execution_is_idempotent(tmp_path, monkeypatch):
    """Running retention more than once is safe and a no-op on later runs.

    Validates repeated-execution semantics: the first run clears the eligible,
    unprotected events in bounded batches; every subsequent run is a no-op
    (zero deletions, zero batches, intact FK integrity) and never erodes the
    protected or retention-period events that survived the first run. A dry-run
    after an execute also reports zero deletable events.
    """
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "3")
    initialize_database()

    with _connection() as conn:
        # Twenty-five old, UNPROTECTED events -> spans multiple batches (batch=7).
        strays = [
            _insert_event(conn, timestamp=_old_timestamp(100)) for _ in range(25)
        ]
        # One old, PROTECTED event (incident-linked) -> never deleted.
        protected = _insert_event(conn, timestamp=_old_timestamp(100))
        inc_id = _insert_incident(conn, status="resolved")
        _link_event_to_incident(conn, inc_id, protected)
        # One RECENT event -> outside the retention window entirely.
        recent = _insert_event(conn, timestamp=_iso_offset(hours=1))
        conn.commit()

    # First run: clears all 25 strays across ceil(25/7) = 4 batches; protects
    # the rest. FK integrity must hold (no orphaned incident_events).
    summary1 = prune_events(dry_run=False, batch_size=7)
    assert summary1.eligible_events == 26  # 25 strays + 1 protected (both old)
    assert summary1.protected_events == 1
    assert summary1.deletable_events == 25
    assert summary1.deleted_events == 25
    assert summary1.batches_run == 4
    assert summary1.fk_violations == 0

    with _connection() as conn:
        ids = {r[0] for r in conn.execute("SELECT id FROM events").fetchall()}
    assert set(strays).isdisjoint(ids)  # all strays gone
    assert protected in ids
    assert recent in ids

    # Second run: nothing eligible-and-unprotected remains -> clean no-op.
    summary2 = prune_events(dry_run=False, batch_size=7)
    assert summary2.deleted_events == 0
    assert summary2.batches_run == 0
    assert summary2.fk_violations == 0
    with _connection() as conn:
        ids = {r[0] for r in conn.execute("SELECT id FROM events").fetchall()}
    assert ids == {protected, recent}

    # A dry-run after execution also reports nothing left to delete.
    summary3 = prune_events(dry_run=True)
    assert summary3.dry_run is True
    assert summary3.deletable_events == 0
    assert summary3.deleted_events == 0

    # Third execute run: still idempotent; the protected event survives.
    summary4 = prune_events(dry_run=False)
    assert summary4.deleted_events == 0
    assert summary4.fk_violations == 0
    with _connection() as conn:
        ids = {r[0] for r in conn.execute("SELECT id FROM events").fetchall()}
    assert ids == {protected, recent}


# --------------------------------------------------------------------------- #
# GREYWATCH_RETENTION_BATCH_SIZE configuration
# --------------------------------------------------------------------------- #


def _seed_n_old_unprotected_events(tmp_path, monkeypatch, n: int, *, batch_env: str | None = None) -> str:
    """Create an isolated DB with ``n`` old, unprotected events.

    Sets ``GREYWATCH_DB`` to a temp path, enables retention (30 days), and
    optionally sets the ``GREYWATCH_RETENTION_BATCH_SIZE`` env var.  Returns
    the path to the temp database.
    """
    db_path = tmp_path / "batch.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "30")
    if batch_env is not None:
        monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, batch_env)
    else:
        monkeypatch.delenv(RETENTION_BATCH_SIZE_ENV, raising=False)
    initialize_database()
    with _connection() as conn:
        for _ in range(n):
            _insert_event(conn, timestamp=_old_timestamp(100))
        conn.commit()
    return str(db_path)


def test_batch_size_env_var_overrides_default(monkeypatch):
    """When GREYWATCH_RETENTION_BATCH_SIZE is set, get_retention_batch_size
    returns the configured value instead of the 1000 default."""
    monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, "50")
    assert get_retention_batch_size() == 50


def test_batch_size_unset_uses_default(monkeypatch):
    """When the env var is unset, the documented default of 1000 is used."""
    monkeypatch.delenv(RETENTION_BATCH_SIZE_ENV, raising=False)
    assert get_retention_batch_size() == DEFAULT_RETENTION_BATCH_SIZE
    assert get_retention_batch_size() == 1000


def test_batch_size_zero_falls_back(monkeypatch):
    """Zero is invalid (would delete nothing per batch); fall back to 1000."""
    monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, "0")
    assert get_retention_batch_size() == DEFAULT_RETENTION_BATCH_SIZE


def test_batch_size_negative_falls_back(monkeypatch):
    """Negative values are invalid; fall back to 1000."""
    monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, "-5")
    assert get_retention_batch_size() == DEFAULT_RETENTION_BATCH_SIZE


def test_batch_size_non_numeric_falls_back(monkeypatch):
    """Non-numeric values are invalid; fall back to 1000."""
    monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, "not-a-number")
    assert get_retention_batch_size() == DEFAULT_RETENTION_BATCH_SIZE


def test_batch_size_zero_is_caught_before_deletion(monkeypatch):
    """Zero must never reach the DELETE LIMIT clause; it resolves to 1000."""
    monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, "0")
    size = get_retention_batch_size()
    assert size == DEFAULT_RETENTION_BATCH_SIZE
    assert size > 0


def test_batch_size_explicit_argument_overrides_env(tmp_path, monkeypatch):
    """An explicit batch_size argument to prune_events must override the
    GREYWATCH_RETENTION_BATCH_SIZE env var."""
    monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, "7")
    _seed_n_old_unprotected_events(tmp_path, monkeypatch, n=3)

    summary = prune_events(dry_run=False, batch_size=3)
    assert summary.batch_size == 3
    # 3 events / 3 per batch => 1 batch
    assert summary.batches_run == 1

    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 0


def test_batch_size_env_respected_by_prune(tmp_path, monkeypatch):
    """prune_events resolves batch_size=None to the env-derived value.

    With a batch size of 1 and 3 eligible events, 3 batches are required —
    proving the env var is honoured by the engine.
    """
    _seed_n_old_unprotected_events(tmp_path, monkeypatch, n=3, batch_env="1")

    summary = prune_events(dry_run=False, batch_size=None)
    assert summary.batch_size == 1
    assert summary.batches_run == 3
    assert summary.deleted_events == 3

    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 0


def test_batch_size_default_respected_by_prune(tmp_path, monkeypatch):
    """prune_events resolves batch_size=None to the default when env unset."""
    _seed_n_old_unprotected_events(tmp_path, monkeypatch, n=3)

    summary = prune_events(dry_run=False, batch_size=None)
    assert summary.batch_size == DEFAULT_RETENTION_BATCH_SIZE
    # 3 events / 1000 per batch => 1 batch
    assert summary.batches_run == 1


def test_compute_retention_summary_reports_batch_size(tmp_path, monkeypatch):
    """compute_retention_summary reports the env-derived batch size for both
    the disabled and the active cases."""
    # Active case — requires a DB to count eligible events.
    _seed_n_old_unprotected_events(tmp_path, monkeypatch, n=3, batch_env="25")
    summary = compute_retention_summary(get_retention_config().retention_days)
    assert summary.batch_size == 25

    # Disabled case — returns early, no DB access needed.
    monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, "42")
    monkeypatch.delenv(RETENTION_DAYS_ENV, raising=False)
    disabled = compute_retention_summary(None)
    assert disabled.disabled is True
    assert disabled.batch_size == 42


def test_cli_main_uses_env_batch_size(tmp_path, monkeypatch, capsys):
    """CLI --execute with --batch-size omitted resolves the env-derived value.

    Env batch-size = 1 and 3 eligible events => the printed summary reports
    'Deletion batches: 3', proving the env var reached the engine.
    """
    from backend.app.retention import main as retention_main

    _seed_n_old_unprotected_events(tmp_path, monkeypatch, n=3, batch_env="1")
    rc = retention_main(["--execute"])
    assert rc == 0

    captured = capsys.readouterr()
    batch_line = next(l for l in captured.out.splitlines() if "Deletion batches" in l)
    assert batch_line.strip().endswith("3")  # 3 events / batch 1 => 3 batches


def test_cli_main_explicit_batch_size_overrides_env(tmp_path, monkeypatch, capsys):
    """An explicit --batch-size wins over GREYWATCH_RETENTION_BATCH_SIZE."""
    from backend.app.retention import main as retention_main

    _seed_n_old_unprotected_events(tmp_path, monkeypatch, n=3, batch_env="7")
    rc = retention_main(["--execute", "--batch-size", "3"])
    assert rc == 0

    captured = capsys.readouterr()
    # explicit 3 overrides env 7 => 1 batch for 3 events
    batch_line = next(l for l in captured.out.splitlines() if "Deletion batches" in l)
    assert batch_line.strip().endswith("1")


def test_cli_parser_batch_size_defaults_to_none(tmp_path, monkeypatch):
    """The CLI --batch-size defaults to None (sentinel) so prune_events resolves
    the env-derived value rather than hardcoding 1000 at parse time."""
    from backend.app.retention import _build_parser

    monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, "33")
    opts = _build_parser().parse_args([])
    assert opts.batch_size is None  # sentinel: prune_events resolves it
    opts2 = _build_parser().parse_args(["--batch-size", "9"])
    assert opts2.batch_size == 9


# --------------------------------------------------------------------------- #
# Explicit batch-size validation (zero/negative rejection)
# --------------------------------------------------------------------------- #


def test_prune_events_rejects_zero_batch_size_explicit(tmp_path, monkeypatch):
    """An explicit batch_size of 0 is rejected at the library boundary before any
    database access or deletion, even in dry-run mode."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "30")
    initialize_database()

    with _connection() as conn:
        _insert_event(conn, timestamp=_old_timestamp(100))
        conn.commit()

    with pytest.raises(ValueError, match="batch_size"):
        prune_events(dry_run=True, batch_size=0)


def test_prune_events_rejects_negative_batch_size_explicit(tmp_path, monkeypatch):
    """A negative explicit batch_size is rejected at the library boundary."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "30")
    initialize_database()

    with pytest.raises(ValueError, match="batch_size"):
        prune_events(dry_run=False, batch_size=-5)


def test_explicit_zero_batch_size_deletes_nothing(tmp_path, monkeypatch):
    """Even with retention enabled, an explicit zero batch size raises before
    deletion and leaves all eligible events in place (no unbounded deletion)."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "30")
    monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, "1000")  # env valid; explicit overrides
    initialize_database()

    with _connection() as conn:
        for _ in range(3):
            _insert_event(conn, timestamp=_old_timestamp(100))
        conn.commit()

    with pytest.raises(ValueError, match="batch_size"):
        prune_events(dry_run=False, batch_size=0)

    # No events were deleted despite execute mode.
    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 3


def test_cli_rejects_zero_batch_size_argument(tmp_path, monkeypatch, capsys):
    """Explicit --batch-size 0 is validated by the CLI and reported as a clear
    error; no deletion occurs."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "30")
    monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, "1000")
    initialize_database()

    with _connection() as conn:
        for _ in range(3):
            _insert_event(conn, timestamp=_old_timestamp(100))
        conn.commit()

    from backend.app.retention import main as retention_main

    rc = retention_main(["--execute", "--batch-size", "0"])
    assert rc != 0

    captured = capsys.readouterr()
    assert "batch_size" in captured.err
    assert "positive integer" in captured.err

    # Nothing was deleted.
    with _connection() as conn:
        count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    assert count == 3


def test_cli_rejects_negative_batch_size_argument(tmp_path, monkeypatch, capsys):
    """Explicit --batch-size=-5 is validated by the CLI (uses = form to avoid
    argparse negative-number ambiguity) and reported as a clear error."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    monkeypatch.setenv(RETENTION_DAYS_ENV, "30")
    monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, "1000")
    initialize_database()

    from backend.app.retention import main as retention_main

    rc = retention_main(["--execute", "--batch-size=-5"])
    assert rc != 0

    captured = capsys.readouterr()
    assert "batch_size" in captured.err


def test_wrapper_zero_batch_size_fails_cleanly(tmp_path, monkeypatch):
    """The shell wrapper must not let an invalid GREYWATCH_RETENTION_BATCH_SIZE
    trigger unbounded deletion: a zero value forwarded as --batch-size is
    rejected by the engine and the wrapper exits non-zero with a clear error."""
    import subprocess
    import sys

    db_path = tmp_path / "gw.db"
    monkeypatch.setenv("GREYWATCH_DB", str(db_path))
    # Retention can be enabled or not -- validation happens before any DB work.
    monkeypatch.setenv(RETENTION_DAYS_ENV, "30")
    monkeypatch.setenv(RETENTION_BATCH_SIZE_ENV, "0")
    initialize_database()

    repo_root = Path(__file__).resolve().parents[2]
    wrapper = repo_root / "scripts" / "gw_retention.sh"

    env = {
        **os.environ,
        "GREYWATCH_DB": str(db_path),
        "GREYWATCH_EVENT_RETENTION_DAYS": "30",
        "GREYWATCH_RETENTION_BATCH_SIZE": "0",
        "GREYWATCH_PYTHON": sys.executable,
    }
    result = subprocess.run(
        ["bash", str(wrapper), "dry-run"],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(repo_root),
        timeout=60,
    )

    assert result.returncode != 0
    assert "batch_size" in (result.stderr + result.stdout)
    assert "positive integer" in (result.stderr + result.stdout)
