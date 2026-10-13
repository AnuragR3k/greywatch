"""Greywatch's first SIEM ingestion and detection engine."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import sqlite3


DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "greywatch.db"

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5

# Traditional Linux syslog format:
# Oct 12 19:41:23 fedora sshd[1234]: Failed password ...
SYSLOG_LINE = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<message>.*)$"
)

# journalctl -o short-iso format:
# 2026-10-12T19:41:23+05:30 fedora sshd[1234]: Failed password ...
ISO_LINE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\S+)"
    r"\s+(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<message>.*)$"
)

# Also supports lines containing only "sshd[1234]: ...".
GENERIC_LINE = re.compile(
    r"^(?P<prefix>.*?)sshd(?:\[\d+\])?:\s+(?P<message>.*)$"
)

FAILED_LOGIN = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) "
    r"for (?:invalid user )?(?P<username>\S+) "
    r"from (?P<ip>\S+) port \d+\b"
)

INVALID_USER = re.compile(
    r"Invalid user (?P<username>\S+) from (?P<ip>\S+)"
)

SUCCESSFUL_LOGIN = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) "
    r"for (?P<username>\S+) from (?P<ip>\S+) port \d+\b"
)


@contextmanager
def _connection():
    """Open a database connection and safely commit or roll back changes."""
    db_path = Path(os.environ.get("GREYWATCH_DB", str(DEFAULT_DB_PATH)))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path, timeout=5)
    connection.row_factory = sqlite3.Row

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _migrate_alerts_table(connection: sqlite3.Connection) -> None:
    """Add columns missing from an alerts table created by an older release.

    SQLite has no "ADD COLUMN IF NOT EXISTS", so the existing columns are
    inspected first. Existing rows are backfilled from created_at so the
    evidence window behaves like it did before the column existed.
    """
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
    }
    if "last_triggered_at" not in columns:
        connection.execute(
            "ALTER TABLE alerts ADD COLUMN last_triggered_at TEXT"
        )

    connection.execute(
        """
        UPDATE alerts
        SET last_triggered_at = created_at
        WHERE last_triggered_at IS NULL
        """
    )


def _migrate_events_table(connection: sqlite3.Connection) -> None:
    """Add provenance columns missing from an events table created by an older
    release.

    `source` records where an event originated (e.g. ``journal`` for genuine
    systemd-journal events, ``test`` for synthetic records). Existing rows are
    left as NULL (unknown/legacy) so they stay queryable without guessing.
    """
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(events)").fetchall()
    }
    if "source" not in columns:
        connection.execute("ALTER TABLE events ADD COLUMN source TEXT")


def initialize_database() -> None:
    """Create Greywatch's event and alert tables if they do not exist."""
    with _connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                host TEXT NOT NULL,
                event_type TEXT NOT NULL,
                username TEXT,
                source_ip TEXT,
                severity TEXT NOT NULL,
                raw_message TEXT NOT NULL,
                source TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_events_ip_time
                ON events(source_ip, timestamp);

            CREATE TABLE IF NOT EXISTS collector_state (
                key TEXT PRIMARY KEY,
                value TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                description TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                closed_at TEXT,
                last_triggered_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_status
                ON alerts(status, created_at);
            """
        )
        _migrate_alerts_table(connection)
        _migrate_events_table(connection)


def _normalize_timestamp(value: str | None, *, syslog: bool = False) -> str:
    """Convert supported timestamps to ISO 8601 UTC."""
    try:
        if syslog and value:
            # Traditional syslog timestamps omit the year and timezone.
            local_time = datetime.strptime(
                f"{datetime.now().year} {value}",
                "%Y %b %d %H:%M:%S",
            ).astimezone()
        elif value:
            local_time = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if local_time.tzinfo is None:
                local_time = local_time.astimezone()
        else:
            local_time = datetime.now(timezone.utc)
    except ValueError:
        local_time = datetime.now(timezone.utc)

    return local_time.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_auth_line(line: str) -> dict | None:
    """
    Parse a supported sshd authentication message.

    Returns None for messages that are not recognized authentication events.
    """
    line = line.strip()
    if not line:
        return None

    match = SYSLOG_LINE.match(line)
    timestamp_kind = "syslog"

    if match:
        timestamp_raw = match.group("timestamp")
        host = match.group("host")
        message = match.group("message")
    else:
        match = ISO_LINE.match(line)
        timestamp_kind = "iso"

        if match:
            timestamp_raw = match.group("timestamp")
            host = match.group("host")
            message = match.group("message")
        else:
            match = GENERIC_LINE.match(line)
            if not match:
                return None

            prefix = match.group("prefix").strip()
            host = prefix.split()[-1] if prefix.split() else "unknown"
            timestamp_raw = None
            timestamp_kind = "none"
            message = match.group("message")

    failed = FAILED_LOGIN.search(message)
    invalid_user = INVALID_USER.search(message)
    successful = SUCCESSFUL_LOGIN.search(message)

    if failed:
        event_type = "ssh_login_failed"
        username = failed.group("username")
        source_ip = failed.group("ip")
        severity = "medium"
    elif invalid_user:
        event_type = "ssh_invalid_user"
        username = invalid_user.group("username")
        source_ip = invalid_user.group("ip")
        severity = "medium"
    elif successful:
        event_type = "ssh_login_success"
        username = successful.group("username")
        source_ip = successful.group("ip")
        severity = "low"
    else:
        return None

    return {
        "timestamp": _normalize_timestamp(
            timestamp_raw,
            syslog=(timestamp_kind == "syslog"),
        ),
        "host": host,
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip,
        "severity": severity,
        "raw_message": line,
    }


def _store_events_and_detect(
    events: list[dict], connection: sqlite3.Connection
) -> tuple[list[dict], list[dict]]:
    """Persist normalized events and evaluate the SSH brute-force rule.

    Events must already be in the shape produced by ``parse_auth_line`` (or the
    journal collector's ``parse_journal_record``). Detection runs inside the
    caller's transaction so the failed-login count reflects the rows just
    inserted. Returns ``(inserted_events, new_alerts)``.
    """
    inserted_events = []
    new_alerts = []

    for event in events:
        cursor = connection.execute(
            """
            INSERT INTO events (
                timestamp, host, event_type, username,
                source_ip, severity, raw_message, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event["timestamp"],
                event["host"],
                event["event_type"],
                event["username"],
                event["source_ip"],
                event["severity"],
                event["raw_message"],
                event.get("source"),
            ),
        )
        inserted_events.append({"id": cursor.lastrowid, **event})

    # Count failed logins only. Invalid-user messages can accompany a
    # failed-login message, so counting both could inflate the threshold.
    source_ips = {
        event["source_ip"]
        for event in events
        if event["event_type"] == "ssh_login_failed"
        and event["source_ip"]
    }

    now = datetime.now(timezone.utc)
    now_text = now.isoformat(timespec="seconds")
    cutoff_text = (
        now - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
    ).isoformat(timespec="seconds")

    for source_ip in sorted(source_ips):
        count = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM events
            WHERE event_type = 'ssh_login_failed'
              AND source_ip = ?
              AND timestamp >= ?
              AND timestamp <= ?
            """,
            (source_ip, cutoff_text, now_text),
        ).fetchone()["total"]

        if count < BRUTE_FORCE_THRESHOLD:
            continue

        existing = connection.execute(
            """
            SELECT id
            FROM alerts
            WHERE rule_id = 'SSH_BRUTE_FORCE'
              AND source_ip = ?
              AND status = 'open'
            LIMIT 1
            """,
            (source_ip,),
        ).fetchone()

        description = (
            f"Observed {count} failed SSH login attempts from {source_ip} "
            f"within {BRUTE_FORCE_WINDOW_MINUTES} minutes. "
            "Investigate the source, targeted accounts, and any related "
            "successful logins."
        )

        # Update an existing alert instead of creating duplicates.
        # last_triggered_at records when the count was last recalculated
        # so the evidence window grows with the alert instead of staying
        # anchored to created_at.
        if existing:
            connection.execute(
                """
                UPDATE alerts
                SET description = ?, event_count = ?,
                    last_triggered_at = ?
                WHERE id = ?
                """,
                (description, count, now_text, existing["id"]),
            )
            continue

        cursor = connection.execute(
            """
            INSERT INTO alerts (
                created_at, rule_id, title, severity,
                source_ip, description, event_count, status,
                last_triggered_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?)
            """,
            (
                now_text,
                "SSH_BRUTE_FORCE",
                "Repeated SSH authentication failures",
                "high",
                source_ip,
                description,
                count,
                now_text,
            ),
        )

        new_alerts.append(
            {
                "id": cursor.lastrowid,
                "created_at": now_text,
                "rule_id": "SSH_BRUTE_FORCE",
                "title": "Repeated SSH authentication failures",
                "severity": "high",
                "source_ip": source_ip,
                "description": description,
                "event_count": count,
                "status": "open",
                "last_triggered_at": now_text,
            }
        )

    return inserted_events, new_alerts


def ingest_lines(lines: list[str]) -> dict:
    """Parse and persist event lines, then evaluate the SSH brute-force rule.

    Behavior is unchanged from the original line-based ingestion path: each
    line is run through ``parse_auth_line`` and unrecognized lines are ignored.
    """
    initialize_database()

    events = [event for line in lines if (event := parse_auth_line(line))]

    with _connection() as connection:
        inserted_events, new_alerts = _store_events_and_detect(
            events, connection
        )

    return {
        "received": len(lines),
        "parsed": len(inserted_events),
        "ignored": len(lines) - len(inserted_events),
        "events": inserted_events,
        "alerts": new_alerts,
    }


def ingest_events(events: list[dict]) -> dict:
    """Persist already-normalized events and evaluate detection rules.

    This is the structured-events entry point used by the journal collector.
    Unlike ``ingest_lines``, callers pass normalized event dicts (the shape
    produced by ``parse_auth_line`` or ``collector.parse_journal_record``)
    directly, so structured journal fields such as exact timestamps and
    provenance survive ingestion without a round-trip through text parsing.
    """
    initialize_database()

    with _connection() as connection:
        inserted_events, new_alerts = _store_events_and_detect(
            events, connection
        )

    parsed = len(inserted_events)
    return {
        "received": parsed,
        "parsed": parsed,
        "ignored": 0,
        "events": inserted_events,
        "alerts": new_alerts,
    }


def get_collector_setting(key: str, default: str | None = None) -> str | None:
    """Read a key/value pair from the collector_state table."""
    initialize_database()
    with _connection() as connection:
        row = connection.execute(
            "SELECT value FROM collector_state WHERE key = ?",
            (key,),
        ).fetchone()
    return row["value"] if row is not None else default


def set_collector_setting(key: str, value: str | None) -> None:
    """Upsert a key/value pair into the collector_state table."""
    initialize_database()
    with _connection() as connection:
        connection.execute(
            """
            INSERT INTO collector_state (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )


def list_events(limit: int = 100) -> list[dict]:
    initialize_database()

    with _connection() as connection:
        rows = connection.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def list_alerts(status: str = "open", limit: int = 100) -> list[dict]:
    initialize_database()

    with _connection() as connection:
        if status == "all":
            rows = connection.execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT * FROM alerts
                WHERE status = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (status, limit),
            ).fetchall()

    return [dict(row) for row in rows]


def close_alert(alert_id: int) -> bool:
    initialize_database()
    closed_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    with _connection() as connection:
        cursor = connection.execute(
            """
            UPDATE alerts
            SET status = 'closed', closed_at = ?
            WHERE id = ? AND status = 'open'
            """,
            (closed_at, alert_id),
        )

    return cursor.rowcount > 0


def get_alert_detail(alert_id: int) -> dict | None:
    """Return an alert and the failed SSH events in its evidence window.

    The window ends at the alert's last trigger time — updated whenever the
    detection count is recalculated — so the returned events stay consistent
    with the alert's event_count as new failures arrive. Alerts migrated from
    an older schema fall back to created_at.
    """
    initialize_database()

    with _connection() as connection:
        row = connection.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()

        if row is None:
            return None

        alert = dict(row)
        window_end = datetime.fromisoformat(
            alert.get("last_triggered_at") or alert["created_at"]
        )
        start = (
            window_end - timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
        ).astimezone(timezone.utc).isoformat(timespec="seconds")
        end = window_end.astimezone(timezone.utc).isoformat(
            timespec="seconds"
        )

        rows = connection.execute(
            """
            SELECT *
            FROM events
            WHERE source_ip = ?
              AND event_type = 'ssh_login_failed'
              AND timestamp >= ?
              AND timestamp <= ?
            ORDER BY timestamp ASC
            """,
            (alert["source_ip"], start, end),
        ).fetchall()

    return {
        "alert": alert,
        "evidence_window_start": start,
        "evidence_window_end": end,
        "evidence_events": [dict(event) for event in rows],
    }
