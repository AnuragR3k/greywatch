"""Greywatch's first SIEM ingestion and detection engine."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import re
import sqlite3


DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "greywatch.db"


def is_production_db_path(path: str | Path) -> bool:
    """True if ``path`` resolves to the default production database.

    This is a pure, side-effect-free helper used by the test-suite safety guard
    (see ``backend/tests/conftest.py``) to detect when a test would use
    ``data/greywatch.db`` — so it can refuse to run rather than silently mutate
    production data. It does **not** change normal application behavior.
    """
    return Path(path).resolve() == DEFAULT_DB_PATH.resolve()

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 5

# Suricata alert aggregation window. Repeated detections of the same Suricata
# rule identity + network 5-tuple within this window aggregate into a single
# open Greywatch alert (see ``_detect_suricata_alerts``). Detections of the
# same key outside the window start a new alert so distinct incidents remain
# distinguishable, while a steady stream of identical alerts cannot multiply
# unboundedly.
SURICATA_ALERT_WINDOW_MINUTES = 60

# Rule id for Greywatch incidents raised by the SSH brute-force then success
# correlation rule.
SSH_BRUTE_FORCE_THEN_SUCCESS_RULE = "SSH_BRUTE_FORCE_THEN_SUCCESS"

# Correlation window: failures and the subsequent success must fall within this
# bounded window and match on source IP. Configurable via
# ``GREYWATCH_CORRELATION_WINDOW_MINUTES``.
CORRELATION_WINDOW_MINUTES = 30


def get_correlation_window_minutes() -> int:
    """Return the correlation window in minutes from the environment.

    Reads ``GREYWATCH_CORRELATION_WINDOW_MINUTES`` on every call so tests stay
    hermetic via ``monkeypatch.setenv``. Invalid values fall back to the safe
    default and never silently disable correlation.
    """
    raw = os.environ.get("GREYWATCH_CORRELATION_WINDOW_MINUTES", "")
    if not raw:
        return CORRELATION_WINDOW_MINUTES
    try:
        value = int(raw)
    except ValueError:
        return CORRELATION_WINDOW_MINUTES
    return value if value > 0 else CORRELATION_WINDOW_MINUTES

# Rule id used for Greywatch alerts raised from Suricata EVE "alert" events.
SURICATA_ALERT_RULE = "SURICATA_ALERT"

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
    """Open a database connection and safely commit or roll back changes.

    WAL mode lets readers and one writer proceed concurrently instead of
    serializing all access behind a single exclusive lock (the default
    DELETE journal mode). The setting is persistent -- once the database is
    switched to WAL it stays WAL -- so subsequent connections see it as a
    no-op. ``synchronous=NORMAL`` is safe with WAL (the WAL file is fsync'd
    at checkpoint, not on every commit) and avoids a per-commit fsync.
    ``busy_timeout`` makes a contended writer wait instead of immediately
    raising ``database is locked``.
    """
    db_path = Path(os.environ.get("GREYWATCH_DB", str(DEFAULT_DB_PATH)))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path, timeout=5)
    connection.row_factory = sqlite3.Row

    try:
        connection.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        # Another connection holds a lock that blocks the WAL switch;
        # WAL may already be active from an earlier connection. Retry
        # on the next _connection() call.
        pass
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA synchronous=NORMAL")

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
    inspected first via ``PRAGMA table_info``. New columns are added with no
    default, so existing rows keep their prior values and legacy SSH alerts
    simply leave the new (Suricata-specific) columns ``NULL``. ``last_triggered_at``
    is special-cased and backfilled from ``created_at`` so pre-existing alerts
    keep their old evidence-window behavior.
    """
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
    }
    additions: list[tuple[str, str]] = [
        ("last_triggered_at", "TEXT"),
        ("dest_ip", "TEXT"),
        ("src_port", "INTEGER"),
        ("dest_port", "INTEGER"),
        ("proto", "TEXT"),
        ("signature", "TEXT"),
        ("signature_id", "INTEGER"),
        ("category", "TEXT"),
    ]
    for column, dtype in additions:
        if column not in columns:
            connection.execute(f"ALTER TABLE alerts ADD COLUMN {column} {dtype}")

    connection.execute(
        """
        UPDATE alerts
        SET last_triggered_at = created_at
        WHERE last_triggered_at IS NULL
        """
    )


def _migrate_events_table(connection: sqlite3.Connection) -> None:
    """Add provenance and network-metadata columns missing from an events
    table created by an older release.

    ``source`` records where an event originated (e.g. ``journal`` for genuine
    systemd-journal events, ``suricata`` for Suricata EVE alerts, ``test`` for
    synthetic records). The network/IDS columns (``dest_ip``, ``src_port``,
    ``dest_port``, ``proto``, ``signature``, ``signature_id``, ``category``)
    are populated by the Suricata collector and left NULL for SSH/journal/test
    events so they stay queryable without guessing. Existing rows are preserved.
    """
    columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(events)").fetchall()
    }
    additions: list[tuple[str, str]] = [
        ("source", "TEXT"),
        ("source_record_id", "TEXT"),
        ("content_hash", "TEXT"),
        ("dest_ip", "TEXT"),
        ("src_port", "INTEGER"),
        ("dest_port", "INTEGER"),
        ("proto", "TEXT"),
        ("signature", "TEXT"),
        ("signature_id", "INTEGER"),
        ("category", "TEXT"),
    ]
    for column, dtype in additions:
        if column not in columns:
            connection.execute(f"ALTER TABLE events ADD COLUMN {column} {dtype}")

    # Stable native record identifiers (e.g. journal __CURSOR) are unique per
    # source so a replayed identifiable record can never create a second event.
    # NULL source_record_id rows (HTTP lines, Suricata EVE records without a
    # native id) are excluded from the constraint.
    connection.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_events_source_record
            ON events(source, source_record_id)
            WHERE source_record_id IS NOT NULL
        """
    )

    # content_hash is stored for observability only and is intentionally not
    # used as a dedup key: identical messages can represent separate genuine
    # authentication failures, so content fingerprinting cannot safely
    # distinguish replays from legitimate repeated events.
    connection.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_events_content_hash
            ON events(content_hash)
            WHERE content_hash IS NOT NULL
        """
    )


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
                source TEXT,
                source_record_id TEXT,
                content_hash TEXT,
                dest_ip TEXT,
                src_port INTEGER,
                dest_port INTEGER,
                proto TEXT,
                signature TEXT,
                signature_id INTEGER,
                category TEXT
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
                last_triggered_at TEXT,
                dest_ip TEXT,
                src_port INTEGER,
                dest_port INTEGER,
                proto TEXT,
                signature TEXT,
                signature_id INTEGER,
                category TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_status
                ON alerts(status, created_at);

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                source_ip TEXT NOT NULL,
                description TEXT NOT NULL,
                event_count INTEGER NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                closed_at TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_incidents_status
                ON incidents(status, created_at);

            CREATE INDEX IF NOT EXISTS idx_incidents_rule_ip
                ON incidents(rule_id, source_ip, status);

            CREATE TABLE IF NOT EXISTS incident_events (
                incident_id INTEGER NOT NULL,
                event_id INTEGER NOT NULL,
                added_at TEXT NOT NULL,
                PRIMARY KEY (incident_id, event_id),
                FOREIGN KEY (incident_id) REFERENCES incidents(id),
                FOREIGN KEY (event_id) REFERENCES events(id)
            );

            CREATE INDEX IF NOT EXISTS idx_incident_events_incident
                ON incident_events(incident_id);

            CREATE INDEX IF NOT EXISTS idx_incident_events_event
                ON incident_events(event_id);
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


def _detect_ssh_brute_force(
    events: list[dict], connection: sqlite3.Connection
) -> list[dict]:
    """Evaluate the ``SSH_BRUTE_FORCE`` rule for one ingested batch.

    Counts failed logins per source IP over the configured window using the
    caller's connection, so the count reflects the rows just inserted. One open
    alert per offending IP is created or updated in place (aggregation, never
    unbounded duplication in a batch). Returns newly-created alerts only;
    updates to an existing open alert are silent, matching the rule's
    de-duplication contract.
    """
    new_alerts: list[dict] = []

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

    return new_alerts


def evaluate_detections(
    events: list[dict],
    inserted_events: list[dict],
    connection: sqlite3.Connection,
) -> list[dict]:
    """Shared detection pipeline: run every enabled rule over one batch.

    Single dispatch point shared by every telemetry source. HTTP ingestion
    (:func:`ingest_lines`), the journal collector and the Suricata collector all
    normalize to Greywatch's event shape and reach detection through
    :func:`_store_events_and_detect`, which calls this function. Everything runs
    inside the caller's transaction, so a rule failure rolls the whole batch
    back with the caller's checkpoint write.

    Two arguments because the rules differ in what they need:

    * ``events`` are the normalized inputs, used by database-backed rules (the
      SSH failed-login window query);
    * ``inserted_events`` are the rows just persisted, carrying their assigned
      ``id`` (used by the Suricata evidence/incident keying).

    Rules dispatched (in order, so alert ordering is stable):

    * ``SSH_BRUTE_FORCE`` -- repeated ``ssh_login_failed`` from one source.
    * ``SURICATA_ALERT`` -- Suricata EVE ``alert`` detections, de-duplicated by
      signature identity + network 5-tuple within the aggregation window.
    * ``SSH_BRUTE_FORCE_THEN_SUCCESS`` -- repeated ``ssh_login_failed`` from one
      source followed by a subsequent ``ssh_login_success`` (correlation rule).

    Returns ``(new_alerts, new_incidents)``. Aggregations into an existing open
    alert/incident are intentionally not returned (they are updates, not new
    records).
    """
    new_alerts = _detect_ssh_brute_force(events, connection)
    # Suricata EVE "alert" records become Greywatch alerts (rule_id
    # SURICATA_ALERT) in the shared alerts table. This runs only on
    # suricata_alert events, so SSH/journal/HTTP ingestion is unaffected.
    new_alerts.extend(_detect_suricata_alerts(inserted_events, connection))
    # Correlation rules run last over the just-stored events so a success that
    # completes a pattern can see failures stored earlier in the same batch.
    new_incidents = _correlate_ssh_brute_force_then_success(events, connection)
    return new_alerts, new_incidents


def _content_hash(event: dict) -> str | None:
    """Content-derived fingerprint for an event without a stable native id.

    Hashes ``(source, timestamp, host, raw_message)`` so that identical records
    from the same source map to one fingerprint. Including ``source`` prevents
    cross-source collisions (requirement: never dedupe unrelated sources).

    Limitation documented in the module design: two genuinely distinct events
    that happen to share source + timestamp + host + raw_message collide into
    one fingerprint and would be treated as a duplicate. Sources with a stable
    native identifier (journal ``__CURSOR``) use ``source_record_id`` instead
    and are never subject to this collision risk.
    """
    source = event.get("source") or ""
    timestamp = event.get("timestamp") or ""
    host = event.get("host") or ""
    raw_message = event.get("raw_message") or ""
    payload = f"{source}|{timestamp}|{host}|{raw_message}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _is_duplicate_event(connection: sqlite3.Connection, event: dict) -> bool:
    """Return True if ``event`` is a replay of an already-stored record.

    Dedup is keyed on the stable native identifier (``source_record_id``,
    e.g. journal ``__CURSOR``) enforced by the DB partial unique index on
    ``(source, source_record_id) WHERE source_record_id IS NOT NULL``. This is
    the only dedup key that is safe to enforce: content-derived fingerprints
    are intentionally NOT used, because identical messages can represent
    separate genuine authentication failures (requirement: legitimate repeated
    events must remain distinguishable even when text and timestamp match).

    Records without a native identifier (``source_record_id`` is NULL — HTTP
    lines, Suricata EVE records) are not deduplicated here. They rely on
    collector-side checkpointing (journal cursor / Suricata byte offset) to
    avoid re-reading, and on application-level overlap checks in the
    collectors. HTTP ingestion is stateless with no native id, so replaying
    identical HTTP lines can inflate counts; this is a documented limitation.
    """
    source_record_id = event.get("source_record_id")
    if not source_record_id:
        return False

    row = connection.execute(
        """
        SELECT 1 FROM events
        WHERE source = ? AND source_record_id = ?
        LIMIT 1
        """,
        (event.get("source"), source_record_id),
    ).fetchone()
    return row is not None


def _store_events_and_detect(
    events: list[dict], connection: sqlite3.Connection
) -> tuple[list[dict], list[dict]]:
    """Persist normalized events and run the shared detection pipeline.

    Events must already be in the shape produced by ``parse_auth_line`` (or the
    journal/Suricata collector normalizers). Storage and detection both run
    inside the caller's transaction, so the failed-login count reflects the rows
    just inserted and a failure leaves nothing partially applied (events,
    alerts and the caller's checkpoint advance are committed or rolled back
    together).

    Replay safety: before inserting, each event is checked against already
    stored records. Identifiable records (``source_record_id`` set, e.g. journal
    ``__CURSOR``) are deduplicated against the DB-enforced unique index on
    ``(source, source_record_id)``; a duplicate insert raises ``IntegrityError``
    which is caught per-row so a single replayed record never rolls back an
    entire batch. Records without a native identifier (``source_record_id`` is
    NULL) are not deduplicated here; they rely on collector-side checkpointing.
    Skipped duplicates are not inserted and therefore cannot inflate detection
    counts. Returns ``(inserted_events, new_alerts, new_incidents)``.
    """
    inserted_events = []

    for event in events:
        # Normalize dedup fields so callers that omit them (e.g. ingest_events
        # with hand-built dicts) still get safe defaults.
        event.setdefault("source_record_id", None)
        event.setdefault("content_hash", _content_hash(event))

        if _is_duplicate_event(connection, event):
            continue  # replayed record: do not insert, do not count

        try:
            cursor = connection.execute(
                """
                INSERT INTO events (
                    timestamp, host, event_type, username,
                    source_ip, severity, raw_message, source,
                    source_record_id, content_hash,
                    dest_ip, src_port, dest_port, proto,
                    signature, signature_id, category
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    event.get("source_record_id"),
                    event.get("content_hash"),
                    event.get("dest_ip"),
                    event.get("src_port"),
                    event.get("dest_port"),
                    event.get("proto"),
                    event.get("signature"),
                    event.get("signature_id"),
                    event.get("category"),
                ),
            )
        except sqlite3.IntegrityError:
            # Concurrent race on the (source, source_record_id) unique index:
            # another transaction inserted the same identifiable record first.
            # Treat this row as a duplicate and continue with the rest of the
            # batch rather than rolling the whole batch back.
            continue

        inserted_events.append({"id": cursor.lastrowid, **event})

    new_alerts, new_incidents = evaluate_detections(events, inserted_events, connection)

    return inserted_events, new_alerts, new_incidents


def _suricata_alert_description(event: dict, count: int) -> str:
    """Build a human-readable description for a Suricata-derived alert.

    Surfaces the *original* numeric Suricata severity (from the event dict's
    ``raw_severity``) alongside the mapped Greywatch severity, so analysts do
    not have to decode the raw EVE JSON to see it. The full original record is
    still available in the alert's evidence events' ``raw_message``.
    """
    signature = event.get("signature")
    signature_id = event.get("signature_id")
    category = event.get("category")
    raw_severity = event.get("raw_severity")
    src_ip = event.get("source_ip") or "0.0.0.0"
    dest_ip = event.get("dest_ip") or "0.0.0.0"
    src_port = event.get("src_port")
    dest_port = event.get("dest_port")
    proto = event.get("proto") or "unknown"
    severity = event.get("severity") or "low"

    if signature:
        sig = f"signature '{signature}' (id {signature_id})"
    elif signature_id is not None:
        sig = f"signature id {signature_id}"
    else:
        sig = "unknown signature"

    orig = (
        f"Suricata severity {raw_severity}"
        if raw_severity is not None
        else "Suricata severity unknown"
    )
    cat = f"category '{category}'" if category else "no category"
    sport = src_port if src_port is not None else "any"
    dport = dest_port if dest_port is not None else "any"

    return (
        f"Suricata IDS alert ({orig}, Greywatch: {severity}); "
        f"{count} event(s) aggregated for {sig}, {cat}. "
        f"Traffic: {src_ip}:{sport} -> {dest_ip}:{dport} over {proto}. "
        "Source: Suricata EVE - see evidence events' raw_message for the "
        "original record (including the original alert.severity)."
    )


#: Columns that identify one Suricata incident. ``signature``/``signature_id``
#: are the rule identity; the rest are the network 5-tuple.
SURICATA_INCIDENT_COLUMNS = (
    "signature_id",
    "signature",
    "source_ip",
    "dest_ip",
    "src_port",
    "dest_port",
    "proto",
)


def _suricata_incident_conditions(record) -> tuple[list[str], list]:
    """Return the NULL-safe ``WHERE`` conditions + values for an incident key.

    Works for both an ingestion event dict and a stored ``alerts`` row, so the
    alert-matching query in :func:`_detect_suricata_alerts` and the evidence
    query in :func:`get_alert_detail` are built from *one* definition and can
    never silently diverge. SQLite's ``IS`` matches both ``NULL IS NULL`` and
    ``value IS value``, so absent optional fields compare correctly.

    ``category`` participates in the key **only** when the record carries no
    rule identity at all (no ``signature`` and no ``signature_id``). Without
    that discriminator, unrelated unknown-signature detections that happen to
    share a network 5-tuple would collapse into a single alert whose stored
    severity/category came from one event while its description came from
    another. When a rule identity *is* present, ``category`` is not part of the
    key, so signature-based aggregation is byte-for-byte unchanged.
    """
    values = [record[column] for column in SURICATA_INCIDENT_COLUMNS]
    conditions = [f"{column} IS ?" for column in SURICATA_INCIDENT_COLUMNS]

    if record["signature"] is None and record["signature_id"] is None:
        conditions.append("category IS ?")
        values.append(record["category"])

    return conditions, values


def _detect_suricata_alerts(
    events: list[dict], connection: sqlite3.Connection
) -> list[dict]:
    """Evaluate the ``SURICATA_ALERT`` rule over stored Suricata alert events.

    Each ``suricata_alert`` event becomes a Greywatch alert (rule_id
    ``SURICATA_ALERT``) in the shared ``alerts`` table, preserving the
    signature identity (``signature``/``signature_id``), network 5-tuple
    (source/destination IPs and ports, protocol), category, and the mapped
    severity. The original numeric Suricata severity (0-4) is kept on the event
    dict as ``raw_severity`` and surfaced in the alert description; the full
    original EVE record (incl. ``alert.severity``) is always retained in event
    ``raw_message`` for investigation.

    **Deduplication / aggregation.** A single incident is identified by the
    key ``(signature_id|signature, source_ip, dest_ip, src_port,
    dest_port, proto)``, plus ``category`` when the record carries no rule
    identity (see :func:`_suricata_incident_conditions`). Repeated detections
    of the same key within ``SURICATA_ALERT_WINDOW_MINUTES`` of the alert's
    last activity aggregate into the existing open alert -- ``event_count``
    grows, ``last_triggered_at`` advances, and the underlying evidence events
    remain stored (never lost). The same key outside the window, or a different
    key, starts a new alert, so distinct attacks remain distinguishable while a
    sustained stream of identical IDS alerts cannot create an unbounded number
    of duplicates.

    Only newly-created alerts are returned (aggregations are silent, matching
    the ``SSH_BRUTE_FORCE`` rule). All writes use the caller's connection and
    transaction, so alerts are created atomically with their events.
    """
    new_alerts: list[dict] = []
    # Maps alert id -> the in-memory alert dict (the same object appended to
    # new_alerts) so a freshly-created alert's count/description stay in sync
    # when later events in the same batch aggregate into it. This mirrors the
    # SSH_BRUTE_FORCE rule, whose returned count reflects all matching events.
    created: dict[int, dict] = {}
    window = timedelta(minutes=SURICATA_ALERT_WINDOW_MINUTES)

    for event in events:
        if event.get("event_type") != "suricata_alert":
            continue

        ts = event["timestamp"]
        window_start = (
            datetime.fromisoformat(ts).astimezone(timezone.utc) - window
        ).isoformat(timespec="seconds")

        signature = event.get("signature")
        signature_id = event.get("signature_id")
        src_ip = event.get("source_ip") or "0.0.0.0"
        dest_ip = event.get("dest_ip") or "0.0.0.0"
        src_port = event.get("src_port")
        dest_port = event.get("dest_port")
        proto = event.get("proto") or "unknown"
        category = event.get("category")
        severity = event.get("severity") or "low"

        # NULL-safe matching across the full incident key (shared with the
        # evidence query). SQLite's ``IS`` matches both NULL=NULL and
        # value=value, so optional fields that are absent on both sides (e.g.
        # an unknown dest_port) still compare correctly.
        key_conditions, key_values = _suricata_incident_conditions(
            {
                "signature_id": signature_id,
                "signature": signature,
                "source_ip": src_ip,
                "dest_ip": dest_ip,
                "src_port": src_port,
                "dest_port": dest_port,
                "proto": proto,
                "category": category,
            }
        )
        where = " AND ".join(
            ["rule_id = ?", "status = 'open'", *key_conditions, "last_triggered_at >= ?"]
        )
        existing = connection.execute(
            f"""
            SELECT id, event_count, last_triggered_at
            FROM alerts
            WHERE {where}
            ORDER BY last_triggered_at DESC
            LIMIT 1
            """,
            (SURICATA_ALERT_RULE, *key_values, window_start),
        ).fetchone()

        if existing:
            old_last = existing["last_triggered_at"]
            # Keep last_triggered_at non-decreasing across out-of-order /
            # replayed events so the dedup window stays monotonic.
            new_last = ts if (old_last is None or ts > old_last) else old_last
            new_count = existing["event_count"] + 1
            connection.execute(
                """
                UPDATE alerts
                SET event_count = ?, last_triggered_at = ?, description = ?
                WHERE id = ?
                """,
                (
                    new_count,
                    new_last,
                    _suricata_alert_description(event, new_count),
                    existing["id"],
                ),
            )
            # Keep the in-memory alert consistent with the DB write so that a
            # batch of identical events reports the aggregated count/description
            # (rather than the count-at-creation of 1).
            cached = created.get(existing["id"])
            if cached is not None:
                cached["event_count"] = new_count
                cached["last_triggered_at"] = new_last
                cached["description"] = _suricata_alert_description(
                    event, new_count
                )
            continue

        description = _suricata_alert_description(event, 1)
        title = (
            signature
            or (
                f"Suricata alert (signature id {signature_id})"
                if signature_id is not None
                else "Suricata alert"
            )
        )
        cursor = connection.execute(
            """
            INSERT INTO alerts (
                created_at, rule_id, title, severity,
                source_ip, description, event_count, status,
                last_triggered_at,
                dest_ip, src_port, dest_port, proto,
                signature, signature_id, category
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                SURICATA_ALERT_RULE,
                title,
                severity,
                src_ip,
                description,
                1,
                ts,
                dest_ip,
                src_port,
                dest_port,
                proto,
                signature,
                signature_id,
                category,
            ),
        )

        new_alerts.append(
            {
                "id": cursor.lastrowid,
                "created_at": ts,
                "rule_id": SURICATA_ALERT_RULE,
                "title": title,
                "severity": severity,
                "source_ip": src_ip,
                "description": description,
                "event_count": 1,
                "status": "open",
                "last_triggered_at": ts,
                "dest_ip": dest_ip,
                "src_port": src_port,
                "dest_port": dest_port,
                "proto": proto,
                "signature": signature,
                "signature_id": signature_id,
                "category": category,
            }
        )
        created[cursor.lastrowid] = new_alerts[-1]

    return new_alerts


def _correlate_ssh_brute_force_then_success(
    events: list[dict], connection: sqlite3.Connection
) -> list[dict]:
    """Evaluate the ``SSH_BRUTE_FORCE_THEN_SUCCESS`` correlation rule.

    Correlates repeated SSH authentication failures with a subsequent
    successful SSH login from the same source IP within a bounded time window.

    The rule is driven by newly ingested ``ssh_login_success`` events: a new
    success is the trigger that can complete the pattern, so failures stored in
    earlier collection cycles (visible on this connection within the transaction)
    are counted. Failures arriving without a later success produce no incident
    -- the missing successful-login signal is deliberately not fabricated.

    Only ``ssh_login_failed`` and ``ssh_login_success`` events are considered,
    so Suricata ``suricata_*`` events can never trigger this SSH-specific rule.
    Matching is by source IP and the events are stored verbatim; no successful
    login events are invented.

    One open incident per (rule_id, source_ip) is maintained: re-evaluation
    updates the existing incident in place (idempotent) rather than creating
    duplicates. All writes use the caller's connection and transaction.

    Returns only newly-created incident dicts; an update to an existing open
    incident is silent (matching the ``SSH_BRUTE_FORCE``/``SURICATA_ALERT``
    alert-aggregation contract).
    """
    new_incidents: list[dict] = []
    window = timedelta(minutes=get_correlation_window_minutes())
    now = datetime.now(timezone.utc)
    cutoff = now - window

    # Latest success per source IP in this batch; a success drives correlation.
    latest_success: dict[str, dict] = {}
    for event in events:
        if event.get("event_type") != "ssh_login_success":
            continue
        source_ip = event.get("source_ip")
        if not source_ip:
            continue
        existing = latest_success.get(source_ip)
        if existing is None or event["timestamp"] > existing["timestamp"]:
            latest_success[source_ip] = event

    for source_ip in sorted(latest_success):
        success = latest_success[source_ip]
        try:
            success_dt = datetime.fromisoformat(success["timestamp"].replace("Z", "+00:00"))
        except (TypeError, ValueError):
            # A success without a usable timestamp cannot be bounded by the
            # window; skip it rather than correlating on the clock.
            continue
        if success_dt.tzinfo is None:
            success_dt = success_dt.astimezone(timezone.utc)
        if success_dt < cutoff:
            # Success is outside the bounded correlation window.
            continue

        window_start = success_dt - window
        window_start_iso = window_start.isoformat(timespec="seconds")
        success_iso = success_dt.astimezone(timezone.utc).isoformat(timespec="seconds")

        count = connection.execute(
            """
            SELECT COUNT(*) AS total
            FROM events
            WHERE event_type = 'ssh_login_failed'
              AND source_ip = ?
              AND timestamp >= ?
              AND timestamp <= ?
            """,
            (source_ip, window_start_iso, success_iso),
        ).fetchone()["total"]

        if count < BRUTE_FORCE_THRESHOLD:
            continue

        first_row = connection.execute(
            """
            SELECT timestamp
            FROM events
            WHERE event_type = 'ssh_login_failed'
              AND source_ip = ?
              AND timestamp >= ?
              AND timestamp <= ?
            ORDER BY timestamp ASC
            LIMIT 1
            """,
            (source_ip, window_start_iso, success_iso),
        ).fetchone()
        first_seen_at = first_row["timestamp"] if first_row else success_iso

        description = (
            f"Observed {count} failed SSH login attempts from {source_ip} "
            f"followed by a successful login from {source_ip} at {success_iso} "
            f"within {get_correlation_window_minutes()} minutes. "
            "Investigate for credential compromise; the successful login "
            "indicates the brute force may have succeeded."
        )

        # Related events: the matching failures plus the successful login.
        failure_rows = connection.execute(
            """
            SELECT id FROM events
            WHERE event_type = 'ssh_login_failed'
              AND source_ip = ?
              AND timestamp >= ?
              AND timestamp <= ?
            ORDER BY timestamp ASC
            """,
            (source_ip, window_start_iso, success_iso),
        ).fetchall()
        related_event_ids = [row["id"] for row in failure_rows]

        success_id = connection.execute(
            """
            SELECT id FROM events
            WHERE event_type = 'ssh_login_success'
              AND source_ip = ?
              AND timestamp = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (source_ip, success_iso),
        ).fetchone()
        if success_id is not None:
            related_event_ids.append(success_id["id"])

        incident, created = _upsert_incident(
            rule_id=SSH_BRUTE_FORCE_THEN_SUCCESS_RULE,
            title="SSH brute force followed by successful login",
            severity="critical",
            source_ip=source_ip,
            description=description,
            event_count=count,
            first_seen_at=first_seen_at,
            last_seen_at=success_iso,
            related_event_ids=related_event_ids,
            connection=connection,
        )
        if created:
            new_incidents.append(incident)

    return new_incidents


def _now_iso() -> str:
    """Current UTC time as a normalized ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _upsert_incident(
    *,
    rule_id: str,
    title: str,
    severity: str,
    source_ip: str,
    description: str,
    event_count: int,
    first_seen_at: str,
    last_seen_at: str,
    related_event_ids: list[int],
    connection: sqlite3.Connection,
) -> tuple[dict, bool]:
    """Create or update the open incident for ``(rule_id, source_ip)``.

    Re-evaluation updates the existing open incident in place (event count,
    last seen, description) so repeated collection never creates duplicate
    incidents. Related events are attached idempotently. Returns
    ``(incident, created)`` where ``created`` is ``True`` only when a new
    incident row was inserted, so callers can honor the documented contract
    that an update is not reported as a newly-created incident.
    """
    now_text = _now_iso()

    existing = connection.execute(
        """
        SELECT id FROM incidents
        WHERE rule_id = ? AND source_ip = ? AND status = 'open'
        LIMIT 1
        """,
        (rule_id, source_ip),
    ).fetchone()

    created = existing is None

    if existing:
        incident_id = existing["id"]
        connection.execute(
            """
            UPDATE incidents
            SET updated_at = ?, event_count = ?, last_seen_at = ?, description = ?
            WHERE id = ?
            """,
            (now_text, event_count, last_seen_at, description, incident_id),
        )
    else:
        cursor = connection.execute(
            """
            INSERT INTO incidents (
                created_at, updated_at, rule_id, title, severity, status,
                source_ip, description, event_count, first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)
            """,
            (
                now_text, now_text, rule_id, title, severity,
                source_ip, description, event_count, first_seen_at, last_seen_at,
            ),
        )
        incident_id = cursor.lastrowid

    for event_id in related_event_ids:
        connection.execute(
            """
            INSERT OR IGNORE INTO incident_events (incident_id, event_id, added_at)
            VALUES (?, ?, ?)
            """,
            (incident_id, event_id, now_text),
        )

    # Read back the persisted row on the same connection (no nested
    # connection, so the caller's transaction stays intact).
    row = connection.execute(
        "SELECT * FROM incidents WHERE id = ?", (incident_id,)
    ).fetchone()
    incident = dict(row)
    incident["related_event_ids"] = sorted(set(related_event_ids))
    return incident, created


def list_incidents(
    status: str = "open", limit: int = 100, offset: int = 0, source_ip: str | None = None
) -> list[dict]:
    """List correlated incidents, ordered by first seen (newest first).

    ``offset`` skips the first ``offset`` matching rows so callers can page
    through the result set. ``source_ip`` narrows results to a single source
    IP when provided. The total number of matching incidents is not returned
    here; callers that need it should run :func:`count_incidents`.
    """
    initialize_database()

    if offset < 0:
        offset = 0

    with _connection() as connection:
        if status == "all":
            rows = connection.execute(
                """
                SELECT * FROM incidents
                WHERE (? IS NULL OR source_ip = ?)
                ORDER BY first_seen_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                (source_ip, source_ip, limit, offset),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT * FROM incidents
                WHERE status = ?
                  AND (? IS NULL OR source_ip = ?)
                ORDER BY first_seen_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                (status, source_ip, source_ip, limit, offset),
            ).fetchall()

    return [dict(row) for row in rows]


def count_incidents(status: str = "open", source_ip: str | None = None) -> int:
    """Return the total number of incidents matching ``status`` and ``source_ip``.

    Used alongside :func:`list_incidents` so clients can compute the number of
    pages without fetching every row.
    """
    initialize_database()

    with _connection() as connection:
        if source_ip is None:
            if status == "all":
                row = connection.execute(
                    "SELECT COUNT(*) AS total FROM incidents"
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS total FROM incidents WHERE status = ?",
                    (status,),
                ).fetchone()
        else:
            if status == "all":
                row = connection.execute(
                    "SELECT COUNT(*) AS total FROM incidents WHERE source_ip = ?",
                    (source_ip,),
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT COUNT(*) AS total FROM incidents
                    WHERE status = ? AND source_ip = ?
                    """,
                    (status, source_ip),
                ).fetchone()

    return int(row["total"])


def get_incident(incident_id: int) -> dict | None:
    """Return an incident with its related events in chronological order."""
    initialize_database()

    with _connection() as connection:
        row = connection.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            return None

        incident = dict(row)
        event_rows = connection.execute(
            """
            SELECT e.*
            FROM events e
            JOIN incident_events ie ON ie.event_id = e.id
            WHERE ie.incident_id = ?
            ORDER BY e.timestamp ASC, e.id ASC
            """,
            (incident_id,),
        ).fetchall()

    incident["related_events"] = [dict(event) for event in event_rows]
    incident["related_event_ids"] = [event["id"] for event in incident["related_events"]]
    return incident


_ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "acknowledged": {"open"},
    "resolved": {"open", "acknowledged"},
}


def _transition_incident(
    incident_id: int, to_status: str
) -> dict:
    """Transition an incident to ``to_status``.

    Returns a dict with ``ok`` and either ``status`` (success) or ``error``
    (``"not_found"`` or ``"invalid_transition"``). Transitions are idempotent:
    an incident already in ``to_status`` is left unchanged and reported ok.
    """
    initialize_database()
    now_text = _now_iso()

    with _connection() as connection:
        row = connection.execute(
            "SELECT status FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        if row is None:
            return {"ok": False, "error": "not_found"}

        current = row["status"]
        if current == to_status:
            return {"ok": True, "status": current}

        allowed = _ALLOWED_TRANSITIONS.get(to_status, set())
        if current not in allowed:
            return {"ok": False, "error": "invalid_transition"}

        if to_status == "resolved":
            connection.execute(
                """
                UPDATE incidents
                SET status = 'resolved', updated_at = ?, closed_at = ?
                WHERE id = ?
                """,
                (now_text, now_text, incident_id),
            )
        else:
            connection.execute(
                """
                UPDATE incidents
                SET status = ?, updated_at = ?
                WHERE id = ?
                """,
                (to_status, now_text, incident_id),
            )

    return {"ok": True, "status": to_status}


def acknowledge_incident(incident_id: int) -> dict:
    """Acknowledge an open incident (open -> acknowledged)."""
    return _transition_incident(incident_id, "acknowledged")


def resolve_incident(incident_id: int) -> dict:
    """Resolve an open or acknowledged incident (-> resolved)."""
    return _transition_incident(incident_id, "resolved")


def ingest_lines(
    lines: list[str], event_ids: list[str | None] | None = None
) -> dict:
    """Parse and persist event lines, then evaluate the SSH brute-force rule.

    Behavior is unchanged from the original line-based ingestion path: each
    line is run through ``parse_auth_line`` and unrecognized lines are ignored.

    Idempotency: when ``event_ids`` is provided, ``event_ids[i]`` is the
    optional client-generated stable identifier for ``lines[i]``. Events that
    carry an identifier are tagged ``source="http"`` and deduplicated against
    the DB-enforced unique index on ``(source, source_record_id)``; replaying
    the same identifier skips the insert and does not increment detection
    counts. Events without an identifier keep the existing stateless behavior
    (``source=None``, no deduplication) -- see the documented limitation in
    :func:`_store_events_and_detect`.

    ``parsed`` is the number of lines that parsed into valid events
    (pre-deduplication); ``duplicates`` is the number of those skipped because
    a prior request already inserted the same identifier; ``ignored`` is the
    number of lines that did not parse.

    Idempotency keys are matched on ``(source, source_record_id)`` only; the
    event content is not compared. Reusing an identifier for *different*
    content is therefore treated as a replay of the first content: the later
    event is skipped and counted in ``duplicates`` (no error). Callers must use
    a stable identifier per distinct event. Detecting key/content conflicts
    would require comparing stored content and is intentionally out of scope to
    keep ingestion backward-compatible.
    """
    initialize_database()

    if event_ids is not None and len(event_ids) != len(lines):
        raise ValueError("event_ids must be the same length as lines")

    parsed_events: list[dict] = []
    for i, line in enumerate(lines):
        event = parse_auth_line(line)
        if event is None:
            continue
        eid = event_ids[i] if event_ids is not None else None
        if eid:
            # Tag idempotent HTTP events with a non-NULL source so the partial
            # unique index on (source, source_record_id) enforces replay safety.
            event["source_record_id"] = eid
            event["source"] = "http"
        parsed_events.append(event)

    with _connection() as connection:
        inserted_events, new_alerts, new_incidents = _store_events_and_detect(
            parsed_events, connection
        )

    parsed = len(parsed_events)
    duplicates = parsed - len(inserted_events)
    return {
        "received": len(lines),
        "parsed": parsed,
        "duplicates": duplicates,
        "ignored": len(lines) - parsed,
        "events": inserted_events,
        "alerts": new_alerts,
        "incidents": new_incidents,
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
        inserted_events, new_alerts, new_incidents = _store_events_and_detect(
            events, connection
        )

    parsed = len(inserted_events)
    return {
        "received": parsed,
        "parsed": parsed,
        "ignored": 0,
        "events": inserted_events,
        "alerts": new_alerts,
        "incidents": new_incidents,
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


def list_alerts(status: str = "open", limit: int = 100, offset: int = 0, source_ip: str | None = None):
    """List alerts, ordered by id descending.

    ``offset`` skips the first ``offset`` matching rows so callers can page
    through the result set. ``source_ip`` narrows results to a single source
    IP when provided. Returns the matching rows (capped by ``limit``); callers
    that need the total should use :func:`count_alerts`.
    """
    initialize_database()

    if offset < 0:
        offset = 0

    with _connection() as connection:
        if status == "all":
            rows = connection.execute(
                """
                SELECT * FROM alerts
                WHERE (? IS NULL OR source_ip = ?)
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (source_ip, source_ip, limit, offset),
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT * FROM alerts
                WHERE status = ?
                  AND (? IS NULL OR source_ip = ?)
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                (status, source_ip, source_ip, limit, offset),
            ).fetchall()

    return [dict(row) for row in rows]


def count_alerts(status: str = "all", source_ip: str | None = None) -> int:
    """Return the total number of alerts matching ``status`` and ``source_ip``.

    Used alongside :func:`list_alerts` so clients can compute the number of
    pages without fetching every row.
    """
    initialize_database()

    with _connection() as connection:
        if source_ip is None:
            if status == "all":
                row = connection.execute(
                    "SELECT COUNT(*) AS total FROM alerts"
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) AS total FROM alerts WHERE status = ?",
                    (status,),
                ).fetchone()
        else:
            if status == "all":
                row = connection.execute(
                    "SELECT COUNT(*) AS total FROM alerts WHERE source_ip = ?",
                    (source_ip,),
                ).fetchone()
            else:
                row = connection.execute(
                    """
                    SELECT COUNT(*) AS total FROM alerts
                    WHERE status = ? AND source_ip = ?
                    """,
                    (status, source_ip),
                ).fetchone()

    return int(row["total"])


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
    """Return an alert and the evidence events in its investigation window.

    The window ends at the alert's last trigger time — updated whenever the
    detection count is recalculated — so the returned events stay consistent
    with the alert's event_count as new events arrive. Alerts migrated from
    an older schema fall back to created_at.

    Evidence querying is rule-specific:
    * ``SSH_BRUTE_FORCE`` — ``ssh_login_failed`` events from the alert's
      ``source_ip`` within ``[last_triggered_at - 5m, last_triggered_at]``.
    * ``SURICATA_ALERT`` — ``suricata_alert`` events matching the alert's
      signature identity and network 5-tuple within
      ``[created_at, last_triggered_at]``. Their ``raw_message`` preserves the
      original EVE record (incl. the original numeric ``alert.severity``).
    * Any other/unknown rule id yields an empty evidence set rather than a
      wrong one, so new rules fail safe.
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
        rule_id = alert.get("rule_id")

        if rule_id == "SSH_BRUTE_FORCE":
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

        elif rule_id == SURICATA_ALERT_RULE:
            # Evidence = the Suricata alert events aggregated into this alert,
            # covering its full lifetime [created_at, last_triggered_at]. The
            # incident key is built by the SAME helper used when matching an
            # existing alert at ingestion time, so evidence can never be scoped
            # differently from the alert it belongs to.
            window_end = datetime.fromisoformat(
                alert.get("last_triggered_at") or alert["created_at"]
            )
            start = datetime.fromisoformat(
                alert.get("created_at") or alert.get("last_triggered_at")
            ).astimezone(timezone.utc).isoformat(timespec="seconds")
            end = window_end.astimezone(timezone.utc).isoformat(
                timespec="seconds"
            )

            key_conditions, key_values = _suricata_incident_conditions(alert)
            where = " AND ".join(
                [
                    "event_type = 'suricata_alert'",
                    *key_conditions,
                    "timestamp >= ?",
                    "timestamp <= ?",
                ]
            )
            rows = connection.execute(
                f"""
                SELECT *
                FROM events
                WHERE {where}
                ORDER BY timestamp ASC
                """,
                (*key_values, start, end),
            ).fetchall()

        else:
            # Unknown / future rule: fail safe — no rule-specific evidence
            # query is attempted rather than returning wrong evidence.
            start = alert.get("created_at")
            end = alert.get("last_triggered_at") or alert.get("created_at")
            rows = []

    return {
        "alert": alert,
        "evidence_window_start": start,
        "evidence_window_end": end,
        "evidence_events": [dict(event) for event in rows],
    }
