"""Suricata EVE JSON integration for Greywatch.

This module ingests Suricata's `EVE JSON <https://suricata.io/documentation/>`_
output file (``eve.json`` by default) and normalizes the security-relevant
records into Greywatch's *existing* event model, feeding them through the SAME
storage and detection engine used by journal/HTTP ingestion
(:func:`siem.ingest_events` -> :func:`siem._store_events_and_detect`).

Design notes
------------
* **Incremental collection.** A byte offset is persisted in the
  ``collector_state`` table (``suricata_last_offset``). Each cycle reads only the
  bytes appended since the last run, so a large ``eve.json`` is never re-scanned
  in full after the first cycle.
* **Safe restart / rotation.** If the file shrinks below the stored offset
  (log rotation / truncation), the offset resets and the recent window is
  de-duplicated against already-stored events, mirroring the journal
  collector's ``--since`` fallback. ``fallback_used`` is reported when this
  rotation reset occurs.
* **Malformed records.** A line that is not valid JSON, or lacks a usable
  timestamp, is skipped; collection of the remaining records continues. Lines
  are read complete (newline-terminated) so a record Suricata is mid-write when
  observed is never half-parsed.
* **Shared detection engine.** EVE ``alert`` records are normalized to
  ``suricata_alert`` events (and ``suricata_dns``/``suricata_tls``/
  ``suricata_http``/``suricata_flow`` for those event types). They feed the
  SAME storage + detection engine used by journal/HTTP ingestion
  (:func:`siem._store_events_and_detect`), so a Suricata ``alert`` now raises a
  Greywatch alert (``rule_id = SURICATA_ALERT``) in the shared ``alerts``
  table. Because they are ``suricata_alert`` (not ``ssh_login_failed``)
  events, the existing ``SSH_BRUTE_FORCE`` rule is left untouched. Repeated
  detections of the same signature + network 5-tuple within
  :data:`siem.SURICATA_ALERT_WINDOW_MINUTES` aggregate into the existing open
  alert (counts grow, evidence is never lost); distinct signatures or
  endpoints, or detections outside the window, start a new alert — so distinct
  attacks remain distinguishable while identical IDS alerts cannot multiply
  unboundedly. See :func:`siem._detect_suricata_alerts`.
* **Provenance.** Normalized events are tagged ``source="suricata"`` so they
  are distinguishable from journal (``"journal"``) and line-based (``NULL``)
  events.
* **Optional & off by default.** Set ``GREYWATCH_SURICATA_ENABLED=1`` to enable
  continuous collection. ``POST /api/v1/suricata/collect`` runs one cycle
  regardless of that flag, exactly like the journal collector.

Greywatch runs without Suricata installed: if the configured EVE file is
missing, ``collect_once`` reports the error via ``result.errors`` instead of
raising, and the ``/api/v1/suricata/*`` endpoints stay available.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import siem
from .collector import CollectResult

logger = logging.getLogger("greywatch.suricata")

#: Default Suricata EVE JSON output path.
DEFAULT_EVE_PATH = "/var/log/suricata/eve.json"

DEFAULT_POLL_INTERVAL = 30.0
DEFAULT_LOOKBACK_MINUTES = 1440.0  # retained for API symmetry with the journal collector
DEFAULT_MAX_RECORDS = 5000

#: EVE event_types this collector understands. Records of any other type are
#: stored as-is only when they carry security-relevant fields; otherwise they
#: are skipped to avoid flooding the event store with low-value noise.
SURICATA_EVENT_TYPES: tuple[str, ...] = (
    "alert",
    "dns",
    "tls",
    "http",
    "flow",
)

# Suricata alert severity (0-4, 0 = most severe) -> Greywatch severity tier.
# Greywatch uses {high, medium, low, info}; Suricata 0/1 map to high.
_SEVERITY_MAP: dict[int, str] = {
    0: "high",
    1: "high",
    2: "medium",
    3: "low",
    4: "low",
}

# State keys (reuse the shared collector_state table the journal collector uses).
_SURICATA_PREFIX = "suricata_"


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass
class SuricataConfig:
    """Runtime configuration for the Suricata EVE collector."""

    enabled: bool = False
    eve_path: str = DEFAULT_EVE_PATH
    poll_interval: float = DEFAULT_POLL_INTERVAL
    max_records: int = DEFAULT_MAX_RECORDS


def get_config() -> SuricataConfig:
    """Build a :class:`SuricataConfig` from environment variables.

    Read on each call (not at import) so tests stay hermetic via
    ``monkeypatch.setenv``.
    """

    def _bool(name: str, default: bool = False) -> bool:
        return os.environ.get(name, "").lower() in ("1", "true", "yes")

    def _float(name: str, default: float) -> float:
        try:
            return float(os.environ.get(name, str(default)))
        except (TypeError, ValueError):
            return default

    def _int(name: str, default: int) -> int:
        try:
            return int(os.environ.get(name, str(default)))
        except (TypeError, ValueError):
            return default

    return SuricataConfig(
        enabled=_bool("GREYWATCH_SURICATA_ENABLED"),
        eve_path=os.environ.get("GREYWATCH_SURICATA_EVE_PATH", DEFAULT_EVE_PATH),
        poll_interval=_float(
            "GREYWATCH_SURICATA_POLL_INTERVAL", DEFAULT_POLL_INTERVAL
        ),
        max_records=_int("GREYWATCH_SURICATA_MAX_RECORDS", DEFAULT_MAX_RECORDS),
    )


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #


class SuricataError(RuntimeError):
    """Raised when the EVE file cannot be read or parsed as expected."""


# --------------------------------------------------------------------------- #
# Checkpoint state (reuses the shared collector_state table)
# --------------------------------------------------------------------------- #


def _state_key_offset() -> str:
    return _SURICATA_PREFIX + "last_offset"


def _state_key_event_ts() -> str:
    return _SURICATA_PREFIX + "last_event_ts"


def _state_key_events_ingested() -> str:
    return _SURICATA_PREFIX + "events_ingested"


def _state_key_last_run_at() -> str:
    return _SURICATA_PREFIX + "last_run_at"


def _get_offset() -> str | None:
    return siem.get_collector_setting(_state_key_offset())


def _get_last_event_ts() -> str | None:
    return siem.get_collector_setting(_state_key_event_ts())


def _count_suricata_events(connection: sqlite3.Connection) -> int:
    """Count stored suricata-sourced events on an open connection.

    Reads on the caller's connection (not a fresh one) to avoid opening a
    second connection inside a write transaction (``database is locked``).
    """
    return connection.execute(
        "SELECT COUNT(*) AS n FROM events WHERE source = 'suricata'"
    ).fetchone()["n"]


def _set_state(connection: sqlite3.Connection, **values: object) -> None:
    """Upsert suricata collector_state rows inside an open transaction."""
    mapping = {
        _state_key_offset(): values.get("offset"),
        _state_key_event_ts(): values.get("event_ts"),
        _state_key_events_ingested(): values.get("events_ingested"),
        _state_key_last_run_at(): values.get("run_at"),
    }
    for key, value in mapping.items():
        if value is None:
            continue
        connection.execute(
            """
            INSERT INTO collector_state (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, str(value)),
        )


# --------------------------------------------------------------------------- #
# Parsing / normalization
# --------------------------------------------------------------------------- #


def _normalize_timestamp(value: str | None) -> str | None:
    """Convert a Suricata EVE timestamp to UTC ISO-8601 (seconds precision).

    EVE timestamps look like ``2024-01-01T12:00:00.123456Z`` (microsecond,
    UTC). They are normalized to match the rest of the event store.
    """
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _to_int_port(value: object) -> int | None:
    """Coerce an EVE port field to int, returning None when absent/invalid."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _suricata_severity(alert_obj: object) -> str:
    """Map a Suricata ``alert.severity`` (0-4, 0 most severe) to a Greywatch tier.

    A missing or unparseable severity is treated conservatively as ``"low"``
    rather than over-classifying an unrated rule.
    """
    if not isinstance(alert_obj, dict):
        return "low"
    sev = alert_obj.get("severity")
    if sev is None:
        return "low"
    try:
        sev = int(sev)
    except (TypeError, ValueError):
        return "low"
    return _SEVERITY_MAP.get(sev, "low")


def _eve_host(record: dict) -> str:
    """Best-effort host identification from an EVE record."""
    return record.get("host") or record.get("sensor") or record.get("sensor_id") or "unknown"


def parse_eve_record(record: object, *, raw_line: str) -> dict | None:
    """Classify a single EVE JSON record into Greywatch's normalized event shape.

    Recognizes ``event_type`` values ``alert``, ``dns``, ``tls``, ``http``
    and ``flow``. Each returns a dict carrying the 8 canonical event fields
    (``timestamp``, ``host``, ``event_type``, ``username``, ``source_ip``,
    ``severity``, ``raw_message``, ``source``) plus the network/IDS fields the
    extended ``events`` schema supports (``dest_ip``, ``src_port``,
    ``dest_port``, ``proto``, ``signature``, ``signature_id``, ``category``).

    Returns ``None`` for records that are not recognized security events or
    that lack a usable timestamp (so they cannot be placed in the time-windowed
    evidence view).
    """
    if not isinstance(record, dict):
        return None

    event_type_raw = record.get("event_type")
    if event_type_raw not in SURICATA_EVENT_TYPES:
        return None

    timestamp = _normalize_timestamp(record.get("timestamp"))
    if timestamp is None:
        # A usable timestamp is mandatory; records without one cannot be
        # placed in a time window and are treated as malformed.
        return None

    src_ip = record.get("src_ip")
    dest_ip = record.get("dest_ip")

    event: dict = {
        "timestamp": timestamp,
        "host": _eve_host(record),
        "event_type": f"suricata_{event_type_raw}",
        "username": None,
        "source_ip": src_ip,
        "severity": "low",
        "raw_message": raw_line,
        "source": "suricata",
        "dest_ip": dest_ip,
        "src_port": _to_int_port(record.get("src_port")),
        "dest_port": _to_int_port(record.get("dest_port")),
        "proto": str(record["proto"]) if record.get("proto") is not None else None,
        "signature": None,
        "signature_id": None,
        "category": None,
        "raw_severity": None,  # original alert.severity (0-4); kept for the
        # alert description / investigation. Not a persisted events column (the
        # INSERT in siem._store_events_and_detect ignores unknown keys), but
        # the full original value is always retained verbatim in raw_message.
    }

    if event_type_raw == "alert":
        alert = record.get("alert") or {}
        if isinstance(alert, dict):
            event["signature"] = alert.get("signature")
            event["signature_id"] = _to_int_port(alert.get("signature_id"))
            event["category"] = alert.get("category")
            event["severity"] = _suricata_severity(alert)
            # Keep the original numeric Suricata severity (0-4, 0 most severe)
            # alongside the mapped Greywatch tier so it survives into the
            # resulting Greywatch alert's description and evidence.
            event["raw_severity"] = _to_int_port(alert.get("severity"))
        # Suricata alert signature text sometimes lives at the top level too.
        if not event["signature"] and record.get("signature"):
            event["signature"] = record.get("signature")

    return event


# --------------------------------------------------------------------------- #
# File reading
# --------------------------------------------------------------------------- #


def _read_eve_records(
    path: str, offset: int, max_records: int
) -> tuple[list[tuple[str, dict]], int, bool]:
    """Read EVE JSON lines from ``path`` starting at byte ``offset``.

    Returns ``(records, new_offset, rotated)`` where ``records`` is a list of
    ``(raw_line, parsed_dict)`` tuples. Malformed JSON lines are skipped (not
    returned) so one corrupt line cannot abort the batch. Only complete,
    newline-terminated lines are processed; a trailing line without a newline
    is held back (and re-read next cycle) so a record Suricata is mid-writing
    is never parsed half-complete.

    ``rotated`` is True when the file shrank below ``offset`` (log rotation /
    truncation) and the offset was reset to 0.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise SuricataError(f"EVE file not found: {file_path}")

    size = file_path.stat().st_size
    rotated = False
    if offset > size:
        # File was rotated/truncated; restart from the beginning and rely on
        # content de-duplication to avoid re-ingesting already-stored records.
        offset = 0
        rotated = True

    records: list[tuple[str, dict]] = []
    last_complete = offset  # byte position after the last complete line

    with file_path.open("rb") as fh:
        fh.seek(offset)
        for raw_bytes in fh:
            if raw_bytes.endswith(b"\n"):
                last_complete = fh.tell()
            else:
                # No trailing newline: either EOF (final complete line) or a
                # partial line mid-write. Hold it back by breaking without
                # advancing the committed offset.
                break
            line = raw_bytes.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # Skip malformed lines; the next record is unaffected.
                continue
            if isinstance(record, dict):
                records.append((line, record))
                if len(records) >= max_records:
                    break

    return records, last_complete, rotated


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #


def _read_existing_keys(
    connection: sqlite3.Connection, since_iso: str
) -> set[tuple[str, str, str]]:
    """Return ``(timestamp, host, raw_message)`` keys already stored recently.

    Used to suppress duplicates when a rotation reset re-reads records that
    were already ingested before the file was rotated.
    """
    rows = connection.execute(
        """
        SELECT timestamp, host, raw_message
        FROM events
        WHERE source = 'suricata'
          AND timestamp >= ?
        """,
        (since_iso,),
    ).fetchall()
    return {(row["timestamp"], row["host"], row["raw_message"]) for row in rows}


def _now_iso() -> str:
    """Current UTC time as a normalized ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def collect_once(config: SuricataConfig | None = None) -> CollectResult:
    """Run a single Suricata EVE collection cycle and return a summary.

    The cycle: read the persisted byte offset, read new EVE lines, normalize
    them, de-duplicate against already-stored recent events, ingest the
    remainder through :func:`siem._store_events_and_detect`, and persist the
    advanced offset atomically with the inserts.
    """
    config = config or get_config()
    result = CollectResult()
    siem.initialize_database()

    try:
        offset = int(_get_offset() or 0)
    except (TypeError, ValueError):
        offset = 0
    last_event_ts = _get_last_event_ts()

    try:
        raw_records, new_offset, rotated = _read_eve_records(
            config.eve_path, offset, config.max_records
        )
    except (OSError, SuricataError) as exc:
        # Missing/unreadable EVE file is reported, not raised: the collector
        # keeps running and will pick the file up on the next cycle.
        result.errors.append(str(exc))
        return result

    result.records_seen = len(raw_records)
    result.fallback_used = rotated

    # Normalize + within-batch de-duplication by raw line.
    events: list[dict] = []
    seen_lines: set[str] = set()
    for raw_line, record in raw_records:
        if raw_line in seen_lines:
            continue
        seen_lines.add(raw_line)
        event = parse_eve_record(record, raw_line=raw_line)
        if event is None:
            continue
        events.append(event)
        if len(events) >= config.max_records:
            break

    # Nothing recognizable happened; still record progress + last_run_at.
    if not events:
        with siem._connection() as connection:
            _set_state(
                connection,
                offset=str(new_offset),
                event_ts=last_event_ts,
                events_ingested=str(_count_suricata_events(connection)),
                run_at=_now_iso(),
            )
        result.cursor_advanced = new_offset != offset
        return result

    # Ingest + detect, then advance the offset in the same transaction so a
    # crash cannot leave events inserted but the offset un-advanced.
    with siem._connection() as connection:
        # De-duplicate against recently-stored events (rotation/reset overlap).
        dedup_since = min(
            (e["timestamp"] for e in events),
            default=_now_iso(),
        )
        existing_keys = _read_existing_keys(connection, dedup_since)
        new_events = [
            e
            for e in events
            if (e["timestamp"], e["host"], e["raw_message"]) not in existing_keys
        ]

        inserted, new_alerts = siem._store_events_and_detect(new_events, connection)

        advanced_ts = inserted[-1]["timestamp"] if inserted else last_event_ts
        _set_state(
            connection,
            offset=str(new_offset),
            event_ts=advanced_ts,
            events_ingested=str(_count_suricata_events(connection)),
            run_at=_now_iso(),
        )

    result.events_ingested = len(inserted)
    result.new_alerts = new_alerts
    result.cursor_advanced = new_offset != offset
    return result


# --------------------------------------------------------------------------- #
# Status
# --------------------------------------------------------------------------- #


def status() -> dict:
    """Return Suricata collector checkpoint state and the enabled flag."""
    siem.initialize_database()
    ingested_value = siem.get_collector_setting(_state_key_events_ingested(), "0")
    try:
        events_ingested = int(ingested_value)
    except (TypeError, ValueError):
        events_ingested = 0
    return {
        "enabled": get_config().enabled,
        "eve_path": get_config().eve_path,
        "last_offset": _get_offset(),
        "last_event_ts": _get_last_event_ts(),
        "events_ingested": events_ingested,
        "last_run_at": siem.get_collector_setting(_state_key_last_run_at()),
    }


# --------------------------------------------------------------------------- #
# Continuous loop + CLI
# --------------------------------------------------------------------------- #


def run_loop(config: SuricataConfig | None = None) -> None:
    """Run :func:`collect_once` on an interval until interrupted.

    The loop is a plain ``while`` + ``sleep`` (no scheduling dependency) so a
    single bad cycle -- e.g. a transient SQLite ``database is locked`` from the
    concurrent API -- never kills the continuously-running collector.
    """
    config = config or get_config()
    if not config.enabled:
        return

    import signal

    stop = {"flag": False}

    def _handle(signum, _frame):
        stop["flag"] = True

    previous = {
        signal.SIGTERM: signal.getsignal(signal.SIGTERM),
        signal.SIGINT: signal.getsignal(signal.SIGINT),
    }
    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)

    try:
        while not stop["flag"]:
            try:
                collect_once(config)
            except Exception as exc:  # noqa: BLE001 - resilient loop
                # collect_once() already reports file/IO errors via
                # result.errors. This outer guard catches anything else so the
                # daemon survives transient faults and resumes on the next poll.
                logger.exception("collection cycle failed: %s", exc)
            time.sleep(config.poll_interval)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main(argv: list[str] | None = None) -> int:
    """Command-line entry point: ``--once``, ``--status``, or loop."""
    argv = list(sys.argv[1:] if argv is None else argv)
    config = get_config()

    if "--status" in argv:
        print(json.dumps(status(), indent=2))
        return 0

    if "--once" in argv or not config.enabled:
        # ``--once`` explicitly runs a single cycle even if auto-collection is
        # disabled; otherwise we only act when enabled.
        if "--once" not in argv and not config.enabled:
            print(
                "Suricata collection is disabled. Set GREYWATCH_SURICATA_ENABLED=1 "
                "or pass --once.",
                file=sys.stderr,
            )
            return 2
        result = collect_once(config)
        print(
            f"collected: records_seen={result.records_seen} "
            f"ingested={result.events_ingested} alerts={len(result.new_alerts)} "
            f"fallback={result.fallback_used} errors={result.errors}",
            file=sys.stderr,
        )
        return 0 if not result.errors else 1

    run_loop(config)
    return 0


if __name__ == "__main__":
    sys.exit(main())
