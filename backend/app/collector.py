"""Native systemd-journal authentication collector for Greywatch.

This module reads structured PAM/SSH/sudo events from the local systemd
journal with ``journalctl -o json`` and feeds normalized events into the SIEM
through :func:`siem.ingest_events`. It reuses the *same* SSH regular
expressions as the line-based parser so that journal-sourced SSH failures
still trigger the ``SSH_BRUTE_FORCE`` rule with identical behavior.

Design notes
------------
* **Incremental collection.** A cursor is persisted in the ``collector_state``
  table. ``journalctl --after-cursor=<cursor>`` reads only entries strictly
  after the last ingested one, so an entire journal is never re-ingested.
* **Safe restart.** The cursor is advanced (in the ``collector_state`` table)
  inside the same transaction as the event inserts, so a crash either keeps the
  old cursor (re-reads, de-duplicated by the recent-window check) or advances
  it past already-ingested rows.
* **Duplicate protection.** Within a single batch, records are de-duplicated by
  journal cursor. A secondary check against recently-stored events (by
  timestamp + host + raw message) catches the overlap that can occur when a
  cursor becomes invalid (journal rotation) and the collector falls back to a
  ``--since`` window.
* **Provenance.** Genuine journal records always carry a ``__CURSOR``; those are
  tagged ``source="journal"``. Hand-crafted / synthetic records (no cursor) are
  tagged ``source="test"`` so real and synthetic events are never confused.
* **Least privilege.** ``journalctl`` reads the journal. The collector process
  therefore needs no special filesystem paths beyond a writable database
  directory; it must run as a user able to read the journal (see the guide in
  ``docs/JOURNAL_COLLECTOR.md``) but the full API does **not** have to run as
  root.

Collection is **optional** and **off by default**. Set
``GREYWATCH_JOURNAL_ENABLED=1`` to turn it on.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import siem
from .siem import (
    FAILED_LOGIN,
    INVALID_USER,
    SUCCESSFUL_LOGIN,
)

logger = logging.getLogger("greywatch.collector")

#: Default journalctl binary. Override with GREYWATCH_JOURNAL_COMMAND for
#: tests or alternate installations.
DEFAULT_JOURNALCTL = "journalctl"

DEFAULT_POLL_INTERVAL = 5.0
DEFAULT_LOOKBACK_MINUTES = 1440.0  # 24h bootstrap / fallback window
DEFAULT_MAX_RECORDS = 1000  # max events stored per collection cycle
DEFAULT_IDENTIFIERS = "sshd,sudo"

#: How far back the ``--since`` fallback reaches from the last ingested event.
FALLBACK_REWIND_SECONDS = 60

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


@dataclass
class CollectorConfig:
    """Runtime configuration for the journal collector."""

    enabled: bool = False
    poll_interval: float = DEFAULT_POLL_INTERVAL
    lookback_minutes: float = DEFAULT_LOOKBACK_MINUTES
    max_records: int = DEFAULT_MAX_RECORDS
    identifiers: list[str] = field(default_factory=lambda: ["sshd", "sudo"])
    command: str = DEFAULT_JOURNALCTL


def get_config() -> CollectorConfig:
    """Build a :class:`CollectorConfig` from environment variables.

    Reading the environment here (rather than at import time) keeps tests
    hermetic: ``monkeypatch.setenv`` takes effect on the next call.
    """

    def _bool(name: str, default: bool = False) -> bool:
        return os.environ.get(name, "").lower() in ("1", "true", "yes")

    def _float(name: str, default: float) -> float:
        try:
            return float(os.environ.get(name, str(default)))
        except ValueError:
            return default

    def _int(name: str, default: int) -> int:
        try:
            return int(os.environ.get(name, str(default)))
        except ValueError:
            return default

    raw_identifiers = os.environ.get(
        "GREYWATCH_JOURNAL_IDENTIFIERS", DEFAULT_IDENTIFIERS
    )
    identifiers = [s.strip() for s in raw_identifiers.split(",") if s.strip()]
    return CollectorConfig(
        enabled=_bool("GREYWATCH_JOURNAL_ENABLED"),
        poll_interval=_float("GREYWATCH_JOURNAL_POLL_INTERVAL", DEFAULT_POLL_INTERVAL),
        lookback_minutes=_float(
            "GREYWATCH_JOURNAL_LOOKBACK_MINUTES", DEFAULT_LOOKBACK_MINUTES
        ),
        max_records=_int("GREYWATCH_JOURNAL_MAX_RECORDS", DEFAULT_MAX_RECORDS),
        identifiers=identifiers,
        command=os.environ.get("GREYWATCH_JOURNAL_COMMAND", DEFAULT_JOURNALCTL),
    )


# --------------------------------------------------------------------------- #
# Journal reading
# --------------------------------------------------------------------------- #


class JournalctlError(RuntimeError):
    """Raised when ``journalctl`` fails or returns invalid output."""


def run_journalctl(args: list[str], *, command: str = DEFAULT_JOURNALCTL) -> list[dict]:
    """Run ``journalctl`` and return its JSON output as a list of records.

    ``--no-pager`` and ``--output=json`` are injected here so that callers only
    ever have to supply query filters (e.g. ``-t``, ``--after-cursor``,
    ``--since``); the same process never receives each flag twice.

    Each line of stdout is expected to be a JSON object (one journal entry).
    Blank or malformed lines are skipped rather than aborting the whole batch,
    so a single corrupt record can never stop collection of the rest.

    Raises :class:`JournalctlError` if the process exits non-zero. A
    non-zero exit usually means the cursor is invalid (journal rotation),
    which the caller translates into a ``--since`` fallback.
    """
    try:
        completed = subprocess.run(
            [command, "--no-pager", "--output=json", *args],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except FileNotFoundError as exc:
        raise JournalctlError(
            f"journalctl binary not found: {command}. Install systemd-journald "
            "or set GREYWATCH_JOURNAL_COMMAND."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise JournalctlError("journalctl timed out after 120s") from exc

    # ``check=False`` so we can turn every failure (most commonly an invalid
    # cursor after journal rotation) into a JournalctlError the caller can react
    # to, while preserving journalctl's own stderr message.
    if completed.returncode != 0:
        stderr = (completed.stderr or "").strip()
        raise JournalctlError(
            stderr or f"journalctl exited with code {completed.returncode}"
        )

    records: list[dict] = []
    for line in completed.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            # A malformed JSON line is skipped; the next record is unaffected.
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

# Strip an optional, syslog-style program prefix so the same classifiers work
# regardless of whether journald included ``sshd[123]:`` / ``sudo[123]:``.
_JOURNAL_PREFIX = re.compile(r"^(?:sshd|sudo)\[\d+\]:\s*", re.IGNORECASE)

# sudo / PAM structured message classifiers operating on the journal MESSAGE.
SUDO_SESSION_OPENED = re.compile(
    r"pam_unix\(sudo:session\): session opened for user "
    r"(?P<user>\S+?)(?:\s*\(uid=\d+\))?\s+by\s+(?P<invoking>\S+)(?:\s*\(uid=\d+\))?"
)
SUDO_SESSION_CLOSED = re.compile(
    r"pam_unix\(sudo:session\): session closed for user (?P<user>\S+)"
)
SUDO_COMMAND = re.compile(
    r"^\s*(?P<invoking>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*"
    r"USER=(?P<user>\S+)\s*;\s*COMMAND=(?P<command>.*)$"
)
# Generic PAM authentication failure (sudo, login, gdm, ...) carrying a user=.
PAM_AUTH_FAILURE = re.compile(
    r"pam_unix\(\S+:\w+\): authentication failure", re.IGNORECASE
)
PAM_USER = re.compile(r"user=(?P<user>\S+)")
# A generic "authentication failure" line that did not match pam_unix above.
GENERIC_AUTH_FAILURE = re.compile(r"authentication failure", re.IGNORECASE)
PAM_INCORRECT = re.compile(r"incorrect password|authentication failure", re.IGNORECASE)


def _journal_timestamp(record: dict) -> str | None:
    """Convert a journal record's real-time timestamp to UTC ISO 8601.

    ``journalctl`` exposes ``__REALTIME_TIMESTAMP`` as microsccends since the
    UNIX epoch (UTC). ``_SOURCE_REALTIME_TIMESTAMP`` is an earlier, source-side
    timestamp used when the realtime field is missing.
    """
    for key in ("__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP"):
        value = record.get(key)
        if value is None:
            continue
        try:
            ts = datetime.fromtimestamp(int(value) / 1_000_000, tz=timezone.utc)
        except (TypeError, ValueError):
            continue
        return ts.astimezone(timezone.utc).isoformat(timespec="seconds")
    return None


def parse_journal_record(record: dict) -> dict | None:
    """Classify a single journal JSON record into a normalized event.

    Returns ``None`` for records that are not recognized authentication
    events. The returned dict has the same shape consumed by
    :func:`siem.ingest_events` (timestamp, host, event_type, username,
    source_ip, severity, raw_message, source).

    ``source`` is ``"journal"`` when the record carries a journal cursor
    (i.e. it genuinely originated from ``journalctl``) and ``"test"`` when it
    is a hand-crafted/synthetic record without a cursor — keeping real events
    clearly distinguishable from test fixtures.
    """
    if not isinstance(record, dict):
        return None

    message = (record.get("MESSAGE") or "")
    if isinstance(message, list):  # journalctl can emit MESSAGE as a list
        message = " ".join(str(part) for part in message)
    message = message.strip()
    if not message:
        return None

    timestamp = _journal_timestamp(record)
    if timestamp is None:
        # A usable timestamp is mandatory; records without one are malformed.
        return None

    host = record.get("_HOSTNAME") or "unknown"
    source = "journal" if record.get("__CURSOR") else "test"

    # Normalize the message text for classification (keep the raw form for
    # raw_message so the genuine journal content is preserved verbatim).
    text = _JOURNAL_PREFIX.sub("", message)

    username: str | None = None
    source_ip: str | None = None
    severity = "info"
    raw_message = message  # preserve the original journal MESSAGE verbatim

    # --- SSH events (reuse the line-based regexes for identical detection) ---
    failed = FAILED_LOGIN.search(text)
    invalid_user = INVALID_USER.search(text)
    successful = SUCCESSFUL_LOGIN.search(text)

    if failed:
        return {
            "timestamp": timestamp,
            "host": host,
            "event_type": "ssh_login_failed",
            "username": failed.group("username"),
            "source_ip": failed.group("ip"),
            "severity": "medium",
            "raw_message": raw_message,
            "source": source,
            "source_record_id": record.get("__CURSOR"),
        }
    if invalid_user:
        return {
            "timestamp": timestamp,
            "host": host,
            "event_type": "ssh_invalid_user",
            "username": invalid_user.group("username"),
            "source_ip": invalid_user.group("ip"),
            "severity": "medium",
            "raw_message": raw_message,
            "source": source,
            "source_record_id": record.get("__CURSOR"),
        }
    if successful:
        return {
            "timestamp": timestamp,
            "host": host,
            "event_type": "ssh_login_success",
            "username": successful.group("username"),
            "source_ip": successful.group("ip"),
            "severity": "low",
            "raw_message": raw_message,
            "source": source,
            "source_record_id": record.get("__CURSOR"),
        }

    # --- sudo session / command events ---
    match = SUDO_SESSION_OPENED.search(text)
    if match:
        return {
            "timestamp": timestamp,
            "host": host,
            "event_type": "sudo_session_opened",
            "username": match.group("user"),
            "source_ip": None,
            "severity": "info",
            "raw_message": raw_message,
            "source": source,
            "source_record_id": record.get("__CURSOR"),
        }

    match = SUDO_SESSION_CLOSED.search(text)
    if match:
        return {
            "timestamp": timestamp,
            "host": host,
            "event_type": "sudo_session_closed",
            "username": match.group("user"),
            "source_ip": None,
            "severity": "info",
            "raw_message": raw_message,
            "source": source,
            "source_record_id": record.get("__CURSOR"),
        }

    match = SUDO_COMMAND.match(text)
    if match:
        return {
            "timestamp": timestamp,
            "host": host,
            "event_type": "sudo_command",
            "username": match.group("user"),
            "source_ip": None,
            "severity": "low",
            "raw_message": raw_message,
            "source": source,
            "source_record_id": record.get("__CURSOR"),
        }

    # --- PAM authentication failures (sudo, login, gdm, ...) ---
    pam_failure = PAM_AUTH_FAILURE.search(text) or GENERIC_AUTH_FAILURE.search(text)
    if pam_failure:
        user_match = PAM_USER.search(text)
        # For sudo auth failures the message looks like:
        #   sudo: pam_unix(sudo:auth): authentication failure; ... user=root
        pam_match = re.search(r"pam_unix\((\S+):(\w+)\)", text)
        auth_source = pam_match.group(1) if pam_match else "pam"
        return {
            "timestamp": timestamp,
            "host": host,
            "event_type": "pam_auth_failed",
            "username": user_match.group("user") if user_match else None,
            "source_ip": None,
            "severity": "high",
            "raw_message": raw_message,
            "source": source,
            "source_record_id": record.get("__CURSOR"),
        }

    # An auth-relevant identifier that did not match any classifier is left
    # alone so unrecognized lines do not pollute the event store.
    return None


# --------------------------------------------------------------------------- #
# Checkpoint state
# --------------------------------------------------------------------------- #


def _state_key_last_cursor() -> str:
    return "journal_last_cursor"


def _state_key_last_event_ts() -> str:
    return "journal_last_event_ts"


def _state_key_events_ingested() -> str:
    return "journal_events_ingested"


def _state_key_last_run_at() -> str:
    return "journal_last_run_at"


def _state_key_attempts() -> str:
    return "journal_attempts"


def _state_key_successful_runs() -> str:
    return "journal_successful_runs"


def _state_key_failed_runs() -> str:
    return "journal_failed_runs"


def _state_key_last_attempt_at() -> str:
    return "journal_last_attempt_at"


def _state_key_last_successful_run_at() -> str:
    return "journal_last_successful_run_at"


def _state_key_records_seen() -> str:
    return "journal_records_seen"


def _state_key_deduplicated() -> str:
    return "journal_deduplicated"


def _state_key_last_error() -> str:
    return "journal_last_error"


def _state_key_last_error_at() -> str:
    return "journal_last_error_at"


def _get_cursor() -> str | None:
    return siem.get_collector_setting(_state_key_last_cursor())


def _get_last_event_ts() -> str | None:
    return siem.get_collector_setting(_state_key_last_event_ts())


def _get_attempts() -> int:
    value = siem.get_collector_setting(_state_key_attempts())
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _get_successful_runs() -> int:
    value = siem.get_collector_setting(_state_key_successful_runs())
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _get_failed_runs() -> int:
    value = siem.get_collector_setting(_state_key_failed_runs())
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _get_last_attempt_at() -> str | None:
    return siem.get_collector_setting(_state_key_last_attempt_at())


def _get_last_successful_run_at() -> str | None:
    return siem.get_collector_setting(_state_key_last_successful_run_at())


def _get_records_seen() -> int | None:
    value = siem.get_collector_setting(_state_key_records_seen())
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _get_deduplicated() -> int | None:
    value = siem.get_collector_setting(_state_key_deduplicated())
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _get_last_error() -> str | None:
    return siem.get_collector_setting(_state_key_last_error())


def _get_last_error_at() -> str | None:
    return siem.get_collector_setting(_state_key_last_error_at())


def _count_journal_events(connection: sqlite3.Connection) -> int:
    """Count stored journal-sourced events on an existing connection.

    Reading on the caller's connection (not a fresh one) avoids opening a
    second connection inside a write transaction, which would otherwise block
    on the write lock and raise ``database is locked``.
    """
    return connection.execute(
        "SELECT COUNT(*) AS n FROM events WHERE source = 'journal'"
    ).fetchone()["n"]


def _set_state(connection: sqlite3.Connection, **values: str | None) -> None:
    """Upsert several collector_state rows inside an open transaction."""
    mapping = {
        _state_key_last_cursor(): values.get("cursor"),
        _state_key_last_event_ts(): values.get("event_ts"),
        _state_key_events_ingested(): values.get("events_ingested"),
        _state_key_last_run_at(): values.get("run_at"),
        _state_key_attempts(): values.get("attempts"),
        _state_key_successful_runs(): values.get("successful_runs"),
        _state_key_failed_runs(): values.get("failed_runs"),
        _state_key_last_attempt_at(): values.get("last_attempt_at"),
        _state_key_last_successful_run_at(): values.get("last_successful_run_at"),
        _state_key_records_seen(): values.get("records_seen"),
        _state_key_deduplicated(): values.get("deduplicated"),
        _state_key_last_error(): values.get("last_error"),
        _state_key_last_error_at(): values.get("last_error_at"),
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
            (key, value),
        )


def _persist_health_state(
    *,
    attempts: int,
    successful_runs: int,
    failed_runs: int,
    last_attempt_at: str,
    records_seen: int,
    deduplicated: int,
    last_error: str | None = None,
    last_error_at: str | None = None,
) -> None:
    """Persist health/observability counters on their own connection.

    Used by the early-return failure paths of :func:`collect_once` which exit
    before the main checkpoint transaction opens. Wraps the upsert in a
    transaction so the counters are committed atomically.
    """
    siem.initialize_database()
    with siem._connection() as connection:
        _set_state(
            connection,
            attempts=str(attempts),
            successful_runs=str(successful_runs),
            failed_runs=str(failed_runs),
            last_attempt_at=last_attempt_at,
            records_seen=str(records_seen),
            deduplicated=str(deduplicated),
            last_error=last_error,
            last_error_at=last_error_at,
        )


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #


@dataclass
class CollectResult:
    """Outcome of a single :func:`collect_once` cycle."""

    records_seen: int = 0
    events_ingested: int = 0
    new_alerts: list[dict] = field(default_factory=list)
    cursor_advanced: bool = False
    fallback_used: bool = False
    errors: list[str] = field(default_factory=list)


def _build_args(config: CollectorConfig, cursor: str | None) -> list[str]:
    """Build the ``journalctl`` argument list for one collection cycle.

    Only query-specific flags are returned (``-t`` filters plus either
    ``--after-cursor`` or ``--since``). ``--no-pager`` and ``--output=json``
    are injected by :func:`run_journalctl`, so they are deliberately *not*
    included here to avoid passing them twice on the command line.

    Incremental reads use ``--after-cursor`` (exclusive). When there is no
    usable cursor (first run, or after the cursor became invalid due to journal
    rotation) we fall back to ``--since`` over the recent lookback window.

    ``--since`` is given as ``@<epoch>`` (Unix seconds). ``journalctl`` accepts
    several human-readable formats but is strict about the ISO-8601 ``T`` form
    with a non-colonized offset, so the epoch form is used for portability
    across systemd versions (Fedora 44 / systemd 259).
    """
    args = []
    for identifier in config.identifiers:
        args += ["-t", identifier]

    if cursor:
        args += ["--after-cursor", cursor]
    else:
        since = _epoch_since(datetime.now(timezone.utc), config.lookback_minutes)
        args += ["--since", since]
    return args


def _epoch_since(now: datetime, minutes: float) -> str:
    """Return ``@<epoch>`` for ``now - minutes`` (journalctl --since form)."""
    target = now - timedelta(minutes=minutes)
    return f"@{int(target.timestamp())}"


def _epoch_since_iso(iso: str, rewind_seconds: int) -> str:
    """Return ``@<epoch>`` for ``iso - rewind_seconds`` (or now on parse error)."""
    try:
        dt = datetime.fromisoformat(iso)
    except (TypeError, ValueError):
        dt = datetime.now(timezone.utc)
    return f"@{int((dt - timedelta(seconds=rewind_seconds)).timestamp())}"


def _read_existing_keys(
    connection: sqlite3.Connection, since_iso: str
) -> set[tuple[str, str, str]]:
    """Return a set of ``(timestamp, host, raw_message)`` keys already stored.

    Used to suppress duplicates when a ``--since`` fallback re-reads records
    that were already ingested before a cursor became invalid.
    """
    rows = connection.execute(
        """
        SELECT timestamp, host, raw_message
        FROM events
        WHERE timestamp >= ?
        """,
        (since_iso,),
    ).fetchall()
    return {(row["timestamp"], row["host"], row["raw_message"]) for row in rows}


def collect_once(config: CollectorConfig | None = None) -> CollectResult:
    """Run a single collection cycle and return a summary.

    The cycle: read the persisted cursor, ask ``journalctl`` for new records,
    parse them, de-duplicate against already-stored recent events, ingest the
    remainder through :func:`siem.ingest_events`, and persist the advanced
    cursor atomically with the inserts.

    Health/observability counters (``attempts``, ``successful_runs``,
    ``failed_runs``, ``last_attempt_at``, ``last_successful_run_at``,
    ``records_seen``, ``deduplicated``, ``last_error``, ``last_error_at``) are
    persisted in the same transaction as the checkpoint so a crash never
    advances one without the other. A cycle that completes without errors is a
    successful run even when it ingests zero events (idle); only a cycle that
    records an error counts as a failed run. ``last_successful_run_at`` is
    therefore the honest signal for distinguishing a live-but-idle collector
    from a failed or stale one.
    """
    config = config or get_config()
    result = CollectResult()
    siem.initialize_database()

    cursor = _get_cursor()
    last_event_ts = _get_last_event_ts()

    now = _now_iso()
    attempts = _get_attempts() + 1
    successful_runs = _get_successful_runs() + 1
    failed_runs = _get_failed_runs()
    last_attempt_at = now

    cursor_deduped = 0
    inserted_events: list[dict] = []

    try:
        records = run_journalctl(_build_args(config, cursor), command=config.command)
    except JournalctlError as exc:
        # Cursor likely invalid (journal rotated/vacuumed): fall back to the
        # lookback window anchored on the last ingested event time.
        if cursor and "Failed to seek" in str(exc):
            result.fallback_used = True
            clock_base = last_event_ts or _now_iso()
            try:
                records = run_journalctl(
                    _build_fallback_args(config, clock_base), command=config.command
                )
            except JournalctlError as exc2:
                result.errors.append(str(exc2))
                _persist_health_state(
                    attempts=attempts,
                    successful_runs=successful_runs - 1,
                    failed_runs=failed_runs + 1,
                    last_attempt_at=last_attempt_at,
                    records_seen=result.records_seen,
                    deduplicated=0,
                    last_error=result.errors[0],
                    last_error_at=now,
                )
                return result
            # Advance past the invalid cursor by forgetting it.
            cursor = None
        else:
            result.errors.append(str(exc))
            _persist_health_state(
                attempts=attempts,
                successful_runs=successful_runs - 1,
                failed_runs=failed_runs + 1,
                last_attempt_at=last_attempt_at,
                records_seen=result.records_seen,
                deduplicated=0,
                last_error=result.errors[0],
                last_error_at=now,
            )
            return result

    result.records_seen = len(records)

    events: list[dict] = []
    seen_cursors: set[str] = set()
    last_cursor: str | None = None
    for record in records:
        cursor_value = record.get("__CURSOR")
        # Within-batch de-duplication by journal cursor.
        if cursor_value and cursor_value in seen_cursors:
            cursor_deduped += 1
            continue
        if cursor_value:
            seen_cursors.add(cursor_value)
            last_cursor = cursor_value

        event = parse_journal_record(record)
        if event is None:
            continue
        events.append(event)
        # Respect the per-cycle cap. The cursor still advances to the last
        # record *seen* so unprocessed entries are picked up next cycle
        # (no loss, just latency).
        if len(events) >= config.max_records:
            break

    # Nothing recognizable happened; still advance the cursor if we saw any
    # records, so unrecognized entries are not re-processed forever.
    if not events and last_cursor:
        deduplicated = cursor_deduped
        with siem._connection() as connection:
            _set_state(
                connection,
                cursor=last_cursor,
                event_ts=last_event_ts,
                events_ingested=str(_count_journal_events(connection)),
                run_at=_now_iso(),
                attempts=str(attempts),
                successful_runs=str(successful_runs),
                failed_runs=str(failed_runs),
                last_attempt_at=last_attempt_at,
                last_successful_run_at=_now_iso(),
                records_seen=str(result.records_seen),
                deduplicated=str(deduplicated),
            )
        result.cursor_advanced = True
        result.events_ingested = 0
        return result

    if not events:
        # Truly nothing new, but the collector still completed a poll cycle.
        # Record ``last_run_at`` even on an idle journal so the status
        # endpoint reflects a live, continuously-polling collector instead of
        # a frozen checkpoint. The cursor and last_event_ts are left
        # unchanged: with no new records there is nothing to advance past.
        deduplicated = cursor_deduped
        with siem._connection() as connection:
            _set_state(
                connection,
                cursor=cursor,
                event_ts=last_event_ts,
                events_ingested=str(_count_journal_events(connection)),
                run_at=_now_iso(),
                attempts=str(attempts),
                successful_runs=str(successful_runs),
                failed_runs=str(failed_runs),
                last_attempt_at=last_attempt_at,
                last_successful_run_at=_now_iso(),
                records_seen=str(result.records_seen),
                deduplicated=str(deduplicated),
            )
        return result

    # Ingest + detect, then advance the checkpoint in the same transaction so
    # a crash cannot leave events inserted but the cursor un-advanced.
    with siem._connection() as connection:
        # De-duplicate against recently-stored events (handles --since
        # fallback overlap).
        dedup_since = min(
            (e["timestamp"] for e in events),
            default=_now_iso(),
        )
        existing_keys = _read_existing_keys(connection, dedup_since)
        new_events = [
            e for e in events
            if (e["timestamp"], e["host"], e["raw_message"]) not in existing_keys
        ]

        inserted_events, new_alerts, _new_incidents = siem._store_events_and_detect(
            new_events, connection
        )

        # Deduplicated = parsed candidates not stored (cursor dupes + content
        # overlap + DB source_record_id uniqueness).
        deduplicated = cursor_deduped + len(events) - len(inserted_events)

        # Advance the checkpoint in the same transaction as the inserts so a
        # crash cannot leave events stored but the cursor un-advanced.
        advanced_cursor = last_cursor or cursor
        advanced_ts = inserted_events[-1]["timestamp"] if inserted_events else last_event_ts
        _set_state(
            connection,
            cursor=advanced_cursor or cursor,
            event_ts=advanced_ts or last_event_ts,
            events_ingested=str(_count_journal_events(connection)),
            run_at=_now_iso(),
            attempts=str(attempts),
            successful_runs=str(successful_runs),
            failed_runs=str(failed_runs),
            last_attempt_at=last_attempt_at,
            last_successful_run_at=_now_iso(),
            records_seen=str(result.records_seen),
            deduplicated=str(deduplicated),
        )

    result.events_ingested = len(inserted_events)
    result.new_alerts = new_alerts
    result.cursor_advanced = advanced_cursor is not None
    return result


def _build_fallback_args(config: CollectorConfig, since_iso: str) -> list[str]:
    """Build ``journalctl`` args for the ``--since`` fallback path.

    ``since_iso`` is a normalized ISO timestamp (from the last ingested event);
    it is converted to the ``@<epoch>`` form journalctl reliably parses. Only
    query filters are returned here: ``--no-pager`` and ``--output=json`` are
    injected by :func:`run_journalctl`.
    """
    args = []
    for identifier in config.identifiers:
        args += ["-t", identifier]
    args += ["--since", _epoch_since_iso(since_iso, FALLBACK_REWIND_SECONDS)]
    return args


def _now_iso() -> str:
    """Current UTC time as a normalized ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --------------------------------------------------------------------------- #
# Continuous loop + CLI
# --------------------------------------------------------------------------- #


def run_loop(config: CollectorConfig | None = None) -> None:
    """Run :func:`collect_once` on an interval until interrupted.

    The loop is a plain ``while`` + ``sleep`` so it does not pull in a
    scheduling dependency. ``SIGTERM``/``SIGINT`` stop it cleanly, which makes
    it straightforward to run under a systemd service.
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
            except Exception as exc:
                # collect_once() already handles JournalctlError internally
                # (it populates result.errors and returns normally). This outer
                # guard catches everything else -- e.g. a transient SQLite
                # "database is locked" from the concurrent API, or an
                # unexpected bug -- so a single bad cycle never kills the
                # continuously-running collector. The traceback is logged so
                # the failure is diagnosable; systemd will still restart the
                # service on a hard crash, but transient faults self-heal.
                logger.exception("collection cycle failed: %s", exc)
            time.sleep(config.poll_interval)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def status() -> dict:
    """Return the current collector checkpoint/state for reporting.

    In addition to the checkpoint fields, the response carries health and
    observability counters so the frontend can distinguish an idle collector
    (successful run, zero ingested) from a failed or stale one. ``last_error``
    is the most recent safe error summary; it is never a credential, token, or
    raw log message.
    """
    siem.initialize_database()
    ingested_value = siem.get_collector_setting(_state_key_events_ingested(), "0")
    try:
        events_ingested = int(ingested_value)
    except (TypeError, ValueError):
        events_ingested = 0
    return {
        "enabled": get_config().enabled,
        "last_cursor": siem.get_collector_setting(_state_key_last_cursor()),
        "last_event_ts": siem.get_collector_setting(_state_key_last_event_ts()),
        "events_ingested": events_ingested,
        "last_run_at": siem.get_collector_setting(_state_key_last_run_at()),
        "attempts": _get_attempts(),
        "successful_runs": _get_successful_runs(),
        "failed_runs": _get_failed_runs(),
        "last_attempt_at": siem.get_collector_setting(_state_key_last_attempt_at()),
        "last_successful_run_at": siem.get_collector_setting(
            _state_key_last_successful_run_at()
        ),
        "records_seen": _get_records_seen(),
        "deduplicated": _get_deduplicated(),
        "last_error": _get_last_error(),
        "last_error_at": siem.get_collector_setting(_state_key_last_error_at()),
    }


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
                "Journal collection is disabled. Set GREYWATCH_JOURNAL_ENABLED=1 "
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
    raise SystemExit(main())
