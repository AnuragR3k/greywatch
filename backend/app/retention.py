"""Greywatch event-retention maintenance CLI.

This module provides an operator-controlled mechanism for safely pruning old
events from the Greywatch SQLite database.  It is a **separate process** from
the API server so that destructive cleanup is never coupled to ordinary
request handling.

Usage
-----

::

    # Preview what *would* be deleted (default — never modifies the DB)
    python -m backend.app.retention --dry-run

    # Actually delete eligible events in bounded batches
    python -m backend.app.retention --execute

    # Custom batch size (default 1000)
    python -m backend.app.retention --execute --batch-size 500

    # Compact the database after deletion (requires downtime — see --vacuum)
    python -m backend.app.retention --vacuum

Design
------

Retention is configured with the ``GREYWATCH_EVENT_RETENTION_DAYS``
environment variable (see ``backend/.env.example``).  When unset, retention
is **disabled** and nothing is ever deleted — this is the safe default.

Only events strictly older than ``now - retention_days`` are candidates.
Before any deletion, the module computes a *protected* set of event IDs:

* Events referenced by ``incident_events`` (any incident, resolved or not).
* Events that match the evidence query of any **open** alert — the same
  per-``rule_id`` queries used by :func:`backend.app.siem.get_alert_detail`,
  so the protected set can never drift from what an analyst would see.

Events in the protected set are never deleted.  If an event's relationship
to existing forensic evidence cannot be established safely, it is retained.

Deletion runs inside explicit transactions in bounded batches, and foreign
keys are enabled (``PRAGMA foreign_keys = ON``) as a safety net: a bug in
the protection logic surfaces as a hard error rather than an orphaned
``incident_events`` row.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .siem import (
    DEFAULT_RETENTION_BATCH_SIZE,
    RETENTION_BATCH_SIZE_ENV,
    RETENTION_DAYS_ENV,
    RetentionSummary,
    get_retention_config,
    prune_events,
    vacuum_database,
)

# Re-export for tests / programmatic callers.
__all__ = [
    "RETENTION_DAYS_ENV",
    "RETENTION_BATCH_SIZE_ENV",
    "RetentionSummary",
    "get_retention_config",
    "prune_events",
    "vacuum_database",
    "format_summary",
    "main",
]


def _format_config_line(config) -> str:
    """Return a one-line human-readable description of the retention config."""
    if config.retention_days is None:
        return (
            f"GREYWATCH_EVENT_RETENTION_DAYS={os.environ.get(RETENTION_DAYS_ENV, '(unset)')}"
            " — retention DISABLED (no events will be deleted)"
        )
    return (
        f"GREYWATCH_EVENT_RETENTION_DAYS={config.retention_days}"
        f" — events older than {config.retention_days} day(s) are eligible"
    )


def format_summary(summary: RetentionSummary) -> str:
    """Render a human-readable retention summary for the terminal."""
    lines: list[str] = []

    config = get_retention_config()
    lines.append(f"Configuration: {_format_config_line(config)}")
    lines.append(f"Mode: {'DRY RUN (no modifications)' if summary.dry_run else 'EXECUTE'}")
    lines.append("")

    if summary.disabled:
        lines.append("Retention is disabled — nothing to do.")
        lines.append("Set GREYWATCH_EVENT_RETENTION_DAYS to a positive integer to enable.")
        return "\n".join(lines)

    lines.append(f"  Retention period:  {summary.retention_days} day(s)")
    lines.append(f"  Eligible events:   {summary.eligible_events:,}")
    lines.append(f"  Protected events:  {summary.protected_events:,}")
    lines.append(f"  Deletable events:  {summary.deletable_events:,}")

    if summary.deleted_events:
        lines.append(f"  Deleted events:    {summary.deleted_events:,}")
        lines.append(f"  Deletion batches:  {summary.batches_run}")
    elif not summary.dry_run:
        lines.append("  Deleted events:    0 (nothing to delete)")

    if summary.fk_violations:
        lines.append(f"  FK violations:     {summary.fk_violations}  *** INVESTIGATE ***")
    else:
        lines.append("  FK integrity:      OK")

    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m backend.app.retention",
        description="Greywatch event-retention maintenance tool.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Preview eligible/protected/deletable counts without modifying "
        "the database (default).",
    )
    mode.add_argument(
        "--execute",
        action="store_true",
        help="Delete eligible events. Requires GREYWATCH_EVENT_RETENTION_DAYS "
        "to be set to a positive integer.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=None,
        help=(
            f"Maximum events to delete per transaction. Overrides the "
            f"{RETENTION_BATCH_SIZE_ENV} env var; defaults to "
            f"{DEFAULT_RETENTION_BATCH_SIZE} when unset."
        ),
    )
    parser.add_argument(
        "--vacuum",
        action="store_true",
        help="Run VACUUM to compact the database. Requires the service to be "
        "STOPPED first (exclusive lock).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Defaults to **dry-run**; the operator must pass ``--execute`` to delete
    anything, and ``GREYWATCH_EVENT_RETENTION_DAYS`` must be set to a positive
    integer.  ``--vacuum`` is an independent maintenance operation that
    requires downtime.
    """
    args = _build_parser().parse_args(argv)

    if args.vacuum:
        print("VACUUM requires the Greywatch service to be STOPPED.")
        print("  sudo systemctl stop greywatch-api")
        confirm = input("Proceed? [y/N] ")
        if confirm.strip().lower() not in ("y", "yes"):
            print("Aborted.", file=sys.stderr)
            return 2
        try:
            result = vacuum_database()
        except FileNotFoundError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        print(
            f"VACUUM complete: {result['rebuilt_db']}\n"
            f"  Before: {result['size_before']:,} bytes\n"
            f"  After:  {result['size_after']:,} bytes\n"
            f"  Freed:  {result['freed_bytes']:,} bytes"
        )
        return 0

    dry_run = not args.execute
    try:
        summary = prune_events(dry_run=dry_run, batch_size=args.batch_size)
    except ValueError as exc:
        # Explicit --batch-size validation failed (e.g. 0 or negative forwarded
        # by gw_retention.sh). Surface a clear error and exit non-zero rather
        # than letting an invalid value reach the deletion loop.
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(format_summary(summary))

    if summary.disabled:
        return 0

    if args.execute and summary.fk_violations:
        print(
            "ERROR: foreign-key violations detected after deletion — "
            "investigate immediately.",
            file=sys.stderr,
        )
        return 1

    if args.execute and not summary.deleted_events:
        print("\nNothing to delete (no eligible unprotected events).")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
