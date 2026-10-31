"""Schema migration ledger foundation for Greywatch.

This module owns the ``schema_migrations`` ledger that records which versioned
schema migrations have been applied to a Greywatch database.

It deliberately contains *only* ledger-table creation -- there is no migration
runner, no version files, and nothing here is wired into the application's
normal initialization path (``siem.initialize_database``). Future
migration-runner code is expected to:

1. call :func:`create_schema_migrations_table` to ensure the ledger exists, and
2. read/write rows here to record which numbered migrations have run.

The ledger is created idempotently with ``CREATE TABLE IF NOT EXISTS``; SQLite
never rebuilds an existing table, so calling this against a database that
already holds Greywatch's normal tables and data is always safe and
non-destructive. This function does **not** enable global foreign-key
enforcement (``PRAGMA foreign_keys``); that remains the caller's choice -- see
:func:`backend.app.siem._safe_retention_connection` for the retention path
that does enable it locally.
"""

from __future__ import annotations

import sqlite3

#: Name of the ledger table that records applied schema migrations.
SCHEMA_MIGRATIONS_TABLE = "schema_migrations"


def create_schema_migrations_table(connection: sqlite3.Connection) -> None:
    """Create the ``schema_migrations`` ledger if it does not already exist.

    Idempotent: repeated calls are no-ops once the table is present, so it is
    safe to run against a fresh database or one that already has the ledger.

    Only the ledger table is ever created here. Pre-existing application tables
    (``events``, ``alerts``, ``incidents``, ``incident_events``,
    ``collector_state``) and their rows are never dropped, rebuilt, or read --
    the ``IF NOT EXISTS`` guard ensures existing tables are left untouched.

    :param connection: an open SQLite connection (any journal mode / FK setting).
        The caller controls transaction boundaries and PRAGMAs; this function
        executes only the single DDL statement and commits nothing -- the
        caller is expected to commit (or roll back) afterwards.
    """
    connection.execute(
        f"""
        CREATE TABLE IF NOT EXISTS {SCHEMA_MIGRATIONS_TABLE} (
            version    INTEGER PRIMARY KEY,
            name       TEXT    NOT NULL,
            applied_at TEXT    NOT NULL
        )
        """
    )
