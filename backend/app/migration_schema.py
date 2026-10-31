"""Read-only structural schema descriptors and comparison for Greywatch.

This module describes the *expected* current schema of Greywatch's five
application tables (``events``, ``alerts``, ``incidents``,
``incident_events``, ``collector_state``), inspects a live SQLite connection
through PRAGMA introspection, and reports structural differences.

It performs **no writes**: no ``CREATE``/``ALTER``/``DROP``, no PRAGMA writes,
and no call to ``create_schema_migrations_table()``. Database lifecycle
classification lives in :mod:`backend.app.migration_state`.

Schema comparison is structural (columns, indexes, foreign keys, constraints,
table options) via ``PRAGMA table_info`` / ``index_list`` / ``index_xinfo`` /
``foreign_key_list``. Raw ``CREATE TABLE`` SQL strings are never compared as
whole strings, and declared column types are matched by SQLite *type affinity*
rather than exact strings, so dialect-equivalent declarations are treated as
compatible.

.. note::

   A few SQLite table options (``AUTOINCREMENT``, ``WITHOUT ROWID``, ``STRICT``)
   have no dedicated introspection PRAGMA. ``WITHOUT ROWID`` and ``STRICT`` are
   read from ``PRAGMA table_list`` (SQLite >= 3.32); ``AUTOINCREMENT`` is
   detected via a targeted regex on the table's ``sqlite_master.sql`` that
   matches ``PRIMARY KEY ... AUTOINCREMENT`` specifically, avoiding false
   positives from the word in column names, defaults, or string literals.
   Partial-index WHERE predicates are extracted from ``sqlite_master.sql``,
   normalized, and compared -- a missing or unreadable predicate on a partial
   index is fail-closed.
"""

from __future__ import annotations

import re
from collections import OrderedDict
from types import MappingProxyType
import sqlite3
from dataclasses import dataclass, field

from .migration_ledger import SCHEMA_MIGRATIONS_TABLE

__all__ = [
    "APP_TABLES",
    "LEDGER_TABLE",
    "ADDABLE_COLUMNS",
    "ADDABLE_INDEXES",
    "ColumnInfo",
    "IndexInfo",
    "ForeignKeyInfo",
    "TableDescriptor",
    "SchemaDifferences",
    "ExpectedSchema",
    "EXPECTED_SCHEMA",
    "column_affinity",
    "schema_fingerprint",
    "compare_schema",
    "inspect_table",
    "table_exists",
    "table_names",
]

APP_TABLES = ("events", "alerts", "incidents", "incident_events", "collector_state")
LEDGER_TABLE = SCHEMA_MIGRATIONS_TABLE

# Columns/indexes introduced by the legacy migration path
# (``_migrate_events_table`` / ``_migrate_alerts_table``). A database that has
# every *core* column but is missing only these is "legacy ready" (safe to
# migrate forward), not "incompatible".
ADDABLE_COLUMNS: dict[str, frozenset[str]] = {
    "events": frozenset(
        {
            "source",
            "source_record_id",
            "content_hash",
            "dest_ip",
            "src_port",
            "dest_port",
            "proto",
            "signature",
            "signature_id",
            "category",
        }
    ),
    "alerts": frozenset(
        {
            "last_triggered_at",
            "dest_ip",
            "src_port",
            "dest_port",
            "proto",
            "signature",
            "signature_id",
            "category",
        }
    ),
    "incidents": frozenset(),
    "incident_events": frozenset(),
    "collector_state": frozenset(),
}

ADDABLE_INDEXES: dict[str, frozenset[str]] = {
    "events": frozenset({"idx_events_source_record", "idx_events_content_hash"}),
    "alerts": frozenset(),
    "incidents": frozenset(),
    "incident_events": frozenset(),
    "collector_state": frozenset(),
}


def column_affinity(declared_type: str | None) -> str:
    """Return SQLite type affinity for a declared column type.

    Follows SQLite's rules (after stripping any parenthesized length/precision
    argument). Comparing affinity instead of raw type strings lets
    ``INTEGER``/``INT4``/``INT8`` and ``TEXT``/``VARCHAR(64)``/``CHAR`` be
    treated as compatible.
    """
    text = (declared_type or "").strip().upper()
    if "(" in text:
        text = text.split("(", 1)[0].strip()
    if "INT" in text:
        return "INTEGER"
    if "CHAR" in text or "CLOB" in text or "TEXT" in text:
        return "TEXT"
    if text == "" or "BLOB" in text:
        return "BLOB"
    if "REAL" in text or "FLOA" in text or "DOUB" in text:
        return "REAL"
    return "NUMERIC"


@dataclass(slots=True, frozen=True)
class ColumnInfo:
    """A single column as captured by introspection or as expected."""

    name: str
    affinity: str
    notnull: bool
    pk: int  # 1-based position in the primary key, or 0
    default_value: str | None = None


@dataclass(slots=True, frozen=True)
class IndexInfo:
    """A single index as captured by introspection or as expected."""

    name: str
    columns: tuple[str, ...]
    collations: tuple[str, ...]
    descending: tuple[bool, ...]
    unique: bool
    partial: bool
    origin: str  # 'c' user index, 'u' unique, 'pk' autoindex
    where_clause: str | None = None  # normalized WHERE predicate for partial indexes


@dataclass(slots=True, frozen=True)
class ForeignKeyInfo:
    """A single foreign key as captured by introspection or as expected."""

    from_column: str
    to_table: str
    to_column: str
    on_update: str
    on_delete: str
    match: str


@dataclass(slots=True, frozen=True)
class TableOptions:
    """Table-level options detected from ``sqlite_master.sql``."""

    autoincrement: bool
    without_rowid: bool
    strict: bool


@dataclass(slots=True, frozen=True)
class TableDescriptor:
    """Full structural description of one table.

    ``columns``, ``indexes`` and ``foreign_keys`` are immutable tuples; the
    descriptor is frozen so expected-schema definitions cannot be mutated at
    runtime.
    """

    name: str
    columns: tuple[ColumnInfo, ...] = ()
    indexes: tuple[IndexInfo, ...] = ()
    foreign_keys: tuple[ForeignKeyInfo, ...] = ()
    options: TableOptions = field(default_factory=lambda: TableOptions(False, False, False))

    def __post_init__(self) -> None:  # support legacy keyword construction
        object.__setattr__(self, "columns", tuple(self.columns))
        object.__setattr__(self, "indexes", tuple(self.indexes))
        object.__setattr__(self, "foreign_keys", tuple(self.foreign_keys))


_WHERE_UNREADABLE = "__where_clause_unreadable__"
# Sentinel characters unlikely to appear in SQL expressions.
_LIT_SEP = "\x00"


def _normalize_where(where_clause: str | None) -> str | None:
    """Normalize a partial-index WHERE expression for deterministic comparison.

    Lowercases SQL keywords and identifiers, strips identifier quoting
    (``"col"`` -> ``col``, ``[col]`` -> ``col``), and collapses internal
    whitespace.  **String literals (single-quoted) are preserved verbatim**, so
    ``name = 'Admin'`` and ``name = 'admin'`` are *not* treated as equivalent.

    Escaped single quotes (``''`` inside a literal) are preserved.  Does **not**
    reorder conjuncts or otherwise parse SQL -- semantically different predicates
    remain distinct (e.g. ``a IS NOT NULL`` vs ``b IS NOT NULL``).
    """
    if where_clause is None:
        return None
    text = where_clause.strip()

    # Step 1: Protect single-quoted string literals (with '' escape).
    literals: list[str] = []

    def _save_literal(m: re.Match[str]) -> str:
        literals.append(m.group(0))
        return f"{_LIT_SEP}lit{len(literals) - 1}{_LIT_SEP}"

    text = re.sub(r"'((?:[^']|'')*)'", _save_literal, text)

    # Step 2: Lowercase the non-literal portion (placeholders are already
    # lowercase so they are unaffected).
    text = text.lower()

    # Step 3: Strip identifier quoting: "col" -> col, [col] -> col.
    text = re.sub(r'"([^"]*)"', r"\1", text)
    text = re.sub(r"\[([^\]]*)\]", r"\1", text)

    # Step 4: Collapse whitespace.
    text = re.sub(r"\s+", " ", text).strip()

    # Step 5: Restore original (case-preserved) string literals.
    for i, lit in enumerate(literals):
        text = text.replace(f"{_LIT_SEP}lit{i}{_LIT_SEP}", lit)
    return text



def _col(name: str, affinity: str, notnull: bool, pk: int = 0, default: str | None = None) -> ColumnInfo:
    return ColumnInfo(name=name, affinity=affinity, notnull=notnull, pk=pk, default_value=default)


def _int(name: str, notnull: bool = True, pk: int = 0, default: str | None = None) -> ColumnInfo:
    return _col(name, "INTEGER", notnull, pk, default)


def _txt(name: str, notnull: bool = True, default: str | None = None) -> ColumnInfo:
    return _col(name, "TEXT", notnull, pk=0, default=default)


def _idx(
    name: str,
    columns: tuple[str, ...],
    collations: tuple[str, ...] | None = None,
    descending: tuple[bool, ...] | None = None,
    unique: bool = False,
    partial: bool = False,
    where: str | None = None,
    origin: str = "c",
) -> IndexInfo:
    n = len(columns)
    coll = collations if collations is not None else ("BINARY",) * n
    desc = descending if descending is not None else (False,) * n
    return IndexInfo(
        name=name,
        columns=columns,
        collations=coll,
        descending=desc,
        unique=unique,
        partial=partial,
        origin=origin,
        where_clause=_normalize_where(where) if where else None,
    )


def _fk(
    from_column: str,
    to_table: str,
    to_column: str,
    on_update: str = "NO ACTION",
    on_delete: str = "NO ACTION",
    match: str = "NONE",
) -> ForeignKeyInfo:
    return ForeignKeyInfo(
        from_column=from_column,
        to_table=to_table,
        to_column=to_column,
        on_update=on_update,
        on_delete=on_delete,
        match=match,
    )


def _opts(autoinc: bool = False, without_rowid: bool = False, strict: bool = False) -> TableOptions:
    return TableOptions(autoincrement=autoinc, without_rowid=without_rowid, strict=strict)


def _build_expected_schema() -> "OrderedDict[str, TableDescriptor]":
    """Build the expected *current* schema descriptors.

    This mirrors ``siem.initialize_database()`` plus the columns/indexes added by
    ``_migrate_alerts_table`` / ``_migrate_events_table`` (i.e. the schema a
    freshly-initialized database has today).
    """
    events = TableDescriptor(
        name="events",
        columns=(
            _int("id", pk=1),
            _txt("timestamp"),
            _txt("host"),
            _txt("event_type"),
            _txt("username", notnull=False),
            _txt("source_ip", notnull=False),
            _txt("severity"),
            _txt("raw_message"),
            _txt("source", notnull=False),
            _txt("source_record_id", notnull=False),
            _txt("content_hash", notnull=False),
            _txt("dest_ip", notnull=False),
            _int("src_port", notnull=False),
            _int("dest_port", notnull=False),
            _txt("proto", notnull=False),
            _txt("signature", notnull=False),
            _int("signature_id", notnull=False),
            _txt("category", notnull=False),
        ),
        indexes=(
            _idx("idx_events_ip_time", ("source_ip", "timestamp")),
            _idx(
                "idx_events_source_record",
                ("source", "source_record_id"),
                unique=True,
                partial=True,
                where="source_record_id IS NOT NULL",
                origin="u",
            ),
            _idx(
                "idx_events_content_hash",
                ("content_hash",),
                partial=True,
                where="content_hash IS NOT NULL",
            ),
        ),
        options=_opts(autoinc=True),
    )

    alerts = TableDescriptor(
        name="alerts",
        columns=(
            _int("id", pk=1),
            _txt("created_at"),
            _txt("rule_id"),
            _txt("title"),
            _txt("severity"),
            _txt("source_ip"),
            _txt("description"),
            _int("event_count"),
            _txt("status", default="'open'"),
            _txt("closed_at", notnull=False),
            _txt("last_triggered_at", notnull=False),
            _txt("dest_ip", notnull=False),
            _int("src_port", notnull=False),
            _int("dest_port", notnull=False),
            _txt("proto", notnull=False),
            _txt("signature", notnull=False),
            _int("signature_id", notnull=False),
            _txt("category", notnull=False),
        ),
        indexes=(_idx("idx_alerts_status", ("status", "created_at")),),
        options=_opts(autoinc=True),
    )

    incidents = TableDescriptor(
        name="incidents",
        columns=(
            _int("id", pk=1),
            _txt("created_at"),
            _txt("updated_at"),
            _txt("rule_id"),
            _txt("title"),
            _txt("severity"),
            _txt("status", default="'open'"),
            _txt("source_ip"),
            _txt("description"),
            _int("event_count"),
            _txt("first_seen_at"),
            _txt("last_seen_at"),
            _txt("closed_at", notnull=False),
        ),
        indexes=(
            _idx("idx_incidents_status", ("status", "created_at")),
            _idx("idx_incidents_rule_ip", ("rule_id", "source_ip", "status")),
        ),
        options=_opts(autoinc=True),
    )

    incident_events = TableDescriptor(
        name="incident_events",
        columns=(
            _int("incident_id", pk=1),
            _int("event_id", pk=2),
            _txt("added_at"),
        ),
        indexes=(
            _idx("idx_incident_events_incident", ("incident_id",)),
            _idx("idx_incident_events_event", ("event_id",)),
        ),
        foreign_keys=(
            _fk("incident_id", "incidents", "id"),
            _fk("event_id", "events", "id"),
        ),
        options=_opts(),
    )

    collector_state = TableDescriptor(
        name="collector_state",
        columns=(
            _col("key", "TEXT", notnull=False, pk=1),
            _txt("value", notnull=False),
        ),
        options=_opts(),
    )

    return OrderedDict(
        [
            ("events", events),
            ("alerts", alerts),
            ("incidents", incidents),
            ("incident_events", incident_events),
            ("collector_state", collector_state),
        ]
    )


class ExpectedSchema:
    """Container for the expected current schema descriptors.

    The descriptor mapping is exposed read-only via :attr:`tables` (a
    :class:`types.MappingProxyType`) so callers cannot mutate the expected
    schema. ``__iter__``/``__contains__``/``__getitem__`` operate on it.
    """

    __slots__ = ("_tables",)

    def __init__(self, tables: "dict[str, TableDescriptor] | None" = None) -> None:
        built = tables if tables is not None else _build_expected_schema()
        # Copy into an OrderedDict then freeze behind a mapping proxy so the
        # internal dicts cannot be replaced from the outside.
        frozen: dict[str, TableDescriptor] = {}
        for name, desc in built.items():
            frozen[name] = desc
        object.__setattr__(self, "_tables", MappingProxyType(frozen))

    @property
    def tables(self) -> "MappingProxyType[str, TableDescriptor]":
        return self._tables  # type: ignore[return-value]

    def __iter__(self):
        return iter(self._tables.values())

    def __contains__(self, name: str) -> bool:
        return name in self._tables

    def __getitem__(self, name: str) -> TableDescriptor:
        return self._tables[name]


#: Singleton description of the expected current schema (immutable).
EXPECTED_SCHEMA = ExpectedSchema()


@dataclass(slots=True)
class SchemaDifferences:
    """Structural differences between a database and the expected schema.

    Missing *and* incompatible items are tracked separately per category so
    callers can distinguish "absent" from "present but wrong".
    """

    missing_tables: list[str] = field(default_factory=list)
    missing_columns: dict[str, list[str]] = field(default_factory=dict)
    incompatible_columns: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    missing_indexes: dict[str, list[str]] = field(default_factory=dict)
    incompatible_indexes: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    missing_foreign_keys: dict[str, list[tuple[str, str, str]]] = field(default_factory=dict)
    incompatible_foreign_keys: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    incompatible_table_options: dict[str, list[str]] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        """True when nothing is missing or incompatible."""
        return not (
            self.missing_tables
            or self.missing_columns
            or self.incompatible_columns
            or self.missing_indexes
            or self.incompatible_indexes
            or self.missing_foreign_keys
            or self.incompatible_foreign_keys
            or self.incompatible_table_options
        )


# --------------------------------------------------------------------------- #
# Introspection helpers (read-only PRAGMAs / sqlite_master SELECTs)
# --------------------------------------------------------------------------- #


def _quote_ident(connection: sqlite3.Connection, identifier: str) -> str:
    """Quote a SQLite identifier using this connection's quoting rules.

    Uses the SQLite-approved ``'["']``-delimited form so that identifiers
    containing spaces, hyphens, ``?``, ``#``, ``%``, or reserved words are
    safe against injection in dynamically-built PRAGMA calls.
    """
    # Connection.execute can quote via the quote() SQL function; fall back to a
    # conservative doubled-quote form validated by quoting.
    try:
        quoted = _text(connection.execute("SELECT quote(?)", (identifier,)).fetchone()[0])
    except sqlite3.Error:
        quoted = identifier.replace('"', '""')
        quoted = f'"{quoted}"'
    if quoted is None:
        quoted = identifier.replace('"', '""')
        quoted = f'"{quoted}"'
    if quoted.startswith("'") and quoted.endswith("'"):
        # quote() produced a string literal; re-emit as an identifier literal.
        inner = quoted[1:-1].replace('"', '""')
        return f'"{inner}"'
    return quoted


def table_names(connection: sqlite3.Connection) -> set[str]:
    """Return the set of user table names (excluding SQLite internals)."""
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {_text(row[0]) for row in rows}


def table_exists(connection: sqlite3.Connection, name: str) -> bool:
    """Return True if a user table (not a SQLite-internal table) exists."""
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? AND name NOT LIKE 'sqlite_%'",
        (name,),
    ).fetchone()
    return row is not None


def _column_rows(connection: sqlite3.Connection, table: str) -> list[tuple]:
    """Return ``PRAGMA table_info`` rows for ``table`` as plain tuples.

    table_info columns: (cid, name, type, notnull, dflt_value, pk).
    """
    quoted = _quote_ident(connection, table)
    return connection.execute(f"PRAGMA table_info({quoted})").fetchall()


def _index_list_rows(connection: sqlite3.Connection, table: str) -> list[tuple]:
    """Return ``PRAGMA index_list`` rows for ``table`` as plain tuples.

    index_list columns: (seq, name, unique, origin, partial, ...).
    """
    quoted = _quote_ident(connection, table)
    return connection.execute(f"PRAGMA index_list({quoted})").fetchall()


def _index_xinfo_rows(connection: sqlite3.Connection, index_name: str) -> list[tuple]:
    """Return ``PRAGMA index_xinfo`` rows for ``index_name`` as plain tuples.

    index_xinfo columns: (seqno, cid, name, desc, coll, key).
    """
    quoted = _quote_ident(connection, index_name)
    return connection.execute(f"PRAGMA index_xinfo({quoted})").fetchall()


def _foreign_key_rows(connection: sqlite3.Connection, table: str) -> list[tuple]:
    """Return ``PRAGMA foreign_key_list`` rows for ``table`` as plain tuples.

    foreign_key_list columns: (id, seq, table, from, to, on_update,
    on_delete, match, ...).
    """
    quoted = _quote_ident(connection, table)
    return connection.execute(f"PRAGMA foreign_key_list({quoted})").fetchall()


def _table_sql(connection: sqlite3.Connection, table: str) -> str:
    """Return the ``CREATE TABLE`` statement for ``table`` (may be empty)."""
    row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
        (_text(table) if isinstance(table, str) else table,),
    ).fetchone()
    sql = _text(row[0]) if row else ""
    return sql if isinstance(sql, str) else ""


_AUTOINCREMENT_RE = re.compile(r"PRIMARY\s+KEY\s+AUTOINCREMENT\b", re.IGNORECASE)

def _extract_index_where(connection: sqlite3.Connection, index_name: str) -> str | None:
    """Extract the WHERE predicate from a partial index's ``sqlite_master.sql``.

    Returns ``None`` when the index is not partial or its SQL is unavailable.
    Returns :data:`_WHERE_UNREADABLE` (handled by the caller) when the index
    *is* partial but the predicate cannot be read — a fail-closed signal so a
    missing predicate is never silently treated as "no predicate".
    """
    quoted = _quote_ident(connection, index_name)
    row = connection.execute(
        f"SELECT sql FROM sqlite_master WHERE type='index' AND name={quoted}"
    ).fetchone()
    if row is None:
        return None
    sql = _text(row[0])
    if not sql:
        return None
    # ``) WHERE expr`` marks the start of the partial-index predicate.
    match = re.search(r"\)\s*WHERE\s+(.+)$", sql, re.IGNORECASE | re.DOTALL)
    if match:
        return _normalize_where(match.group(1).strip())
    return None


def _table_options(connection: sqlite3.Connection, table: str) -> TableOptions:
    """Detect AUTOINCREMENT / WITHOUT ROWID / STRICT.

    * ``AUTOINCREMENT`` is detected via a targeted regex on the table's
      ``sqlite_master.sql`` that matches ``PRIMARY KEY … AUTOINCREMENT``
      specifically, avoiding false positives from the word appearing in column
      names, defaults, comments, foreign keys, or string literals.
    * ``WITHOUT ROWID`` and ``STRICT`` are read from ``PRAGMA table_list``
      (``wr`` / ``strict`` columns) where supported (SQLite ≥ 3.32).  Falls
      back to a conservative SQL scan on older engines.
    """
    sql = _table_sql(connection, table)
    autoinc = bool(_AUTOINCREMENT_RE.search(sql)) if sql else False

    strict = False
    without_rowid = False
    try:
        for row in connection.execute("PRAGMA table_list"):
            row_name = _text(row[1])
            row_type = _text(row[2])
            if row_name is not None and row_name.lower() == table.lower() and row_type == "table":
                without_rowid = bool(row[4])  # 'wr' column
                strict = bool(row[5])  # 'strict' column
                break
    except sqlite3.OperationalError:
        # PRAGMA table_list unavailable; fall back to conservative scan.
        lowered = sql.lower() if sql else ""
        without_rowid = "without rowid" in lowered
        strict = "strict" in lowered

    return _opts(autoinc=autoinc, without_rowid=without_rowid, strict=strict)


def _normalize_default(value: object) -> str | None:
    """Normalize a ``dflt_value`` for comparison (None stays None)."""
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    return str(value)


def _text(value: object) -> str | None:
    """Decode a possibly-bytes SQLite text value to ``str`` (None passthrough).

    Makes introspection robust against connections configured with
    ``text_factory = bytes`` / custom row factories without mutating the
    caller's connection.
    """
    if value is None:
        return None
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    return str(value)


def _actual_column_infos(connection: sqlite3.Connection, table: str) -> dict[str, ColumnInfo]:
    result: dict[str, ColumnInfo] = {}
    for row in _column_rows(connection, table):
        # (cid, name, type, notnull, dflt_value, pk)
        name = _text(row[1])
        if name is None:
            continue
        result[name] = ColumnInfo(
            name=name,
            affinity=column_affinity(_text(row[2])),
            notnull=bool(row[3]),
            pk=row[5] if row[5] else 0,
            default_value=_normalize_default(row[4]),
        )
    return result


def _index_where_clause(connection: sqlite3.Connection, idx_name: str, partial: bool) -> str | None:
    """Return the normalized WHERE predicate of a partial index.

    For non-partial indexes returns ``None``.  For partial indexes returns the
    normalized predicate, or :data:`_WHERE_UNREADABLE` if the predicate cannot
    be reliably inspected (fail-closed).
    """
    if not partial:
        return None
    where = _extract_index_where(connection, idx_name)
    if where is None:
        return _WHERE_UNREADABLE
    return where


def _actual_index_infos(connection: sqlite3.Connection, table: str) -> dict[str, IndexInfo]:
    result: dict[str, IndexInfo] = {}
    for idx_row in _index_list_rows(connection, table):
        # (seq, name, unique, origin, partial)
        idx_name = _text(idx_row[1])
        if idx_name is None or idx_name.startswith("sqlite_autoindex_"):
            continue
        unique = bool(idx_row[2])
        origin = _text(idx_row[3]) if len(idx_row) > 3 else "c"
        partial = bool(idx_row[4]) if len(idx_row) > 4 else False
        cols: list[str] = []
        colls: list[str] = []
        descs: list[bool] = []
        for xrow in _index_xinfo_rows(connection, idx_name):
            # (seqno, cid, name, desc, coll, key)
            if len(xrow) > 5 and xrow[5] == 0:
                # not a key column (e.g. implicit rowid coverage entry)
                continue
            col_name = _text(xrow[2])
            if col_name is None:
                continue
            cols.append(col_name)
            descs.append(bool(xrow[3]) if len(xrow) > 3 else False)
            colls.append(_text(xrow[4]) if len(xrow) > 4 else "BINARY")
        result[idx_name] = IndexInfo(
            name=idx_name,
            columns=tuple(cols),
            collations=tuple(colls),
            descending=tuple(descs),
            unique=unique,
            partial=partial,
            origin=origin,
            where_clause=_index_where_clause(connection, idx_name, partial),
        )
    return result


def _actual_foreign_keys(connection: sqlite3.Connection, table: str) -> list[ForeignKeyInfo]:
    fks: list[ForeignKeyInfo] = []
    for row in _foreign_key_rows(connection, table):
        # (id, seq, table, from, to, on_update, on_delete, match)
        from_col = _text(row[3])
        to_table = _text(row[2])
        to_col = _text(row[4])
        on_update = _text(row[5]) if len(row) > 5 else "NO ACTION"
        on_delete = _text(row[6]) if len(row) > 6 else "NO ACTION"
        match = _text(row[7]) if len(row) > 7 else "NONE"
        fks.append(
            ForeignKeyInfo(
                from_column=from_col,
                to_table=to_table,
                to_column=to_col,
                on_update=on_update.upper(),
                on_delete=on_delete.upper(),
                match=match.upper(),
            )
        )
    return fks


def inspect_table(connection: sqlite3.Connection, table: str) -> TableDescriptor:
    """Build a :class:`TableDescriptor` from live introspection of ``table``."""
    return TableDescriptor(
        name=table,
        columns=tuple(_actual_column_infos(connection, table).values()),
        indexes=tuple(_actual_index_infos(connection, table).values()),
        foreign_keys=tuple(_actual_foreign_keys(connection, table)),
        options=_table_options(connection, table),
    )


# --------------------------------------------------------------------------- #
# Comparison
# --------------------------------------------------------------------------- #


def _is_int_rowid_alias(descriptor: TableDescriptor, col: ColumnInfo) -> bool:
    """True if *col* is a single-column ``INTEGER PRIMARY KEY`` rowid alias.

    SQLite implicitly enforces NOT NULL on ``INTEGER PRIMARY KEY`` columns and
    reports their ``notnull`` flag inconsistently, so the explicit NOT NULL
    check is skipped for them only.  Composite-PK columns with INTEGER affinity
    are *not* rowid aliases and are checked normally.
    """
    pk_cols = [c for c in descriptor.columns if c.pk != 0]
    return col.pk != 0 and len(pk_cols) == 1 and col.affinity == "INTEGER"


def compare_schema(
    connection: sqlite3.Connection,
    expected: ExpectedSchema | None = None,
) -> SchemaDifferences:
    """Report structural differences between ``connection`` and the expected schema.

    Compared material: column affinity, primary-key position, NOT NULL
    (all columns except ``INTEGER PRIMARY KEY`` rowid aliases), column default
    value (both missing and unexpected defaults), index column list, index
    column collation, index ASC/DESC ordering, index uniqueness, index partial
    flag, index WHERE predicate, foreign-key target + ON DELETE/UPDATE
    actions + MATCH, and table options (``AUTOINCREMENT`` / ``WITHOUT ROWID`` /
    ``STRICT``).

    NOT NULL is asserted for all columns except ``INTEGER PRIMARY KEY``
    (rowid aliases), whose ``notnull`` flag SQLite reports inconsistently.
    For composite-PK columns (including those with INTEGER affinity) and
    non-PK columns, the expected NOT NULL flag is honoured.
    Identifier case-insensitivity is honoured by matching column/index/foreign-key
    names case-insensitively where SQLite does.

    Column collations on non-indexed columns are **not** compared (``PRAGMA
    table_info`` does not expose them; ``table_xinfo`` would).  Index column
    collations are compared via ``PRAGMA index_xinfo``.

    Only *missing* or *incompatible* items are reported; unexpected extras
    (extra columns/indexes/FKs) are ignored so an extended schema is not
    falsely flagged.
    """
    expected = expected if expected is not None else EXPECTED_SCHEMA
    diffs: SchemaDifferences = SchemaDifferences()
    actual_tables = {t.lower() for t in table_names(connection)}

    for table_name in APP_TABLES:
        descriptor = expected[table_name]
        if table_name.lower() not in actual_tables:
            diffs.missing_tables.append(table_name)
            continue

        actual_columns = _actual_column_infos(connection, table_name)
        actual_by_lower = {name.lower(): (name, info) for name, info in actual_columns.items()}
        for col in descriptor.columns:
            match = actual_by_lower.get(col.name.lower())
            if match is None:
                diffs.missing_columns.setdefault(table_name, []).append(col.name)
                continue
            _actual_name, info = match
            if info.affinity != col.affinity:
                diffs.incompatible_columns.setdefault(table_name, []).append(
                    (col.name, f"affinity {info.affinity} != expected {col.affinity}")
                )
            elif info.pk != col.pk:
                diffs.incompatible_columns.setdefault(table_name, []).append(
                    (col.name, f"pk {info.pk} != expected {col.pk}")
                )
            elif (
                col.notnull
                and not info.notnull
                and not _is_int_rowid_alias(descriptor, col)
            ):
                diffs.incompatible_columns.setdefault(table_name, []).append(
                    (col.name, "NOT NULL expected but column is nullable")
                )
            elif info.default_value != col.default_value:
                diffs.incompatible_columns.setdefault(table_name, []).append(
                    (col.name, f"default {info.default_value!r} != expected {col.default_value!r}")
                )

        actual_indexes = _actual_index_infos(connection, table_name)
        actual_idx_by_lower = {name.lower(): (name, info) for name, info in actual_indexes.items()}
        for idx in descriptor.indexes:
            match = actual_idx_by_lower.get(idx.name.lower())
            if match is None:
                diffs.missing_indexes.setdefault(table_name, []).append(idx.name)
                continue
            _actual_name, info = match
            if info.columns != idx.columns:
                diffs.incompatible_indexes.setdefault(table_name, []).append(
                    (idx.name, f"columns {info.columns} != expected {idx.columns}")
                )
            elif info.collations != idx.collations:
                diffs.incompatible_indexes.setdefault(table_name, []).append(
                    (idx.name, f"collations {info.collations} != expected {idx.collations}")
                )
            elif info.descending != idx.descending:
                diffs.incompatible_indexes.setdefault(table_name, []).append(
                    (idx.name, f"order {info.descending} != expected {idx.descending}")
                )
            elif info.unique != idx.unique:
                diffs.incompatible_indexes.setdefault(table_name, []).append(
                    (idx.name, f"unique {info.unique} != expected {idx.unique}")
                )
            elif info.partial != idx.partial:
                diffs.incompatible_indexes.setdefault(table_name, []).append(
                    (idx.name, f"partial {info.partial} != expected {idx.partial}")
                )
            elif info.where_clause != idx.where_clause:
                diffs.incompatible_indexes.setdefault(table_name, []).append(
                    (idx.name, f"where {info.where_clause!r} != expected {idx.where_clause!r}")
                )

        actual_fks = _actual_foreign_keys(connection, table_name)
        for fk in descriptor.foreign_keys:
            found = any(
                (a.from_column.lower() == fk.from_column.lower())
                and a.to_table.lower() == fk.to_table.lower()
                and a.to_column.lower() == fk.to_column.lower()
                and a.on_delete == fk.on_delete
                and a.on_update == fk.on_update
                and a.match == fk.match
                for a in actual_fks
            )
            if not found:
                # Distinguish "missing entirely" from "present but actions differ".
                col_match = any(
                    a.from_column.lower() == fk.from_column.lower()
                    and a.to_table.lower() == fk.to_table.lower()
                    and a.to_column.lower() == fk.to_column.lower()
                    for a in actual_fks
                )
                if col_match:
                    diffs.incompatible_foreign_keys.setdefault(table_name, []).append(
                        (fk.from_column, "FK actions/match differ from expected")
                    )
                else:
                    diffs.missing_foreign_keys.setdefault(table_name, []).append(
                        (fk.from_column, fk.to_table, fk.to_column)
                    )

        # Table options.
        actual_opts = _table_options(connection, table_name)
        opt_reasons: list[str] = []
        if actual_opts.autoincrement != descriptor.options.autoincrement:
            opt_reasons.append(
                f"autoincrement {actual_opts.autoincrement} != expected {descriptor.options.autoincrement}"
            )
        if actual_opts.without_rowid != descriptor.options.without_rowid:
            opt_reasons.append(
                f"without_rowid {actual_opts.without_rowid} != expected {descriptor.options.without_rowid}"
            )
        if actual_opts.strict != descriptor.options.strict:
            opt_reasons.append(f"strict {actual_opts.strict} != expected {descriptor.options.strict}")
        if opt_reasons:
            diffs.incompatible_table_options.setdefault(table_name, []).extend(opt_reasons)

    return diffs


def schema_fingerprint(connection: sqlite3.Connection) -> str:
    """Return a deterministic fingerprint of the Greywatch *application* schema.

    Only the five application tables (``APP_TABLES``) are included -- unrelated
    tables and the migration ledger are deliberately excluded so the fingerprint
    reflects the application's own structure. The fingerprint encodes every
    property checked by :func:`compare_schema` (columns with affinity / PK
    position / NOT NULL / default, indexes with columns / collation / order /
    unique / partial / where-predicate, foreign keys with target and actions,
    and table options)
    so equivalent schemas produce identical fingerprints and materially
    different schemas produce different ones.
    """
    parts: list[str] = []
    for table_name in APP_TABLES:
        if table_name.lower() not in {t.lower() for t in table_names(connection)}:
            parts.append(f"missing:{table_name}")
            continue
        desc = inspect_table(connection, table_name)
        for col in desc.columns:
            parts.append(
                f"col:{table_name}:{col.name}:{col.affinity}:{int(col.notnull)}:"
                f"{col.pk}:{col.default_value}"
            )
        for idx in desc.indexes:
            parts.append(
                f"idx:{table_name}:{idx.name}:"
                f"{','.join(idx.columns)}:{','.join(idx.collations)}:"
                f"{','.join(str(b) for b in idx.descending)}:"
                f"{int(idx.unique)}:{int(idx.partial)}:{idx.origin}:"
                f"{idx.where_clause}"
            )
        for fk in desc.foreign_keys:
            parts.append(
                f"fk:{table_name}:{fk.from_column}->{fk.to_table}.{fk.to_column}:"
                f"{fk.on_delete}/{fk.on_update}/{fk.match}"
            )
        opts = desc.options
        parts.append(
            f"opt:{table_name}:{int(opts.autoincrement)}:"
            f"{int(opts.without_rowid)}:{int(opts.strict)}"
        )
    return ";".join(sorted(parts))
