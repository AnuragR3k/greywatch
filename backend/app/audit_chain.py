"""Canonical audit-log hash-chain helpers.

The audit chain is ordered by **insertion order** (``id ASC``).  This is the
only ordering used by the application when appending records and by
:func:`verify_chain` when checking integrity.  It is independent of the
``timestamp`` column, so a backward system-clock adjustment cannot make a
legitimately appended chain look tampered with.

Migration v003 was released with a timestamp-ordered backfill
(``timestamp ASC, id ASC``) and the original append path selected its
predecessor with ``timestamp DESC, id DESC``.  Migration v004 rebuilds any
existing chain in insertion order.  To avoid silently repairing unrelated
corruption, v004 first validates that the stored chain is consistent with the
known v003 history:

* a prefix of rows backfilled by v003 in timestamp order, followed by
* zero or more rows appended by the legacy ``max(timestamp, id)`` lookup.

Rows are never deleted and their IDs and event contents are never changed.

This module is read-only except for the explicit migration v004 rebuild.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Sequence

__all__ = [
    "AUDIT_CHAIN_FIELDS",
    "canonical_audit_row",
    "compute_chain_hash",
    "read_chain_rows",
    "validate_legacy_rows",
    "validate_legacy_chain",
    "verify_chain",
    "verify_chain_timestamp_order",
    "verify_path",
]

#: Fields included in the canonical audit-row serialization.
AUDIT_CHAIN_FIELDS = (
    "timestamp",
    "event_type",
    "agent_id",
    "api_key_id",
    "actor",
    "detail",
)

_CHAIN_SELECT = """
    SELECT id, timestamp, event_type, agent_id, api_key_id, actor, detail,
           prev_hash, chain_hash
    FROM audit_log
"""


def canonical_audit_row(row: dict[str, Any]) -> str:
    """Produce the deterministic canonical JSON string for an audit row.

    Only non-NULL fields are included and keys are sorted, matching the
    serialization frozen in migration v003.
    """
    canonical = {key: value for key, value in row.items() if value is not None}
    return json.dumps(canonical, separators=(",", ":"), sort_keys=True)


def compute_chain_hash(prev_hash: str | None, canonical_row: str) -> str:
    """Return ``SHA256(prev_hash + canonical_row)`` as lowercase hex.

    The first record uses an empty string for ``prev_hash``.
    """
    combined = ((prev_hash or "") + canonical_row).encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


def _canonical_fields(row: Any) -> dict[str, Any]:
    """Extract the canonical fields from a row-like object."""
    return {field: row[field] for field in AUDIT_CHAIN_FIELDS}


def read_chain_rows(
    connection: sqlite3.Connection,
    *,
    order_by: str = "id ASC",
) -> list[dict[str, Any]]:
    """Read audit rows in an explicit order, independent of ``row_factory``.

    Rows are returned as dictionaries keyed by column name so callers work the
    same whether the connection uses :class:`sqlite3.Row`, tuples, or a custom
    factory.

    ``order_by`` is intentionally restricted to the two orders understood by
    this module so a caller cannot inject SQL through it.
    """
    if order_by not in {"id ASC", "timestamp ASC, id ASC"}:
        raise ValueError(f"unsupported audit-chain order: {order_by!r}")
    cursor = connection.execute(f"{_CHAIN_SELECT} ORDER BY {order_by}")
    columns = [description[0] for description in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def _verify_rows(
    rows: Sequence[Any],
) -> tuple[bool, list[str]]:
    errors: list[str] = []
    prev_chain_hash: str | None = None

    for row in rows:
        row_dict = dict(row)
        row_id = row_dict["id"]
        stored_prev_hash = row_dict["prev_hash"]
        stored_chain_hash = row_dict["chain_hash"]

        if stored_prev_hash != prev_chain_hash:
            errors.append(
                f"Record id={row_id}: prev_hash mismatch "
                f"(expected {prev_chain_hash}, got {stored_prev_hash})"
            )

        canonical = canonical_audit_row(_canonical_fields(row_dict))
        expected_chain_hash = compute_chain_hash(stored_prev_hash, canonical)
        if stored_chain_hash != expected_chain_hash:
            errors.append(
                f"Record id={row_id}: chain_hash mismatch "
                f"(expected {expected_chain_hash}, got {stored_chain_hash})"
            )

        prev_chain_hash = stored_chain_hash

    return len(errors) == 0, errors


def verify_chain(connection: sqlite3.Connection) -> tuple[bool, list[str]]:
    """Verify the audit chain in canonical insertion order (``id ASC``).

    Returns ``(is_valid, errors)``.  An empty table is valid.  This function is
    read-only and never repairs the chain.
    """
    return _verify_rows(read_chain_rows(connection))


def verify_chain_timestamp_order(
    connection: sqlite3.Connection,
) -> tuple[bool, list[str]]:
    """Verify the historical v003 timestamp ordering (read-only).

    This applies the pre-v004 verifier: timestamp order with the canonical
    id-exclusive hash formula.  v003's frozen backfill wrote id-inclusive
    hashes, so this diagnostic cannot validate that data; use
    :func:`validate_legacy_rows` for pre-v004 chain compatibility checks.
    It is not the canonical application order.
    """
    rows = read_chain_rows(connection, order_by="timestamp ASC, id ASC")
    return _verify_rows(rows)


# --------------------------------------------------------------------------- #
# Migration v004 compatibility validation
# --------------------------------------------------------------------------- #


class _Fenwick:
    """Small Fenwick tree used to find predecessor/successor ranks in O(log n)."""

    def __init__(self, size: int) -> None:
        self.size = size
        self.tree = [0] * (size + 1)

    def add(self, index: int) -> None:
        while index <= self.size:
            self.tree[index] += 1
            index += index & -index

    def prefix_sum(self, index: int) -> int:
        total = 0
        while index > 0:
            total += self.tree[index]
            index -= index & -index
        return total

    def kth(self, k: int) -> int:
        """Return the 1-based index of the k-th present element."""
        if k <= 0:
            raise ValueError("k must be positive")
        index = 0
        step = 1 << (self.size.bit_length() - 1)
        while step:
            candidate = index + step
            if candidate <= self.size and self.tree[candidate] < k:
                index = candidate
                k -= self.tree[candidate]
            step >>= 1
        return index + 1


def _content_style_validity(
    rows: Sequence[Any],
) -> tuple[list[bool], list[bool]]:
    """Return per-row validity for the two known hash shapes.

    The first list accepts either the v003 backfill shape (which included the
    row ``id`` in the canonical JSON) or the runtime append shape (which did
    not).  The second list accepts only the runtime append shape, which is what
    every post-v003 legacy append used.
    """
    backfill_ok: list[bool] = []
    append_ok: list[bool] = []

    for row in rows:
        fields = _canonical_fields(row)
        no_id_canonical = canonical_audit_row(fields)
        with_id_canonical = canonical_audit_row({**fields, "id": row["id"]})
        expected_no_id = compute_chain_hash(row["prev_hash"], no_id_canonical)
        expected_with_id = compute_chain_hash(row["prev_hash"], with_id_canonical)

        append_ok.append(row["chain_hash"] == expected_no_id)
        backfill_ok.append(
            row["chain_hash"] == expected_no_id
            or row["chain_hash"] == expected_with_id
        )

    return backfill_ok, append_ok


def _prefix_timestamp_validity(rows: Sequence[Any]) -> list[bool]:
    """Return ``prefix_ok[k]`` for the first ``k`` rows in id order.

    ``prefix_ok[k]`` is true when those ``k`` rows form a valid v003 backfill
    chain ordered by ``timestamp ASC, id ASC``.
    """
    count = len(rows)
    result = [False] * (count + 1)
    result[0] = True
    if count == 0:
        return result

    keys = [(row["timestamp"], row["id"]) for row in rows]
    ordered_keys = sorted(keys)
    rank = {key: index + 1 for index, key in enumerate(ordered_keys)}
    rows_by_rank: list[Any | None] = [None] * (count + 1)
    for row in rows:
        rows_by_rank[rank[(row["timestamp"], row["id"])]] = row

    tree = _Fenwick(count)
    invalid = 0

    for index, row in enumerate(rows):
        row_rank = rank[(row["timestamp"], row["id"])]
        inserted = index

        before_count = tree.prefix_sum(row_rank - 1)
        predecessor = (
            rows_by_rank[tree.kth(before_count)] if before_count else None
        )

        through_count = tree.prefix_sum(row_rank)
        successor = (
            rows_by_rank[tree.kth(through_count + 1)]
            if through_count < inserted
            else None
        )

        predecessor_hash = (
            predecessor["chain_hash"] if predecessor is not None else None
        )

        if successor is not None:
            was_valid = successor["prev_hash"] == predecessor_hash
            becomes_valid = successor["prev_hash"] == row["chain_hash"]
            invalid += (0 if becomes_valid else 1) - (0 if was_valid else 1)

        if row["prev_hash"] != predecessor_hash:
            invalid += 1

        tree.add(row_rank)
        result[index + 1] = invalid == 0

    return result


def _suffix_append_validity(rows: Sequence[Any]) -> list[bool]:
    """Return ``suffix_ok[k]`` for rows appended with the legacy lookup.

    A legacy append linked to the row with the greatest
    ``(timestamp, id)`` among rows with a smaller id.  ``suffix_ok[k]`` is true
    when every row from index ``k`` onward satisfies that rule.
    """
    count = len(rows)
    append_ok = [False] * count
    timestamp_max: Any | None = None

    for index, row in enumerate(rows):
        expected_prev = (
            timestamp_max["chain_hash"] if timestamp_max is not None else None
        )
        append_ok[index] = row["prev_hash"] == expected_prev
        if timestamp_max is None or row["timestamp"] >= timestamp_max["timestamp"]:
            timestamp_max = row

    suffix_ok = [False] * (count + 1)
    suffix_ok[count] = True
    for index in range(count - 1, -1, -1):
        suffix_ok[index] = suffix_ok[index + 1] and append_ok[index]
    return suffix_ok


def _prefix_all(flags: Sequence[bool]) -> list[bool]:
    result = [False] * (len(flags) + 1)
    result[0] = True
    for index, flag in enumerate(flags):
        result[index + 1] = result[index] and flag
    return result


def _suffix_all(flags: Sequence[bool]) -> list[bool]:
    result = [False] * (len(flags) + 1)
    result[len(flags)] = True
    for index in range(len(flags) - 1, -1, -1):
        result[index] = result[index + 1] and flags[index]
    return result


def validate_legacy_rows(
    rows: Sequence[Any],
) -> tuple[bool, list[str], int | None]:
    """Validate a pre-v004 chain against the known v003 history.

    Returns ``(compatible, errors, split)``.  ``split`` is the number of rows
    attributed to the v003 timestamp-ordered backfill; rows from ``split``
    onward are attributed to legacy appends.  ``split`` is ``None`` when no
    compatible history exists.

    Every row's hash must match one of the two known serializations.  Content
    tampering is reported instead of rebuilt.  Linkage is accepted only if it
    matches a prefix backfilled in timestamp order followed by legacy
    ``max(timestamp, id)`` appends.
    """
    count = len(rows)
    backfill_content, append_content = _content_style_validity(rows)

    content_errors = [
        (
            f"Record id={row['id']}: chain_hash {row['chain_hash']} matches "
            "neither the v003 backfill nor the append serialization"
        )
        for row, valid_any in zip(
            rows, (b or a for b, a in zip(backfill_content, append_content))
        )
        if not valid_any
    ]
    if content_errors:
        return False, content_errors, None

    prefix_link_ok = _prefix_timestamp_validity(rows)
    suffix_link_ok = _suffix_append_validity(rows)
    prefix_content_ok = _prefix_all(backfill_content)
    suffix_content_ok = _suffix_all(append_content)

    candidates = [
        index
        for index in range(count + 1)
        if prefix_link_ok[index]
        and prefix_content_ok[index]
        and suffix_link_ok[index]
        and suffix_content_ok[index]
    ]
    if candidates:
        # Prefer the largest compatible prefix: this attributes as many rows
        # as possible to the documented v003 timestamp backfill.
        return True, [], candidates[-1]

    # Surface the first concrete linkage mismatch for operators.
    mismatch: str | None = None
    timestamp_max: Any | None = None
    for index, row in enumerate(rows):
        expected_prev = (
            timestamp_max["chain_hash"] if timestamp_max is not None else None
        )
        if row["prev_hash"] != expected_prev:
            mismatch = (
                f"Record id={row['id']}: prev_hash {row['prev_hash']} does not "
                f"match legacy append predecessor {expected_prev}"
            )
            break
        if timestamp_max is None or row["timestamp"] >= timestamp_max["timestamp"]:
            timestamp_max = row

    detail = (
        f"; first mismatch: {mismatch}"
        if mismatch
        else "; no timestamp-backfill/append boundary is consistent"
    )
    return (
        False,
        [
            "audit chain linkage does not match any known v3 history "
            "(timestamp-ordered backfill plus legacy max-timestamp appends)"
            + detail
        ],
        None,
    )


def validate_legacy_chain(
    connection: sqlite3.Connection,
) -> tuple[bool, list[str], int | None]:
    """Validate the stored chain in id order against the known v003 history."""
    return validate_legacy_rows(read_chain_rows(connection))


# --------------------------------------------------------------------------- #
# Operator-facing read-only path verification
# --------------------------------------------------------------------------- #


def verify_path(
    path: str | Path,
) -> tuple[bool, list[str], int]:
    """Verify the audit chain at ``path`` without modifying the database.

    WAL databases are copied to a private temporary directory before being
    opened read-only, so verification never creates or changes ``-wal`` /
    ``-shm`` sidecars beside the original file.

    Returns ``(is_valid, errors, record_count)``.  Operational failures such as
    a missing file or missing ``audit_log`` table propagate as exceptions.
    """
    # Imported lazily so the canonical hash helpers stay usable without the
    # migration-state machinery.
    from .migration_state import _maybe_cleanup, _open_readonly_with_wal_copy

    connection: sqlite3.Connection | None = None
    temp_dir: str | None = None
    try:
        connection, temp_dir = _open_readonly_with_wal_copy(Path(path))
        connection.row_factory = sqlite3.Row
        count = connection.execute(
            "SELECT COUNT(*) FROM audit_log"
        ).fetchone()[0]
        is_valid, errors = verify_chain(connection)
        return is_valid, errors, count
    finally:
        _maybe_cleanup(connection, temp_dir)
