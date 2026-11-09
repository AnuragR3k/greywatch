"""Agent management and API key authentication for Greywatch.

This module provides:
- Agent lifecycle management (create, list, get, deactivate)
- Secure API key generation, hashing, rotation, and revocation
- Authentication integration with FastAPI
- Event attribution with agent identity
- Audit logging for agent/key lifecycle
- Rate limiting per agent
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Optional

if TYPE_CHECKING:
    from fastapi import Request

from .audit_chain import canonical_audit_row as _canonical_audit_row
from .audit_chain import compute_chain_hash as _compute_chain_hash
from .siem import DEFAULT_DB_PATH, _connection

logger = logging.getLogger("greywatch.agents")

# Audit log chain computation is shared with the migration modules.  The
# canonical chain order is insertion order (``id ASC``).


@contextmanager
def _audit_connection():
    """Open a database connection with IMMEDIATE transaction for audit log writes.

    This ensures serialized access to the audit log chain, preventing
    concurrent writers from creating forks. The connection uses the same
    configuration as the standard _connection() but begins an IMMEDIATE
    transaction to acquire the write lock upfront.
    """
    db_path = Path(os.environ.get("GREYWATCH_DB", str(DEFAULT_DB_PATH)))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(db_path, timeout=5)
    connection.row_factory = sqlite3.Row

    try:
        connection.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass
    connection.execute("PRAGMA busy_timeout=5000")
    connection.execute("PRAGMA synchronous=NORMAL")
    connection.execute("PRAGMA foreign_keys=ON")

    # Begin IMMEDIATE transaction to serialize audit log writers. Keep this
    # inside the try/finally so a lock timeout still closes the connection.
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

# API key format: gw_<32 random base64url chars> = 3 + 43 = 46 chars
# Prefix "gw_" identifies Greywatch keys
KEY_PREFIX = "gw_"
KEY_RANDOM_BYTES = 32  # 256 bits of entropy
KEY_PREFIX_LENGTH = 8  # "gw_" + 5 chars = 8 chars for identification

# PBKDF2-HMAC-SHA256 iteration count.
# Default raised from 100,000 to 600,000 per security review.
# Configurable via GREYWATCH_KEY_HASH_ITERATIONS for operational flexibility.
DEFAULT_KEY_HASH_ITERATIONS = 600_000

# Maximum iterations accepted when verifying a stored hash.
# Prevents a malicious or corrupted hash from forcing unbounded CPU.
# CVE-2026-xxxx mitigation: stored iteration counts above this are rejected.
MAX_KEY_HASH_ITERATIONS = 10_000_000

# Rate limit categories for agents
AGENT_RATE_LIMIT_CATEGORIES = ("ingestion", "reads", "collector", "alert_close")


@dataclass(frozen=True, slots=True)
class Agent:
    """Agent representation."""
    id: int
    name: str
    display_name: Optional[str]
    description: Optional[str]
    status: Literal["active", "inactive", "revoked"]
    created_at: str
    updated_at: str
    last_seen_at: Optional[str]
    deactivated_at: Optional[str]
    deactivated_reason: Optional[str]


@dataclass(frozen=True, slots=True)
class ApiKey:
    """API key representation (without plaintext)."""
    id: int
    agent_id: int
    key_prefix: str
    name: Optional[str]
    status: Literal["active", "revoked", "expired"]
    created_at: str
    expires_at: Optional[str]
    revoked_at: Optional[str]
    revoked_reason: Optional[str]
    last_used_at: Optional[str]


@dataclass(frozen=True, slots=True)
class ApiKeyWithSecret:
    """API key with plaintext secret (returned only once at creation)."""
    id: int
    agent_id: int
    key_prefix: str
    name: Optional[str]
    plaintext_key: str  # Only returned once!
    status: Literal["active", "revoked", "expired"]
    created_at: str
    expires_at: Optional[str]


@dataclass(frozen=True, slots=True)
class RateLimitConfig:
    """Per-agent rate limit configuration."""
    ingestion: int = 60      # requests per minute
    reads: int = 120
    collector: int = 10
    alert_close: int = 30
    burst_multiplier: float = 1.5
    enabled: bool = True


def _env_positive_int(name: str, default: int) -> int:
    """Parse a positive integer from environment, failing closed on garbage."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip()
    if not value.isdigit():
        raise ValueError(f"Invalid {name}={raw!r}: must be a positive integer")
    parsed = int(value)
    if parsed <= 0:
        raise ValueError(f"Invalid {name}={raw!r}: must be a positive integer")
    return parsed


def _env_positive_float(name: str, default: float) -> float:
    """Parse a positive float from environment, failing closed on garbage."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    value = raw.strip()
    try:
        parsed = float(value)
    except ValueError:
        raise ValueError(f"Invalid {name}={raw!r}: must be a positive number")
    if parsed <= 0:
        raise ValueError(f"Invalid {name}={raw!r}: must be a positive number")
    return parsed


def get_agent_rate_limit_config() -> RateLimitConfig:
    """Get per-agent rate limit configuration from environment."""
    return RateLimitConfig(
        ingestion=_env_positive_int("GREYWATCH_AGENT_RATE_INGESTION", 60),
        reads=_env_positive_int("GREYWATCH_AGENT_RATE_READS", 120),
        collector=_env_positive_int("GREYWATCH_AGENT_RATE_COLLECTOR", 10),
        alert_close=_env_positive_int("GREYWATCH_AGENT_RATE_ALERT_CLOSE", 30),
        burst_multiplier=_env_positive_float("GREYWATCH_AGENT_RATE_BURST", 1.5),
        enabled=os.environ.get("GREYWATCH_AGENT_RATE_LIMIT_ENABLED", "1").lower() in ("1", "true", "yes", "on"),
    )


def _utc_now_datetime() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def _utc_now() -> str:
    """Return current UTC timestamp in ISO format."""
    return _utc_now_datetime().isoformat(timespec="seconds")


def _parse_expiration_timestamp(value: str) -> datetime:
    """Parse an API-key expiration value into a timezone-aware UTC datetime.

    ISO-8601 timestamps ending in ``Z`` and timestamps with explicit UTC
    offsets are supported. Timestamps without an explicit timezone are
    interpreted as UTC for backward compatibility.

    Raises:
        ValueError: If ``value`` is not a valid ISO-8601 timestamp. Callers
            must reject the key; an invalid expiration must never be treated
            as a non-expiring key.
    """
    if not isinstance(value, str):
        raise ValueError("expiration timestamp must be a string")

    raw = value.strip()
    if not raw:
        raise ValueError("expiration timestamp must not be empty")

    if raw.endswith(("Z", "z")):
        raw = raw[:-1] + "+00:00"

    try:
        expires = datetime.fromisoformat(raw)
        if expires.tzinfo is None:
            # Legacy keys may contain naive timestamps. Treat them as UTC
            # rather than allowing a naive/aware comparison to raise.
            expires = expires.replace(tzinfo=timezone.utc)
        return expires.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ValueError(f"invalid expiration timestamp: {value!r}") from exc


def _hash_key(plaintext_key: str, iterations: Optional[int] = None) -> str:
    """Hash an API key using PBKDF2-HMAC-SHA256.

    Uses constant-time comparison for verification.

    Args:
        plaintext_key: The key to hash.
        iterations: Optional iteration count. Defaults to DEFAULT_KEY_HASH_ITERATIONS
            (configurable via GREYWATCH_KEY_HASH_ITERATIONS env var).
    """
    if iterations is None:
        iterations = int(os.environ.get("GREYWATCH_KEY_HASH_ITERATIONS", str(DEFAULT_KEY_HASH_ITERATIONS)))
    salt = secrets.token_bytes(16)
    key_hash = hashlib.pbkdf2_hmac("sha256", plaintext_key.encode("utf-8"), salt, iterations)
    # Store as: algorithm$iterations$salt$hash (all hex)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${key_hash.hex()}"


def _verify_key(plaintext_key: str, stored_hash: str) -> tuple[bool, Optional[int]]:
    """Verify a plaintext key against its stored hash using constant-time comparison.

    Supports pbkdf2_sha256 format: pbkdf2_sha256$iterations$salt$hash

    Returns:
        Tuple of (verified: bool, iterations: Optional[int]).
        Iterations is returned to enable rehash-on-auth when the stored hash
        uses fewer iterations than the current default.

    Security:
        Rejects iteration counts above MAX_KEY_HASH_ITERATIONS to prevent
        resource exhaustion via a maliciously stored hash. Catches OverflowError
        from excessively large iteration counts.
    """
    try:
        parts = stored_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False, None

        iterations = int(parts[1])
        if iterations > MAX_KEY_HASH_ITERATIONS:
            # Stored hash requests an unsafe iteration count; reject it.
            # This prevents a corrupted/malicious hash from forcing unbounded CPU.
            return False, None
        salt = bytes.fromhex(parts[2])
        expected_hash = bytes.fromhex(parts[3])

        try:
            computed_hash = hashlib.pbkdf2_hmac(
                "sha256", plaintext_key.encode("utf-8"), salt, iterations
            )
        except OverflowError:
            # Iteration count too large for the platform's PBKDF2 implementation.
            # Treat as verification failure (log and return False).
            logger.error("PBKDF2 OverflowError during verification (iterations=%d)", iterations)
            return False, None

        verified = hmac.compare_digest(computed_hash, expected_hash)
        return verified, iterations if verified else None
    except (ValueError, IndexError):
        return False, None


def _generate_api_key() -> str:
    """Generate a cryptographically secure API key.

    Format: gw_<base64url-encoded-32-random-bytes>
    """
    random_bytes = secrets.token_bytes(KEY_RANDOM_BYTES)
    # Use base64url encoding (no padding, URL-safe)
    import base64
    encoded = base64.urlsafe_b64encode(random_bytes).decode("ascii").rstrip("=")
    return f"{KEY_PREFIX}{encoded}"


def _key_prefix(plaintext_key: str) -> str:
    """Extract the key prefix for identification (first 8 chars)."""
    return plaintext_key[:KEY_PREFIX_LENGTH]


def _append_audit_record(
    conn: sqlite3.Connection,
    event_type: str,
    agent_id: Optional[int] = None,
    api_key_id: Optional[int] = None,
    actor: str = "system",
    detail: Optional[dict] = None,
) -> None:
    """Append one audit row using the caller's open transaction.

    The caller owns the transaction and must roll it back on any exception.
    ``_audit_connection()`` takes ``BEGIN IMMEDIATE``, so the chain-head SELECT
    and the INSERT cannot interleave with another writer.  This function never
    catches errors: security-sensitive lifecycle mutations must fail together
    with their audit record rather than commit an unaudited state change.

    Never logs secrets or hashes.
    """
    # Get the latest inserted chain_hash within the same transaction.
    # The canonical chain order is insertion order (``id ASC``), so the
    # predecessor is the greatest id.  ``id`` is the INTEGER PRIMARY KEY, so
    # this is an indexed reverse rowid lookup with LIMIT 1 -- no table scan or
    # temporary sort.
    row = conn.execute(
        """
        SELECT chain_hash FROM audit_log
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    prev_chain_hash = row["chain_hash"] if row else None

    timestamp = _utc_now()
    detail_json = json.dumps(detail) if detail else None

    # Build the row data for canonical serialization
    row_data = {
        "timestamp": timestamp,
        "event_type": event_type,
        "agent_id": agent_id,
        "api_key_id": api_key_id,
        "actor": actor,
        "detail": detail_json,
    }

    canonical = _canonical_audit_row(row_data)
    chain_hash = _compute_chain_hash(prev_chain_hash, canonical)

    conn.execute(
        """
        INSERT INTO audit_log (timestamp, event_type, agent_id, api_key_id, actor, detail, prev_hash, chain_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            event_type,
            agent_id,
            api_key_id,
            actor,
            detail_json,
            prev_chain_hash,
            chain_hash,
        ),
    )


def _audit_log(
    event_type: str,
    agent_id: Optional[int] = None,
    api_key_id: Optional[int] = None,
    actor: str = "system",
    detail: Optional[dict] = None,
) -> None:
    """Best-effort audit append for non-lifecycle events.

    Authentication failures and other observational events must not turn into
    a different failure mode when audit storage is unavailable, so this wrapper
    logs and continues. Security-sensitive lifecycle mutations (agent/key
    creation, update, deactivation, rotation, revocation) must instead call
    :func:`_append_audit_record` inside their own ``_audit_connection()``
    transaction so the state change and its audit row commit or roll back
    together.
    """
    try:
        with _audit_connection() as conn:
            _append_audit_record(
                conn,
                event_type,
                agent_id=agent_id,
                api_key_id=api_key_id,
                actor=actor,
                detail=detail,
            )
    except Exception as exc:
        # Observational logging is best-effort; lifecycle writes are not.
        logger.error("Audit log failed: %s", exc)


# =============================================================================
# Agent Management
# =============================================================================

def create_agent(
    name: str,
    display_name: Optional[str] = None,
    description: Optional[str] = None,
    actor: str = "admin",
) -> Agent:
    """Create a new agent.

    Args:
        name: Unique machine-readable name (e.g., "web-server-01")
        display_name: Human-readable display name
        description: Optional description
        actor: Who created the agent (for audit log)

    Returns:
        The created Agent.

    Raises:
        ValueError: If name already exists.
    """
    now = _utc_now()
    # BEGIN IMMEDIATE serializes the agent insert with the audit-chain append
    # so both commit together or neither does. An audit failure rolls back the
    # new agent row instead of leaving an unaudited mutation behind.
    with _audit_connection() as conn:
        try:
            cursor = conn.execute(
                """
                INSERT INTO agents (name, display_name, description, status, created_at, updated_at)
                VALUES (?, ?, ?, 'active', ?, ?)
                """,
                (name, display_name, description, now, now),
            )
            agent_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            raise ValueError(f"Agent with name '{name}' already exists")

        _append_audit_record(
            conn,
            "agent_created",
            agent_id=agent_id,
            actor=actor,
            detail={
                "name": name,
                "display_name": display_name,
            },
        )

    return get_agent(agent_id)


def get_agent(agent_id: int) -> Optional[Agent]:
    """Get an agent by ID."""
    with _connection() as conn:
        row = conn.execute(
            "SELECT * FROM agents WHERE id = ?", (agent_id,)
        ).fetchone()
    return _row_to_agent(row) if row else None


def get_agent_by_name(name: str) -> Optional[Agent]:
    """Get an agent by name."""
    with _connection() as conn:
        row = conn.execute(
            "SELECT * FROM agents WHERE name = ?", (name,)
        ).fetchone()
    return _row_to_agent(row) if row else None


def list_agents(
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Agent]:
    """List agents with optional status filter."""
    with _connection() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM agents WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (status, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM agents ORDER BY created_at DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
    return [_row_to_agent(row) for row in rows]


def update_agent(
    agent_id: int,
    display_name: Optional[str] = None,
    description: Optional[str] = None,
    actor: str = "admin",
) -> Optional[Agent]:
    """Update agent metadata."""
    # Read, mutate, and audit under one IMMEDIATE transaction so a failed
    # audit insert rolls back the metadata change and the audit cannot describe
    # a state that was not committed.
    with _audit_connection() as conn:
        row = conn.execute(
            "SELECT * FROM agents WHERE id = ?", (agent_id,)
        ).fetchone()
        if not row:
            return None
        agent = _row_to_agent(row)

        updates = []
        params = []
        if display_name is not None:
            updates.append("display_name = ?")
            params.append(display_name)
        if description is not None:
            updates.append("description = ?")
            params.append(description)

        if not updates:
            return agent

        updates.append("updated_at = ?")
        params.append(_utc_now())
        params.append(agent_id)

        conn.execute(
            f"UPDATE agents SET {', '.join(updates)} WHERE id = ?",
            params,
        )

        audited_changes = {}
        if display_name is not None:
            audited_changes["display_name"] = display_name
        if description is not None:
            audited_changes["description"] = description

        _append_audit_record(
            conn,
            "agent_updated",
            agent_id=agent_id,
            actor=actor,
            detail=audited_changes,
        )

    return get_agent(agent_id)


def deactivate_agent(agent_id: int, reason: str, actor: str = "admin") -> bool:
    """Deactivate an agent (soft delete - revokes all keys).

    Args:
        agent_id: Agent to deactivate
        reason: Reason for deactivation
        actor: Who deactivated the agent

    Returns:
        True if agent was deactivated, False if not found.
    """
    # Deactivation revokes every active key; keep that bulk change and its
    # single audit event in the same transaction.
    with _audit_connection() as conn:
        row = conn.execute(
            "SELECT * FROM agents WHERE id = ?", (agent_id,)
        ).fetchone()
        if not row:
            return False
        agent = _row_to_agent(row)
        if agent.status != "active":
            return False

        now = _utc_now()
        # Deactivate agent
        conn.execute(
            """
            UPDATE agents
            SET status = 'inactive', updated_at = ?, deactivated_at = ?, deactivated_reason = ?
            WHERE id = ?
            """,
            (now, now, reason, agent_id),
        )
        # Revoke all active keys for this agent
        conn.execute(
            """
            UPDATE api_keys
            SET status = 'revoked', revoked_at = ?, revoked_reason = ?
            WHERE agent_id = ? AND status = 'active'
            """,
            (now, f"Agent deactivated: {reason}", agent_id),
        )

        _append_audit_record(
            conn,
            "agent_deactivated",
            agent_id=agent_id,
            actor=actor,
            detail={
                "reason": reason,
                "previous_status": agent.status,
            },
        )

    return True


def _row_to_agent(row: sqlite3.Row) -> Agent:
    return Agent(
        id=row["id"],
        name=row["name"],
        display_name=row["display_name"],
        description=row["description"],
        status=row["status"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        last_seen_at=row["last_seen_at"],
        deactivated_at=row["deactivated_at"],
        deactivated_reason=row["deactivated_reason"],
    )


# =============================================================================
# API Key Management
# =============================================================================

def create_api_key(
    agent_id: int,
    name: Optional[str] = None,
    expires_at: Optional[str] = None,
    actor: str = "admin",
) -> ApiKeyWithSecret:
    """Create a new API key for an agent.

    The plaintext key is returned ONLY ONCE. Store it securely.

    Args:
        agent_id: Agent to create the key for
        name: Optional human-readable name for the key
        expires_at: Optional ISO timestamp for expiration
        actor: Who created the key (for audit log)

    Returns:
        ApiKeyWithSecret containing the plaintext key (only time it's returned).

    Raises:
        ValueError: If agent not found or inactive.
    """
    # Cheap pre-check avoids paying for PBKDF2 when the agent is obviously
    # invalid. The authoritative check is repeated inside the transaction
    # below so a concurrent deactivation cannot create an active key for an
    # inactive agent.
    agent = get_agent(agent_id)
    if not agent:
        raise ValueError(f"Agent {agent_id} not found")
    if agent.status != "active":
        raise ValueError(f"Agent {agent_id} is not active (status: {agent.status})")

    plaintext_key = _generate_api_key()
    key_hash = _hash_key(plaintext_key)
    prefix = _key_prefix(plaintext_key)
    now = _utc_now()

    # Hash outside the transaction (PBKDF2 is intentionally expensive), then
    # re-check and write the key + audit row atomically under BEGIN IMMEDIATE.
    with _audit_connection() as conn:
        row = conn.execute(
            "SELECT status FROM agents WHERE id = ?", (agent_id,)
        ).fetchone()
        if not row:
            raise ValueError(f"Agent {agent_id} not found")
        if row["status"] != "active":
            raise ValueError(
                f"Agent {agent_id} is not active (status: {row['status']})"
            )

        cursor = conn.execute(
            """
            INSERT INTO api_keys (agent_id, key_hash, key_prefix, name, status, created_at, expires_at)
            VALUES (?, ?, ?, ?, 'active', ?, ?)
            """,
            (agent_id, key_hash, prefix, name, now, expires_at),
        )
        key_id = cursor.lastrowid

        _append_audit_record(
            conn,
            "key_generated",
            agent_id=agent_id,
            api_key_id=key_id,
            actor=actor,
            detail={
                "key_prefix": prefix,
                "key_name": name,
                "expires_at": expires_at,
            },
        )

    return ApiKeyWithSecret(
        id=key_id,
        agent_id=agent_id,
        key_prefix=prefix,
        name=name,
        plaintext_key=plaintext_key,
        status="active",
        created_at=now,
        expires_at=expires_at,
    )


def get_api_key(key_id: int) -> Optional[ApiKey]:
    """Get an API key by ID (without plaintext)."""
    with _connection() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()
    return _row_to_api_key(row) if row else None


def list_api_keys(agent_id: int, status: Optional[str] = None) -> list[ApiKey]:
    """List API keys for an agent."""
    with _connection() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM api_keys WHERE agent_id = ? AND status = ? ORDER BY created_at DESC",
                (agent_id, status),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM api_keys WHERE agent_id = ? ORDER BY created_at DESC",
                (agent_id,),
            ).fetchall()
    return [_row_to_api_key(row) for row in rows]


def revoke_api_key(key_id: int, reason: str, actor: str = "admin") -> bool:
    """Revoke an API key.

    Args:
        key_id: API key to revoke
        reason: Reason for revocation
        actor: Who revoked the key

    Returns:
        True if key was revoked, False if not found or already revoked.
    """
    # Read, mutate, and audit under one IMMEDIATE transaction so the key is
    # never revoked without its audit record (or vice versa).
    with _audit_connection() as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()
        if not row:
            return False
        key = _row_to_api_key(row)
        if key.status != "active":
            return False

        agent_id = key.agent_id
        now = _utc_now()
        conn.execute(
            """
            UPDATE api_keys
            SET status = 'revoked', revoked_at = ?, revoked_reason = ?
            WHERE id = ?
            """,
            (now, reason, key_id),
        )

        _append_audit_record(
            conn,
            "key_revoked",
            agent_id=agent_id,
            api_key_id=key_id,
            actor=actor,
            detail={
                "key_prefix": key.key_prefix,
                "key_name": key.name,
                "reason": reason,
            },
        )

    # Invalidate rate-limit bucket for this agent to prevent continued use
    # of the revoked key's rate allowance.
    reset_agent_rate_limit(agent_id)

    return True


def rotate_api_key(key_id: int, actor: str = "admin") -> ApiKeyWithSecret:
    """Rotate an API key (create new, revoke old in same transaction).

    The old key is immediately invalidated. The new key's plaintext is returned once.

    Args:
        key_id: API key to rotate
        actor: Who performed the rotation

    Returns:
        ApiKeyWithSecret for the new key.

    Raises:
        ValueError: If key not found, not active, or agent inactive.
    """
    # Cheap pre-check avoids paying for PBKDF2 when the key is obviously
    # invalid. The authoritative key/agent checks are repeated inside the
    # transaction so concurrent rotations cannot both create a new key.
    old_key = get_api_key(key_id)
    if not old_key:
        raise ValueError(f"API key {key_id} not found")
    if old_key.status != "active":
        raise ValueError(f"API key {key_id} is not active (status: {old_key.status})")

    agent = get_agent(old_key.agent_id)
    if not agent or agent.status != "active":
        raise ValueError(f"Agent {old_key.agent_id} is not active")

    agent_id = old_key.agent_id
    now = _utc_now()
    plaintext_key = _generate_api_key()
    key_hash = _hash_key(plaintext_key)
    prefix = _key_prefix(plaintext_key)

    # Revoke-old, create-new, and the single rotation audit event commit
    # together. A failed audit insert leaves the old key active and no new key
    # behind.
    with _audit_connection() as conn:
        old_row = conn.execute(
            "SELECT * FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()
        if not old_row:
            raise ValueError(f"API key {key_id} not found")
        locked_old_key = _row_to_api_key(old_row)
        if locked_old_key.status != "active":
            raise ValueError(
                f"API key {key_id} is not active (status: {locked_old_key.status})"
            )

        agent_row = conn.execute(
            "SELECT status FROM agents WHERE id = ?", (agent_id,)
        ).fetchone()
        if not agent_row or agent_row["status"] != "active":
            raise ValueError(f"Agent {agent_id} is not active")

        # Revoke old key
        conn.execute(
            """
            UPDATE api_keys
            SET status = 'revoked', revoked_at = ?, revoked_reason = ?
            WHERE id = ?
            """,
            (now, f"Rotated by {actor}", key_id),
        )
        # Create new key
        cursor = conn.execute(
            """
            INSERT INTO api_keys (agent_id, key_hash, key_prefix, name, status, created_at)
            VALUES (?, ?, ?, ?, 'active', ?)
            """,
            (agent_id, key_hash, prefix, locked_old_key.name, now),
        )
        new_key_id = cursor.lastrowid

        _append_audit_record(
            conn,
            "key_rotated",
            agent_id=agent_id,
            api_key_id=new_key_id,
            actor=actor,
            detail={
                "old_key_id": key_id,
                "old_key_prefix": locked_old_key.key_prefix,
                "new_key_prefix": prefix,
                "key_name": locked_old_key.name,
            },
        )

    # Invalidate rate-limit bucket for this agent to prevent continued use
    # of the old key's rate allowance.
    reset_agent_rate_limit(agent_id)

    return ApiKeyWithSecret(
        id=new_key_id,
        agent_id=agent_id,
        key_prefix=prefix,
        name=locked_old_key.name,
        plaintext_key=plaintext_key,
        status="active",
        created_at=now,
        expires_at=None,
    )


def _row_to_api_key(row: sqlite3.Row) -> ApiKey:
    return ApiKey(
        id=row["id"],
        agent_id=row["agent_id"],
        key_prefix=row["key_prefix"],
        name=row["name"],
        status=row["status"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        revoked_at=row["revoked_at"],
        revoked_reason=row["revoked_reason"],
        last_used_at=row["last_used_at"],
    )


# =============================================================================
# Authentication
# =============================================================================

@dataclass(frozen=True, slots=True)
class AuthResult:
    """Result of API key authentication."""
    agent: Agent
    api_key: ApiKey
    plaintext_key: str  # The key that was presented (for rate limiting)


def authenticate_api_key(plaintext_key: str) -> Optional[AuthResult]:
    """Authenticate an API key.

    Returns AuthResult if valid, None if invalid/expired/revoked/unknown.
    Uses constant-time comparison for hash verification.
    Includes agent status in initial SQL query to prevent timing side-channels.
    Implements rehash-on-auth when stored hash uses fewer iterations than current default.
    """
    if not plaintext_key or not plaintext_key.startswith(KEY_PREFIX):
        return None

    prefix = _key_prefix(plaintext_key)

    with _connection() as conn:
        # Find candidate keys by prefix (indexed)
        # Agent status is checked in the JOIN to prevent timing side-channels
        # (inactive agents never appear in candidates, so no per-candidate timing variation)
        # Use explicit columns to avoid name conflicts between api_keys and agents tables
        rows = conn.execute(
            """
            SELECT 
                k.id as key_id, k.agent_id, k.key_hash, k.key_prefix, k.name as key_name,
                k.status as key_status, k.created_at as key_created_at, k.expires_at,
                k.revoked_at, k.revoked_reason, k.last_used_at,
                a.id as agent_id, a.name as agent_name, a.display_name, a.description,
                a.status as agent_status, a.created_at as agent_created_at,
                a.updated_at, a.last_seen_at, a.deactivated_at, a.deactivated_reason
            FROM api_keys k
            JOIN agents a ON a.id = k.agent_id AND a.status = 'active'
            WHERE k.key_prefix = ? AND k.status = 'active'
            """,
            (prefix,),
        ).fetchall()

    if not rows:
        _audit_log("auth_failure", actor="unknown", detail={
            "reason": "key_not_found",
            "key_prefix": prefix,
        })
        return None

    # Verify each candidate (constant-time comparison)
    for row in rows:
        key_hash = row["key_hash"]
        verified, stored_iterations = _verify_key(plaintext_key, key_hash)
        if verified:
            # Check expiration. A missing value (NULL) means the key does not
            # expire; any present value is parsed strictly. Malformed values
            # are rejected rather than treated as non-expiring.
            if row["expires_at"] is not None:
                try:
                    expires = _parse_expiration_timestamp(row["expires_at"])
                except ValueError:
                    _audit_log("auth_failure", agent_id=row["agent_id"], api_key_id=row["key_id"], actor="system", detail={
                        "reason": "invalid_expiration",
                        "key_prefix": prefix,
                    })
                    return None

                if expires <= _utc_now_datetime():
                    _audit_log("auth_failure", agent_id=row["agent_id"], api_key_id=row["key_id"], actor="system", detail={
                        "reason": "key_expired",
                        "key_prefix": prefix,
                    })
                    return None

            # Rehash-on-auth: if stored hash uses fewer iterations than current default,
            # re-hash the key with current default and update the stored hash.
            # This gradually upgrades all existing hashes over time.
            current_iterations = int(os.environ.get("GREYWATCH_KEY_HASH_ITERATIONS", str(DEFAULT_KEY_HASH_ITERATIONS)))
            if stored_iterations is not None and stored_iterations < current_iterations:
                new_hash = _hash_key(plaintext_key, current_iterations)
                try:
                    # Keep the optional hash upgrade and its audit row atomic.
                    # If audit persistence fails, roll back to the previous
                    # (still valid) hash and continue authentication: a
                    # background upgrade must not turn a valid login into an
                    # outage.
                    with _audit_connection() as conn:
                        conn.execute(
                            "UPDATE api_keys SET key_hash = ? WHERE id = ?",
                            (new_hash, row["key_id"]),
                        )
                        _append_audit_record(
                            conn,
                            "key_rehashed",
                            agent_id=row["agent_id"],
                            api_key_id=row["key_id"],
                            actor="system",
                            detail={
                                "old_iterations": stored_iterations,
                                "new_iterations": current_iterations,
                                "key_prefix": prefix,
                            },
                        )
                except Exception as exc:
                    logger.error(
                        "Audit-protected key rehash failed; keeping previous hash: %s",
                        exc,
                    )

            # Update last_used_at
            now = _utc_now()
            with _connection() as conn:
                conn.execute(
                    "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                    (now, row["key_id"]),
                )
            # Update agent last_seen_at
            with _connection() as conn:
                conn.execute(
                    "UPDATE agents SET last_seen_at = ? WHERE id = ?",
                    (now, row["agent_id"]),
                )

            agent = Agent(
                id=row["agent_id"],
                name=row["agent_name"],
                display_name=row["display_name"],
                description=row["description"],
                status=row["agent_status"],
                created_at=row["agent_created_at"],
                updated_at=row["updated_at"],
                last_seen_at=row["last_seen_at"],
                deactivated_at=row["deactivated_at"],
                deactivated_reason=row["deactivated_reason"],
            )
            api_key = ApiKey(
                id=row["key_id"],
                agent_id=row["agent_id"],
                key_prefix=row["key_prefix"],
                name=row["key_name"],
                status=row["key_status"],
                created_at=row["key_created_at"],
                expires_at=row["expires_at"],
                revoked_at=row["revoked_at"],
                revoked_reason=row["revoked_reason"],
                last_used_at=now,
            )
            return AuthResult(agent=agent, api_key=api_key, plaintext_key=plaintext_key)

    _audit_log("auth_failure", actor="unknown", detail={
        "reason": "invalid_credentials",
        "key_prefix": prefix,
    })
    return None


# =============================================================================
# Rate Limiting (Per-Agent)
# =============================================================================

# In-memory token bucket store for per-agent rate limiting
# Key: (agent_id, category) -> [tokens, last_update]
_agent_buckets: dict[tuple[int, str], list[float]] = {}
_agent_buckets_lock = None  # Will be initialized on first use


def _get_agent_buckets_lock():
    """Get or create the asyncio lock for bucket access."""
    global _agent_buckets_lock
    if _agent_buckets_lock is None:
        import asyncio
        _agent_buckets_lock = asyncio.Lock()
    return _agent_buckets_lock


async def check_agent_rate_limit(
    agent_id: int,
    category: Literal["ingestion", "reads", "collector", "alert_close"],
    config: Optional[RateLimitConfig] = None,
) -> tuple[bool, int]:
    """Check and consume a rate limit token for an agent.

    Returns (allowed, retry_after_seconds).
    """
    if config is None:
        config = get_agent_rate_limit_config()

    if not config.enabled:
        return True, 0

    limit = getattr(config, category)
    if limit is None:
        return True, 0

    capacity = int(limit * config.burst_multiplier)
    refill_per_sec = limit / 60.0
    now = time.monotonic()
    bucket_key = (agent_id, category)

    lock = _get_agent_buckets_lock()
    async with lock:
        tokens, last_update = _agent_buckets.get(bucket_key, [capacity, now])
        elapsed = max(0.0, now - last_update)
        tokens = min(capacity, tokens + elapsed * refill_per_sec)

        if tokens < 1.0:
            retry_after = max(1, int((1.0 - tokens) / refill_per_sec))
            _agent_buckets[bucket_key] = [tokens, now]
            return False, retry_after

        tokens -= 1.0
        _agent_buckets[bucket_key] = [tokens, now]
        return True, 0


def reset_agent_rate_limit(agent_id: int) -> None:
    """Reset rate limit buckets for an agent (e.g., after key rotation)."""
    global _agent_buckets
    keys_to_remove = [k for k in _agent_buckets if k[0] == agent_id]
    for k in keys_to_remove:
        del _agent_buckets[k]


# =============================================================================
# Event Attribution
# =============================================================================

def set_event_agent_id(event: dict, agent_id: int) -> dict:
    """Attach agent_id to an event dict for ingestion.

    This ensures the event is attributed to the authenticated agent.
    The agent_id comes from the authenticated request context, never from the event body.
    """
    event["agent_id"] = agent_id
    return event


def get_agent_events(agent_id: int, limit: int = 100, offset: int = 0) -> list[dict]:
    """Get events attributed to a specific agent."""
    with _connection() as conn:
        rows = conn.execute(
            """
            SELECT * FROM events
            WHERE agent_id = ?
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (agent_id, limit, offset),
        ).fetchall()
    return [dict(row) for row in rows]


# =============================================================================
# Audit Log Queries
# =============================================================================

def get_audit_log(
    agent_id: Optional[int] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[dict]:
    """Query audit log entries."""
    with _connection() as conn:
        query = "SELECT * FROM audit_log WHERE 1=1"
        params: list = []

        if agent_id is not None:
            query += " AND agent_id = ?"
            params.append(agent_id)
        if event_type is not None:
            query += " AND event_type = ?"
            params.append(event_type)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]


# =============================================================================
# FastAPI Integration
# =============================================================================

# Request context key for agent identity
class AgentContext:
    """Request-scoped agent context."""

    def __init__(self):
        self.agent: Optional[Agent] = None
        self.api_key: Optional[ApiKey] = None
        self.authenticated: bool = False


_agent_context_var: Optional[Any] = None


def get_agent_context() -> AgentContext:
    """Get the current request's agent context.

    Returns an AgentContext with agent/api_key set if authenticated,
    or an empty context if not authenticated (e.g., legacy token or loopback).
    """
    import contextvars
    global _agent_context_var
    if _agent_context_var is None:
        _agent_context_var = contextvars.ContextVar("agent_context", default=AgentContext())
    return _agent_context_var.get()


def set_agent_context(agent: Agent, api_key: ApiKey) -> None:
    """Set the agent context for the current request."""
    import contextvars
    global _agent_context_var
    if _agent_context_var is None:
        _agent_context_var = contextvars.ContextVar("agent_context", default=AgentContext())
    ctx = AgentContext()
    ctx.agent = agent
    ctx.api_key = api_key
    ctx.authenticated = True
    _agent_context_var.set(ctx)


def clear_agent_context() -> None:
    """Clear the agent context (set to unauthenticated)."""
    import contextvars
    global _agent_context_var
    if _agent_context_var is None:
        _agent_context_var = contextvars.ContextVar("agent_context", default=AgentContext())
    _agent_context_var.set(AgentContext())


async def agent_auth_dependency(
    request: "Request",
) -> Optional[AuthResult]:
    """FastAPI dependency for agent authentication.

    Checks for API key in Authorization: Bearer or X-API-Key header.
    Returns AuthResult if valid agent credentials, None otherwise.
    Does NOT raise - let the trust boundary handle 401/403.
    """
    # Check for agent API key (format: gw_...)
    auth_header = request.headers.get("Authorization", "")
    api_key_header = request.headers.get("X-API-Key", "")

    provided_key = None
    if auth_header.startswith("Bearer "):
        provided_key = auth_header[len("Bearer "):].strip()
    elif api_key_header:
        provided_key = api_key_header.strip()

    if not provided_key or not provided_key.startswith(KEY_PREFIX):
        return None

    result = authenticate_api_key(provided_key)
    if result:
        set_agent_context(result.agent, result.api_key)
    return result


async def require_agent_auth(
    request: "Request",
    auth_result: Optional[AuthResult] = None,
) -> AuthResult:
    """FastAPI dependency that requires valid agent authentication.

    Raises HTTPException 401 if not authenticated as an agent.
    """
    if auth_result is None:
        auth_result = await agent_auth_dependency(request)

    if not auth_result:
        raise HTTPException(
            status_code=401,
            detail="Valid agent API key required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return auth_result


def is_agent_request(request: "Request") -> bool:
    """Check if the request is authenticated as an agent (vs legacy token/loopback)."""
    ctx = get_agent_context()
    return ctx.authenticated


# Import HTTPException for the dependency
from fastapi import HTTPException