"""Greywatch API entry point."""

import hmac
import ipaddress
import logging
import math
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from contextlib import asynccontextmanager

logger = logging.getLogger("greywatch.api")

from .siem import (
    acknowledge_incident,
    close_alert,
    count_alerts,
    count_incidents,
    get_alert_detail,
    get_incident,
    ingest_lines,
    list_incidents,
    list_alerts,
    list_events,
    resolve_incident,
    DEFAULT_DB_PATH,
)
from . import collector
from . import suricata
from .migration_state import ensure_database_file_exists, inspect_path, DatabaseState
from .migrations.runner import migrate, MigrationError, MigrationStateError, MigrationConflictError
from .agents import (
    Agent,
    ApiKey,
    ApiKeyWithSecret,
    create_agent,
    get_agent,
    get_agent_by_name,
    list_agents,
    update_agent,
    deactivate_agent,
    create_api_key,
    get_api_key,
    list_api_keys,
    revoke_api_key,
    rotate_api_key,
    authenticate_api_key,
    check_agent_rate_limit,
    require_agent_auth,
    is_agent_request,
    get_audit_log,
    set_event_agent_id,
    KEY_PREFIX,
)

# Maximum HTTP request body size, in bytes. Configurable via the
# ``GREYWATCH_MAX_REQUEST_BYTES`` environment variable; defaults to 1 MiB.
# A value of 0 or negative disables the limit (explicit operator choice).
# Invalid (non-numeric) values fall back to this safe default and never
# silently disable the protection.
MAX_REQUEST_BYTES_DEFAULT = 1024 * 1024  # 1 MiB = 1,048,576 bytes

#: Sentinel distinguishing "no explicit limit passed" (resolve from the
#: environment on every request) from an explicit ``None`` ("disabled").
_UNSET = object()


def get_max_request_bytes() -> int | None:
    """Return the max request-body size in bytes, or ``None`` to disable.

    Reads ``GREYWATCH_MAX_REQUEST_BYTES`` from the environment on every call
    so tests stay hermetic via ``monkeypatch.setenv``.

    * Unset or empty -> ``MAX_REQUEST_BYTES_DEFAULT`` (1 MiB).
    * Positive integer -> that limit.
    * Zero or negative -> ``None`` (limit disabled by explicit operator choice).
    * Non-numeric -> ``MAX_REQUEST_BYTES_DEFAULT`` (safe default; never
      silently disable the protection because configuration parsing failed).
    """
    raw = os.environ.get("GREYWATCH_MAX_REQUEST_BYTES", "")
    if not raw:
        return MAX_REQUEST_BYTES_DEFAULT
    try:
        value = int(raw)
    except ValueError:
        return MAX_REQUEST_BYTES_DEFAULT
    if value <= 0:
        return None
    return value


def _client_peer(scope: dict) -> str:
    """Return the ASGI peer host; client-supplied forwarding headers are never consulted."""
    client = scope.get("client")
    if isinstance(client, (list, tuple)) and len(client) >= 1 and client[0]:
        return str(client[0])
    return "unknown"


def _log_denied_request(
    *,
    reason: str,
    method: str,
    path: str,
    status_code: int,
    peer: str,
) -> None:
    """Emit a structured denial log record.

    Best-effort: logging errors are swallowed so a logging failure can never
    turn a denied request into an allowed one (access control stays fail-closed).
    Never logs credentials, cookies, bodies, or query strings.
    """
    try:
        logger.info(
            "denied_request",
            extra={
                "event": "request_denied",
                "reason": reason,
                "method": method,
                "path": path,
                "status": status_code,
                "peer": peer,
            },
        )
    except Exception:
        pass


def _sanitize_error_message(message: str) -> str:
    """Return a client-safe error message with filesystem paths removed.

    Internal collector error messages may contain filesystem paths (EVE file
    paths, journalctl command paths, journalctl stderr). Replace Unix absolute
    paths with a generic placeholder so API clients do not receive internal
    implementation details. Full details remain available in server-side logs
    (run_loop / _run_cycle log the raw ``result.errors``).
    """
    return re.sub(r"/[^\s\"']+", "[path]", message)


def _sanitize_errors(errors: list[str]) -> list[str]:
    """Return a list of client-safe error messages."""
    return [_sanitize_error_message(e) for e in errors]


def get_api_token() -> str | None:
    """Return the configured API token, or ``None`` when unset or empty.

    This is the single point of truth for the shared-secret token used by both
    the trust boundary (access control) and the rate limiter (client identity
    in token mode). Centralizing token retrieval here prevents the two
    consumers from diverging if the environment variable is ever read
    differently elsewhere.

    * Unset or empty string -> ``None`` (no token configured).
    * Any non-empty value (including whitespace-only) -> that value, returned
      as-is. A whitespace-only token is truthy and enables token mode, but no
      caller can ever authenticate against it because the Bearer path strips
      whitespace from the provided value before comparison -- fail-closed.
    """
    token = os.environ.get("GREYWATCH_API_TOKEN")
    if not token:
        return None
    return token


def _credentials_match(provided: str, expected: str) -> bool:
    """Constant-time credential comparison tolerant of non-ASCII input.

    ``hmac.compare_digest`` raises ``TypeError`` when handed ``str`` arguments
    containing non-ASCII characters. HTTP header values are decoded as latin-1,
    so a remote client can deliver non-ASCII bytes and a denied request
    previously surfaced as an unhandled 500 instead of a fail-closed 401.
    Comparing UTF-8 *bytes* keeps the comparison constant-time and makes any
    non-matching input simply compare as unequal.
    """
    try:
        return hmac.compare_digest(
            provided.encode("utf-8"), expected.encode("utf-8")
        )
    except (AttributeError, UnicodeError):
        return False


class MaxBodySizeMiddleware:
    """ASGI middleware that rejects request bodies exceeding a byte limit.

    The limit is enforced against the *actual bytes received* as they stream
    in through ASGI ``http.request`` messages, not the ``Content-Length``
    header. Missing, malformed, or misleading length headers are therefore
    handled safely: we count real bytes and stop reading as soon as the limit
    is exceeded, so an unbounded body is never buffered.

    When the limit is exceeded, an HTTP ``413 Payload Too Large`` response is
    sent directly and the inner application is never invoked. When the limit
    is not exceeded, the bounded body is replayed to the inner application.
    """

    def __init__(self, app, max_bytes=_UNSET):
        self.app = app
        # When no explicit limit is supplied, the effective limit is resolved
        # from ``GREYWATCH_MAX_REQUEST_BYTES`` on every request (mirroring
        # RateLimitMiddleware's config=None pattern), so a running process
        # honors operator configuration without a code change. Passing an
        # explicit value (including ``None`` for "disabled") pins the limit.
        if max_bytes is _UNSET:
            self._read_env = True
            self.max_bytes = None
        else:
            self._read_env = False
            # A limit of 0 or negative is treated as "disabled" (no limit).
            if max_bytes is not None and max_bytes <= 0:
                max_bytes = None
            self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        max_bytes = get_max_request_bytes() if self._read_env else self.max_bytes
        if scope["type"] != "http" or max_bytes is None:
            await self.app(scope, receive, send)
            return
        received = 0
        chunks: list[bytes] = []

        while True:
            message = await receive()
            message_type = message["type"]
            if message_type == "http.request":
                body = message.get("body", b"")
                received += len(body)
                chunks.append(body)
                if received > max_bytes:
                    _log_denied_request(
                        reason="request_body_too_large",
                        method=scope.get("method", ""),
                        path=scope.get("path", "/"),
                        status_code=413,
                        peer=_client_peer(scope),
                    )
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 413,
                            "headers": [[b"content-type", b"application/json"]],
                        }
                    )
                    await send(
                        {
                            "type": "http.response.body",
                            "body": b'{"detail":"Request body too large"}',
                        }
                    )
                    return
                if not message.get("more_body"):
                    break
            elif message_type == "http.disconnect":
                await self.app(scope, receive, send)
                return
            else:
                await self.app(scope, receive, send)
                return

        full_body = b"".join(chunks)

        async def replay_receive():
            return {
                "type": "http.request",
                "body": full_body,
                "more_body": False,
            }

        await self.app(scope, replay_receive, send)


# --------------------------------------------------------------------------- #
# Configurable API rate limiting (security review F2)
# --------------------------------------------------------------------------- #


@dataclass
class RateLimitConfig:
    """Runtime configuration for the API rate limiter.

    Limits are expressed as requests per minute. The burst capacity for a
    category is ``limit * burst_multiplier``.
    """

    enabled: bool = True
    ingestion: int = 60      # POST /api/v1/events/ingest
    reads: int = 120         # GET /api/v1/events, /alerts, /alerts/{id}, status
    collector: int = 30      # POST /api/v1/journal/collect, /suricata/collect
    alert_close: int = 30    # POST /api/v1/alerts/{id}/close
    burst_multiplier: int = 2


def _parse_positive_int(raw: str | None, default: int) -> int:
    """Parse a positive integer, returning ``default`` on any failure.

    Non-numeric, empty, zero, or negative values all fall back to ``default``
    so that misconfiguration never silently disables protection.
    """
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _parse_bool(raw: str | None, default: bool) -> bool:
    """Parse a boolean environment variable; invalid values fall back to default."""
    if raw is None:
        return default
    v = raw.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


def get_rate_limit_config() -> RateLimitConfig:
    """Return the rate-limiter configuration from the environment.

    Reads on every call so tests stay hermetic via ``monkeypatch.setenv``.
    Invalid values fall back to the documented safe defaults and never
    silently disable rate limiting. Disabling must be an explicit operator
    choice (``GREYWATCH_RATE_LIMIT_ENABLED=0/false/no``).
    """
    return RateLimitConfig(
        enabled=_parse_bool(os.environ.get("GREYWATCH_RATE_LIMIT_ENABLED"), True),
        ingestion=_parse_positive_int(
            os.environ.get("GREYWATCH_RATE_LIMIT_INGESTION"), 60
        ),
        reads=_parse_positive_int(os.environ.get("GREYWATCH_RATE_LIMIT_READS"), 120),
        collector=_parse_positive_int(
            os.environ.get("GREYWATCH_RATE_LIMIT_COLLECTOR"), 30
        ),
        alert_close=_parse_positive_int(
            os.environ.get("GREYWATCH_RATE_LIMIT_ALERT_CLOSE"), 30
        ),
        burst_multiplier=_parse_positive_int(
            os.environ.get("GREYWATCH_RATE_LIMIT_BURST_MULTIPLIER"), 2
        ),
    )


# Category of each protected path, used to select the per-category limit.
_PATH_CATEGORIES: dict[str, str] = {
    "/api/v1/events/ingest": "ingestion",
    "/api/v1/incidents": "reads",
    "/api/v1/journal/collect": "collector",
    "/api/v1/suricata/collect": "collector",
    "/api/v1/alerts/{alert_id}/close": "alert_close",
}


def _category_for_path(path: str) -> str | None:
    """Return the rate-limit category for a path, or None if it is exempt."""
    if path in PUBLIC_PATHS:
        return None
    if path.startswith("/api/v1/alerts/") and path.endswith("/close"):
        return "alert_close"
    if path.startswith("/api/v1/incidents/") and (
        path.endswith("/acknowledge") or path.endswith("/resolve")
    ):
        return "alert_close"
    return _PATH_CATEGORIES.get(path, "reads")


class RateLimitMiddleware:
    """ASGI middleware that rate limits requests using a token bucket.

    A token bucket is kept per client identity. Each allowed request consumes
    one token; tokens refill at the configured rate (requests per minute).
    When the bucket is empty the request is rejected with HTTP 429 and a
    ``Retry-After`` header.

    The bucket store is bounded by ``max_entries``; when full the least
    recently used entry is evicted so memory growth is capped. The middleware
    never logs, exposes, or returns the shared API token. Client identity is
    derived solely from the ASGI peer (``scope["client"]``) or, in token mode,
    the shared token value itself -- forwarding headers are never consulted.
    """

    def __init__(
        self,
        app,
        config: RateLimitConfig | None = None,
        clock: Callable[[], float] | None = None,
        max_entries: int = 10000,
    ):
        self.app = app
        # ``config`` may be ``None``: in that case configuration is resolved
        # from the environment on every request (used by the shared global
        # app so tests can flip it via conftest). When an explicit config is
        # passed (as focused tests do), it takes precedence.
        self.config = config
        self.clock = clock or time.monotonic
        self._max_entries = max(1, int(max_entries))
        #: bucket key -> [tokens, last_update]
        self._buckets: dict[object, list] = {}

    def _client_key(self, scope) -> object:
        """Derive a rate-limit key from the request, never forwarding headers.

        In token mode (``GREYWATCH_API_TOKEN`` set) all authenticated callers
        share one bucket keyed by the token value itself (shared-secret model).
        In loopback mode the key is the ASGI peer host. The raw token is used
        only as an internal dictionary key and is never logged or returned.
        """
        token = get_api_token()
        if token:
            return ("token", token)
        client = scope.get("client")
        host = client[0] if client else None
        return ("ip", host or "unknown")

    def _limit_for_path(self, path: str, cfg: RateLimitConfig) -> int | None:
        """Return the requests-per-minute limit for a path, or None if exempt."""
        category = _category_for_path(path)
        if category is None:
            return None
        return getattr(cfg, category)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        cfg = self.config or get_rate_limit_config()
        if not cfg.enabled:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "/")
        limit = self._limit_for_path(path, cfg)
        if limit is None:
            # Public path or otherwise exempt.
            await self.app(scope, receive, send)
            return

        key = self._client_key(scope)
        now = self.clock()
        refill_per_sec = limit / 60.0
        capacity = limit * cfg.burst_multiplier

        tokens, last_update = self._buckets.get(key, [capacity, now])
        elapsed = max(0.0, now - last_update)
        tokens = min(capacity, tokens + elapsed * refill_per_sec)
        last_update = now

        if tokens < 1.0:
            _log_denied_request(
                reason="rate_limit_exceeded",
                method=scope.get("method", ""),
                path=scope.get("path", "/"),
                status_code=429,
                peer=_client_peer(scope),
            )
            retry_after = max(1, math.ceil((1.0 - tokens) / refill_per_sec))
            await send(
                {
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"retry-after", str(retry_after).encode("ascii")],
                    ],
                }
            )
            await send(
                {"type": "http.response.body", "body": b'{"detail":"Rate limit exceeded"}'}
            )
            return

        tokens -= 1.0
        self._buckets[key] = [tokens, last_update]

        # Bound the store: evict the least recently used entry when full.
        if len(self._buckets) > self._max_entries:
            oldest = min(self._buckets.items(), key=lambda kv: kv[1][1])
            del self._buckets[oldest[0]]

        await self.app(scope, receive, send)


def _get_backup_dir(require: bool = False) -> Path:
    """Get the backup directory from environment.

    Args:
        require: If True, raise RuntimeError for missing/invalid configuration
                 instead of returning None. Used when GREYWATCH_REQUIRE_BACKUP=1.

    Returns:
        Path to the backup directory.

    Raises:
        RuntimeError: If directory is not configured, empty, nonexistent,
                      or not a directory (when require=True).
    """
    raw = os.environ.get("GREYWATCH_BACKUP_DIR", "")
    if not raw:
        if require:
            raise RuntimeError(
                "GREYWATCH_REQUIRE_BACKUP=1 is set but GREYWATCH_BACKUP_DIR "
                "is not configured. Set GREYWATCH_BACKUP_DIR to a valid "
                "directory path, e.g., '/var/backups/greywatch'."
            )
        return None  # type: ignore[return-value]

    path = Path(raw)
    if not path.exists():
        if require:
            raise RuntimeError(
                f"GREYWATCH_BACKUP_DIR is set to '{path}' but the directory "
                "does not exist. Create the directory or correct the path."
            )
        return None  # type: ignore[return-value]

    if not path.is_dir():
        if require:
            raise RuntimeError(
                f"GREYWATCH_BACKUP_DIR is set to '{path}' but it is not a "
                "directory. Provide a valid directory path."
            )
        return None  # type: ignore[return-value]

    return path


def _verify_backup_exists(db_path: Path) -> Path | None:
    """Find and verify the most recent backup.

    Returns the backup path if a valid backup exists, None otherwise.

    Expected verification failures (corrupt backup, inaccessible file, etc.)
    are logged and result in None being returned, triggering fail-closed startup.
    Truly unexpected exceptions are propagated with context.
    """
    import time
    import sqlite3

    from scripts.gw_db_backup import BackupError

    # When backup is required, validate the directory configuration strictly
    require_backup = os.environ.get("GREYWATCH_REQUIRE_BACKUP", "").lower() in ("1", "true", "yes", "on")
    backup_dir = _get_backup_dir(require=require_backup)
    if not backup_dir:
        return None

    # Find the latest backup file
    backups = sorted(backup_dir.glob("greywatch.db.*"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not backups:
        return None

    latest_backup = backups[0]

    # Check backup age against GREYWATCH_MAX_BACKUP_AGE_HOURS (default 24h)
    max_age_hours = int(os.environ.get("GREYWATCH_MAX_BACKUP_AGE_HOURS", "24"))
    max_age_seconds = max_age_hours * 3600
    backup_age = time.time() - latest_backup.stat().st_mtime
    if backup_age > max_age_seconds:
        logger.warning(
            f"Latest backup {latest_backup} is {backup_age / 3600:.1f}h old, "
            f"exceeds max age of {max_age_hours}h"
        )
        return None

    # Verify the backup is a valid SQLite database
    try:
        from scripts.gw_db_backup import verify_database
        verify_database(str(latest_backup), what="backup")
    except (sqlite3.DatabaseError, OSError, ValueError, BackupError) as exc:
        # Expected verification failures: corrupt database, permission denied,
        # invalid format, or BackupError from verify_database (integrity/fk check)
        logger.warning(f"Backup verification failed for {latest_backup}: {exc}")
        return None

    return latest_backup


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for database initialization.

    Startup sequence:
    1. Resolve configured database path
    2. Ensure parent directory exists
    3. Safely create database file if necessary (atomic publication)
    4. Inspect migration state
    5. If migration required, perform backup preflight (when required)
    6. Execute migration runner
    7. Verify final database state
    8. Mark schema as managed by runner (guard activation)
    9. Start application

    Fails closed on any error -- application will not start.
    """
    # 1. Resolve database path
    db_path = Path(os.environ.get("GREYWATCH_DB", str(DEFAULT_DB_PATH)))

    # 2. Ensure parent directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)

    # 3. Safely create database file if missing
    try:
        ensure_database_file_exists(db_path)
    except MigrationStateError as exc:
        logger.error(f"Failed to create database file: {exc}")
        raise RuntimeError(f"Database initialization failed: {exc}") from exc

    # 4. Inspect migration state
    report = inspect_path(db_path)

    # 5. Check if migration is required
    migratable_states = {
        DatabaseState.FRESH,
        DatabaseState.LEDGER_ONLY,
        DatabaseState.LEGACY_READY,
        DatabaseState.PENDING,
    }

    # Track if migration was applied
    migration_applied = 0

    # 6. Backup preflight for migratable states
    require_backup = os.environ.get("GREYWATCH_REQUIRE_BACKUP", "").lower() in ("1", "true", "yes", "on")
    if require_backup and report.state in migratable_states:
        backup_path = _verify_backup_exists(db_path)
        if backup_path is None:
            # _verify_backup_exists will have logged the specific reason
            raise RuntimeError(
                f"Backup required but no valid backup found. "
                f"Check logs for details (age, corruption, missing directory)."
            )
        logger.info(f"Backup verified: {backup_path}")

    # 7. Execute migration if needed
    if report.state in migratable_states:
        try:
            result = migrate(str(db_path), dry_run=False)
            logger.info(f"Migration completed: {result}")
            if result.get("applied", 0) > 0:
                migration_applied = 1
        except (MigrationError, MigrationStateError, MigrationConflictError) as exc:
            logger.error(f"Migration failed: {exc}")
            raise RuntimeError(f"Database migration failed: {exc}") from exc
    else:
        # For CURRENT, UNVERSIONED, etc. - no migration needed
        logger.info(f"Database state: {report.state.value}; no migration required")

    # Store migration status in app state for health endpoint
    app.state.migration_applied = migration_applied
    app.state.schema_ready = True

    # 8. Verify final state
    final_report = inspect_path(db_path)
    if final_report.state not in (DatabaseState.CURRENT, DatabaseState.UNVERSIONED):
        logger.error(f"Database in unexpected state after startup: {final_report.state.value}")
        raise RuntimeError(
            f"Database in unexpected state after startup: {final_report.state.value}"
        )

    # 9. Activate guard so legacy initialize_database() cannot bypass
    from .siem import _set_schema_managed_by_runner
    _set_schema_managed_by_runner()

    logger.info("Database startup initialization complete")

    yield

    # Shutdown: nothing to clean up


app = FastAPI(
    title="Greywatch API",
    description="Open-source security monitoring and SIEM platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(RateLimitMiddleware)

app.add_middleware(MaxBodySizeMiddleware)


class IngestRequest(BaseModel):
    lines: list[str] = Field(min_length=1, max_length=1000)
    # Optional, client-generated idempotency key per event. ``event_ids[i]`` is
    # the stable identifier for ``lines[i]``; entries may be ``None`` for events
    # the client does not wish to idempotency-key (they keep the existing
    # stateless, non-deduplicated behavior). When provided, the list must be the
    # same length as ``lines``.
    event_ids: list[str | None] | None = None


# --------------------------------------------------------------------------- #
# Trust boundary (applied to ALL requests by the _trust_boundary middleware)
# --------------------------------------------------------------------------- #
#
# The ``GREYWATCH_JOURNAL_ENABLED`` and ``GREYWATCH_SURICATA_ENABLED`` flags are
# *collection toggles* (they start/stop the continuous collector loop), never
# access control. The endpoint docstrings below make this explicit. Access to
# the write/collect endpoints is instead enforced here, in two modes:
#
#   * Token (network exposure): if ``GREYWATCH_API_TOKEN`` is set, callers must
#     authenticate with ``Authorization: Bearer <token>`` or ``X-API-Key:
#     <token>``. Comparison is constant-time. Missing/invalid -> 401.
#   * Loopback (local default): with no token set (the default for local
#     development), only loopback peers may invoke these endpoints; remote
#     peers get 403. Set ``GREYWATCH_API_LOOPBACK_ONLY=0`` to disable this
#     check (e.g. behind an authenticating reverse proxy).
#
# The server is launched with ``uvicorn`` (see README), whose default bind is
# loopback, so the intended local/trusted-host deployment already passes this
# gate. This guard additionally protects operators who re-launch with
# ``--host 0.0.0.0``: only ``/`` and ``/health`` are public, while every other
# endpoint -- including the read endpoints that expose raw_message and alert
# evidence -- is gated (loopback peer or a valid token). The dashboard (static
# JS) cannot carry a token, so it assumes a local / trusted-host browser; a
# network-exposed dashboard requires an auth-terminating reverse proxy.


def _is_loopback_host(host: str | None) -> bool:
    """Whether the request peer is the local/trusted host.

    Starlette's :class:`~starlette.testclient.TestClient` advertises the
    sentinel peer host ``"testclient"``, which is treated as local so local
    development and tests are unaffected. A concrete peer is matched with
    :func:`ipaddress.ip_address` -- only loopback addresses (``127.0.0.0/8``,
    ``::1``) are accepted.

    An **unknown** peer (``host is None``; the ASGI scope provided no client
    address) is treated as **not** loopback: fail-closed, never silently
    trusted. Operators behind a peer-hiding proxy should set a token or disable
    the loopback check (see :func:`_check_trust_boundary`) instead of relying on
    the peer alone.
    """
    if host == "testclient":
        # Starlette's TestClient advertises the sentinel peer host "testclient";
        # treat it as local so local dev / tests are unaffected.
        return True
    # An unknown peer (ASGI scope provided no client address) is NOT trusted:
    # fail-closed. Operators behind a peer-hiding proxy must set a token or
    # GREYWATCH_API_LOOPBACK_ONLY=0 rather than relying on the peer check.
    if not host:
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


PUBLIC_PATHS = frozenset({"/", "/health"})


def _check_trust_boundary(request: Request) -> tuple[int, str] | None:
    """Evaluate Greywatch's trust boundary for a single request.

    Returns ``(status_code, detail)`` when the request must be denied, or
    ``None`` when it is allowed through.

    Three authentication modes:
    1. Agent API Key (gw_*): Valid for ingestion endpoints only (/api/v1/events/ingest).
       Agent keys are denied for admin/read endpoints.
    2. Legacy Token (GREYWATCH_API_TOKEN): Valid for all non-public endpoints.
    3. Loopback (default): Only loopback peers allowed for non-public endpoints.

    The check applies uniformly to reads and writes in modes 2 and 3.
    In mode 1 (agent key), access is restricted to ingestion endpoints only.
    """
    path = request.url.path

    # Check for agent API key first (gw_* prefix)
    auth_header = request.headers.get("Authorization", "")
    api_key_header = request.headers.get("X-API-Key", "")

    provided_key = None
    if auth_header.startswith("Bearer "):
        provided_key = auth_header[len("Bearer "):].strip()
    elif api_key_header:
        provided_key = api_key_header.strip()

    if provided_key and provided_key.startswith(KEY_PREFIX):
        # Agent API key authentication - only allow ingestion endpoints
        result = authenticate_api_key(provided_key)
        if not result:
            return 401, "Invalid or revoked agent API key"

        # Agent keys can ONLY access ingestion endpoints
        allowed_agent_paths = {
            "/api/v1/events/ingest",
        }
        if path not in allowed_agent_paths:
            return 403, "Agent API keys are restricted to ingestion endpoints only"

        # Attach agent context to request for downstream use
        request.state.agent = result.agent
        request.state.api_key = result.api_key
        return None

    # Legacy token authentication (GREYWATCH_API_TOKEN)
    token = get_api_token()
    if token:
        provided = request.headers.get("Authorization", "")
        credentials_ok = False
        if provided.startswith("Bearer "):
            credentials_ok = _credentials_match(
                provided[len("Bearer "):].strip(), token
            )
        if not credentials_ok:
            api_key = request.headers.get("X-API-Key", "")
            if api_key:
                credentials_ok = _credentials_match(api_key, token)
        if not credentials_ok:
            return 401, "Authentication required"
        return None

    # Loopback mode (default)
    if os.environ.get("GREYWATCH_API_LOOPBACK_ONLY", "1").lower() in (
        "0",
        "false",
        "no",
    ):
        return None

    peer = request.client.host if request.client else None
    if not _is_loopback_host(peer):
        return (
            403,
            "Greywatch's API is restricted to the local host by default. Set "
            "GREYWATCH_API_TOKEN to authenticate remote callers, or set "
            "GREYWATCH_API_LOOPBACK_ONLY=0 behind an authenticating reverse "
            "proxy.",
        )
    return None


@app.middleware("http")
async def _trust_boundary(request: Request, call_next):
    """Apply the trust boundary to every request.

    ``/`` and ``/health`` are public (load-balancer boot checks); every other
    endpoint -- including the read endpoints that expose event/alert data -- is
    subject to :func:`_check_trust_boundary`. A denied request never reaches the
    downstream handler, so a failed-auth request has no collection/ingest side
    effects.
    """
    if request.url.path in PUBLIC_PATHS:
        return await call_next(request)
    denied = _check_trust_boundary(request)
    if denied is not None:
        status_code, detail = denied
        _log_denied_request(
            reason="authentication_required"
            if status_code == 401
            else "remote_peer_not_allowed",
            method=request.method,
            path=request.url.path,
            status_code=status_code,
            peer=_client_peer(request.scope),
        )
        headers = {"WWW-Authenticate": "Bearer"} if status_code == 401 else {}
        return JSONResponse(
            status_code=status_code,
            headers=headers,
            content={"detail": detail},
        )
    return await call_next(request)


@app.get("/", tags=["meta"])
def root():
    return {
        "name": "Greywatch",
        "status": "in-development",
        "docs": "/docs",
    }


@app.get("/health", tags=["meta"])
def health(request: Request):
    # Lightweight health check - avoid PRAGMA quick_check on every request
    # Just verify the database file exists and we can connect
    import os
    from pathlib import Path
    from .siem import DEFAULT_DB_PATH, _connection

    db_path = Path(os.environ.get("GREYWATCH_DB", str(DEFAULT_DB_PATH)))
    db_exists = db_path.exists()

    # Try a simple connection test without full inspection
    schema_ready = False
    database_state = "unknown"
    if db_exists:
        try:
            with _connection() as conn:
                conn.execute("SELECT 1").fetchone()
            schema_ready = True
            database_state = "connected"
        except Exception:
            schema_ready = False
            database_state = "error"

    # Get migration status from app state
    migration_applied = getattr(request.app.state, "migration_applied", 0)

    return {
        "status": "ok" if schema_ready else "degraded",
        "service": "greywatch-api",
        "version": "0.1.0",
        "schema_ready": schema_ready,
        "migration_applied": migration_applied,
        "database_state": database_state,
    }


@app.post("/api/v1/events/ingest", tags=["ingestion"])
def ingest(request: IngestRequest, http_request: Request):
    """Ingest raw log lines and evaluate configured detection rules.

    Access is governed by the Greywatch trust boundary (see
    :func:`_trust_boundary`); this endpoint is not gated by any
    ``GREYWATCH_*_ENABLED`` feature flag.

    Each ``lines[i]`` may be idempotency-keyed by ``event_ids[i]`` (a
    client-generated stable identifier). Replaying the same identifier does not
    insert a duplicate event or increment detection counts; see
    :func:`backend.app.siem.ingest_lines` for the count contract.

    Agent attribution: if authenticated with an agent API key, events are
    automatically attributed to that agent. The agent identity comes from the
    authenticated request context, never from the event body.
    """
    # Get agent_id from request context (set by trust boundary for agent auth)
    agent_id = getattr(http_request.state, "agent", None)
    agent_id = agent_id.id if agent_id else None

    try:
        return ingest_lines(request.lines, request.event_ids, agent_id=agent_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/v1/events", tags=["events"])
def get_events(
    limit: int = Query(default=100, ge=1, le=500),
):
    events = list_events(limit)
    return {"count": len(events), "events": events}


@app.get("/api/v1/alerts", tags=["alerts"])
def get_alerts(
    status: Literal["open", "closed", "all"] = "open",
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    source_ip: str | None = Query(default=None),
):
    """List alerts with server-side pagination and optional source-IP filter.

    ``count`` is the number of alerts on this page; ``total`` is the number of
    alerts matching ``status``/``source_ip`` across all pages.
    """
    alerts = list_alerts(status=status, limit=limit, offset=offset, source_ip=source_ip)
    return {
        "count": len(alerts),
        "total": count_alerts(status=status, source_ip=source_ip),
        "alerts": alerts,
    }


@app.get("/api/v1/alerts/{alert_id}", tags=["alerts"])
def get_alert(alert_id: int):
    result = get_alert_detail(alert_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return result


@app.post("/api/v1/alerts/{alert_id}/close", tags=["alerts"])
def resolve_alert(alert_id: int):
    if not close_alert(alert_id):
        raise HTTPException(
            status_code=404,
            detail="Open alert not found",
        )

    return {"id": alert_id, "status": "closed"}


@app.get("/api/v1/incidents", tags=["incidents"])
def get_incidents(
    status: Literal["open", "acknowledged", "resolved", "all"] = "open",
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    source_ip: str | None = Query(default=None),
):
    """List correlated incidents.

    Supports server-side pagination via ``limit`` and ``offset`` and optional
    filtering by ``source_ip``. ``count`` is the number of incidents on this
    page; ``total`` is the number of incidents matching ``status``/``source_ip``
    across all pages.

    Access is governed by the Greywatch trust boundary (see
    :func:`_trust_boundary`).
    """
    incidents = list_incidents(
        status=status, limit=limit, offset=offset, source_ip=source_ip
    )
    return {
        "count": len(incidents),
        "total": count_incidents(status=status, source_ip=source_ip),
        "incidents": incidents,
    }


@app.get("/api/v1/incidents/{incident_id}", tags=["incidents"])
def get_incident_endpoint(incident_id: int):
    """Return a single incident with its related events in chronological order."""
    result = get_incident(incident_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return result


@app.post("/api/v1/incidents/{incident_id}/acknowledge", tags=["incidents"])
def acknowledge_incident_endpoint(incident_id: int):
    """Acknowledge an open incident (open -> acknowledged)."""
    result = acknowledge_incident(incident_id)
    if not result["ok"]:
        if result["error"] == "not_found":
            raise HTTPException(status_code=404, detail="Incident not found")
        raise HTTPException(
            status_code=409,
            detail=(
                f"Cannot acknowledge incident in status "
                f"'{result.get('status', 'unknown')}'"
            ),
        )
    incident = get_incident(incident_id)
    return {"id": incident_id, "status": incident["status"]}


@app.post("/api/v1/incidents/{incident_id}/resolve", tags=["incidents"])
def resolve_incident_endpoint(incident_id: int):
    """Resolve an open or acknowledged incident (-> resolved)."""
    result = resolve_incident(incident_id)
    if not result["ok"]:
        if result["error"] == "not_found":
            raise HTTPException(status_code=404, detail="Incident not found")
        raise HTTPException(
            status_code=409,
            detail=(
                f"Cannot resolve incident in status "
                f"'{result.get('status', 'unknown')}'"
            ),
        )
    incident = get_incident(incident_id)
    return {"id": incident_id, "status": incident["status"]}


@app.get("/api/v1/journal/status", tags=["journal"])
def journal_status():
    """Report journal-collection checkpoint state and enabled flag."""
    return collector.status()


@app.post("/api/v1/journal/collect", tags=["journal"])
def journal_collect():
    """Trigger a single journal collection cycle.

    Useful for manual collection and verification. **Continuous collection** is
    controlled by ``GREYWATCH_JOURNAL_ENABLED`` (a collection *toggle*); this
    endpoint runs one cycle regardless of that toggle. **Access** is governed by
    the Greywatch trust boundary (``GREYWATCH_API_TOKEN``, or loopback
    enforcement) -- see :func:`_trust_boundary` -- and is never implied by
    this flag. Returns a summary of the cycle.
    """
    config = collector.get_config()
    result = collector.collect_once(config)
    return {
        "records_seen": result.records_seen,
        "events_ingested": result.events_ingested,
        "alerts": result.new_alerts,
        "fallback_used": result.fallback_used,
        "errors": _sanitize_errors(result.errors),
    }


@app.get("/api/v1/suricata/status", tags=["suricata"])
def suricata_status():
    """Return Suricata EVE collector checkpoint state.

    Suricata collection is optional and disabled by default. The collector
    state (`last_offset`, `last_event_ts`, `events_ingested`, `last_run_at`)
    lives in the shared `collector_state` table alongside the journal
    collector. A missing EVE file is reported here as ``last_offset: null``.
    """
    return suricata.status()


@app.post("/api/v1/suricata/collect", tags=["suricata"])
def suricata_collect():
    """Trigger a single Suricata EVE collection cycle.

    Useful for manual collection and verification. **Continuous collection** is
    controlled by ``GREYWATCH_SURICATA_ENABLED`` (a collection *toggle*); this
    endpoint runs one cycle regardless of that toggle. **Access** is governed by
    the Greywatch trust boundary (``GREYWATCH_API_TOKEN``, or loopback
    enforcement) -- see :func:`_trust_boundary` -- and is never implied by
    this flag. If the EVE file is missing or unreadable the error is reported in
    `errors` (HTTP 200) rather than raised.
    """
    config = suricata.get_config()
    result = suricata.collect_once(config)
    return {
        "records_seen": result.records_seen,
        "events_ingested": result.events_ingested,
        "alerts": result.new_alerts,
        "fallback_used": result.fallback_used,
        "errors": _sanitize_errors(result.errors),
    }


# =============================================================================
# Agent Management Endpoints (Admin Only)
# =============================================================================

class AgentCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, pattern=r"^[a-zA-Z0-9_-]+$")
    display_name: str | None = Field(default=None, max_length=256)
    description: str | None = Field(default=None, max_length=1024)


class AgentUpdateRequest(BaseModel):
    display_name: str | None = Field(default=None, max_length=256)
    description: str | None = Field(default=None, max_length=1024)


class AgentDeactivateRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=512)


class ApiKeyCreateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=128)
    expires_at: str | None = Field(default=None, pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:?\d{2})?$")


class ApiKeyRevokeRequest(BaseModel):
    reason: str = Field(..., min_length=1, max_length=512)


class ApiKeyRotateRequest(BaseModel):
    pass  # No body needed


@app.get("/api/v1/admin/agents", tags=["admin", "agents"])
def admin_list_agents(
    status: str | None = Query(default=None, pattern=r"^(active|inactive|revoked)$"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """List all agents (admin only).

    Requires legacy token authentication or loopback access.
    Agent API keys cannot access this endpoint.
    """
    agents = list_agents(status=status, limit=limit, offset=offset)
    return {
        "count": len(agents),
        "agents": [
            {
                "id": a.id,
                "name": a.name,
                "display_name": a.display_name,
                "description": a.description,
                "status": a.status,
                "created_at": a.created_at,
                "updated_at": a.updated_at,
                "last_seen_at": a.last_seen_at,
                "deactivated_at": a.deactivated_at,
                "deactivated_reason": a.deactivated_reason,
            }
            for a in agents
        ],
    }


@app.get("/api/v1/admin/agents/{agent_id}", tags=["admin", "agents"])
def admin_get_agent(agent_id: int):
    """Get agent details (admin only)."""
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "id": agent.id,
        "name": agent.name,
        "display_name": agent.display_name,
        "description": agent.description,
        "status": agent.status,
        "created_at": agent.created_at,
        "updated_at": agent.updated_at,
        "last_seen_at": agent.last_seen_at,
        "deactivated_at": agent.deactivated_at,
        "deactivated_reason": agent.deactivated_reason,
    }


@app.post("/api/v1/admin/agents", tags=["admin", "agents"])
def admin_create_agent(request: AgentCreateRequest):
    """Create a new agent (admin only)."""
    try:
        agent = create_agent(
            name=request.name,
            display_name=request.display_name,
            description=request.description,
            actor="admin_api",
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return {
        "id": agent.id,
        "name": agent.name,
        "display_name": agent.display_name,
        "description": agent.description,
        "status": agent.status,
        "created_at": agent.created_at,
        "updated_at": agent.updated_at,
    }


@app.patch("/api/v1/admin/agents/{agent_id}", tags=["admin", "agents"])
def admin_update_agent(agent_id: int, request: AgentUpdateRequest):
    """Update agent metadata (admin only)."""
    agent = update_agent(
        agent_id,
        display_name=request.display_name,
        description=request.description,
        actor="admin_api",
    )
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return {
        "id": agent.id,
        "name": agent.name,
        "display_name": agent.display_name,
        "description": agent.description,
        "status": agent.status,
        "created_at": agent.created_at,
        "updated_at": agent.updated_at,
    }


@app.post("/api/v1/admin/agents/{agent_id}/deactivate", tags=["admin", "agents"])
def admin_deactivate_agent(agent_id: int, request: AgentDeactivateRequest):
    """Deactivate an agent and revoke all its keys (admin only)."""
    success = deactivate_agent(agent_id, request.reason, actor="admin_api")
    if not success:
        agent = get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        raise HTTPException(status_code=409, detail="Agent is not active")
    return {"id": agent_id, "status": "inactive"}


@app.get("/api/v1/admin/agents/{agent_id}/keys", tags=["admin", "agents"])
def admin_list_agent_keys(agent_id: int, status: str | None = Query(default=None, pattern=r"^(active|revoked|expired)$")):
    """List API keys for an agent (admin only)."""
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    keys = list_api_keys(agent_id, status=status)
    return {
        "count": len(keys),
        "keys": [
            {
                "id": k.id,
                "key_prefix": k.key_prefix,
                "name": k.name,
                "status": k.status,
                "created_at": k.created_at,
                "expires_at": k.expires_at,
                "revoked_at": k.revoked_at,
                "revoked_reason": k.revoked_reason,
                "last_used_at": k.last_used_at,
            }
            for k in keys
        ],
    }


@app.post("/api/v1/admin/agents/{agent_id}/keys", tags=["admin", "agents"])
def admin_create_agent_key(agent_id: int, request: ApiKeyCreateRequest):
    """Create a new API key for an agent (admin only).

    The plaintext key is returned ONLY ONCE in the response.
    Store it securely - it cannot be retrieved again.
    """
    agent = get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    if agent.status != "active":
        raise HTTPException(status_code=409, detail="Agent is not active")

    try:
        key = create_api_key(
            agent_id=agent_id,
            name=request.name,
            expires_at=request.expires_at,
            actor="admin_api",
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    return {
        "id": key.id,
        "key_prefix": key.key_prefix,
        "name": key.name,
        "plaintext_key": key.plaintext_key,  # ONLY returned once!
        "status": key.status,
        "created_at": key.created_at,
        "expires_at": key.expires_at,
    }


@app.post("/api/v1/admin/keys/{key_id}/revoke", tags=["admin", "agents"])
def admin_revoke_key(key_id: int, request: ApiKeyRevokeRequest):
    """Revoke an API key (admin only)."""
    success = revoke_api_key(key_id, request.reason, actor="admin_api")
    if not success:
        key = get_api_key(key_id)
        if not key:
            raise HTTPException(status_code=404, detail="API key not found")
        raise HTTPException(status_code=409, detail="Key is not active")
    return {"id": key_id, "status": "revoked"}


@app.post("/api/v1/admin/keys/{key_id}/rotate", tags=["admin", "agents"])
def admin_rotate_key(key_id: int):
    """Rotate an API key (admin only).

    Creates a new key and immediately revokes the old one in a single transaction.
    The new key's plaintext is returned ONLY ONCE in the response.
    """
    try:
        key = rotate_api_key(key_id, actor="admin_api")
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    return {
        "id": key.id,
        "key_prefix": key.key_prefix,
        "name": key.name,
        "plaintext_key": key.plaintext_key,  # ONLY returned once!
        "status": key.status,
        "created_at": key.created_at,
        "expires_at": key.expires_at,
    }


@app.get("/api/v1/admin/audit-log", tags=["admin", "audit"])
def admin_get_audit_log(
    agent_id: int | None = Query(default=None),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    """Get audit log entries (admin only)."""
    entries = get_audit_log(agent_id=agent_id, event_type=event_type, limit=limit, offset=offset)
    return {
        "count": len(entries),
        "entries": entries,
    }
