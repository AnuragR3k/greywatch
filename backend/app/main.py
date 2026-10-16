"""Greywatch API entry point."""

import hmac
import ipaddress
import os
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .siem import (
    close_alert,
    get_alert_detail,
    ingest_lines,
    list_alerts,
    list_events,
)
from . import collector
from . import suricata

# Maximum HTTP request body size, in bytes. Configurable via the
# ``GREYWATCH_MAX_REQUEST_BYTES`` environment variable; defaults to 1 MiB.
# A value of 0 or negative disables the limit (explicit operator choice).
# Invalid (non-numeric) values fall back to this safe default and never
# silently disable the protection.
MAX_REQUEST_BYTES_DEFAULT = 1024 * 1024  # 1 MiB = 1,048,576 bytes


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

    def __init__(self, app, max_bytes: int | None = None):
        self.app = app
        # A limit of 0 or negative is treated as "disabled" (no limit).
        if max_bytes is not None and max_bytes <= 0:
            max_bytes = None
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or self.max_bytes is None:
            await self.app(scope, receive, send)
            return

        max_bytes = self.max_bytes
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


app = FastAPI(
    title="Greywatch API",
    description="Open-source security monitoring and SIEM platform",
    version="0.1.0",
)

app.add_middleware(MaxBodySizeMiddleware, max_bytes=get_max_request_bytes())


class IngestRequest(BaseModel):
    lines: list[str] = Field(min_length=1, max_length=1000)


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
    ``None`` when it is allowed through. See the module-level comment above for
    the two modes:

    * Token (network exposure): if ``GREYWATCH_API_TOKEN`` is set, the caller
      must authenticate with ``Authorization: Bearer <token>`` or
      ``X-API-Key: <token>``; missing/invalid -> 401. IP is irrelevant in this
      mode, so the check applies uniformly to reads and writes.
    * Loopback (local default): with no token set, only loopback peers
      (127.0.0.1 / ::1, plus the TestClient sentinel "testclient") may use
      non-public endpoints; a remote or UNKNOWN peer -> 403. The peer is read
      from the ASGI connection (``request.client.host``); forwarding headers
      are not consulted, so they cannot spoof loopback.
    """
    token = os.environ.get("GREYWATCH_API_TOKEN")
    if token:
        provided = request.headers.get("Authorization", "")
        credentials_ok = False
        if provided.startswith("Bearer "):
            credentials_ok = hmac.compare_digest(
                provided[len("Bearer "):].strip(), token
            )
        if not credentials_ok:
            api_key = request.headers.get("X-API-Key", "")
            if api_key:
                credentials_ok = hmac.compare_digest(api_key, token)
        if not credentials_ok:
            return 401, "Authentication required"
        return None

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
def health():
    return {
        "status": "ok",
        "service": "greywatch-api",
        "version": "0.1.0",
    }


@app.post("/api/v1/events/ingest", tags=["ingestion"])
def ingest(request: IngestRequest):
    """Ingest raw log lines and evaluate configured detection rules.

    Access is governed by the Greywatch trust boundary (see
    :func:`_trust_boundary`); this endpoint is not gated by any
    ``GREYWATCH_*_ENABLED`` feature flag.
    """
    return ingest_lines(request.lines)


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
):
    alerts = list_alerts(status=status, limit=limit)
    return {"count": len(alerts), "alerts": alerts}


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
        "errors": result.errors,
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
        "errors": result.errors,
    }
