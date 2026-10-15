# Greywatch

Open-source security monitoring and SIEM platform.

Greywatch collects security events, detects suspicious activity,
and helps analysts investigate threats through a unified dashboard.

## Initial Features

- Linux security log ingestion
- Event normalization
- Rule-based threat detection
- Security alerts and severity levels
- Event search and investigation
- SOC dashboard

## Journal Collection (Linux)

Greywatch can collect **real PAM/SSH/sudo authentication events** from the
systemd journal on Linux hosts (developed on Fedora) without enabling or
reconfiguring SSH. The collector is optional and off by default. See
[`docs/JOURNAL_COLLECTOR.md`](docs/JOURNAL_COLLECTOR.md) for installation,
least-privilege permissions, configuration, and how to verify real events.

```bash
GREYWATCH_JOURNAL_ENABLED=1 python -m backend.app.collector --once   # one cycle
python -m backend.app.collector                                    # continuous loop
curl http://127.0.0.1:8000/api/v1/journal/status                   # checkpoint state
```

## Security & Trust Boundary

Greywatch is a **local/trusted-host** SIEM: it reads the local systemd journal,
a local Suricata `eve.json`, and a local SQLite database, and the API is
reached on `127.0.0.1:8000` by default (`uvicorn backend.app.main:app`).

The `GREYWATCH_JOURNAL_ENABLED` / `GREYWATCH_SURICATA_ENABLED` flags are
**collection toggles** (they start or stop the continuous collector loop) —
they are **not** access control.

Every endpoint **except `/` and `/health`** is gated by the trust boundary
(`backend/app/main.py`); the gate is applied uniformly to reads **and** writes,
so the event/alert/journal/suricata endpoints that expose `raw_message` or alert
evidence are protected in either mode:

- **Local (default):** with no `GREYWATCH_API_TOKEN` set, every non-public
  endpoint only accepts loopback peers (`127.0.0.1` / `::1`); remote or unknown
  peers get `403`.
- **Network exposed:** set `GREYWATCH_API_TOKEN` to a strong secret and send it
  as `Authorization: Bearer <token>` or `X-API-Key: <token>`; missing/invalid
  credentials get `401`.

### Proxy configuration (deployment safety)

- The loopback decision is based **only** on the ASGI connection peer
  (`request.client.host`). Forwarding headers (`X-Forwarded-For`,
  `X-Real-IP`, `Forwarded`) are **never** read, so they cannot spoof loopback —
  even when the API binds `0.0.0.0`. Do **not** enable Uvicorn's
  `--proxy-headers` / Starlette `ProxyHeadersMiddleware` unless the server sits
  behind a single trusted reverse proxy; an untrusted client cannot spoof the
  peer check (it is ignored), but your own application logic must not trust
  forwarded headers from untrusted clients.
- Behind a trusted reverse proxy, run the API on a loopback bind and let the
  proxy terminate TLS + authentication (or set `GREYWATCH_API_TOKEN`). With a
  token configured, the proxy does not need to forward the original client IP for
  authorization.
- An **unknown peer** (an ASGI scope with no `request.client`, e.g. a misrouted
  request) is treated as **not** loopback → `403` (**fail-closed**), never
  silently trusted.

### Dashboard

The dashboard is a static JS bundle and cannot hold a secret, so it cannot
carry `GREYWATCH_API_TOKEN`. Dashboard use therefore assumes a **local /
trusted-host** browser (loopback peer). Network-exposed dashboard access is out
of scope for token auth and requires an authenticating reverse proxy.
