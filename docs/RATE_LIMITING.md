# Greywatch Rate Limiting

Greywatch has three independent token-bucket rate limiters. All are
**process-local**: each uvicorn worker or application replica keeps its own
bucket state. There is no Redis or other distributed coordination.

| Limiter | Applies to | Bucket key | Configuration |
|---------|------------|------------|---------------|
| Pre-auth agent | Requests presenting a `gw_*` agent credential, before authentication and audit writes | Trusted client identity (see below) | `GREYWATCH_PREAUTH_RATE_*`, `GREYWATCH_TRUSTED_PROXIES` |
| Global | Every non-public HTTP path, after the trust boundary | Client identity (one shared bucket in token mode) | `GREYWATCH_RATE_LIMIT_*` |
| Per-agent | Requests authenticated with an agent API key; currently only `POST /api/v1/events/ingest` | `(agent_id, category)` | `GREYWATCH_AGENT_RATE_*` |

All three reject excess requests with HTTP **429 Too Many Requests** and a
numeric `Retry-After` header. The global and per-agent limiters run only after
successful authentication, so a 401/403 never consumes their tokens. The
pre-auth limiter deliberately counts every agent-key attempt — valid or not —
because its job is to bound authentication work and audit writes before they
happen. Rejections there are logged but never written to the audit chain.

---

## Pre-authentication agent-key limiter

The pre-auth limiter is `PreAuthAgentRateLimitMiddleware` in
`backend/app/main.py`. It is the **outermost** middleware, so an excess request
is rejected before the trust boundary performs PBKDF2 verification, before any
`auth_failure` audit row is written, before body buffering, and before the
global limiter.

### Enforcement scope

- It applies only to requests that present a `gw_*` credential in
  `Authorization: Bearer` or `X-API-Key`. Legacy shared-token requests,
  loopback-only requests without an agent key, dashboard traffic, and public
  paths are not counted and pass through untouched.
- Invalid, revoked, expired, and unknown agent keys are all covered because the
  limiter runs before authentication.
- A request rejected here returns `429` and never reaches authentication, so it
  produces no `audit_log` row. The operator still gets one structured
  `denied_request` log record with reason `agent_auth_rate_limit_exceeded`.

### Client identity and trusted proxies

The bucket key is the immediate ASGI peer (`scope["client"]`) by default.
Forwarding headers are consulted **only** when that peer is listed in
`GREYWATCH_TRUSTED_PROXIES` (default: loopback, `127.0.0.1/32,::1/128`).

When the peer is trusted, the limiter uses:

1. `X-Greywatch-Client-IP`, set by the supplied `Caddyfile` to
   `{http.request.remote.host}`; then
2. the **right-most** `X-Forwarded-For` hop, which is the only value a correct
   proxy appends.

Headers from an untrusted peer are ignored entirely, so a direct client cannot
spoof or rotate its bucket key. When the trusted proxy is Caddy, keep both
headers overwritten rather than appended so client-supplied values cannot
survive. The supplied `Caddyfile` does this on every `reverse_proxy` block.

If the proxy is on a non-loopback address, add its exact address or CIDR to
`GREYWATCH_TRUSTED_PROXIES`; otherwise all proxied requests share the proxy's
own bucket. Do **not** trust a range that includes untrusted clients.

### Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `GREYWATCH_PREAUTH_RATE_LIMIT_ENABLED` | `1` | Enables the pre-auth limiter. `1`/`true`/`yes`/`on` enable it; `0`/`false`/`no`/`off` disable it. |
| `GREYWATCH_PREAUTH_RATE_LIMIT` | `120` | Sustained agent-key attempts/min per client identity. |
| `GREYWATCH_PREAUTH_RATE_BURST_MULTIPLIER` | `2` | Burst capacity = `limit × multiplier`. |
| `GREYWATCH_PREAUTH_RATE_MAX_ENTRIES` | `10000` | Maximum distinct identities retained in memory. |
| `GREYWATCH_TRUSTED_PROXIES` | `127.0.0.1/32,::1/128` | Comma/space-separated CIDRs whose forwarding headers are trusted. Invalid entries are ignored. |

Numeric values are read as positive integers. Empty, non-numeric, zero, or
negative values fall back to the documented default. Disabling must be explicit
with `GREYWATCH_PREAUTH_RATE_LIMIT_ENABLED=0`.

### Bucket behavior

- One bucket per trusted client identity. Each bucket starts full at
  `limit × burst_multiplier`, refills at `limit / 60` per second, and an allowed
  agent-key attempt consumes one token.
- The bucket store is a bounded LRU. When `GREYWATCH_PREAUTH_RATE_MAX_ENTRIES`
  is reached, the least-recently-used identity is evicted. Memory is therefore
  bounded even under a flood of distinct source addresses.
- Rejections do not extend the window: the refilled token count is retained, so
  repeated denied requests cannot keep resetting the wait.
- Buckets are process-local and lost on restart, like the other limiters.

### HTTP 429 response

- Status: `429 Too Many Requests`
- Body: `{"detail":"Agent authentication rate limit exceeded"}`
- Header: `Retry-After` with a positive integer number of seconds until at least
  one token is available

---

## Global rate limiter

The global limiter is `RateLimitMiddleware` in `backend/app/main.py`. It
applies to every non-public HTTP request that passes the trust boundary.
`/` and `/health` are exempt, and non-HTTP ASGI scopes pass through unchanged.

### Scope and categories

Path classification is by path, not HTTP method. All methods on a protected
path use the same category.

| Path | Category | Default requests/min |
|------|----------|----------------------|
| `POST /api/v1/events/ingest` | `ingestion` | `60` |
| `POST /api/v1/journal/collect`, `POST /api/v1/suricata/collect` | `collector` | `30` |
| `POST /api/v1/alerts/{id}/close` | `alert_close` | `30` |
| `POST /api/v1/incidents/{id}/acknowledge`, `POST /api/v1/incidents/{id}/resolve` | `alert_close` | `30` |
| Every other non-public path, including read, admin, and documentation routes | `reads` | `120` |

### Environment variables

| Variable | Default | Meaning |
|----------|---------|---------|
| `GREYWATCH_RATE_LIMIT_ENABLED` | `1` | Enables the global limiter. `1`/`true`/`yes`/`on` enable it; `0`/`false`/`no`/`off` disable it. Any other value falls back to enabled. |
| `GREYWATCH_RATE_LIMIT_INGESTION` | `60` | Sustained requests/min for the `ingestion` category. |
| `GREYWATCH_RATE_LIMIT_READS` | `120` | Sustained requests/min for the `reads` category. |
| `GREYWATCH_RATE_LIMIT_COLLECTOR` | `30` | Sustained requests/min for the `collector` category. |
| `GREYWATCH_RATE_LIMIT_ALERT_CLOSE` | `30` | Sustained requests/min for the `alert_close` category. |
| `GREYWATCH_RATE_LIMIT_BURST_MULTIPLIER` | `2` | Positive integer multiplier for burst capacity: `limit × multiplier`. |

Numeric values are read as positive integers. Empty, non-numeric, zero, or
negative values fall back to the documented default; they never silently
disable the limiter. A fractional burst multiplier (for example `2.5`) is
invalid for the global limiter and also falls back to `2`. Disabling the global
limiter must be an explicit `GREYWATCH_RATE_LIMIT_ENABLED=0` (or an equivalent
false value).

### Bucket behavior

- The global limiter keeps **one bucket per client identity**, shared across all
  protected paths. The current request's category only selects the refill rate
  and burst capacity applied to that bucket; categories do not get separate
  buckets.
- If `GREYWATCH_API_TOKEN` is set, the bucket key is the token value itself, so
  **all callers share one bucket**. This includes requests authenticated with
  agent API keys while a shared token is configured.
- Otherwise the key is the ASGI peer host (`scope["client"]`). Forwarding
  headers such as `X-Forwarded-For` are never consulted. Behind a reverse proxy,
  requests normally appear as the proxy's peer address unless token mode is
  active.
- Each bucket starts full. Capacity is `limit × burst_multiplier`; tokens
  refill at `limit / 60` per second. An allowed request consumes one token.
- The global bucket store is capped at 10,000 entries. When full, the least
  recently used entry is evicted.

### HTTP 429 response

When the bucket has fewer than one token, the global limiter returns:

- Status: `429 Too Many Requests`
- Body: `{"detail":"Rate limit exceeded"}`
- Header: `Retry-After` with a positive integer number of seconds until at
  least one token is available

---

## Per-agent rate limiter

The per-agent limiter is `check_agent_rate_limit()` in
`backend/app/agents.py`. The trust boundary calls it after an agent API key has
been authenticated successfully.

### Enforcement scope

- It applies only to requests authenticated with an **agent API key**
  (`gw_...`), supplied as either `Authorization: Bearer gw_...` or
  `X-API-Key: gw_...`.
- Agent API keys are currently restricted to `POST /api/v1/events/ingest`.
  Therefore only the `ingestion` category is enforced.
- `reads`, `collector`, and `alert_close` are present in the per-agent
  configuration and bucket API, but **no endpoint currently enforces them**.
  Setting those variables does not rate limit read, collector, or alert-close
  requests.
- Requests authenticated with the shared `GREYWATCH_API_TOKEN`, and loopback
  requests, are not subject to per-agent buckets. They remain subject to the
  global limiter.

### Environment variables

| Variable | Default | Enforced today | Meaning |
|----------|---------|----------------|---------|
| `GREYWATCH_AGENT_RATE_LIMIT_ENABLED` | `1` | Yes | Enables per-agent limiting. Only `1`/`true`/`yes`/`on` (case-insensitive) enable it; any other value disables it. |
| `GREYWATCH_AGENT_RATE_INGESTION` | `60` | Yes | Sustained requests/min per agent for ingestion. |
| `GREYWATCH_AGENT_RATE_READS` | `120` | No | Configured read limit; not currently applied to any request. |
| `GREYWATCH_AGENT_RATE_COLLECTOR` | `10` | No | Configured collector limit; not currently applied to any request. |
| `GREYWATCH_AGENT_RATE_ALERT_CLOSE` | `30` | No | Configured alert-close limit; not currently applied to any request. |
| `GREYWATCH_AGENT_RATE_BURST` | `1.5` | Yes | Decimal burst multiplier: capacity is `int(limit × multiplier)`. |

The per-agent numeric values are loaded directly from the environment when the
limiter runs. Use valid positive numbers; unlike the global limiter, malformed
per-agent values do not fall back to defaults.

### Bucket behavior

- Buckets are keyed by `(agent_id, category)`. They are independent per agent
  and per category. All API keys belonging to the same agent share that agent's
  bucket.
- With the default ingestion limit of `60` and burst multiplier `1.5`, a new
  agent starts with 90 tokens and refills at one token per second.
- A bucket starts full. An allowed request consumes one token. Denied requests
  do not consume a token.
- Bucket state lives in process memory and is lost on restart. It is not shared
  between workers or replicas.

### HTTP 429 response

When an agent's bucket has fewer than one token, the trust boundary returns:

- Status: `429 Too Many Requests`
- Body: `{"detail":"Agent rate limit exceeded"}`
- Header: `Retry-After` with a positive integer number of seconds until at
  least one token is available

### Disabling per-agent enforcement

Set:

```dotenv
GREYWATCH_AGENT_RATE_LIMIT_ENABLED=0
```

This disables only the per-agent limiter. The global limiter remains enabled
unless `GREYWATCH_RATE_LIMIT_ENABLED=0` is set as well. Disabling either limiter
does not disable the other.

---

## Interaction between the limiters

- An agent API-key request first passes the pre-auth limiter (outermost), then
  the per-agent check during the trust boundary, then the separate global
  middleware. Unless explicitly disabled, all three apply.
- The pre-auth limiter counts the attempt before authentication. The per-agent
  and global checks run only after successful authentication, so failed
  authentication never consumes their tokens.
- In token mode, the global limiter's single shared bucket is common to all
  callers, including agent-key callers. The pre-auth and per-agent buckets are
  additional state on top of that shared global bucket.
- A legitimate agent sharing one egress IP with other agents (for example
  behind a NAT or a single proxy that does not forward client IPs) shares the
  pre-auth bucket. Raise `GREYWATCH_PREAUTH_RATE_LIMIT` or configure
  `GREYWATCH_TRUSTED_PROXIES` and client-IP forwarding if that becomes a
  constraint.

## Process-local buckets and multi-worker deployments

All three limiters use in-process dictionaries. Consequences:

- Each uvicorn worker or application replica has independent bucket state.
- Running `N` workers or replicas can multiply the effective allowed rate by
  up to `N`; the configured limit is not cluster-wide.
- There is no distributed coordination, shared cache, or persistence. Restarting
  a process resets its buckets.
- The global and pre-auth bucket stores are bounded (10,000 entries by default)
  with LRU eviction. Per-agent buckets live for the lifetime of the process.

For the documented limits to be meaningful, run a single uvicorn worker (the
provided service unit does not pass `--workers`) and enforce coarse
multi-instance limits at the reverse proxy or edge. If multiple workers are
required, do not rely on the built-in limiters as cluster-wide controls.

### Example staging configuration

The following environment block enables all three limiters with their defaults.
Only the per-agent `INGESTION` value is currently enforced; the other
per-agent category values are shown for completeness.

```dotenv
# Pre-auth agent-key limiter (outermost; before auth and audit writes)
GREYWATCH_PREAUTH_RATE_LIMIT_ENABLED=1
GREYWATCH_PREAUTH_RATE_LIMIT=120
GREYWATCH_PREAUTH_RATE_BURST_MULTIPLIER=2
GREYWATCH_PREAUTH_RATE_MAX_ENTRIES=10000
GREYWATCH_TRUSTED_PROXIES=127.0.0.1/32,::1/128

# Global limiter (all non-public routes)
GREYWATCH_RATE_LIMIT_ENABLED=1
GREYWATCH_RATE_LIMIT_INGESTION=60
GREYWATCH_RATE_LIMIT_READS=120
GREYWATCH_RATE_LIMIT_COLLECTOR=30
GREYWATCH_RATE_LIMIT_ALERT_CLOSE=30
GREYWATCH_RATE_LIMIT_BURST_MULTIPLIER=2

# Per-agent limiter (agent API-key ingestion only)
GREYWATCH_AGENT_RATE_LIMIT_ENABLED=1
GREYWATCH_AGENT_RATE_INGESTION=60
GREYWATCH_AGENT_RATE_READS=120
GREYWATCH_AGENT_RATE_COLLECTOR=10
GREYWATCH_AGENT_RATE_ALERT_CLOSE=30
GREYWATCH_AGENT_RATE_BURST=1.5
```

For a multi-worker deployment, either disable the limiters that cannot be
enforced cluster-wide and apply limits at the proxy, or keep the API at a
single worker. Disabling a limiter is explicit:

```dotenv
# Disable pre-auth limiting only
GREYWATCH_PREAUTH_RATE_LIMIT_ENABLED=0

# Disable per-agent limiting only
GREYWATCH_AGENT_RATE_LIMIT_ENABLED=0

# Disable global limiting only
GREYWATCH_RATE_LIMIT_ENABLED=0
```

---

## Related documentation

- [README API Security](../README.md#api-security) — authentication modes and
  request-body limits.
- [Staging deployment](DEPLOYMENT.md) — environment setup and verification
  checklist.
- [Project state](PROJECT_STATE.md) — implementation snapshot.
