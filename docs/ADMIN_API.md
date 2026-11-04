# Greywatch Admin API Reference

Operator reference for agent and API-key administration in Greywatch v0.2.

> **Scope:** this document covers the ten administration routes registered under
> `/api/v1/admin/`. The independent audit brief referred to "13 agent/API-key
> administration endpoints"; inspection of `backend/app/main.py` on branch
> `feat/migration-startup-integration` finds **10**. The inventory below is
> verified against the running FastAPI route table, not the brief's count.

## 1. Authentication and authorization

All administration routes are protected by the backend's global
`_trust_boundary` middleware. There are **no per-route roles or scopes**: one
valid administrator credential grants every admin operation. Agent API keys
(`gw_...`) are ingestion-only and are never administrator credentials.

The middleware supports three deployments:

| Mode | Configuration | Admin access |
|---|---|---|
| Shared token | `GREYWATCH_API_TOKEN` set | Requires the token in one accepted header |
| Loopback default | No token; `GREYWATCH_API_LOOPBACK_ONLY=1` (default) | Only loopback peers |
| Proxy-trust | No token; `GREYWATCH_API_LOOPBACK_ONLY=0` | Any peer that reaches the backend; the proxy must authenticate callers |

Accepted shared-token headers (constant-time comparison):

```http
Authorization: Bearer $GREYWATCH_ADMIN_TOKEN
X-API-Key: $GREYWATCH_ADMIN_TOKEN
X-Greywatch-Token: $GREYWATCH_ADMIN_TOKEN
```

`X-Greywatch-Token` is the header injected by the supplied Caddy deployment.
Caddy also applies dashboard `basic_auth` to `/api/*`; that is a separate
proxy-layer control. The backend authorizes on the shared token or loopback
peer, not on a per-user identity.

Credential precedence is strict:

- Any `gw_...` value in `Authorization` or `X-API-Key` is treated as an agent
  key. A valid agent key on an admin route returns **403**.
- An invalid, revoked, or expired agent key returns **401**, even if a valid
  shared token is supplied in another header. There is no downgrade.
- A missing or invalid shared token returns **401**.
- A non-loopback peer returns **403** in loopback mode.

Set the token through the environment; never put it in a URL, shell history,
dashboard bundle, or source file:

```bash
# Operator shell only. Use your secret manager or the 0600 env file.
export GREYWATCH_ADMIN_TOKEN="$(cat /etc/greywatch/admin-token)"
export GREYWATCH_URL="https://greywatch.example.net"
```

The examples below assume those variables. A literal token never appears in
this document.

## 2. Endpoint inventory

All successful administrative operations return **HTTP 200**. There are no
`201` responses. `count` is the number of items in the current page, not a
total row count.

| # | Method | Path | Purpose | Persistent change | Audit event |
|---|---|---|---|---|---|
| 1 | GET | `/api/v1/admin/agents` | List agents | No | — |
| 2 | GET | `/api/v1/admin/agents/{agent_id}` | Get one agent | No | — |
| 3 | POST | `/api/v1/admin/agents` | Create an agent | Yes | `agent_created` |
| 4 | PATCH | `/api/v1/admin/agents/{agent_id}` | Update metadata | Yes, if fields supplied | `agent_updated` |
| 5 | POST | `/api/v1/admin/agents/{agent_id}/deactivate` | Deactivate agent and revoke its active keys | Yes | `agent_deactivated` |
| 6 | GET | `/api/v1/admin/agents/{agent_id}/keys` | List an agent's keys | No | — |
| 7 | POST | `/api/v1/admin/agents/{agent_id}/keys` | Create a key | Yes | `key_generated` |
| 8 | POST | `/api/v1/admin/keys/{key_id}/revoke` | Revoke a key | Yes | `key_revoked` |
| 9 | POST | `/api/v1/admin/keys/{key_id}/rotate` | Revoke old key, create replacement | Yes | `key_rotated` |
| 10 | GET | `/api/v1/admin/audit-log` | Read audit records | No | — |

Common error responses:

| Status | Meaning |
|---|---|
| 401 | Missing/invalid shared token; invalid/revoked/expired agent key |
| 403 | Valid agent key used off the ingestion route; remote peer in loopback mode |
| 404 | Unknown agent ID (and unknown key ID for revocation) |
| 409 | Duplicate name, inactive agent, already-inactive agent, already-revoked key, invalid rotation |
| 422 | Request validation failure (body, path ID, or query parameter) |
| 429 | Global request-rate limit |
| 500 | Database/audit persistence failure; the lifecycle transaction was rolled back |

## 3. Agent endpoints

### 3.1 List agents

```http
GET /api/v1/admin/agents?status=active&limit=100&offset=0
```

Query parameters:

| Name | Type | Rules |
|---|---|---|
| `status` | string | `active`, `inactive`, or `revoked` |
| `limit` | integer | 1–500, default 100 |
| `offset` | integer | ≥ 0, default 0 |

Response:

```json
{
  "count": 1,
  "agents": [
    {
      "id": 7,
      "name": "sensor-web-01",
      "display_name": "Web sensor",
      "description": "Ingest from web tier",
      "status": "active",
      "created_at": "2026-01-01T00:00:00+00:00",
      "updated_at": "2026-01-01T00:00:00+00:00",
      "last_seen_at": null,
      "deactivated_at": null,
      "deactivated_reason": null
    }
  ]
}
```

Ordering is `created_at DESC`. Timestamps are stored at whole-second
precision, so rows created in the same second can tie; do not rely on a strict
order between ties.

```bash
curl --fail-with-body -sS \
  -H "Authorization: Bearer $GREYWATCH_ADMIN_TOKEN" \
  "$GREYWATCH_URL/api/v1/admin/agents?status=active&limit=50&offset=0"
```

### 3.2 Get one agent

```http
GET /api/v1/admin/agents/{agent_id}
```

Returns one agent object with the same fields as the list response. Unknown ID
→ **404**; non-integer ID → **422**.

```bash
curl --fail-with-body -sS \
  -H "Authorization: Bearer $GREYWATCH_ADMIN_TOKEN" \
  "$GREYWATCH_URL/api/v1/admin/agents/7"
```

### 3.3 Create an agent

```http
POST /api/v1/admin/agents
Content-Type: application/json

{
  "name": "sensor-web-01",
  "display_name": "Web sensor",
  "description": "Ingest from web tier"
}
```

| Field | Required | Rules |
|---|---|---|
| `name` | Yes | 1–128 chars, `^[a-zA-Z0-9_-]+$`, unique |
| `display_name` | No | ≤ 256 chars |
| `description` | No | ≤ 1024 chars |

Response is the agent summary:

```json
{
  "id": 7,
  "name": "sensor-web-01",
  "display_name": "Web sensor",
  "description": "Ingest from web tier",
  "status": "active",
  "created_at": "2026-01-01T00:00:00+00:00",
  "updated_at": "2026-01-01T00:00:00+00:00"
}
```

Duplicate `name` → **409**. Validation failure → **422**. Audit event:
`agent_created` with actor `admin_api`.

```bash
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $GREYWATCH_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"sensor-web-01","display_name":"Web sensor"}' \
  "$GREYWATCH_URL/api/v1/admin/agents"
```

### 3.4 Update agent metadata

```http
PATCH /api/v1/admin/agents/{agent_id}
Content-Type: application/json

{"display_name": "Renamed sensor", "description": "Updated"}
```

Only supplied fields change. An empty JSON object (`{}`) is a successful
no-op and emits **no** audit event. A successful update emits `agent_updated`
with only the supplied fields in `detail`.

Unknown ID → **404**; field too long → **422**. `name` and `status` cannot be
changed through this route.

```bash
curl --fail-with-body -sS -X PATCH \
  -H "Authorization: Bearer $GREYWATCH_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"display_name":"Renamed sensor"}' \
  "$GREYWATCH_URL/api/v1/admin/agents/7"
```

### 3.5 Deactivate an agent

```http
POST /api/v1/admin/agents/{agent_id}/deactivate
Content-Type: application/json

{"reason": "host retired"}
```

`reason` is required, 1–512 chars. Response:

```json
{"id": 7, "status": "inactive"}
```

The same transaction marks the agent inactive and bulk-revokes every active key
belonging to it. The key revocation reason is
`Agent deactivated: <reason>`. Exactly one audit event is emitted for the
operation: `agent_deactivated` (there are no separate per-key `key_revoked`
events for the bulk revoke).

Unknown ID → **404**. Already inactive → **409**. An agent cannot be reactivated
through the API.

```bash
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $GREYWATCH_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason":"host retired"}' \
  "$GREYWATCH_URL/api/v1/admin/agents/7/deactivate"
```

## 4. API-key endpoints

### 4.1 List an agent's keys

```http
GET /api/v1/admin/agents/{agent_id}/keys?status=active
```

| Name | Type | Rules |
|---|---|---|
| `status` | string | `active`, `revoked`, or `expired` |

There is **no pagination** on this route. Response:

```json
{
  "count": 1,
  "keys": [
    {
      "id": 12,
      "key_prefix": "gw_ab12",
      "name": "web-ingest",
      "status": "active",
      "created_at": "2026-01-01T00:00:00+00:00",
      "expires_at": null,
      "revoked_at": null,
      "revoked_reason": null,
      "last_used_at": null
    }
  ]
}
```

`key_prefix` is an identifier, not a credential. `key_hash` and plaintext keys
are never returned by this route. Ordering is `created_at DESC`.

**Expiry caveat:** authentication enforces `expires_at` (a time-expired key is
rejected), but there is no background job that changes `api_keys.status` to
`expired`. A time-expired key therefore still appears with status `active`, and
`?status=expired` returns no rows unless a row was set to that status by other
means. Use `expires_at` in operator checks, and explicitly revoke keys that
must be unusable immediately.

Unknown agent → **404**; invalid status → **422**.

```bash
curl --fail-with-body -sS \
  -H "Authorization: Bearer $GREYWATCH_ADMIN_TOKEN" \
  "$GREYWATCH_URL/api/v1/admin/agents/7/keys?status=active"
```

### 4.2 Create an API key

```http
POST /api/v1/admin/agents/{agent_id}/keys
Content-Type: application/json

{"name": "web-ingest", "expires_at": "2026-12-31T23:59:59Z"}
```

| Field | Required | Rules |
|---|---|---|
| `name` | No | ≤ 128 chars |
| `expires_at` | No | ISO-8601 timestamp; timezone optional (naive values are treated as UTC) |

Response (the only time the plaintext key is available):

```json
{
  "id": 12,
  "key_prefix": "gw_ab12",
  "name": "web-ingest",
  "plaintext_key": "<one-time-secret-redacted>",
  "status": "active",
  "created_at": "2026-01-01T00:00:00+00:00",
  "expires_at": "2026-12-31T23:59:59Z"
}
```

The plaintext key is generated with 256 bits of randomness and stored only as a
PBKDF2-HMAC-SHA256 hash. It cannot be retrieved again. Store it immediately in
the agent's secret store and do not log the response. If it is lost, rotate the
key rather than attempting recovery.

Unknown agent → **404**. Inactive/deactivated agent → **409**. Validation
failure → **422**. Audit event: `key_generated` (prefix, name, expiry only —
never plaintext or hash).

```bash
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $GREYWATCH_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"web-ingest","expires_at":"2026-12-31T23:59:59Z"}' \
  "$GREYWATCH_URL/api/v1/admin/agents/7/keys"
```

### 4.3 Revoke an API key

```http
POST /api/v1/admin/keys/{key_id}/revoke
Content-Type: application/json

{"reason": "credential exposed"}
```

`reason` is required, 1–512 chars. Response:

```json
{"id": 12, "status": "revoked"}
```

The key is invalid immediately. Unknown key → **404**. Already revoked →
**409**. Audit event: `key_revoked`.

```bash
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $GREYWATCH_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason":"credential exposed"}' \
  "$GREYWATCH_URL/api/v1/admin/keys/12/revoke"
```

### 4.4 Rotate an API key

```http
POST /api/v1/admin/keys/{key_id}/rotate
```

No request body is required. The old key is revoked with reason
`Rotated by admin_api`, and a replacement key with the same `name` is created in
the same transaction. Response is the same shape as key creation, including the
new one-time `plaintext_key`.

The replacement key is created **without an expiry**, even if the old key had
one. If expiry is required, either create the replacement with
`POST /agents/{agent_id}/keys` or apply an external expiry policy.

Unknown key → **409**. Revoked key → **409**. Agent inactive → **409**. Audit
event: `key_rotated` (old/new key IDs, prefixes, and name; no secrets).

```bash
curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer $GREYWATCH_ADMIN_TOKEN" \
  "$GREYWATCH_URL/api/v1/admin/keys/12/rotate"
```

## 5. Audit-log inspection

```http
GET /api/v1/admin/audit-log?agent_id=7&event_type=key_generated&limit=100&offset=0
```

| Name | Type | Rules |
|---|---|---|
| `agent_id` | integer | Optional exact filter |
| `event_type` | string | Optional exact filter; not restricted to a fixed enum |
| `limit` | integer | 1–500, default 100 |
| `offset` | integer | ≥ 0, default 0 |

Response:

```json
{
  "count": 1,
  "entries": [
    {
      "id": 42,
      "timestamp": "2026-01-01T00:00:00+00:00",
      "event_type": "key_generated",
      "agent_id": 7,
      "api_key_id": 12,
      "actor": "admin_api",
      "detail": "{\"key_prefix\": \"gw_ab12\", \"key_name\": \"web-ingest\", \"expires_at\": null}",
      "prev_hash": "...",
      "chain_hash": "..."
    }
  ]
}
```

`detail` is a JSON **string**, not a nested object. `prev_hash`/`chain_hash` are
audit-chain linkage values, not key material. Plaintext keys, key hashes, and
the shared token never appear in audit rows.

Ordering is `timestamp DESC`, which is a display order, not the canonical
hash-chain order. The chain is verified in insertion order (`id ASC`). Because
timestamps are whole-second precision, equal timestamps may tie and pagination
over ties can be unstable; use filters to narrow a range. `count` is the page
size, not the total number of matching records.

Lifecycle events and their actors:

| Event | Emitted by |
|---|---|
| `agent_created` | Successful agent creation |
| `agent_updated` | Successful metadata update with at least one field |
| `agent_deactivated` | Successful deactivation (includes bulk key revoke) |
| `key_generated` | Successful key creation |
| `key_revoked` | Successful explicit revocation |
| `key_rotated` | Successful rotation (old revoked + new created) |
| `auth_failure` | Failed agent-key authentication (observational; best-effort) |
| `key_rehashed` | Opportunistic PBKDF2 upgrade during authentication |

```bash
curl --fail-with-body -sS \
  -H "Authorization: Bearer $GREYWATCH_ADMIN_TOKEN" \
  "$GREYWATCH_URL/api/v1/admin/audit-log?event_type=agent_deactivated&limit=50"
```

Verify the chain independently, read-only:

```bash
python3 ./scripts/gw_migrate audit-verify /var/lib/greywatch/greywatch.db
```

Exit code `0` means the chain is valid. Exit code `1` means verification failed;
do not repair or delete rows before preserving a backup and investigating.

## 6. Pagination and filtering patterns

`count` is the number of returned rows. To enumerate agents or audit records,
page until a page returns fewer than `limit` rows:

```bash
offset=0
limit=500
while :; do
  page="$(curl --fail-with-body -sS \
    -H "Authorization: Bearer $GREYWATCH_ADMIN_TOKEN" \
    "$GREYWATCH_URL/api/v1/admin/agents?limit=$limit&offset=$offset")"
  # Consume page here.
  returned="$(printf '%s' "$page" | python3 -c 'import json,sys; print(json.load(sys.stdin)["count"])')"
  [ "$returned" -lt "$limit" ] && break
  offset=$((offset + limit))
done
```

Key listing is not paginated. Audit records can be filtered by `agent_id` and
`event_type`; agents by lifecycle `status`.

## 7. Failure and recovery behavior

- **401/403** — authentication/authorization failure. Fix credentials or the
  trust-boundary configuration; no state changed.
- **404** — unknown agent ID. Verify the ID from `GET /admin/agents`.
- **409** — conflict. Duplicate agent names, inactive agents, already-revoked
  keys, and unknown-key rotation use this status. Re-read state before retrying.
- **422** — validation failure. FastAPI returns field-level details; no state
  changed.
- **429** — request-rate limit. Retry after the interval indicated by the
  response headers; no state changed.
- **500 during a lifecycle mutation** — the database or audit append failed.
  The mutation and its audit record are in one SQLite transaction, so the
  operation was **rolled back**. Verify state before retrying. Once storage is
  healthy, a retry is safe; duplicate-name and already-revoked conflicts will
  report 409 if a previous attempt actually succeeded.
- **Audit outage** — lifecycle operations fail closed with 500 rather than
  committing an unaudited change. Authentication-failure audit records remain
  best-effort and do not change authentication outcomes.

## 8. Security warnings

1. **The shared admin token is all-powerful.** Compromise grants full agent and
   key administration. Use a long random value, HTTPS only, a secret manager or
   `0600` environment file, and rotate it through deployment configuration.
2. **Never put tokens or plaintext keys in URLs, logs, tickets, shell history,
   dashboards, or source control.** The API accepts credentials only in
   headers.
3. **Agent keys are not admin credentials.** They are restricted to
   `POST /api/v1/events/ingest`. A valid agent key on an admin route is denied.
4. **Plaintext API keys are shown once.** Creation and rotation responses are
   the only places they appear. Read endpoints and audit records expose only
   prefixes and metadata.
5. **Revocation and rotation are immediate.** Rotation revokes the old key in
   the same transaction that creates the replacement; deactivation bulk-revokes
   all active keys. Neither operation can be undone.
6. **Rotation drops expiry.** The replacement key has no `expires_at`. Recreate
   with an explicit expiry when required.
7. **Time-expired keys remain status `active` in admin listings.** Authentication
   rejects them, but `?status=expired` does not match them. Revoke keys that must
   be visibly terminated.
8. **The audit chain is tamper-evident, not tamper-proof.** It detects edits and
   deletions relative to a known-good chain, but an attacker with database write
   access can replace the whole database. Restrict DB access, back up, and run
   `audit-verify` regularly.
9. **Pagination is offset-based and timestamp-ordered.** Same-second ties can
   make pages unstable. Prefer filters and treat `count` as page size.
10. **Do not expose `/docs`, `/openapi.json`, or the admin API directly.** The
    supplied Caddy deployment does not proxy the docs routes, and `/api/*`
    remains behind proxy authentication plus the backend shared token.
