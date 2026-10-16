# TDD Evidence Report — API Rate Limiting (security review F2)

## Source plan

No `*.plan.md` file was provided. The design follows the approved F2 rate-limiting
proposal: stdlib-only token-bucket ASGI middleware, no new dependencies, no
frontend changes.

## User journeys

1. As an operator, I want to cap the request rate per client so a single client
   cannot exhaust API resources.
2. As a client, I want requests under my rate allowance to be processed normally.
3. As a client, I want requests over my allowance to receive HTTP 429 with a
   deterministic `Retry-After` so I know when to retry.
4. As an operator, I want per-endpoint-category limits and burst capacity,
   configurable via environment variables, with safe defaults.
5. As an operator, I want failed authentication (401/403) to never consume
   rate-limit tokens.

## Task report

| Task | Execution summary | Validation command | Output excerpt | Guarantee |
|------|-------------------|-------------------|----------------|-----------|
| Add `RateLimitConfig` + `get_rate_limit_config()` | Parses all env vars; invalid/non-positive fall back to defaults; enabled defaults True and must be explicitly disabled | `.venv/bin/python -m pytest backend/tests/test_rate_limit.py -k "get_rate_limit_config" -v` | 12/12 PASSED | Config never silently disables protection |
| Add `RateLimitMiddleware` token bucket | Per-client buckets, injectable clock, deterministic Retry-After, bounded store with LRU eviction | `.venv/bin/python -m pytest backend/tests/test_rate_limit.py -v` | 31/31 PASSED | Rate enforced on actual request count; per-client isolation |
| Register middleware on global app | Effective order TrustBoundary → MaxBodySize → RateLimit → app verified | `.venv/bin/python -m pytest backend/tests/test_rate_limit.py::test_middleware_registration_order -v` | PASSED | Auth failures don't consume tokens; rate limit inside trust boundary |
| No regressions | Full backend suite | `.venv/bin/python -m pytest backend/tests -q` | 241 passed | Existing API behavior preserved within limits |

## Test specification

| # | What is guaranteed | Test file or command | Test type | Result | Evidence |
|---|--------------------|----------------------|-----------|--------|----------|
| 1 | Defaults: enabled, ingestion 60, reads 120, collector 30, alert_close 30, burst 2 | `test_rate_limit.py::test_default_config_values` | unit | PASS | `RateLimitConfig()` matches docs |
| 2 | Unset env -> documented defaults | `test_get_rate_limit_config_defaults` | unit | PASS | All category defaults correct |
| 3 | Enabled parsing (1/true/yes/0/false/no/whitespace/invalid) | `test_get_rate_limit_config_enabled_parsing[*]` | unit | PASS | 8 cases; invalid -> True (safe) |
| 4 | Invalid/non-positive limits fall back to default | `test_get_rate_limit_config_limits_invalid_fall_back_to_default[*]` | unit | PASS | ingestion/reads/collector/alert_close |
| 5 | Invalid burst multiplier falls back to 2 | `test_get_rate_limit_config_burst_multiplier_invalid_defaults_to_two` | unit | PASS | "not-an-int", 0, -1 -> 2 |
| 6 | Request under limit accepted (200), body reaches inner app | `test_under_limit_passes_through` | unit (ASGI) | PASS | status 200 |
| 7 | Exactly at burst capacity accepted (boundary) | `test_exactly_at_capacity_is_accepted` | unit (ASGI) | PASS | 3 requests at limit 1 x multiplier 3 -> all 200 |
| 8 | One over capacity rejected with 429 | `test_one_over_capacity_is_rejected_429` | unit (ASGI) | PASS | 4th request -> 429 |
| 9 | 429 includes numeric Retry-After header | `test_429_includes_retry_after_header` | unit (ASGI) | PASS | `retry-after == 60` for 1 req/min |
| 10 | Tokens refill over simulated (injectable) clock | `test_refill_over_simulated_time` | unit (ASGI) | PASS | 200 -> 429 -> advance 60s -> 200 |
| 11 | Per-client isolation (A exhausted, B still allowed) | `test_per_client_isolation` | unit (ASGI) | PASS | different IPs, independent buckets |
| 12 | Public paths (/ and /health) never rate limited | `test_public_paths_exempt` | unit (ASGI) | PASS | 10 requests each -> all 200 |
| 13 | enabled=False allows all requests | `test_disabled_rate_limit_allows_all` | unit (ASGI) | PASS | 100 requests -> all 200 |
| 14 | Missing client host keyed as "unknown", no crash | `test_missing_client_host_uses_unknown_key` | unit (ASGI) | PASS | no "client" key -> keyed "unknown" |
| 15 | Non-HTTP scope (lifespan) passes through | `test_non_http_scope_passes_through` | unit (ASGI) | PASS | lifespan scope -> 200 |
| 16 | Bucket store bounded with LRU eviction | `test_bucket_store_is_bounded_with_eviction` | unit | PASS | max_entries=3 -> 4th evicts oldest |
| 17 | TestClient under limit -> 200 | `test_client_under_limit_is_accepted` | integration | PASS | POST /ingest -> 200 |
| 18 | TestClient over limit -> 429 + Retry-After + JSON detail | `test_client_over_limit_returns_429` | integration | PASS | status 429, retry-after >= 1, detail key |
| 19 | TestClient public path exempt | `test_client_public_path_exempt` | integration | PASS | /ingest 429, /health still 200 |
| 20 | Auth failure (401) does not consume rate token | `test_auth_failure_does_not_consume_rate_token` | integration | PASS | 401 then authenticated 200 (not 429) |
| 21 | Registration order -> TrustBoundary→MaxBodySize→RateLimit→app | `test_middleware_registration_order` | unit | PASS | user_middleware == [BaseHTTPMiddleware, MaxBodySizeMiddleware, RateLimitMiddleware] |
| 22 | All existing tests pass (no regressions) | `.venv/bin/python -m pytest backend/tests -q` | integration | PASS | 241 passed, 0 failed |

## Coverage and known gaps

Coverage command: `.venv/bin/python -m pytest backend/tests -q` → 241 passed.

- No coverage plugin installed in `.venv` (requirements.txt: fastapi, uvicorn, httpx, pytest). Coverage percentage not instrumented; the 80% target cannot be quantitatively verified without adding `pytest-cov` (deferred — no new dependencies per constraints).
- The `http.disconnect` passthrough branch is not directly exercised; it is defensive code for client disconnects mid-stream.
- Existing tests using the shared global `app` have rate limiting disabled via conftest (`_disable_rate_limit_for_global_app`) to prevent cross-test bucket depletion; rate-limiter behavior itself is covered by focused tests using fresh middleware instances with explicit config.

## Configuration examples

```bash
# Default: 60 req/min ingestion, 120 req/min reads, burst = limit x 2
GREYWATCH_RATE_LIMIT_ENABLED=1 uvicorn backend.app.main:app

# Custom: 30 req/min ingestion, burst multiplier 1 (no burst)
GREYWATCH_RATE_LIMIT_INGESTION=30 GREYWATCH_RATE_LIMIT_BURST_MULTIPLIER=1 uvicorn backend.app.main:app

# Disable rate limiting (explicit operator choice)
GREYWATCH_RATE_LIMIT_ENABLED=0 uvicorn backend.app.main:app

# Invalid value falls back to safe default (enabled, defaults), never silently disabled
GREYWATCH_RATE_LIMIT_ENABLED=not-a-boolean uvicorn backend.app.main:app
```

## Middleware execution order

Confirmed empirically via Starlette's `build_middleware_stack` (reverses
`user_middleware`, which `add_middleware` builds with `insert(0, ...)`):

Registration order: `[BaseHTTPMiddleware(trust boundary), MaxBodySizeMiddleware, RateLimitMiddleware]`

Effective order: **TrustBoundary → MaxBodySize → RateLimit → app**

Auth failures (401/403) are short-circuited by the outermost trust boundary
*before* rate-limit accounting, so they never consume tokens.

## Memory-bound strategy

- One token bucket per client identity, stored in `self._buckets` dict.
- Hard maximum entry count `max_entries` (default 10,000).
- When full, the least-recently-updated entry is evicted (LRU by `last_update`
  timestamp), capping memory growth.
- Tradeoff: under heavy distinct-client load, eviction may reset a returning
  client's bucket (full capacity restored). This is an acceptable tradeoff for
  a stdlib-only, single-process limiter; multi-worker deployments should use a
  reverse proxy for shared limits.

## RED / GREEN evidence

- **RED:** `ImportError: cannot import name 'RateLimitConfig' from 'backend.app.main'` — the rate limiter did not exist before implementation. Confirmed by running the focused test file before implementing.
- **GREEN:** All 31 focused rate-limit tests pass; all 241 backend tests pass with zero regressions.

## Remaining limitations or risks

1. **Single-process in-memory store:** Buckets are per-process. Multiple uvicorn workers each maintain independent buckets; a client could multiply their allowance by the worker count. Documented mitigation: use a reverse proxy (nginx/etc.) for shared rate limits in multi-worker production deployments.
2. **No coverage plugin:** Cannot quantitatively verify 80% coverage target without adding a dependency.
3. **LRU eviction may reset buckets** under very high distinct-client churn (acceptable tradeoff, documented).
4. **TestClient shares one peer identity** ("testclient") across all tests using the global app; existing tests have rate limiting disabled via conftest to avoid order-dependent 429 flakiness.

## Files changed

| File | Change |
|------|--------|
| `backend/app/main.py` | Added `RateLimitConfig`, `get_rate_limit_config()`, `_parse_positive_int`, `_parse_bool`, `_category_for_path`, `RateLimitMiddleware`; registered `RateLimitMiddleware` on the app |
| `backend/tests/test_rate_limit.py` | New focused TDD test file (31 tests) |
| `backend/tests/conftest.py` | Added `_disable_rate_limit_for_global_app` autouse fixture to prevent cross-test bucket depletion on the shared global app |
| `README.md` | Added "API rate limiting" section (env vars, defaults, 429 behavior, identity, exemptions) |
| `docs/PROJECT_STATE.md` | Extended section 2.13 with rate-limiting details |
| `.claude/tdd/rate-limit.tdd.md` | This evidence report |

## Merge evidence

No checkpoint commits were created (per task constraint: do not commit). If this work is committed/squashed, copy this report into the PR body or squash commit body so reviewers can verify what was tested and how.