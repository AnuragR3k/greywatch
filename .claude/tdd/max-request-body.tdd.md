# TDD Evidence Report — Configurable API Request-Body Limits (F1)

## Source plan

No `*.plan.md` file was provided. User journeys and acceptance criteria were
derived directly from the task requirements (security review finding F1).

## User journeys

1. As an operator, I want to cap HTTP request-body size so that excessively
   large bodies cannot exhaust memory or resources.
2. As a client, I want requests under the limit to be processed normally.
3. As a client, I want requests exceeding the limit to receive a clear 413
   error so I can reduce my payload.
4. As an operator, I want the limit configurable via environment variable,
   with a safe default and no silent disable-on-misconfiguration.

## Task report

| Task | Execution summary | Validation command | Output excerpt | Guarantee |
|------|-------------------|-------------------|----------------|-----------|
| Add `get_max_request_bytes()` config | Parses `GREYWATCH_MAX_REQUEST_BYTES`; default 1 MiB; invalid falls back to default; 0/negative disables | `.venv/bin/python -m pytest backend/tests/test_max_request_body.py -k "get_max_request_bytes" -v` | 8/8 config tests PASSED | Config never silently disables protection |
| Add `MaxBodySizeMiddleware` | ASGI middleware counts actual bytes streamed via `http.request`; rejects with 413 when exceeded; replays bounded body to inner app | `.venv/bin/python -m pytest backend/tests/test_max_request_body.py -v` | 22/22 PASSED | Body size enforced on actual bytes, not Content-Length |
| Register middleware on FastAPI app | `app.add_middleware(MaxBodySizeMiddleware, max_bytes=get_max_request_bytes())` after app creation | `.venv/bin/python -m pytest backend/tests -q` | 210 passed, 0 failed | No regressions across all existing suites |

## Test specification

| # | What is guaranteed | Test file or command | Test type | Result | Evidence |
|---|--------------------|----------------------|-----------|--------|----------|
| 1 | Default limit is 1 MiB (1,048,576 bytes) | `test_max_request_body.py::test_get_max_request_bytes_default_is_one_mebibyte` | unit | PASS | 8 config tests passed |
| 2 | Custom limit via env var is honored | `test_get_max_request_bytes_parses_values[1000-1000]` | unit | PASS | `GREYWATCH_MAX_REQUEST_BYTES=1000` -> limit 1000 |
| 3 | Zero/negative disables the limit | `test_get_max_request_bytes_parses_values[0-None]` | unit | PASS | `0` -> `None` (disabled) |
| 4 | Invalid config falls back to default, never disabled | `test_get_max_request_bytes_invalid_falls_back_to_default` | unit | PASS | `"not-a-number"` -> 1 MiB |
| 5 | Body under limit is accepted (200) | `test_under_limit_is_accepted` | integration | PASS | 100-byte body -> 200 |
| 6 | Body exactly at limit is accepted (boundary) | `test_at_limit_is_accepted` | integration | PASS | 100-byte body at limit 100 -> 200 |
| 7 | Body over limit is rejected with 413 | `test_over_limit_is_rejected` | integration | PASS | 101-byte body at limit 100 -> 413 |
| 8 | Large body over 1 MiB default rejected with 413 | `test_over_limit_by_a_lot_is_rejected` | integration | PASS | 1 MiB + 1 bytes -> 413 |
| 9 | Actual bytes enforced, not Content-Length header | `test_asgi_misleading_content_length_actual_bytes_enforced` | unit (ASGI) | PASS | Content-Length: 10 but 150 bytes sent -> 413 |
| 10 | Missing Content-Length handled safely | `test_asgi_missing_content_length_oversized_rejected` | unit (ASGI) | PASS | No Content-Length header, 150 bytes -> 413 |
| 11 | Chunked/streamed body over limit rejected | `test_streamed_body_over_limit_is_rejected` | unit (ASGI) | PASS | 60+60 bytes at limit 100 -> 413 |
| 12 | Chunked/streamed body under limit passes through | `test_streamed_body_under_limit_passes_through` | unit (ASGI) | PASS | 60 bytes at limit 100 -> reaches inner app |
| 13 | Custom max-bytes override works | `test_custom_max_bytes_override` | integration | PASS | Limit 50: 50 bytes -> 200, 51 bytes -> 413 |
| 14 | Limit disabled (0) accepts large bodies | `test_limit_zero_disables_protection` | integration | PASS | 10 MiB body with limit=0 -> 200 |
| 15 | GET /health unaffected by body limit | `test_public_endpoints_unaffected_by_body_limit` | integration | PASS | GET /health -> 200 |
| 16 | Body limit applies to protected endpoints | `test_body_limit_applies_to_protected_endpoints` | integration | PASS | Large POST to /ingest -> 413 |
| 17 | 413 response has JSON detail body | `test_over_limit_is_rejected` | integration | PASS | `resp.json()["detail"]` contains "too large" |
| 18 | All existing tests still pass (no regressions) | `.venv/bin/python -m pytest backend/tests -q` | integration | PASS | 210 passed, 0 failed |

## Coverage and known gaps

Coverage command: `.venv/bin/python -m pytest backend/tests -q` (no separate coverage plugin configured; pytest alone).

- **Coverage gap:** The `http.disconnect` passthrough branch in `MaxBodySizeMiddleware.__call__` is not directly exercised by a test. It is a defensive branch for client disconnects mid-body; no test simulates a disconnect during streaming.
- **Coverage gap:** The "unknown message type" passthrough branch (non-http.request, non-http.disconnect ASGI messages) is not directly exercised.
- **No coverage plugin installed** in `.venv` (requirements.txt only lists fastapi, uvicorn, httpx, pytest). Coverage percentage is not instrumented.
- **No frontend changes** — frontend is out of scope per task constraints.

## Configuration examples

```bash
# Default: 1 MiB limit (no env var needed)
GREYWATCH_MAX_REQUEST_BYTES=1048576 uvicorn backend.app.main:app

# Custom 512 KiB limit
GREYWATCH_MAX_REQUEST_BYTES=524288 uvicorn backend.app.main:app

# Disable the limit (explicit operator choice, not recommended for untrusted networks)
GREYWATCH_MAX_REQUEST_BYTES=0 uvicorn backend.app.main:app

# Invalid value falls back to 1 MiB default (safe, never silently disabled)
GREYWATCH_MAX_REQUEST_BYTES=not-a-number uvicorn backend.app.main:app
```

## Merge evidence

No checkpoint commits were created (per task constraint: do not commit). The RED/GREEN cycle was validated as follows:

- **RED:** `ImportError: cannot import name 'MaxBodySizeMiddleware'` — confirmed the middleware did not exist before implementation.
- **GREEN:** All 22 new tests pass (`backend/tests/test_max_request_body.py`); all 210 existing backend tests pass with no regressions.

If this work is committed/squashed, the summary above should be copied into the PR body or squash commit body so reviewers can verify what was tested and how.

## Remaining limitations or risks

1. **Unread body on 413:** When the middleware rejects an oversized body, it does not read the remaining request bytes. The ASGI server (uvicorn) handles connection cleanup. This is standard for 413 responses but may leave the connection in a half-closed state until the server closes it.
2. **Bounded buffering:** The middleware buffers up to `max_bytes + final_chunk` bytes in memory before enforcing the limit. This is bounded by the limit (1 MiB default) plus one final chunk, so memory usage is predictable.
3. **No coverage plugin:** Coverage percentage is not instrumented in CI. The 80% coverage target from the TDD skill cannot be quantitatively verified without adding a coverage tool (e.g., `pytest-cov`).
4. **http.disconnect branch untested:** The defensive branch for client disconnects during body streaming is not covered by a test.