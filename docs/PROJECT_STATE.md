# Greywatch — Project State

> **Status:** Under active development. This document is a verified snapshot of the repository as of the date below. Update it after every completed feature.

- **Last verified:** 2026-10-15 (the commands in §4 were re-run on this date; rows marked NOT RERUN were not re-executed and may be stale)
- **Python:** 3.14.3 (.venv) · **Node:** 22.23.1 · **npm:** 10.9.8
- **Backend:** FastAPI 0.143.0 · Uvicorn 0.54.0 · Starlette 1.7.0 · httpx 0.28.1 · SQLite3 (stdlib) · pytest 9.1.1
- **Frontend:** React 19.3.0 · Vite 8.3.4 · @vitejs/plugin-react 6.1.2 · Oxlint 1.87.0

---

## 1. Project Overview

Greywatch is an open-source Security Information and Event Management (SIEM) platform. It collects Linux SSH authentication logs, normalizes them into structured security events, detects brute-force attacks using a threshold-based sliding window rule, surfaces detected activity as actionable security alerts, and presents them in a light, soft-grey React SOC dashboard (teal gradient telemetry panel) with alert evidence drill-down for analyst investigation.

### Current Maturity
The project is **experimental and under active development**. Core ingestion, normalization, detection, storage, alert management, and investigation interfaces are implemented and operational. No authentication, role-based access control, or rate limiting is currently enforced on any API endpoint.

### Technology Stack
- **Backend:** Python 3.14, FastAPI, Pydantic, Uvicorn, SQLite3 (embedded)
- **Frontend:** React 19, Vite, Vanilla CSS (custom design system, Urbanist interface type + JetBrains Mono for IPs/timestamps), Oxlint
- **Testing & Tooling:** pytest, TestClient (Starlette/httpx)
- **Data Store:** SQLite (`data/greywatch.db` via stdlib `sqlite3`)

### Repository Structure

```
greywatch/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py          # FastAPI application & REST endpoints (143 lines)
│   │   ├── siem.py          # Log parsing, normalization, detection, DB layer (950 lines)
│   │   ├── collector.py     # systemd-journal auth collector + CLI (769 lines)
│   │   └── suricata.py      # Suricata EVE JSON collector + CLI (623 lines)
│   ├── requirements.txt     # fastapi, uvicorn[standard], httpx, pytest
│   └── tests/
│       ├── test_siem.py     # 16 cases (parsing, ingestion, alerts, evidence, migration, end-to-end + below-threshold + per-IP)
│       ├── test_collector.py # 41 cases: parsing, checkpoint recovery, dedup, malformed, SSH brute-force, journal→alert→evidence (new)
│       ├── test_suricata.py  # 61 cases: parsing/normalization, malformed, dedup, rotation, progress, max-records, SSH-isolation, API, alert creation/evidence, unknown-signature keying, reliability/recovery
│       └── test_live_threat_workflow.py # 3 cases: live-detection contract + provenance distinction (new)
├── frontend/                # React + Vite SOC dashboard
│   ├── index.html           # HTML template
│   ├── package.json         # React 19, Vite 8, Oxlint scripts and dependencies
│   ├── vite.config.js       # Dev proxy configuration (routes /api, /health to :8000)
│   ├── .oxlintrc.json       # Linter configuration (React hooks rules)
│   └── src/
│       ├── main.jsx         # React application root (StrictMode)
│       ├── App.jsx          # Dashboard views, state, polling, modal (2155 lines)
│       ├── App.css          # SOC light theme, layout, components, alert/evidence styles (2164 lines)
│       ├── index.css        # Global reset + Urbanist/JetBrains Mono imports (185 lines)
│       ├── lib/
│       │   ├── telemetry.js # Event/alert presentation helpers + Suricata status view (431 lines)
│       │   └── utils.js     # `cn()` class-name join (clsx + tailwind-merge), 6 lines
│       └── components/
│           ├── Dock.jsx     # Magnification toolbar (Motion + cva), 128 lines
│           └── DropdownMenu.jsx # Accessible dropdown primitives (408 lines)
├── data/
│   └── greywatch.db         # SQLite database file (local only, gitignored)
├── docs/
│   ├── PROJECT_STATE.md     # Permanent verified project state document
│   ├── JOURNAL_COLLECTOR.md # Journal collection guide (install, config, verify)
│   ├── SURICATA.md          # Suricata EVE JSON collector guide (install, config, verify) (new)
│   └── LIVE_THREAT_TEST.md  # Safe, repeatable end-to-end SSH brute-force live test guide (new)
├── rules/
│   └── .gitkeep             # Placeholder for modular detection rules
├── sample-logs/
│   ├── ssh-auth.log         # Sample authentication log data (failed and accepted logins)
│   └── eve.json             # Sample sanitized Suricata EVE JSON (alert/dns/tls/http/flow) (new)
├── scripts/
│   └── live_ssh_brute_force_test.sh  # Safe, reproducible end-to-end SSH brute-force live test (new)
├── .freebuff/               # Freebuff project metadata (untracked)
├── .gitignore               # Ignores .venv/, node_modules/, dist/, *.db, etc.
├── README.md                # Project README documentation
├── vite.config.js           # Untracked root duplicate of frontend/vite.config.js
└── .venv/                   # Python virtual environment (gitignored)
```

---

## 2. Implemented Features

Only features verified in the codebase are documented below:

### 2.1 FastAPI Backend & Health Endpoint (`backend/app/main.py`)
- FastAPI application instance with tagged OpenAPI documentation (`/docs`, `/openapi.json`).
- Metadata endpoints:
  - `GET /` — Returns service name, development status, and link to docs.
  - `GET /health` — Service health check returning `{"status": "ok", "service": "greywatch-api", "version": "0.1.0"}`.
- Request validation powered by Pydantic (`IngestRequest` limits input lines between 1 and 1,000 strings).

### 2.2 SQLite Event & Alert Storage (`backend/app/siem.py`)
- SQLite database connection manager `_connection()` using Python stdlib `sqlite3`:
  - `sqlite3.Row` factory for dict-like row access.
  - Automatic commit on success and rollback on exceptions.
  - Configurable database path via `GREYWATCH_DB` environment variable (defaults to `data/greywatch.db`).
- Tables created on initialization (`initialize_database()`):
  - `events`: `id` (INTEGER PK AUTOINCREMENT), `timestamp` (TEXT ISO 8601), `host` (TEXT), `event_type` (TEXT), `username` (TEXT), `source_ip` (TEXT), `severity` (TEXT), `raw_message` (TEXT)`; plus nullable provenance + IDS fields `source` (`journal`/`suricata`/`test`/`NULL`), `dest_ip`, `src_port`, `dest_port`, `proto`, `signature`, `signature_id`, `category`.
  - `alerts`: `id` (INTEGER PK AUTOINCREMENT), `created_at` (TEXT ISO 8601), `rule_id` (TEXT), `title` (TEXT), `severity` (TEXT), `source_ip` (TEXT), `description` (TEXT), `event_count` (INTEGER), `status` (TEXT DEFAULT 'open'), `closed_at` (TEXT), `last_triggered_at` (TEXT ISO 8601, nullable).
- Schema migration: `initialize_database()` runs `_migrate_alerts_table()`, which adds `last_triggered_at` to databases created before the column existed (`ALTER TABLE` guarded by `PRAGMA table_info`) and backfills it from `created_at`, so pre-existing alerts keep their old evidence-window behavior. It also runs `_migrate_events_table()`, which extends the `events` table with the nullable `source` + network/IDS columns above via idempotent `ALTER TABLE ... ADD COLUMN` (guarded by `PRAGMA table_info`), so legacy databases keep working without data loss — Suricata/journal/test events populate the new columns while SSH and legacy line-based events leave them `NULL`.
- Indexes:
  - `idx_events_ip_time` on `events(source_ip, timestamp)`
  - `idx_alerts_status` on `alerts(status, created_at)`

### 2.3 Authentication-Log Parsing & Normalization (`backend/app/siem.py`)
- Multi-format parser `parse_auth_line(line)` supporting:
  1. Traditional syslog: `Oct 12 19:41:23 fedora sshd[1234]: Failed password...`
  2. ISO 8601 journalctl: `2026-10-12T19:41:23+05:30 fedora sshd[1234]: Failed password...`
  3. Generic prefix / no syslog header: `sshd[1234]: Failed password...` (timestamps fall back to current UTC `now()`).
- Normalization logic:
  - `_normalize_timestamp()` converts legacy syslog months/days/times and ISO strings into UTC timezone-aware ISO 8601 strings.
  - Extracted security event types:
    - `ssh_login_failed` (severity: `medium`) — regex matches failed passwords, public keys, or PAM.
    - `ssh_invalid_user` (severity: `medium`) — regex matches attempts with non-existent usernames.
    - `ssh_login_success` (severity: `low`) — regex matches accepted authentication attempts.
  - Unrecognized log lines are safely ignored without raising exceptions.

### 2.4 SSH Brute-Force Detection Engine (`backend/app/siem.py`)
- Sliding window rule `SSH_BRUTE_FORCE`:
  - **Threshold:** 5 failed logins (`ssh_login_failed`).
  - **Window:** 5 minutes (`[now - 5m, now]`).
  - **Grouping:** Per `source_ip`.
- Alert state handling:
  - When threshold is first exceeded for a source IP, creates a new alert (`status: open`, `severity: high`, `title: Repeated SSH authentication failures`).
  - On subsequent ingestions within the window while the alert is still `open`, updates the existing alert's `event_count`, `description`, and `last_triggered_at` (set to the recalculation time) rather than creating duplicate open alerts.

### 2.5 Event and Alert APIs (`backend/app/main.py`)
- `POST /api/v1/events/ingest` — Ingests a batch of raw log strings, parses lines, saves events to SQLite, runs detection rules, and returns `{received, parsed, ignored, events, alerts}`.
- `GET /api/v1/events` — Returns normalized events `{count, events}` with optional query parameter `limit` (1–500, default 100).
- `GET /api/v1/alerts` — Returns alerts `{count, alerts}` filtered by `status` (`open`, `closed`, or `all`) and `limit` (1–500, default 100).
- `GET /api/v1/alerts/{alert_id}` — Returns specific alert details along with the calculated evidence time window and matching evidence events. Returns 404 if the alert ID is not found.
- `POST /api/v1/alerts/{alert_id}/close` — Closes an open alert, setting `status` to `closed` and recording `closed_at` timestamp. Returns 404 if the alert does not exist or is already closed.

### 2.6 React SOC Dashboard (`frontend/src/App.jsx`, `frontend/src/App.css`)
- Professional light, soft-grey Security Operations Center (SOC) dashboard with a teal gradient telemetry panel.
- Top stats summary: Total events, open alerts, failed SSH logins, and distinct host count.
- Navigation views:
  - **Overview:** Metric cards, event-type distribution breakdown, and recent high-priority alerts preview.
  - **Security Events:** Tabular event explorer displaying Event ID, Timestamp, Host, Type, Username, Source IP, Severity, and Raw Log Message.
  - **Alerts:** Full alert feed with columns Last triggered, Alert (rule chip + signature + signature ID + title/description), Network (`src:port → dst:port · proto`), Severity (Greywatch tier + original Suricata tier), Events (count), Status (with resolved time), Actions (Investigate / Resolve). Alert rows for `SSH_BRUTE_FORCE` degrade gracefully to the source-IP-only layout when the Suricata-only fields are absent.
- Real-time client-side search filtering across both events and alerts.
- Auto-refresh mechanism: Polls `/api/v1/events`, `/api/v1/alerts?status=all`, and `/health` every 10 seconds.
- Live backend connection status indicator (Online / Offline), plus a Suricata EVE collector status badge (idle / error / disabled) sourced from `GET /api/v1/suricata/status`.
- Event provenance badges: each event's `source` field is rendered as a colored badge — `NULL`→`HTTP ingest` (grey), `journal`→`systemd journal` (teal), `suricata`→`Suricata` (purple), `test`→`Test` (grey) — so synthetic HTTP-ingested events are visually distinct from genuine journal/Suricata telemetry.
- Event-type category badges (SSH, sudo, Suricata alert/DNS/TLS/HTTP/flow) with dedicated color tones.
- Network metadata: a Network column/button summarizes source/dest IP, ports, and proto per event; an expandable detail row renders all parsed fields and the raw log message via `evidence-meta-grid`/`event-raw-pre`.

### 2.7 Alert Resolution Flow
- "Resolve" button on active alert cards.
- Sends `POST /api/v1/alerts/{id}/close`.
- Handles pending "Saving…" state, updates alert status to `closed`, and triggers a dashboard refresh.
- Closed alerts display a neutral status badge and disable resolution actions.

### 2.8 Alert Evidence Investigation (`AlertEvidencePanel`)
- "View evidence" action on alert cards opens an interactive investigation modal.
- Calls `GET /api/v1/alerts/{alert_id}` to retrieve alert metadata, time window, and matching events.
- Modal displays:
  - Alert title, severity, rule ID, status, source IP, creation timestamp, and total event count.
  - Calculated evidence time window (`evidence_window_start` → `evidence_window_end`).
  - Evidence event count and tabular display (`EvidenceTable`) showing timestamp, host, username, source IP, severity, and exact raw log messages.
- Dismissable via "Close" button, background overlay click, or pressing the `Escape` keyboard key.
- Includes loading state, error display, and empty state handling.

### 2.9 GitHub Actions CI (`.github/workflows/ci.yml`)
- **Triggers:** `push` and `pull_request` targeting `main`.
- **Permissions:** `contents: read` (minimum required).
- **Backend tests job:** `ubuntu-latest`, Python 3.14, pip dependency caching (via `backend/requirements.txt`), installs from `requirements.txt`, runs `python -m pytest -v`.
- **Frontend checks job:** `ubuntu-latest`, Node.js 22, npm dependency caching (via `frontend/package-lock.json`), runs from `frontend/` working directory, executes `npm ci`, `npm run lint`, `npm run build`.
- Both jobs run independently (no inter-job dependencies). Lint warnings are **not** suppressed — `npm run lint` exits 0 with 2 pre-existing warnings.
- Local equivalents of all CI checks pass (see §4). GitHub Actions has executed successfully on PR #2 — both the **Backend tests** and **Frontend checks** jobs passed on the latest commit (`e251926`). [Successful workflow run](https://github.com/AnuragR3k/greywatch/actions/runs/38286017323).

### 2.10 Linux Authentication Journal Collector (`backend/app/collector.py`)
- **Native systemd-journal collection.** A new optional collector reads structured PAM/SSH/sudo events from the local journal with `journalctl -o json` (developed and verified on Fedora 44 / systemd 259) and normalizes them into the same event shape as the line-based parser, so journal-sourced SSH failures still trigger the `SSH_BRUTE_FORCE` rule with identical behavior.
- **Structured fields.** Uses `journalctl --output=json` to read `__CURSOR` (checkpoint), `__REALTIME_TIMESTAMP` (µs-since-epoch → UTC ISO 8601), `_HOSTNAME`, `MESSAGE` (raw message preserved verbatim), and `SYSLOG_IDENTIFIER`.
- **Incremental + safe restart.** The cursor is persisted in a new `collector_state` table and advanced **inside the same transaction** as the event inserts, so a crash never leaves events stored with an un-advanced cursor. The next cycle uses `journalctl --after-cursor`.
- **Duplicate protection.** Within-batch de-duplication by journal cursor; plus a `--since` fallback (triggered automatically when a cursor becomes invalid after journal rotation) that re-reads a recent window and de-duplicates against already-stored events.
- **Supported event types:** `ssh_login_failed`, `ssh_login_success`, `ssh_invalid_user` (SSH); `sudo_session_opened`, `sudo_session_closed`, `sudo_command`, `pam_auth_failed`.
- **Provenance / genuine-vs-synthetic distinction.** A new `events.source` column records where an event came from: `journal` for genuine journal records (those carrying a `__CURSOR`), `test` for synthetic records, and `NULL` for legacy line-based ingestion. Added via an additive `ALTER TABLE` migration (`_migrate_events_table`), so existing databases keep working.
- **Optional & configurable** (off by default; `GREYWATCH_JOURNAL_ENABLED=1`). Configurable: poll interval, lookback window, per-cycle max records, identifier filter (`-t`), journalctl binary path, and `GREYWATCH_DB`.
- **Least privilege.** Reads the journal via `journalctl` (no root required for the collection path); the API is not required to run as root and is not needed at all for collection. Does **not** start, enable, or reconfigure SSH.
- **Operational endpoints:** `GET /api/v1/journal/status` (checkpoint/lag) and `POST /api/v1/journal/collect` (trigger one cycle).
- **API trust boundary.** An `@app.middleware("http")` trust boundary in `main.py` gates **every endpoint except `/` and `/health`** — including the read endpoints that expose `raw_message` and alert evidence (`GET /api/v1/events`, `/api/v1/alerts`, `/api/v1/alerts/{id}`, `/api/v1/journal/status`, `/api/v1/suricata/status`) and the write/collect endpoints (`POST /api/v1/events/ingest`, `/api/v1/journal/collect`, `/api/v1/suricata/collect`, `/api/v1/alerts/{id}/close`): loopback-only by default (`127.0.0.1`/`::1`; a remote or *unknown* peer → `403`, fail-closed) or, when network-exposed, a `GREYWATCH_API_TOKEN` shared secret sent as `Authorization: Bearer <token>` or `X-API-Key` (constant-time `hmac.compare_digest`; missing/invalid → `401`). The loopback check uses only the ASGI peer (`request.client.host`); `X-Forwarded-For`/`X-Real-IP`/`Forwarded` are **never** consulted, so binding `0.0.0.0` or enabling Uvicorn `--proxy-headers` behind an untrusted client cannot spoof loopback — do not trust forwarded headers unless behind a single trusted reverse proxy. The `GREYWATCH_JOURNAL_ENABLED`/`GREYWATCH_SURICATA_ENABLED` flags are collection *toggles*, **not** access control; the gate is independent of them.
- **CLI:** `python -m backend.app.collector [--once|--status]` or a continuous loop (example systemd unit in `docs/JOURNAL_COLLECTOR.md`).
- **Resilient collection loop.** `run_loop()` wraps each `collect_once()` cycle in a guard that catches and logs unexpected failures (e.g. a transient SQLite `database is locked` from a concurrent API writer) via `logger.exception`, so a single bad cycle resumes on the next poll instead of killing the daemon. `JournalctlError` is still handled inside `collect_once()` (reported via `result.errors`); only truly unexpected exceptions reach the outer guard. systemd still restarts on a hard crash.
- **Clean argument construction.** `run_journalctl()` is the single place that injects `--no-pager`/`--output=json`, so those flags are never duplicated on the resulting `journalctl` invocation (the per-cycle arg builders now contribute only query filters: `-t`, `--after-cursor`/`--since`).
- Documented in `docs/JOURNAL_COLLECTOR.md` (install, permissions, config, startup, troubleshooting, verify-real-events on Fedora).

### 2.11 Suricata EVE JSON Collector (`backend/app/suricata.py`)
- **EVE JSON import.** A new optional collector reads Suricata's `eve.json` (one JSON record per line) and normalizes `alert`, `dns`, `tls`, `http`, and `flow` records into Greywatch's existing event model, feeding them through the **same** storage + detection engine used by journal/HTTP ingestion (`siem._store_events_and_detect`, the shared `collector_state` table). No separate alert database is introduced.
- **Normalized event types:** `suricata_alert`, `suricata_dns`, `suricata_tls`, `suricata_http`, `suricata_flow` (unrecognized `event_type` values are skipped, mirroring the journal collector's skip-on-unrecognized behavior).
- **Fields preserved:** EVE `timestamp` (microsecond `Z` → UTC ISO 8601 seconds); `host`/`sensor` → `host` (fallback `"unknown"`); `src_ip`→`source_ip`, plus `dest_ip`, `src_port`, `dest_port`, `proto`. For `alert`: `alert.signature`→`signature`, `alert.signature_id`→`signature_id` (int), `alert.category`→`category`, `alert.severity` (0–4)→Greywatch severity (0/1=high, 2=medium, 3/4=low; missing=conservative low). The full EVE record is retained verbatim in `raw_message` (incl. DNS/TLS/HTTP/flow context not yet promoted to columns).
- **Provenance:** stored with `events.source = 'suricata'` (vs journal `'journal'`, legacy line-based `NULL`).
- **Incremental + safe restart:** a byte offset (`suricata_last_offset`) is persisted in the shared `collector_state` table and advanced **inside the same transaction** as the event inserts, so a crash never leaves events stored with an un-advanced offset — mirroring the journal collector's atomic state advance.
- **Duplicate protection:** within-batch dedup by raw JSON line; plus an offset-rollback + content-dedup against recently-stored events when the file shrinks below the stored offset (log rotation/truncation), mirroring the journal `--since` fallback. `fallback_used` is reported on a rotation reset.
- **Malformed-record tolerant:** non-JSON lines are skipped (not raised); only newline-terminated lines are processed so a record Suricata is mid-writing is never half-parsed. `max_records` bounds memory on large files (remainder picked up next cycle — no loss, just latency).
- **Reliability / recovery behaviors (Day 5, each covered by a hermetic test):** an *empty* EVE file is a clean no-op (offset `0`, `last_run_at` still recorded); a trailing record still being written (no newline) is **held back** and its offset is not committed past it; an unreadable file reports `[Errno 13] Permission denied` via `errors` without raising; a truncation to 0 bytes (or any shrink) resets the offset, sets `fallback_used=true` and re-reads content-deduplicated; a restart resumes from the persisted checkpoint; and invalid neighbors (JSON scalars, non-JSON text, missing/unparseable timestamps, unknown types) never abort a batch. A restart cannot silently enable collection: with `GREYWATCH_SURICATA_ENABLED` unset the CLI exits `2` and ingests nothing until `--once` (or the collect endpoint) is used explicitly. See `docs/SURICATA.md` §9.
- **No SSH-rule breakage / alert reuse:** Suricata `alert` records become `suricata_alert` *events* (stored, queryable via `GET /api/v1/events`). They are **not** `ssh_login_failed`, so `SSH_BRUTE_FORCE` is completely unaffected. A Suricata `alert` does however raise a Greywatch alert (`rule_id = SURICATA_ALERT`) in the **existing** `alerts` table via the shared detection engine — no separate alert system is introduced. The alert preserves signature identity, the network 5-tuple, category and mapped severity; the original numeric Suricata severity (0–4) survives in the alert `description` and in the evidence events' `raw_message`. Repeated detections of the same signature + 5-tuple within `SURICATA_ALERT_WINDOW_MINUTES` (constant, 60) aggregate into the open alert (`event_count` grows, evidence is never lost); distinct signatures/endpoints or out-of-window detections start new alerts. `get_alert_detail()` now branches on `rule_id` — the SSH evidence query is byte-identical, with a new `SURICATA_ALERT` branch returning the matching `suricata_alert` events as evidence.
- **Unknown-signature keying (Day 5 fix):** `siem._suricata_incident_conditions()` is the single definition of the incident key and is used by **both** the aggregation lookup and the evidence lookup, so the two cannot drift. When a record has *neither* `signature` nor `signature_id`, `category` joins the key, so two unknown-signature detections that merely share a 5-tuple but were categorised differently (`attempted-recon` vs `attempted-admin`) now become two alerts instead of one self-contradicting alert (whose stored severity/category came from the first event while its description came from the last). Genuinely indistinguishable records (no identity, no category, same tuple) still aggregate, preserving the bounded-duplication guarantee; signature-bearing records keep the 7-tuple key, so existing behaviour is unchanged.
- **Optional & off by default** (`GREYWATCH_SURICATA_ENABLED=1`). `/suricata/collect` runs one cycle regardless of the flag; a missing EVE file is reported via `errors` (not raised). Stdlib only — no Suricata installation required to run or test. `CollectResult` is reused from the journal collector for a consistent API shape.
- **Operational endpoints:** `GET /api/v1/suricata/status` (`enabled`, `eve_path`, `last_offset`, `last_event_ts`, `events_ingested`, `last_run_at`) and `POST /api/v1/suricata/collect` (`records_seen`, `events_ingested`, `alerts` — `SURICATA_ALERT` alerts raised/aggregated this cycle, `[]` when only aggregation occurred, `fallback_used`, `errors`).
- **CLI:** `python -m backend.app.suricata [--once|--status]` or a continuous loop; example systemd unit in `docs/SURICATA.md`.
- Documented in `docs/SURICATA.md` (including new §9 reliability/recovery reference, §10 how to run tests safely, §11 experimental/limited areas). Verified by **61** hermetic cases in `backend/tests/test_suricata.py` (parsing/severity/timestamp normalization, malformed-line skipping, offset-based progress, within-batch + rotation dedup, max-records cap, missing-file resilience, SSH-rule isolation, API endpoints, alert creation/field preservation, severity mapping on alerts, invalid field types, dedup aggregation, distinct-alert disambiguation, out-of-window boundaries, cross-cycle aggregation, evidence/investigation via `GET /alerts/{id}`, and — Day 5 — empty file, partial record hold-back, unreadable file, truncation-to-zero, restart resume, invalid-neighbour robustness, no-silent-enable, and unknown-signature keying).

### 2.12 Live End-to-End Detection Test (`scripts/live_ssh_brute_force_test.sh`)
- A documented, reproducible, **safe** script that validates the full `SSH_BRUTE_FORCE` pipeline on the real HTTP path (`POST /api/v1/events/ingest` → detection → `GET /api/v1/alerts` → `GET /api/v1/alerts/{id}` evidence).
- Starts a **throwaway** uvicorn instance on a temporary SQLite database (`GREYWATCH_DB` → `/tmp/gw-live-*.db`), so `data/greywatch.db` is never touched.
- Injects exactly five synthetic `Failed password` SSH log lines from the reserved RFC 5737 address `203.0.113.10` (not routable; no real SSH, no real accounts, no firewall/SSH config changes).
- Asserts: 5 lines parsed, 5 events stored & queryable, exactly 1 `SSH_BRUTE_FORCE` alert (`high`/`open`/source_ip/`event_count=5`), 5 evidence events in window, and `source=NULL` provenance (so test events are distinguishable from journal/Suricata telemetry).
- Fully self-cleaning (`trap ... EXIT` kills uvicorn and deletes its own temp DB). Run with `./scripts/live_ssh_brute_force_test.sh`; see `docs/LIVE_THREAT_TEST.md`.

---

## 3. Current Architecture

```
                      Raw SSH Logs (syslog / journalctl / plain)
                                         │
                                         ▼
                     ┌─────────────────────────────────────────┐
                     │          FastAPI HTTP Service           │
                     │          (backend/app/main.py)          │
                     │  - REST Endpoints (/events, /alerts)    │
                     │  - /journal/status + /journal/collect   │
                     │  - /suricata/status + /suricata/collect │
                     │  - Ingest & Alert Resolution Controls   │
                     └────────────────────┬────────────────────┘
                                          │
        (optional, see §2.10/§2.11)       │
        ┌─────────────────────────────────┘
        ▼
                     ┌─────────────────────────────────────────┐
                     │   Journal Auth Collector                │
                     │   (backend/app/collector.py)            │
                     │  - journalctl -o json (cursor checkpt)  │
                     │  - parse_journal_record() PAM/SSH/sudo  │
                     │  - collect_once() dedup + ingest_events │
                     │  + Suricata EVE collector (suricata.py) │
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
                     ┌─────────────────────────────────────────┐
                     │          SIEM Detection Engine          │
                     │          (backend/app/siem.py)          │
                     │  - parse_auth_line() / ingest_events()  │
                     │  - _normalize_timestamp(): UTC standard │
                     │  - SSH_BRUTE_FORCE sliding window rule  │
                     │  - get_alert_detail(): evidence query   │
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
                     ┌─────────────────────────────────────────┐
                     │           SQLite Storage Layer          │
                     │            (data/greywatch.db)          │
                     │  - events(+source): (source_ip, time)  │
                     │  - alerts: (status, created)           │
                     │  - collector_state: checkpoint cursor   │
                     └────────────────────▲────────────────────┘
                                          │
                            API Requests  │  Responses
                                          │
                     ┌────────────────────┴────────────────────┐
                     │           React SOC Dashboard           │
                     │             (frontend/src/)             │
                     │  - App.jsx: State, Polling, Views       │
                     │  - AlertEvidencePanel: Investigation    │
                     │  - Vite Proxy: /api, /health → :8000    │
                     └─────────────────────────────────────────┘
```

### Ingestion & Detection Lifecycle
1. **Ingest (lines):** A client POSTs raw log strings to `/api/v1/events/ingest` → `ingest_lines` → `parse_auth_line`.
2. **Ingest (journal):** The journal collector reads `journalctl -o json` incrementally (cursor from `collector_state`), classifies records with `parse_journal_record`, de-duplicates, and persists them via `siem.ingest_events` — reusing the **same** SSH regexes so `ssh_login_failed` events flow into the identical detection path.
3. **Ingest (Suricata):** The optional EVE collector reads `eve.json` incrementally (byte-offset from `collector_state`), classifies records with `parse_eve_record` (alert/dns/tls/http/flow → `suricata_*`), de-duplicates, and persists them via the same `siem._store_events_and_detect` — stored as `suricata_*` events with `source='suricata'`, coexisting with journal/HTTP events.
4. **Normalization:** `parse_auth_line` (lines) / `parse_journal_record` (journal) / `parse_eve_record` (Suricata) extract event fields; timestamps are converted to UTC ISO 8601. Every event carries a `source` provenance tag.
5. **Storage:** Normalized events are written to the `events` table in SQLite; the journal cursor and Suricata byte-offset are advanced in the same transaction.
6. **Detection:** The engine queries `events` for failed logins (`ssh_login_failed`) from the same source IP in the preceding 5-minute rolling window. (Suricata `suricata_alert` events are raw IDS events, not `ssh_login_failed`, so they are stored and queryable without triggering `SSH_BRUTE_FORCE`.)
7. **Alerting:** If the count reaches 5 or more, an alert is inserted into `alerts` (or updated if an open alert already exists for that source IP).

### Investigation & Evidence Lifecycle
1. **Trigger:** The analyst clicks "View evidence" on an alert in the React dashboard.
2. **Fetch:** Frontend calls `GET /api/v1/alerts/{alert_id}`.
3. **Query:** `get_alert_detail` retrieves the alert row, calculates `[last_triggered_at - 5m, last_triggered_at]` (falling back to `created_at` for rows backfilled by the migration), and queries `events` for `ssh_login_failed` matching the alert's `source_ip` within that window — keeping the returned evidence consistent with the alert's live `event_count` as new failures arrive.
4. **Presentation:** The frontend renders the alert metadata and evidence events table with full raw log messages inside the modal.

---

## 4. Verification Status

Commands re-run on **2026-10-15** on the host system, with exit codes
preserved. Rows marked **NOT RERUN** were executed during an earlier session
and were **not** repeated for this snapshot — treat them as stale until
re-verified.

| Verification Target | Command | Rerun? | Status | Result / Details |
|---------------------|---------|--------|--------|------------------|
| **Backend Tests** | `.venv/bin/python -m pytest backend/tests -q` | Rerun 2026-10-15 | **PASSING** | `124 passed, 1 warning`, exit code 0 — verified by `--collect-only` per file: 16 `test_siem.py` + 41 `test_collector.py` + **61 `test_suricata.py`** + 3 `test_live_threat_workflow.py` + 3 `test_db_safety.py`. The Day-5 increase (108 → 121) is +13 hermetic cases: initially-empty EVE file, partial-record hold-back, unreadable file (skipped as root), truncation-to-zero, restart-from-checkpoint, invalid-neighbour robustness, no-silent-enable CLI behaviour, unknown-signature keying (distinct categories, scoped evidence, same-category aggregation, cross-cycle aggregation, out-of-window), and a signature-bearing-dedup regression guard. No regressions; the line-based SSH brute-force tests are unchanged and still green. (The 91→108 increase is +17 new hermetic cases for Suricata alert creation, severity mapping on alerts, invalid field types, missing optional fields, dedup aggregation, distinct-alert disambiguation, and evidence/investigation — added in the Day-4 Suricata alert/dedup change; see §6 item 9.) Adds 35 new cases (31 `test_suricata.py` + 4 journal end-to-end): `test_end_to_end_http_detection_flow` (full HTTP→alert→evidence chain, below/at-threshold + per-IP isolation, duplicate-alert prevention, unrelated/out-of-window evidence exclusion), `test_below_threshold_does_not_create_alert` (4 failures → no alert), `test_brute_force_threshold_is_per_source_ip` (two IPs at threshold → two alerts), and `test_journal_records_produce_brute_force_evidence` (journal record → parsed event → SQLite → SSH_BRUTE_FORCE → evidence via `/api/v1/alerts/{id}` with `source=journal` provenance). A root `pyproject.toml` (`[tool.pytest.ini_options]` with `pythonpath = ["."]`) lets `pytest` resolve the `backend` package without `PYTHONPATH="$PWD"`, so `.venv/bin/pytest -v`, `python -m pytest -v`, and `PYTHONPATH="$PWD" .venv/bin/pytest -v` are all equivalent.<br>*Warning: StarletteDeprecationWarning regarding httpx with testclient (pre-existing, from Starlette/FastAPI — not actionable until `httpx2` is released).*<br>Added `backend/tests/test_live_threat_workflow.py` (3 cases) codifying `docs/LIVE_THREAT_TEST.md` as a permanent regression: the live-detection contract (5 synthetic failures &rarr; 1 `SSH_BRUTE_FORCE` alert &rarr; 5 evidence events via `/alerts/{id}`) and the provenance distinction (`source=NULL`/`journal`/`suricata`). Run: `.venv/bin/python -m pytest -q backend/tests/test_live_threat_workflow.py -v` (expect 3 passed). |
| **Journal Collector (real Fedora journal)** | `logger -t sudo …` → `python -m backend.app.collector --once` → `curl /api/v1/events`+`/api/v1/alerts` | Rerun 2026-10-13 | **PASSING** | A controlled `sudo` session event injected with `logger` was collected by real `journalctl --output=json` and returned via the API with `source=journal`, correct UTC timestamp, and host. 5 `sshd` failures from one IP raised `SSH_BRUTE_FORCE`. A second `--once` reported `records_seen=0 ingested=0` (cursor-based restart safety; no duplicates). |
| **Suricata EVE Integration** | `.venv/bin/python -m pytest backend/tests/test_suricata.py -q` | Rerun 2026-10-15 | **PASSING** | `61 passed`, exit code 0 (of 124 total backend tests; `--collect-only` confirms 61 collected, 0 skipped in this environment). Covers `parse_eve_record` normalization (alert/dns/tls/http/flow + severity 0–4 + UTC timestamp), malformed-line & unknown-event-type skipping, successful ingest with `source='suricata'` + all network/IDS fields, within-batch + offset + rotation-reset dedup, offset progress + idle resume, `max_records` cap, missing-file resilience, Suricata-alerts-do-not-trigger-SSH-brute-force isolation, and `GET/POST /api/v1/suricata/*` endpoints (verified in-process via FastAPI `TestClient`). Fixture: `sample-logs/eve.json`. No Suricata installation required; a missing EVE file is reported via `errors` and never raises. (+17 cases added in the Day-4 alert/dedup change: alert creation + field preservation, severity mapping on alerts, invalid field types, missing optional fields, dedup aggregation within-batch/across-cycles/out-of-window, distinct-alert disambiguation, and `GET /alerts/{id}` evidence/investigation including original Suricata severity recovery.) |
| **Frontend Lint** | `npm run lint` (in `frontend/`) | Rerun 2026-10-15 | **PASSING (3 warnings)** | `Found 3 warnings and 0 errors`, exit code 0 (Oxlint 1.87.0, 104 rules, 7 files).<br>1. `react(refs)` — "Cannot access refs during render" in `Dock.jsx` (pre-existing).<br>2. `react(set-state-in-effect)` in `App.jsx:829` (`refresh()` called synchronously in `useEffect` — pre-existing; line moved by the Day-4 restyle).<br>3. `no-unused-vars` — unused `catch (err)` parameter (pre-existing).<br>No new warnings were introduced on Day 5 (no frontend files were changed). |
| **Frontend Production Build** | `npm run build` (in `frontend/`) | Rerun 2026-10-15 | **PASSING** | Vite 8.3.4, `✓ 433 modules transformed`, built in 290ms, exit code 0.<br>Output: `dist/index.html` (1.01 kB), `dist/assets/index-BiD_m0lC.css` (28.27 kB / gzip 6.30 kB), `dist/assets/index-BiENbPQV.js` (438.38 kB / gzip 132.98 kB). |
| **Whitespace / conflict-marker Audit** | `git diff --check` | Rerun 2026-10-15 | **PASSING** | No output, exit code 0 — no trailing whitespace, no conflict markers, no whitespace errors in the working-tree diff. |
| **GitHub Actions CI** | Workflow run #38286017323 on PR #2 | Verified 2026-10-12 | **PASSING** | Both **Backend tests** and **Frontend checks** jobs passed on `chore/github-ci` commit `e251926`. [View run](https://github.com/AnuragR3k/greywatch/actions/runs/38286017323). |
| **System Python Pytest** | `python -m pytest -v` | **NOT RERUN** | Unknown this session | Earlier finding (unverified now): system `/usr/bin/python` lacks `pytest`; the virtualenv `.venv` must be used. |
| **Live Backend API** | `curl -s http://127.0.0.1:8000/health` | Rerun 2026-10-14 | **PASSING** | HTTP 200 `{"status":"ok","service":"greywatch-api","version":"0.1.0"}`. Read-only probe only — also hit `/api/v1/suricata/status` and `/api/v1/journal/status` (both 200); **no writes** were made to the production DB. (`:8000` runs current code + `data/greywatch.db`; the live test in §2.12 uses an isolated temp DB instead.) |
| **Live Alert Evidence API** | `curl -s http://127.0.0.1:8000/api/v1/alerts/1` | Rerun 2026-10-14 | **PASSING** | HTTP 200; response shape `{alert, evidence_window_start, evidence_window_end, evidence_events}` matches the dashboard evidence drawer exactly. The sample alert (`SSH_BRUTE_FORCE`, `severity=high`, `status=closed`, `source_ip=203.0.113.10`, `event_count=5`) returned 5 `ssh_login_failed` evidence events with `raw_message` containing "Failed password". Field compatibility between API and frontend verified. |
| **Live Frontend Dev Server** | `curl -s http://localhost:5173/` (plus a throwaway Vite :5174 → temp API :8001) | Rerun 2026-10-14 | **PASSING** | The user's `:5173`→`:8000` dev pair was left running untouched; the dashboard fetch-path was verified on throwaway ports `:5174` (Vite, `root=frontend`) proxying to `:8001` (isolated temp DB). SPA shell `GET /` → HTTP 200 with a `<script type="module">`; `/api/v1/events` (5 events, `source=NULL`), `/api/v1/alerts?status=all` (1 `SSH_BRUTE_FORCE`, high/open, count=5), `/api/v1/alerts/1` (5 evidence events in window), and `/api/v1/suricata/status` all returned through the dev proxy with the exact JSON shapes `App.jsx` renders (events table with source badge, alert feed, evidence drawer, Suricata status badge). Production DB untouched. |
| **Live End-to-End Detection Test** | `./scripts/live_ssh_brute_force_test.sh` | Rerun 2026-10-14 | **PASSING** | 16 checks, exit code 0; isolated temp DB on `:8010`, 5 synthetic `Failed password` lines from reserved IP `203.0.113.10` (RFC 5737), exactly 1 `SSH_BRUTE_FORCE` alert (`high`/`open`/`source_ip=203.0.113.10`/`event_count=5`), 5 evidence events in window, `source=NULL` provenance. Production `data/greywatch.db` untouched (108 events / 1 alert before & after). |
| **Live Detection Regression Tests** | `.venv/bin/python -m pytest -q backend/tests/test_live_threat_workflow.py -v` | Rerun 2026-10-14 | **PASSING** | `3 passed`; codifies the live workflow contract + provenance distinction as a permanent hermetic regression against a temp DB. |

---

## 5. Current Known Issues

### Verified Issues & Limitations
1. **README discrepancies:**
   - `README.md` lists PostgreSQL as a technology, but the project uses SQLite exclusively (`data/greywatch.db`). No PostgreSQL code or libraries are present.
   - `README.md` lists Docker, but no `Dockerfile` or `docker-compose.yml` exists in the repository.
2. **Missing authentication and authorization:**
   - All backend API routes (`/api/v1/*`, `/health`) are unauthenticated. Anyone with network access can ingest logs, read alerts, or resolve alerts.
3. **Duplicate untracked `vite.config.js`:**
   - An untracked `vite.config.js` exists at the root of the project with a slightly different proxy syntax than `frontend/vite.config.js`.
4. **Generic HTML title:**
   - `frontend/index.html` contains `<title>frontend</title>` instead of `<title>Greywatch</title>`.
5. **Unpinned backend dependencies:**
   - `backend/requirements.txt` lists package names without versions (`fastapi`, `uvicorn[standard]`, `httpx`, `pytest`).
6. **Rule-specific evidence querying coupling:**
   - `get_alert_detail()` now branches on `rule_id`. The `SSH_BRUTE_FORCE` branch is byte-identical to the original (source_ip + `ssh_login_failed` + 5-min window); a new `SURICATA_ALERT` branch returns the matching `suricata_alert` events as evidence (key + `[created_at, last_triggered_at]` window, with `raw_message` carrying the original severity). Adding *further* rules still requires a new branch here, but the pattern is now established and the SSH path is provably unchanged. Unknown rule ids fail safe (empty evidence, no wrong data).
7. **Frontend linter warnings:**
   - 3 minor warnings exist in the frontend (`react(refs)` in `Dock.jsx`, `react(set-state-in-effect)` at `App.jsx` `useEffect`, and an unused `catch` parameter). 0 errors; build is green. Address as time permits.
8. **Environment requirement:**
   - Backend tests and commands must be executed using `.venv` (`.venv/bin/python` or after activating the venv), as the system Python lacks the required dependencies. Running tests no longer requires `PYTHONPATH="$PWD"`: a root `pyproject.toml` (`[tool.pytest.ini_options]` → `pythonpath = ["."]`) makes `.venv/bin/pytest -v` resolve the `backend` package directly, matching `python -m pytest -v`.
9. **Suricata alerts are now Greywatch alerts (resolved — done in this change):**
   - Suricata EVE `alert` records are normalized to `suricata_alert` *events* (queryable via `GET /api/v1/events`, `source='suricata'`) **and** raise Greywatch alerts (`rule_id = SURICATA_ALERT`) in the shared `alerts` table via `siem._detect_suricata_alerts` inside the detection engine. They never fire `SSH_BRUTE_FORCE` (different event type). Each alert preserves signature identity, the network 5-tuple, category and mapped severity; the original numeric Suricata severity (0–4) is retained in the alert `description` and in the evidence events' `raw_message`. Repeated identical detections within `SURICATA_ALERT_WINDOW_MINUTES` (60) aggregate into one open alert (evidence never lost); out-of-window or differently-keyed detections start new alerts so distinct attacks stay distinguishable. `get_alert_detail()` (item 6) was generalized to serve `SURICATA_ALERT` evidence. See §2.11 and `docs/SURICATA.md` §3.
10. **Synthetic live test is a pipeline validation, not real-intrusion proof:**
   - `scripts/live_ssh_brute_force_test.sh` and `docs/LIVE_THREAT_TEST.md` inject synthetic `Failed password` lines from the reserved RFC 5737 address `203.0.113.10` into an isolated temp database. They prove the ingest → parse → detect → alert → evidence → dashboard data contract works, but **do not prove Greywatch detects real attacks**. Synthetic test events carry `source=NULL` ("HTTP ingest") in the dashboard, clearly distinct from real `journal`/`suricata` telemetry (see §2.6 provenance badges and §4 distinction table).

11. **Unknown-signature dedup keying (fixed 2026-10-15):**
   - Before: two Suricata `alert` records with *neither* `signature` nor `signature_id` but the same network 5-tuple collapsed into a single alert even when their `category` differed — producing a self-contradicting row whose stored `severity`/`category` came from the first event while its `description` came from the last (verified by probe before the change).
   - Now: `siem._suricata_incident_conditions()` defines the incident key once and is used by both the aggregation lookup and the evidence lookup, so they cannot drift. `category` joins the key **only** when the record has no rule identity. Result: different categories → separate alerts; identical unknown-signature records → still aggregated (bounded); signature-bearing records → key unchanged (7-tuple), so existing aggregation is byte-identical. Verified by 6 new tests plus the unchanged `SSH_BRUTE_FORCE`/journal suites.
   - Migration note: for any alert created *before* this change that has a NULL rule identity and a non-NULL `category`, the evidence query now matches its own category, so its evidence list is scoped to that category. Its historical `event_count` is not rewritten. No such rows exist in the current production database (0 Suricata alerts), so this is a forward-looking note, not a data-repair requirement.

### Items Needing Further Investigation
- **Production deployment strategy:** There is currently no configured production server setup (e.g., Nginx config or FastAPI static file mounting) for serving the frontend `dist/` bundle alongside the API.
- **Log file watcher / ingestion daemon:** Ingestion via manual HTTP POST is the legacy path. Continuous collection is now provided by the native **journal collector** (`backend/app/collector.py`, §2.10) reading `journalctl -o json`; it does not tail `/var/log/auth.log` or `/var/log/secure`, which is acceptable on journald-based hosts (Fedora) but a syslog-file tailer would still be needed for non-journald systems.

---

## 6. Git and Release Status

This section records durable facts only. Transient state — the currently
checked-out branch, open pull-request counts, and uncommitted working-tree
changes — changes constantly and is deliberately **not** recorded here; read
it live with `git status` / `git log` and on the GitHub repository page.

- **Remote:** `https://github.com/AnuragR3k/greywatch.git`
- **Workflow:** changes land on feature branches and are merged via pull
  requests (see §8); `main` is never pushed to directly.
- **Release tags / published releases:** none as of 2026-10-12.

### Core history (fixed snapshot, 2026-10-12 — run `git log` for current)

| Commit | Message |
|--------|---------|
| `74fe146` | `feat: add alert evidence investigation` |
| `90cd35b` | `fix: update existing SSH brute-force alert counts` |
| `f4b0242` | `feat: add Greywatch security operations dashboard` |
| `1ad4582` | `feat: add SSH authentication ingestion and brute-force detection` |
| `928d855` | `chore: initialize Greywatch SIEM API` |

### In-progress work
- **`chore/github-ci`** branch — PR [#2](https://github.com/AnuragR3k/greywatch/pull/2) adds
  `.github/workflows/ci.yml`. Commits `ec102eb` (workflow) and `e251926` (docs) on this
  branch. GitHub Actions has **passed** on both jobs (run [#38286017323](https://github.com/AnuragR3k/greywatch/actions/runs/38286017323)).
  Not yet merged into `main`.

---

## 7. Next Priorities

A prioritized list of near-term engineering tasks:

1. **Clean up repository configuration:**
   - Remove the redundant root `vite.config.js` (duplicate of `frontend/vite.config.js`).
   - Decide whether `.freebuff/` should be gitignored or tracked deliberately.
2. **Pin backend dependencies:**
   - Freeze versions in `backend/requirements.txt` to guarantee reproducible installations across environments.
3. **Fix frontend warnings & metadata:**
   - Fix HTML title in `frontend/index.html` to "Greywatch".
   - Address the Oxlint warnings in `frontend/src/App.jsx` (`catch` parameter and `useEffect` state sync).
   - Fix the uncolored event-category badges: `categorizeEventType` assigns `teal`/`orange`/`purple`/`grey` tones to the Events-table badges, but `App.css` only defined `.badge` color rules for severities (`high`/`medium`/`low`/`info`) and statuses (`open`/`closed`). Added `.badge.teal`/`.orange`/`.purple`/`.grey` (using the existing accent-color palette) so category badges render with their intended fill. Verified `npm run lint` (0 errors) and `npm run build` (passing).
4. **Generalize alert evidence engine:**
   - Refactor `get_alert_detail()` to support dynamic rule definitions rather than hardcoding `ssh_login_failed`.
5. **Basic authentication & security controls:**
   - Implement API key or HTTP basic authentication on `/api/v1/*` endpoints.
6. **Containerization:**
   - Add a `Dockerfile` and `docker-compose.yml` that builds the React frontend, packages the FastAPI backend, and serves them together.
7. **Continuous log streaming / collector:**
   - **DONE (2026-10-13).** Added `backend/app/collector.py` — a native systemd-journal reader (`journalctl -o json`) with cursor-based incremental collection, safe restart, duplicate protection, and `sudo`/PAM/SSH event parsing. See §2.10 and `docs/JOURNAL_COLLECTOR.md`. The line-based `/api/v1/events/ingest` path is unchanged.
   - **DONE (2026-10-14).** Added `backend/app/suricata.py` — a Suricata EVE JSON collector (byte-offset incremental collection, rotation-safe dedup, malformed-line tolerance, severity/timestamp field normalization) that reuses the journal collector's `CollectResult` and `collector_state` table. See §2.11 and `docs/SURICATA.md`. Optional and off by default (`GREYWATCH_SURICATA_ENABLED=1`).

8. **Live end-to-end detection test & documentation** — **DONE (2026-10-14).**
   - Added `scripts/live_ssh_brute_force_test.sh`: a safe, reproducible live test that starts a throwaway uvicorn on a **temp** SQLite DB (`:8010`, never `data/greywatch.db`), injects 5 synthetic `Failed password` lines from the reserved RFC 5737 IP `203.0.113.10` via the existing `/api/v1/events/ingest` endpoint, and asserts the detection contract + alert evidence + `source=NULL` provenance. Self-cleaning (`trap ... EXIT` removes the temp DB and stops the test server).
   - Added `backend/tests/test_live_threat_workflow.py` (3 hermetic pytest cases): the live-detection contract (5 failures → 1 `SSH_BRUTE_FORCE` alert → 5 evidence events) and the provenance distinction (`source=NULL`/`journal`/`suricata`).
   - Added `docs/LIVE_THREAT_TEST.md` (prerequisites, exact commands, expected output, inspection, simulated-vs-real distinction, optional real-journal step, safe cleanup, troubleshooting).
   - Verified: script → 16/16 PASS; pytest → 91 passed, 1 warning; backend + frontend lint/build green; `git diff --check` clean; production `data/greywatch.db` confirmed at 108 events / 1 alert before and after.
9. **Suricata alert creation + deduplication (Day 4 Suricata IDS integration, Phase 3/4):** **DONE.**
   - `siem._detect_suricata_alerts` evaluates `suricata_alert` events in the shared `_store_events_and_detect` engine: each raises a Greywatch alert (`rule_id = SURICATA_ALERT`) in the existing `alerts` table. No new endpoints or tables — the `alerts` table gained nullable columns (`dest_ip`, `src_port`, `dest_port`, `proto`, `signature`, `signature_id`, `category`) via `CREATE TABLE` + idempotent `PRAGMA table_info`-guarded `ALTER` migration, so legacy `SSH_BRUTE_FORCE` alerts keep all original columns and are unaffected.
   - Each alert preserves signature identity (`signature`/`signature_id`), category, the network 5-tuple, mapped severity; the original numeric Suricata severity (0–4) is retained in `raw_severity` (surfaced in the alert `description`) and verbatim in the evidence events' `raw_message`. Event provenance stays `source='suricata'`.
   - **Deduplication / aggregation:** key `(signature_id, signature, source_ip, dest_ip, src_port, dest_port, proto)` compared NULL-safely with SQLite `IS`; same-key detections within `SURICATA_ALERT_WINDOW_MINUTES` (constant 60) aggregate into the open alert (`event_count` grows, `last_triggered_at` advances, `description` refreshes — **no evidence loss**, every event stays stored). Same key but outside the window, or a different key, starts a new alert, so distinct attacks stay distinguishable while identical IDS alerts cannot multiply unboundedly. Alert timestamps use the EVE event timestamp (deterministic for replayed/historical logs).
   - **Compatibility:** `SSH_BRUTE_FORCE`, journal collection, and HTTP ingestion are unchanged; `get_alert_detail()` now branches on `rule_id` — the SSH evidence query is byte-identical, with a new `SURICATA_ALERT` branch returning the matching `suricata_alert` events as evidence. `POST /api/v1/suricata/collect` now returns the raised `SURICATA_ALERT` alerts in its `alerts` payload (`[]` when only aggregation occurred).
   - **Limitations:** records with no rule identity, no category and identical network fields are indistinguishable and therefore aggregate into one "unknown" alert; the 60-minute window is a fixed constant (not per-signature); only `alert` EVE records raise alerts (`dns`/`tls`/`http`/`flow` stay events). See `docs/SURICATA.md` §2 and §11.
   - **Verified:** `.venv/bin/python -m pytest -v` → `108 passed, 1 warning` (16 `test_siem.py` + 41 `test_collector.py` + 48 `test_suricata.py` + 3 `test_live_threat_workflow.py`), exit 0; `git diff --check` clean. The 3 prior "no alerts" assertions were reconciled to expect `SURICATA_ALERT` alerts while preserving their SSH-isolation intent. 17 new hermetic cases added for alert creation/field preservation, severity mapping on alerts, invalid field types, missing optional fields, dedup aggregation (within-batch, across cycles, out-of-window), distinct-alert disambiguation, and `GET /alerts/{id}` evidence/investigation. **Production `data/greywatch.db` was NOT modified** (all tests run against temp DBs via the `GREYWATCH_DB` env fixture; `initialize_database()` is lazy per-request, so importing the app never touches the prod DB — confirmed: prod `alerts` schema unchanged, 0 Suricata rows before and after).

10. **Operational readiness & reliability hardening (Day 5, 2026-10-15):** **DONE.**
   - **Audit result:** the Day-4 backend/frontend work was present in the working tree but entirely **uncommitted** (5 modified + 9 untracked paths); the reported Day-4 verification numbers (108 tests, 3 lint warnings, build passing) were reproducible, and `docs/SURICATA.md` / §2.11 already matched the code except for the dedup limitation.
   - **Reliability probes before writing tests** (isolated temp DBs): empty EVE file → clean no-op with offset `0` and `last_run_at` recorded; mid-write partial line → held back, ingested once when completed; `chmod 000` → `[Errno 13] Permission denied` reported without raising; truncate-to-zero → `fallback_used=true`, offset reset, nothing lost; restart → resumed from the persisted checkpoint. No defect was found in these paths, so they were **documented and locked down with tests** rather than changed.
   - **The one real defect found and fixed** was the unknown-signature dedup collapse (see §5 item 11). The fix is ~25 lines in `siem.py` plus 6 tests; `get_alert_detail()` now builds its evidence key from the same helper, removing the possibility of the two diverging.
   - **Docs updated (no new redundant documents):** `docs/SURICATA.md` gained CLI exit codes, `suricata/status` field semantics, a per-situation reliability/recovery reference, a "how to run the tests safely" section (including the root-skip and unshipped-fixture caveats), and an "experimental / limited" section; `docs/PROJECT_STATE.md` §2.11, §4, §5 and §7 were refreshed.
   - **Verified:** `.venv/bin/python -m pytest backend/tests -q` → `121 passed, 1 warning`, exit 0; `npm run lint` → `Found 3 warnings and 0 errors`, exit 0 (all pre-existing); `npm run build` → exit 0 (28.27 kB CSS / 438.38 kB JS); `git diff --check` → clean, exit 0.
   - **Production database safety — with one honest exception.** All 121 tests are hermetic (`GREYWATCH_DB` → per-test temp file), and the isolated probe scripts also used temp databases: `data/greywatch.db` still holds exactly `108 events / 1 alert / 0 suricata events`, its single alert row is byte-for-byte unchanged (`id=1, rule_id=SSH_BRUTE_FORCE, severity=high, status=closed, event_count=5, source_ip=203.0.113.10`), and a read-only `PRAGMA integrity_check` returns `ok`. **However**, one Day-5 verification command (`python -c "from backend.app.main import app; TestClient(app).get(...)"`, run *without* `GREYWATCH_DB`) imported the app against the default database path; `initialize_database()` is lazy per request, so that call performed its usual additive migration and added the seven nullable Suricata columns (`dest_ip`, `src_port`, `dest_port`, `proto`, `signature`, `signature_id`, `category`) to `alerts`, moving the file's mtime to `2026-10-15 16:07`. No row values changed (every added column is NULL on the existing row) and no data was written — but the *schema* was touched, which is what the app does by design on first use. The command was re-run correctly afterwards with `GREYWATCH_DB` pointed at a temp file, and all remaining verification used isolated databases. To restore the exact pre-session schema, drop those seven columns (the app re-adds them on its next request).

11. **Production database safety guard (Day 5.1, 2026-10-15):** **DONE.**
   - **Root cause closed:** a DB-touching operation run without `GREYWATCH_DB` migrates/writes `data/greywatch.db` via the lazy per-request `initialize_database()`. Added a **test-only** guard that does not affect normal application startup: `backend/tests/conftest.py` (autouse `_isolate_test_database` fixture) redirects an unset `GREYWATCH_DB` to an isolated temp database and **fails loudly** (`pytest.fail`) if a test explicitly points at the production path; `backend/app/siem.py::is_production_db_path` is the pure detector; `backend/tests/test_db_safety.py` adds 3 regression tests (detection, unset-redirect, and a subprocess refusal check). `docs/DB_SAFETY_INCIDENT.md` is the authoritative incident record. The seven Suricata columns are retained as required -- no destructive `DROP COLUMN`.
   - **Verified:** full suite passes with `GREYWATCH_DB` unset (the conftest redirects every test to a temp DB); `data/greywatch.db` is unchanged post-run (108 events / 1 `SSH_BRUTE_FORCE` alert / 0 `SURICATA_ALERT`; `PRAGMA integrity_check = ok`). Current count: `124 passed, 1 warning`.

---

## 8. Agent Collaboration Rules

These rules govern multi-agent collaboration across ChatGPT, Freebuff, Poolside, and Antigravity:

### Agent Responsibilities
| Agent | Role & Scope |
|-------|--------------|
| **ChatGPT** | Architecture design, system planning, debugging triage, PR/code reviews, and writing task specifications. Does not author application code directly. |
| **Freebuff** | Focused frontend implementation (React components, styling, UI state, Vite configuration). |
| **Poolside** | Backend implementation (FastAPI endpoints, SIEM engine, detection logic, SQLite schemas, and test suites). |
| **Antigravity** | Complex debugging, multi-file refactoring, performance optimization, and specialized technical reviews. |

### Process & Workflow Rules
- **One active editor per set of files:** Agents must not edit the same files concurrently. Confirm ownership before modifying shared components.
- **Feature branches and pull requests:** All changes must be developed on feature branches and submitted via PRs. Never commit directly to `main`.
- **Run and report verification before claiming completion:**
  - Backend changes: Execute and report `.venv/bin/python -m pytest -v`.
  - Frontend changes: Execute and report `npm run lint` and `npm run build`.
  - CI changes: Ensure the new workflow runs on GitHub Actions; do not claim a "passing CI" badge until GitHub has actually executed the workflow successfully.
  - Report exact test counts, warning messages, and output summaries.
- **Update documentation:** Always update `docs/PROJECT_STATE.md` after completing a feature milestone.
- **Safeguards & Security:**
  - Never commit API secrets, private credentials, real customer logs, local SQLite databases (`*.db`), or virtual environments (`.venv`).
  - Respect `.gitignore` rules at all times.
  - Preserve existing working code; avoid full-file rewrites without clear justification.
