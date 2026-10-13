# Greywatch — Project State

> **Status:** Under active development. This document is a verified snapshot of the repository as of the date below. Update it after every completed feature.

- **Last verified:** 2026-10-12 (the three commands in §4 were re-run on this date; rows marked NOT RERUN were not re-executed and may be stale)
- **Python:** 3.14.3 (.venv) · **Node:** 22.23.1 · **npm:** 10.9.8
- **Backend:** FastAPI 0.143.0 · Uvicorn 0.54.0 · Starlette 1.7.0 · httpx 0.28.1 · SQLite3 (stdlib) · pytest 9.1.1
- **Frontend:** React 19.3.0 · Vite 8.3.4 · @vitejs/plugin-react 6.1.2 · Oxlint 1.87.0

---

## 1. Project Overview

Greywatch is an open-source Security Information and Event Management (SIEM) platform. It collects Linux SSH authentication logs, normalizes them into structured security events, detects brute-force attacks using a threshold-based sliding window rule, surfaces detected activity as actionable security alerts, and presents them in a dark-themed React SOC dashboard with alert evidence drill-down for analyst investigation.

### Current Maturity
The project is **experimental and under active development**. Core ingestion, normalization, detection, storage, alert management, and investigation interfaces are implemented and operational. No authentication, role-based access control, or rate limiting is currently enforced on any API endpoint.

### Technology Stack
- **Backend:** Python 3.14, FastAPI, Pydantic, Uvicorn, SQLite3 (embedded)
- **Frontend:** React 19, Vite, Vanilla CSS (custom design system, DM Sans & DM Mono typography), Oxlint
- **Testing & Tooling:** pytest, TestClient (Starlette/httpx)
- **Data Store:** SQLite (`data/greywatch.db` via stdlib `sqlite3`)

### Repository Structure

```
greywatch/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py          # FastAPI application & REST endpoints (84 lines)
│   │   └── siem.py          # Log parsing, normalization, detection, DB layer (472 lines)
│   ├── requirements.txt     # fastapi, uvicorn[standard], httpx, pytest
│   └── tests/
│       └── test_siem.py     # 11 test cases (parsing, ingestion, alerts, evidence, migration) (382 lines)
├── frontend/                # React + Vite SOC dashboard
│   ├── index.html           # HTML template
│   ├── package.json         # React 19, Vite 8, Oxlint scripts and dependencies
│   ├── vite.config.js       # Dev proxy configuration (routes /api, /health to :8000)
│   ├── .oxlintrc.json       # Linter configuration (React hooks rules)
│   └── src/
│       ├── main.jsx         # React application root (StrictMode)
│       ├── App.jsx          # Dashboard views, state, polling, modal (718 lines)
│       ├── App.css          # SOC dark theme, layout, components, modal styles (1093 lines)
│       └── index.css        # Global CSS reset & typography imports (42 lines)
├── data/
│   └── greywatch.db         # SQLite database file (local only, gitignored)
├── docs/
│   └── PROJECT_STATE.md     # Permanent verified project state document
├── rules/
│   └── .gitkeep             # Placeholder for modular detection rules
├── sample-logs/
│   └── ssh-auth.log         # Sample authentication log data (failed and accepted logins)
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
  - `events`: `id` (INTEGER PK AUTOINCREMENT), `timestamp` (TEXT ISO 8601), `host` (TEXT), `event_type` (TEXT), `username` (TEXT), `source_ip` (TEXT), `severity` (TEXT), `raw_message` (TEXT).
  - `alerts`: `id` (INTEGER PK AUTOINCREMENT), `created_at` (TEXT ISO 8601), `rule_id` (TEXT), `title` (TEXT), `severity` (TEXT), `source_ip` (TEXT), `description` (TEXT), `event_count` (INTEGER), `status` (TEXT DEFAULT 'open'), `closed_at` (TEXT), `last_triggered_at` (TEXT ISO 8601, nullable).
- Schema migration: `initialize_database()` runs `_migrate_alerts_table()`, which adds `last_triggered_at` to databases created before the column existed (`ALTER TABLE` guarded by `PRAGMA table_info`) and backfills it from `created_at`, so pre-existing alerts keep their old evidence-window behavior.
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
- Professional dark-themed Security Operations Center (SOC) dashboard.
- Top stats summary: Total events, open alerts, failed SSH logins, and distinct host count.
- Navigation views:
  - **Overview:** Metric cards, event-type distribution breakdown, and recent high-priority alerts preview.
  - **Security Events:** Tabular event explorer displaying Event ID, Timestamp, Host, Type, Username, Source IP, Severity, and Raw Log Message.
  - **Alerts:** Full alert feed showing Rule ID, Title, Severity badge, Source IP, Event count, Timestamp, Status, and Action buttons.
- Real-time client-side search filtering across both events and alerts.
- Auto-refresh mechanism: Polls `/api/v1/events`, `/api/v1/alerts?status=all`, and `/health` every 10 seconds.
- Live backend connection status indicator (Online / Offline).

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
                     │  - Ingest & Alert Resolution Controls   │
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
                     ┌─────────────────────────────────────────┐
                     │          SIEM Detection Engine          │
                     │          (backend/app/siem.py)          │
                     │  - parse_auth_line(): regex extraction  │
                     │  - _normalize_timestamp(): UTC standard │
                     │  - SSH_BRUTE_FORCE sliding window rule  │
                     │  - get_alert_detail(): evidence query   │
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
                     ┌─────────────────────────────────────────┐
                     │           SQLite Storage Layer          │
                     │            (data/greywatch.db)          │
                     │  - events: indexed on (source_ip, time) │
                     │  - alerts: indexed on (status, created) │
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
1. **Ingest:** A client POSTs raw log strings to `/api/v1/events/ingest`.
2. **Normalization:** `parse_auth_line` matches each line against regex rules. Timestamps are converted to UTC ISO 8601 strings.
3. **Storage:** Normalized events are written to the `events` table in SQLite.
4. **Detection:** The engine queries `events` for failed logins (`ssh_login_failed`) from the same source IP in the preceding 5-minute rolling window.
5. **Alerting:** If the count reaches 5 or more, an alert is inserted into `alerts` (or updated if an open alert already exists for that source IP).

### Investigation & Evidence Lifecycle
1. **Trigger:** The analyst clicks "View evidence" on an alert in the React dashboard.
2. **Fetch:** Frontend calls `GET /api/v1/alerts/{alert_id}`.
3. **Query:** `get_alert_detail` retrieves the alert row, calculates `[last_triggered_at - 5m, last_triggered_at]` (falling back to `created_at` for rows backfilled by the migration), and queries `events` for `ssh_login_failed` matching the alert's `source_ip` within that window — keeping the returned evidence consistent with the alert's live `event_count` as new failures arrive.
4. **Presentation:** The frontend renders the alert metadata and evidence events table with full raw log messages inside the modal.

---

## 4. Verification Status

Commands re-run on **2026-10-12** on the host system, with exit codes
preserved. Rows marked **NOT RERUN** were executed during an earlier session
and were **not** repeated for this snapshot — treat them as stale until
re-verified.

| Verification Target | Command | Rerun? | Status | Result / Details |
|---------------------|---------|--------|--------|------------------|
| **Backend Tests** | `.venv/bin/python -m pytest -v` | Rerun 2026-10-12 | **PASSING** | `11 passed, 1 warning in 1.48s`, exit code 0.<br>*Warning: StarletteDeprecationWarning regarding httpx with testclient (pre-existing).* |
| **Frontend Lint** | `npm run lint` (in `frontend/`) | Rerun 2026-10-12 | **PASSING (2 warnings)** | `Found 2 warnings and 0 errors`, exit code 0 (Oxlint 1.87.0).<br>1. `eslint(no-unused-vars)` in `App.jsx:294` (`catch (err)` unused).<br>2. `react(set-state-in-effect)` in `App.jsx:304` (`refresh()` called synchronously in `useEffect`). |
| **Frontend Production Build** | `npm run build` (in `frontend/`) | Rerun 2026-10-12 | **PASSING** | Vite 8.3.4, `✓ 17 modules transformed`, built in 266ms, exit code 0.<br>Output: `dist/index.html` (0.45 kB), `dist/assets/index-*.css` (12.92 kB), `dist/assets/index-*.js` (235.97 kB). |
| **GitHub Actions CI** | Workflow run #38286017323 on PR #2 | Verified 2026-10-12 | **PASSING** | Both **Backend tests** and **Frontend checks** jobs passed on `chore/github-ci` commit `e251926`. [View run](https://github.com/AnuragR3k/greywatch/actions/runs/38286017323). |
| **System Python Pytest** | `python -m pytest -v` | **NOT RERUN** | Unknown this session | Earlier finding (unverified now): system `/usr/bin/python` lacks `pytest`; the virtualenv `.venv` must be used. |
| **Live Backend API** | `curl -s http://127.0.0.1:8000/health` | **NOT RERUN** | Unknown this session | Earlier result was HTTP 200 with `{"status":"ok",...}`; live server state was not re-checked. |
| **Live Alert Evidence API** | `curl -s http://127.0.0.1:8000/api/v1/alerts/1` | **NOT RERUN** | Unknown this session | Earlier result was HTTP 200 with evidence events; not re-checked. |
| **Live Frontend Dev Server** | `curl -I -s http://localhost:5173/` | **NOT RERUN** | Unknown this session | Earlier result was HTTP 200 through the Vite proxy; not re-checked. |

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
   - `get_alert_detail()` hardcodes `event_type = 'ssh_login_failed'`. When additional detection rules are introduced (e.g. web attacks, privilege escalation), this query must be generalized or delegated to rule-specific handlers.
7. **Frontend linter warnings:**
   - Two minor warnings exist in `frontend/src/App.jsx` regarding `catch (err)` and synchronous `setState` in `useEffect`.
8. **Environment requirement:**
   - Backend tests and commands must be executed using `.venv` (`.venv/bin/python` or after activating the venv), as the system Python lacks the required dependencies.

### Items Needing Further Investigation
- **Production deployment strategy:** There is currently no configured production server setup (e.g., Nginx config or FastAPI static file mounting) for serving the frontend `dist/` bundle alongside the API.
- **Log file watcher / ingestion daemon:** Ingestion currently only happens via manual HTTP POST requests. No syslog forwarder agent, file watcher (`watchfiles`/`inotify`), or systemd service exists to stream logs continuously from host files (`/var/log/auth.log` or `/var/log/secure`).

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
   - Address the 2 Oxlint warnings in `frontend/src/App.jsx` (`catch` parameter and `useEffect` state sync).
4. **Generalize alert evidence engine:**
   - Refactor `get_alert_detail()` to support dynamic rule definitions rather than hardcoding `ssh_login_failed`.
5. **Basic authentication & security controls:**
   - Implement API key or HTTP basic authentication on `/api/v1/*` endpoints.
6. **Containerization:**
   - Add a `Dockerfile` and `docker-compose.yml` that builds the React frontend, packages the FastAPI backend, and serves them together.
7. **Continuous log streaming / collector:**
   - Add a lightweight collector script (or CLI utility) that tails local `/var/log/auth.log` or reads from `journalctl` and sends lines to `/api/v1/events/ingest`.

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
