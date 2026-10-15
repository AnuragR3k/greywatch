# Live Threat Test — End-to-End SSH Brute-Force Detection

This document describes a **safe, repeatable, end-to-end live test** that proves
Greywatch's existing `SSH_BRUTE_FORCE` detection pipeline works from ingestion
through to alert persistence and dashboard display.

> **This is a pipeline validation, not an intrusion-detection proof.** It injects
> five synthetic SSH authentication-failure events using a reserved
> documentation IP and asserts the detection, alert, and evidence logic behaves
> exactly as designed. It does **not** prove Greywatch can detect real network
> attacks, and it performs **no real SSH logins, targets no real accounts, and
> touches no production data.**

---

## 1. What the test proves

| # | Acceptance criterion | How it's verified |
|---|----------------------|-------------------|
| 1 | 5 failed SSH auth events are accepted | `POST /api/v1/events/ingest` returns `parsed: 5` |
| 2 | Events are stored and queryable | `GET /api/v1/events?limit=100` returns `count: 5`, all `ssh_login_failed`, all `source_ip: 203.0.113.10` |
| 3 | The detection rule fires at threshold | `POST .../ingest` returns 1 alert with `rule_id: SSH_BRUTE_FORCE` (threshold = 5 failed logins in 5 minutes, per `source_ip`; see `BRUTE_FORCE_THRESHOLD`/`BRUTE_FORCE_WINDOW_MINUTES` in `backend/app/siem.py`) |
| 4 | An alert is persisted with the expected attributes | `GET /api/v1/alerts?status=all` returns 1 alert: `rule_id=SSH_BRUTE_FORCE`, `severity=high`, `status=open`, `source_ip=203.0.113.10`, `event_count=5` |
| 5 | Alert evidence points to the relevant events | `GET /api/v1/alerts/{id}` returns `evidence_events` (5 events, all `ssh_login_failed` from `203.0.113.10`) within an `evidence_window_start`/`evidence_window_end` |
| 6 | The alert appears through the existing alerts API | `GET /api/v1/alerts?status=all&limit=100` → `count: 1`; detail retrievable by id |

The same contract is also encoded permanently as an automated regression test in
`backend/tests/test_live_threat_workflow.py` (run by the normal test suite).

---

## 2. Safety model (read carefully)

- **Reserved test IP.** The attack source is `203.0.113.10`, a reserved
  RFC 5737 documentation address. It is not routable and never targets any real
  host.
- **Isolated database.** The test starts its **own** throwaway uvicorn instance on
  a **temporary** SQLite database (`GREYWATCH_DB` → `/tmp/gw-live-*.db`). It does
  **not** use `data/greywatch.db`, the production database. The existing dev API
  on `:8000` (which serves `data/greywatch.db`) is left untouched — the test uses
  port `:8010` by default.
- **No real SSH.** Five *log lines* of the form
  `sshd[600X]: Failed password for attackerX from 203.0.113.10 port ... ssh2`
  are POSTed to the ingestion API and parsed with the existing `parse_auth_line`
  regex. No SSH daemon is contacted; no credentials are used; no SSH/firewall/OS
  security settings are changed.
- **Deterministic & idempotent.** A fresh temp database is created on every run,
  so re-running produces the same result every time with no duplicate events or
  alerts.
- **Cleanup is automatic.** The script kills its own uvicorn process and deletes
  only its own temp database (`trap ... EXIT`). It never deletes, modifies, or
  queries `data/greywatch.db`.

---

## 3. Prerequisites

- A Linux host with systemd (the test itself only needs the API; journal
  testing is a separate optional step in §7).
- Python 3.14 virtualenv at `.venv` with `uvicorn` and `fastapi` installed, and
  `backend.app.main:app` importable from the repo root:
  ```bash
  .venv/bin/uvicorn backend.app.main:app --help
  ```
- `curl` on `PATH`.
- (Dashboard viewing only, §6) `node`/`npm` and `frontend/node_modules` installed
  (`npm install` in `frontend/`).

---

## 4. Exact commands

### A. Run the automated live test (recommended)

From the repository root:

```bash
./scripts/live_ssh_brute_force_test.sh
```

That single command starts an isolated API on `:8010` using a temp database,
injects 5 synthetic failures, queries every relevant endpoint, asserts the
contract, prints a per-check report, and cleans up automatically. Run it from any
directory; it always operates on the repo at its own location.

Optional overrides (env vars):

```bash
LIVE_TEST_PORT=9020 LIVE_TEST_ATTACK_IP=203.0.113.99 ./scripts/live_ssh_brute_force_test.sh
```

### B. Run the automated regression test

```bash
.venv/bin/python -m pytest -q backend/tests/test_live_threat_workflow.py -v
```

### C. Full test + lint suite

```bash
.venv/bin/python -m pytest -q                 # backend (expect 91 passed, 1 warning)
cd frontend && npm run lint && npm run build   # frontend (0 errors; 3 pre-existing warnings)
git diff --check                              # whitespace clean
```

---

## 5. Expected output

A successful run ends with:

```
== Greywatch live SSH brute-force detection test ==
...
[1/5] Starting throwaway Greywatch API on 127.0.0.1:8010 ...
    health: {"status":"ok","service":"greywatch-api","version":"0.1.0"}
[2/5] Ingesting 5 synthetic 'Failed password' lines from 203.0.113.10 ...
    ingest: {"received":5,"parsed":5,"ignored":0,"events":[...],"alerts":[{"rule_id":"SSH_BRUTE_FORCE","severity":"high","status":"open","source_ip":"203.0.113.10","event_count":5,...}]}
[3/5] Verifying detection contract ...
  OK   : ingest parsed 5/5 lines = '5'
  OK   : 0 lines ignored = '0'
  OK   : 5 events stored & queryable via GET /api/v1/events = '5'
  OK   : all 5 events carry 203.0.113.10 = '5'
  OK   : exactly one alert raised = '1'
  OK   : alert rule_id == SSH_BRUTE_FORCE = 'SSH_BRUTE_FORCE'
  OK   : alert severity == high = 'high'
  OK   : alert status == open = 'open'
  OK   : alert source_ip == 203.0.113.10 = '203.0.113.10'
  OK   : alert event_count == 5 = '5'
[4/5] Verifying alert evidence (GET /api/v1/alerts/1) ...
  OK   : evidence window_start present = 'yes'
  OK   : evidence window_end present = 'yes'
  OK   : evidence_events length == 5 = '5'
  OK   : all evidence events from 203.0.113.10 = '203.0.113.10'
  OK   : evidence events are ssh_login_failed = 'ssh_login_failed'
[5/5] Provenance distinction ...
  OK   : synthetic HTTP events have source=NULL (HTTP ingest line) = 'null'

== RESULT: 16 passed, 0 failed ==
PASS — SSH_BRUTE_FORCE fired end-to-end on synthetic data.
Simulated only: no real SSH login, no real accounts, no production DB touched.
Cleanup: stopped test API on :8010; removed temp DB /tmp/gw-live-*.db.
```

Exit code is `0` on PASS and non-zero on FAIL.

---

## 6. Inspecting events and alerts by hand

The script does this for you, but you can also replicate it against any running
API instance. By default the script's API lives on `:8010` while it runs — point
`curl` at it during the run, or at `:8000` for the dev server:

```bash
# Health
curl -s http://127.0.0.1:8010/health
# Stored events (the 5 synthetic failures)
curl -s "http://127.0.0.1:8010/api/v1/events?limit=100" | python3 -m json.tool
# Alert list (SSH_BRUTE_FORCE, open)
curl -s "http://127.0.0.1:8010/api/v1/alerts?status=all&limit=100" | python3 -m json.tool
# Alert detail + evidence events
curl -s "http://127.0.0.1:8010/api/v1/alerts/1" | python3 -m json.tool
```

Expected key fields:

- `GET /api/v1/events` → `count: 5`; each event `event_type: ssh_login_failed`,
  `source_ip: 203.0.113.10`, `source: null`.
- `GET /api/v1/alerts?status=all` → `count: 1`; the alert has
  `rule_id: SSH_BRUTE_FORCE`, `severity: high`, `status: open`,
  `source_ip: 203.0.113.10`, `event_count: 5`.
- `GET /api/v1/alerts/1` → `evidence_events` containing 5 events, plus an
  `evidence_window_start`/`evidence_window_end` window.

### Viewing the result in the dashboard

The dashboard polls exactly these endpoints every 10 seconds and renders them in
the **Alerts** feed (Rule ID, Severity badge, Status badge, Source IP, Event
count), the **Security Events** table (Source badge, Type badge, Severity, Raw
message, expandable detail), and the **Alert Evidence** drawer
(`GET /api/v1/alerts/{id}`).

To see the synthetic test data in the browser dashboard against an **isolated**
database (so production data is never used):

```bash
# Terminal 1 — isolated API on a temp DB (stop any existing API on :8000 first)
GREYWATCH_DB=/tmp/gw-demo.db .venv/bin/uvicorn backend.app.main:app --port 8000 --log-level warning
# Terminal 2 — dashboard (proxies /api -> http://127.0.0.1:8000 per frontend/vite.config.js)
cd frontend && npm run dev
# Terminal 3 — inject the synthetic failures into the isolated DB
curl -s -X POST http://127.0.0.1:8000/api/v1/events/ingest \
  -H 'Content-Type: application/json' \
  -d '{"lines":["sshd[6000]: Failed password for attacker0 from 203.0.113.10 port 54000 ssh2","sshd[6001]: Failed password for attacker1 from 203.0.113.10 port 540100 ssh2","sshd[6002]: Failed password for attacker2 from 203.0.113.10 port 540200 ssh2","sshd[6003]: Failed password for attacker3 from 203.0.113.10 port 540300 ssh2","sshd[6004]: Failed password for attacker4 from 203.0.113.10 port 540400 ssh2"]}'
# Then open http://localhost:5173 in a browser.
```

This uses port `:8000` only because the Vite dev proxy is configured to forward
`/api` and `/health` to `http://127.0.0.1:8000`. If `:8000` is already in use by
your dev server, stop that server first (or temporarily change the proxy target
in `frontend/vite.config.js`, or use the script in §4A which needs no browser).

---

## 7. Distinguishing simulated events from real telemetry

Greywatch records the provenance of every event in `events.source` (the dashboard
reads this to render a colored source badge):

| `source` value | Meaning | Dashboard badge |
|----------------|---------|-----------------|
| `NULL` / unset | Legacy line-based HTTP ingestion (`POST /api/v1/events/ingest`) — **this is how the synthetic test injects events** | `HTTP ingest` (grey) |
| `journal` | Genuine systemd-journal records (read by `backend/app/collector.py`) | `systemd journal` (teal) |
| `suricata` | Genuine Suricata EVE JSON records (read by `backend/app/suricata.py`) | `Suricata` (purple) |
| `test` | Synthetic records explicitly tagged `test` by the journal collector | `Test` (grey) |

**The synthetic live test writes events with `source = NULL`**, so in the
dashboard they render as `HTTP ingest` and are clearly distinguishable from real
`systemd journal` or `Suricata` telemetry. The pytest
[`test_synthetic_events_are_distinguished_from_journal_and_suricata`](backend/tests/test_live_threat_workflow.py)
asserts this distinction automatically.

To confirm by hand against a running API:

```bash
curl -s "http://127.0.0.1:8010/api/v1/events?limit=100" | \
  python3 -c 'import json,sys; d=json.load(sys.stdin); print({ (e["source"] or "NULL") for e in d["events"] })'
# synthetic HTTP test -> {'NULL'}
# real journal run      -> {'journal'}
# real Suricata run     -> {'suricata'}
```

> Synthetic log lines are also human-readable (`sshd[600X]: ...` with usernames
> `attacker0..4`); real SSH failures from production will have real usernames and
> real syslog/journal timestamps.

---

## 8. Optional: testing against the real systemd journal

This is **separate from and not required by** the detection test above. It
validates the genuine journal collector path (`collector.py`) reading real
`journalctl -o json` output.

### Prerequisites
- Fedora 44 / systemd 259 (or any systemd-journald host).
- A user account permitted to read the journal:
  ```bash
  sudo usermod -aG systemd-journal $USER   # then re-login
  journalctl --disk-usage                  # should return data, not "permission denied"
  ```
- No real SSH activity is needed.

### Steps (isolated DB)

```bash
# 1. Isolated database (so real journal data does not mix with production)
export GREYWATCH_DB=/tmp/gw-journal-verify.db
# 2. Inject ONE synthetic SSH failure into the real journal (reserved IP)
logger -t sshd "Failed password for invalid user attacker0 from 203.0.113.10 port 54000 ssh2"
# 3. Collect one cycle
.venv/bin/python -m backend.app.collector --once
# 4. Inspect — the event should be sourced from the journal
curl -s "http://127.0.0.1:8000/api/v1/events?limit=20" | python3 -m json.tool | grep source
# 5. (Optional) 5 such entries raise SSH_BRUTE_FORCE just like HTTP ingestion
```

### Cleanup
- Stop any long-running collector loop: `python -m backend.app.collector` runs in
  the foreground; press `Ctrl-C` to stop it. The `--once` mode exits on its own.
- Remove the temp database: `rm -f /tmp/gw-journal-verify.db`.
- **Never** delete events or alerts from `data/greywatch.db`. Removing the journal
  test entry is not strictly required (it is tagged `source='journal'`), but you
  can find it by the `203.0.113.10` source IP and the synthetic timestamp if you
  want a pristine journal.

> The journal collector reads **existing** journal entries; it does not create
> entries. `logger` writes a synthetic entry only into the local journal for
> verification, using a reserved IP — it is not an SSH login and does not weaken
> any SSH security setting.

---

## 9. Troubleshooting

| Symptom | Likely cause / fix |
|---------|---------------------|
| `ERROR: API did not become healthy` | Another process occupies `LIVE_TEST_PORT` (default 8010). Set `LIVE_TEST_PORT=9020`. |
| `API did not become healthy` on `:8010` but `:8000` is up | The script uses `:8010`+temp DB by design — do **not** change it to `:8000` (`:8000` serves the production DB). |
| `temp DB not empty` abort | A stale `/tmp/gw-live-*.db` exists. The script cleans its own; remove stragglers: `rm -f /tmp/gw-live-*.db`. |
| `required tool 'uvicorn' not found` | Activate the venv: `source .venv/bin/activate`, or run from the repo root so `.venv/bin/uvicorn` resolves. |
| Alert not raised after ingest | Confirm exactly 5 lines were sent and all parsed (`parsed: 5`). Fewer than 5 within the 5-minute window raises no alert by design. |
| Production `data/greywatch.db` shows unexpected rows | The test never writes to it (temp DB only). If you ever see otherwise, stop the script and report it; the script refuses to start if the temp DB is non-empty. |
| Dashboard shows stale data | The dashboard polls every 10 s; wait one poll, or click refresh in the UI. |
| Vite proxy 502 / cannot reach API | The dashboard proxies to `:8000`. Start your dev API on `:8000` (isolated DB per §6) or adjust `frontend/vite.config.js`. |

---

## 10. Safe cleanup summary

- **Live test script** (`§4A`): fully self-cleaning — kills its uvicorn and deletes
  its temp DB on exit (`trap ... EXIT`). No action required.
- **Dashboard view** (`§6`): kill both terminals (API + `npm run dev`), then
  `rm -f /tmp/gw-demo.db`.
- **Journal step** (`§8`): stop the collector loop, `rm -f /tmp/gw-journal-verify.db`.
- **Never** run `rm` against `data/greywatch.db`, and never `DELETE` rows from
  the production database to "clean up" test data — the test is designed so that
  is unnecessary.
