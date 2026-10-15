# Suricata EVE JSON Integration

Greywatch can import **Suricata** intrusion-detection alerts and flow metadata
from Suricata's [EVE JSON](https://suricata.io/documentation/) output file
(`eve.json` by default) and normalize them into the same event model used by
the line-based and journal ingestion paths — feeding them through the **same**
storage layer (`backend/app/siem.py`). Imported events appear in the Events
view with `source = "suricata"`, so IDS activity is queryable alongside SSH
auth events.

> Suricata is **optional**. Greywatch runs without Suricata installed: if the
> configured EVE file is absent, collection reports the error and continues.
> Suricata EVE `alert` records are stored as `suricata_alert` *events* (visible
> in `GET /api/v1/events` with `source = "suricata"`) and **also** raise Greywatch
> alerts (`rule_id = SURICATA_ALERT`) in the shared `alerts` table, reusing the
> existing detection engine (`siem._store_events_and_detect`). The
> `SSH_BRUTE_FORCE` rule only counts `ssh_login_failed` events and is left
> completely untouched: Suricata events are `suricata_alert`, never
> `ssh_login_failed`, so they never fire the SSH rule. Each Suricata alert
> preserves its signature identity, network 5-tuple, category and mapped
> severity; the original numeric Suricata severity (0–4) survives in the alert
> description and in the evidence events' `raw_message`. Repeated detections of
> the same signature + 5-tuple within `SURICATA_ALERT_WINDOW_MINUTES` (default 60)
> aggregate into one open alert, so distinct attacks stay distinguishable while
> identical IDS alerts do not multiply unboundedly (see §7 and §8).

---

## 1. How it works

```
                   Suricata EVE JSON file (eve.json)
                                    │  JSON-per-line, one record per line
                                    ▼
            ┌──────────────────────────────────────────┐
            │  backend/app/suricata.py                  │
            │  - get_config()       : env-driven config │
            │  - _read_eve_records() : incremental file │
            │    reader (byte-offset checkpoint,        │
            │    skips malformed lines, rotation-safe)  │
            │  - parse_eve_record()  : classify +       │
            │    normalize alert/dns/tls/http/flow      │
            │  - collect_once()      : dedup + store    │
            │    offset advanced in the INSERT tx        │
            └──────────────┬───────────────────────────┘
                           │  siem._store_events_and_detect  (reuse of the
                           │  existing storage + SSH_brute_force engine)
                           ▼
            ┌──────────────────────────────────────────┐
            │  backend/app/siem.py                       │
            │  events table (source='suricata')         │
            │  collector_state table (offset cursor)    │
            └──────────────┬───────────────────────────┘
                           │
              GET /api/v1/events , /api/v1/suricata/status
```

Key properties:

* **Incremental.** A byte offset (`suricata_last_offset`) is persisted in the
  shared `collector_state` table after every successful cycle. The next cycle
  reads only bytes appended since the last run — a large `eve.json` is never
  re-scanned in full after the first cycle.
* **Safe restart.** The offset is advanced **inside the same transaction** as
  the event inserts, so a crash either keeps the old offset (the bytes are
  re-read and de-duplicated) or advances it past already-ingested rows. No
  partial state.
* **Duplicate protection.** Two layers: (1) within a batch, records are
  de-duplicated by their raw JSON line; (2) when the file shrinks below the
  stored offset (log rotation / truncation), the offset resets to 0 and the
  recent window is re-read and de-duplicated against events already stored
  (mirroring the journal collector's `--since` fallback).
* **Malformed-record tolerant.** Non-JSON lines are skipped (not raised), and
  only newline-terminated lines are processed, so a record Suricata is
  mid-writing is never half-parsed. Unrecognized `event_type` values are
  skipped by `parse_eve_record`.
* **Empty file is a clean no-op.** An EVE file that exists but holds no records
  reports `records_seen=0, events_ingested=0, errors=[]`, stores the checkpoint
  at byte `0` and still records `last_run_at`, so a healthy-but-idle collector
  is distinguishable from one that has never run. See §9.
* **Bounded memory.** `max_records` caps how many records a single cycle reads
  and stores; the remaining bytes are picked up on the next cycle (no loss,
  just latency — like the journal collector).
* **No root required.** Suricata (and its `eve.json`) are typically readable by
  a dedicated group; see §3. The API/collector only needs read access to the
  EVE file and write access to the SQLite database.
* **No new detection/alert system.** Suricata events reuse `siem.ingest_events`
  / `siem._store_events_and_detect` and the existing `events` + `alerts`
  + `collector_state` tables. A separate alert database is deliberately **not**
  created.

Collection is **optional and off by default**. Set
`GREYWATCH_SURICATA_ENABLED=1` to enable automatic polling; `python -m
backend.app.suricata --once` always runs one cycle regardless of that flag.

---

## 2. Supported EVE event types

Suricata EVE records are identified by `event_type`. The collector
normalizes the following into dedicated Greywatch event types, extracting the
network/IDS fields the `events` schema supports:

| `event_type` | Greywatch `event_type` | severity | fields extracted |
|---|---|---|---|
| `alert` | `suricata_alert` | `alert.severity` → see below | signature, signature_id, category |
| `dns` | `suricata_dns` | `low` | src/dst IP/port, proto |
| `tls` | `suricata_tls` | `low` | src/dst IP/port, proto |
| `http` | `suricata_http` | `low` | src/dst IP/port, proto |
| `flow` | `suricata_flow` | `low` | src/dst IP/port, proto |

**Suricata severity → Greywatch tier** (for `alert` events, from `alert.severity` 0–4, 0 most severe):

| Suricata severity | Greywatch severity |
|---|---|
| 0, 1 | `high` |
| 2 | `medium` |
| 3, 4 | `low` |
| missing / unknown | `low` (conservative) |

Other EVE event types (e.g. `stats`, `capture`, `fileinfo`) are skipped — they
are not security events and would only add noise.

### Common fields preserved

For every ingested event the collector preserves the **exact EVE timestamp**
(`timestamp`, microsecond precision with `Z`, normalized to UTC ISO 8601
seconds), the **host** (`host`/`sensor` field, falling back to `"unknown"`),
the **source IPs and ports and protocol** (`src_ip`/`dest_ip`/`src_port`/
`dest_port`/`proto`), and the **raw EVE JSON line verbatim** in `raw_message`
so the full record remains searchable. Provenance is recorded in
`events.source = "suricata"`.

The full EVE context (DNS query names, TLS subject/SNI, HTTP URL/UA/status,
flow byte/packet counts) is retained inside `raw_message`, since the core
`events` schema has no dedicated columns for it. Future schema extensions can
promote these without re-ingesting.

### Alerts & deduplication

A Suricata `alert` record does not just sit in the Events view — it raises a
Greywatch alert (`rule_id = SURICATA_ALERT`) in the **shared** `alerts` table,
produced by the same detection engine as `SSH_BRUTE_FORCE`. The alert row
preserves:

| alert column | value |
|---|---|
| `rule_id` | `SURICATA_ALERT` |
| `signature` / `signature_id` | `alert.signature` / `alert.signature_id` |
| `category` | `alert.category` |
| `severity` | Suricata severity mapped to a Greywatch tier (see §2) |
| `source_ip` / `dest_ip` / `src_port` / `dest_port` / `proto` | the event 5-tuple |
| `description` | signature, sig id, category, mapped **and** original Suricata severity |
| `created_at` / `last_triggered_at` | the EVE event `timestamp` (not wall-clock) |
| `event_count` | number of matching detections aggregated into this alert |

The **original numeric Suricata severity** (0–4) is kept on the event dict as
`raw_severity`, surfaced in the alert `description`, and retained verbatim in
the evidence events' `raw_message` (`alert.severity`) — so it is always
available for investigation without a schema column.

**Deduplication.** Repeated detections of the same incident are identified by
the key `(signature_id, signature, source_ip, dest_ip, src_port, dest_port,
proto)`, compared NULL-safely (so absent optional fields such as an unknown
`dest_port` still match). Detections within `SURICATA_ALERT_WINDOW_MINUTES`
(a module constant, default **60 minutes**) of the alert's last activity
aggregate into the existing open alert: `event_count` grows,
`last_triggered_at` advances, the `description` refreshes, and — crucially —
**no evidence is lost** (every matching event stays stored and is returned by
`GET /api/v1/alerts/{id}`). A detection with the **same key but outside the
window**, or a **different key**, starts a new alert. This keeps distinct
attacks distinguishable while a sustained stream of identical IDS alerts cannot
create an unbounded number of duplicates. (The SSH `SSH_BRUTE_FORCE` rule is
unaffected: Suricata events are `suricata_alert`, never `ssh_login_failed`.)

**Records with no rule identity.** When a record carries *neither*
`alert.signature` *nor* `alert.signature_id`, `category` joins the key, so two
detections that merely share a 5-tuple but were categorised differently
(`attempted-recon` vs `attempted-admin`) become separate alerts instead of one
self-contradicting alert. Records that are genuinely indistinguishable — no
rule identity, no category, same 5-tuple — still aggregate, so the
anti-duplication guarantee is preserved. `siem._suricata_incident_conditions()`
is the single definition of this key and is used by **both** the
aggregation lookup and the evidence lookup in `GET /api/v1/alerts/{id}`, so the
two can never drift apart. Alerts whose signature identity *is* present keep
keying on the 7-tuple only: a re-categorised signature still aggregates as
before.

**Limitations:**

* Records with **no rule identity, no category, and identical network fields**
  are indistinguishable by any persisted field, so they aggregate into one
  "unknown" alert rather than being split. This is the best determinable
  grouping: nothing distinguishes them. A stream of identical such records
  therefore stays bounded at one open alert.
* The window is a fixed 60-minute constant, not per-signature tuning; a
  long-lived recurring scan within the window stays one alert until closed.
* Alert timestamps use the **EVE event timestamp** (deterministic for
  replayed/historical logs). Severely out-of-order events still aggregate
  within the window, but a timestamp older than the alert's
  `last_triggered_at` cannot move that field backward.
* Only `alert` EVE records raise alerts today; `dns`/`tls`/`http`/`flow`
  records are stored as events (see §2) but do not raise alerts.

---

## 3. Prerequisites & least-privilege access

You do **not** need Suricata installed to run Greywatch or its tests. Suricata
itself is only required if you want to produce `eve.json`.

If you *are* running Suricata, give the collector read access to the EVE file:

* The default EVE path is `/var/log/suricata/eve.json`. Create the EVE output
  in `suricata.yaml`:

  ```yaml
  eve-log:
    enabled: yes
    type: file
    filename: /var/log/suricata/eve.json
    types:
      - alert
      - http:
          extended: yes
      - dns:
          version: 2
      - tls:
          version: 2
      - flow
      - stats
  ```

* Make sure the service account running the collector can read the EVE file and
  directory. The most common approaches:

  ```bash
  # Option A: share a group
  sudo groupadd suricata    # or reuse an existing group that owns eve.json
  sudo usermod -aG suricata greywatch
  # then re-login / restart the service so the new group takes effect

  # Option B: read-only permissions on the file
  sudo chmod 640 /var/log/suricata/eve.json
  sudo chown root:suricata /var/log/suricata/eve.json
  ```

* Verify read access before installing:

  ```bash
  head -n 1 /var/log/suricata/eve.json
  ```

  If the command prints an EVE JSON record, the account can read it.

### What the collector does **not** do

* It does **not** start, enable, or modify Suricata.
* It does **not** parse or execute Suricata rules — it only reads the JSON
  output Suricata already produced.
* It does **not** need the API to be running; it writes to the shared SQLite
  database directly.
* It does **not** start itself: an unset/`0` `GREYWATCH_SURICATA_ENABLED`
  always means "do nothing" until you run a cycle explicitly (see §4).

---

## 4. Installation & configuration

The collector ships with the backend (no extra dependencies — it uses only the
Python standard library plus `backend.app.siem`).

```bash
# from the repository root, with the venv active
. .venv/bin/activate
python -m backend.app.suricata --once        # one cycle now
python -m backend.app.suricata                # continuous loop (see §5)
python -m backend.app.suricata --status       # print checkpoint state
```

**Exit codes** (useful for cron / CI / monitoring, all verified):

| Code | When |
|---|---|
| `0` | `--status` printed, or a `--once` cycle completed with no `errors` |
| `1` | A `--once` cycle completed but reported `errors` (e.g. the EVE file is missing or unreadable). The cycle does **not** raise. |
| `2` | Collection is disabled and no `--once` was given. Nothing is collected; the reason is printed to stderr. |

### Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `GREYWATCH_SURICATA_ENABLED` | `0` | `1`/`true`/`yes` to enable the continuous loop. `--once` runs a cycle regardless. |
| `GREYWATCH_SURICATA_EVE_PATH` | `/var/log/suricata/eve.json` | Path to the Suricata EVE JSON file. Set this for tests and non-standard installs. |
| `GREYWATCH_SURICATA_POLL_INTERVAL` | `30` | Seconds between polls in continuous mode. |
| `GREYWATCH_SURICATA_MAX_RECORDS` | `5000` | Cap on records read *and* stored per cycle. If more are available, the offset still advances and the remainder is picked up next cycle (no loss, just latency). Lower this on memory-constrained hosts. |
| `GREYWATCH_DB` | `data/greywatch.db` | SQLite database path (shared with the API). Use a writable directory. |

Example: enable continuous collection, polling every 10 seconds, against a
non-default EVE path:

```bash
export GREYWATCH_SURICATA_ENABLED=1
export GREYWATCH_SURICATA_EVE_PATH=/var/log/suricata/eve.json
export GREYWATCH_SURICATA_POLL_INTERVAL=10
python -m backend.app.suricata
```

---

## 5. Startup

### One-shot / cron
```bash
. .venv/bin/activate
GREYWATCH_SURICATA_ENABLED=1 python -m backend.app.suricata --once
```

### Continuous (foreground)
```bash
. .venv/bin/activate
GREYWATCH_SURICATA_ENABLED=1 python -m backend.app.suricata
```

### systemd service (recommended)
Save as `/etc/systemd/system/greywatch-suricata.service`:

```ini
[Unit]
Description=Greywatch Suricata EVE JSON collector
After=network.target

[Service]
Type=simple
User=greywatch
Group=greywatch
WorkingDirectory=/opt/greywatch
Environment=GREYWATCH_SURICATA_ENABLED=1
Environment=GREYWATCH_DB=/var/lib/greywatch/greywatch.db
Environment=GREYWATCH_SURICATA_EVE_PATH=/var/log/suricata/eve.json
Environment=GREYWATCH_SURICATA_POLL_INTERVAL=30
ExecStart=/opt/greywatch/.venv/bin/python -m backend.app.suricata
Restart=on-failure
RestartSec=10

# The greywatch user must be able to READ the EVE file:
#   sudo usermod -aG suricata greywatch

[Install]
WantedBy=multi-user.target
```

Make sure the database directory is owned by the service user:

```bash
sudo mkdir -p /var/lib/greywatch
sudo chown greywatch:greywatch /var/lib/greywatch
sudo systemctl daemon-reload
sudo systemctl enable --now greywatch-suricata
```

> The collector writes to the **same SQLite database** the API reads. If the API
> and collector run concurrently against the same file and you see `database is
> locked`, consider enabling WAL mode on that database (see §8).

---

## 6. Verifying with the sample fixture

A sanitized sample EVE file is provided at `sample-logs/eve.json` (RFC 1918 /
TEST-NET IPs, no real hosts or users). You can ingest it end-to-end without
running Suricata:

```bash
. .venv/bin/activate
export GREYWATCH_DB=/tmp/gw-suricata-verify.db
uvicorn backend.app.main:app --port 8000 &

# Ingest the sample file.
python -m backend.app.suricata --once    # with GREYWATCH_SURICATA_EVE_PATH set to sample-logs/eve.json
#   or, one shot with an explicit path:
GREYWATCH_SURICATA_EVE_PATH=$(pwd)/sample-logs/eve.json python -m backend.app.suricata --once

# Query through the API (only suricata_alert / suricata_dns / ... events show).
curl -s "http://127.0.0.1:8000/api/v1/events?limit=100" | python -m json.tool | grep suricata
curl -s http://127.0.0.1:8000/api/v1/suricata/status | python -m json.tool

# Run again: it should report records_seen=0, events_ingested=0 (offset-based; no duplicates).
GREYWATCH_SURICATA_EVE_PATH=$(pwd)/sample-logs/eve.json python -m backend.app.suricata --once

# Tear down.
rm -f /tmp/gw-suricata-verify.db /tmp/gw-suricata-verify.db-*
kill %1
```

> **Note:** the sample file is static, so repeated `--once` runs return
> `records_seen=0` after the first cycle because the byte offset has already
> advanced past the whole file. To demonstrate incremental collection, append a
> new record to the file before re-running.

---

## 7. Monitoring & operational endpoints

* `GET /api/v1/suricata/status` — returns `enabled`, `eve_path`,
  `last_offset`, `last_event_ts`, `events_ingested`, and `last_run_at`.
  Field semantics, so the values are not misread:

  | Field | Meaning |
  |---|---|
  | `enabled` | Whether `GREYWATCH_SURICATA_ENABLED` is on. `false` does **not** mean the data is stale — manual `--once`/`POST .../collect` cycles still work. |
  | `eve_path` | The path the collector will read (config value, whether or not it exists). |
  | `last_offset` | Byte offset of the last committed checkpoint. `null` means **no cycle has ever persisted a checkpoint**; `"0"` means a cycle ran and the file was empty or at its start. |
  | `last_event_ts` | Timestamp of the newest ingested record (EVE time, not wall-clock). |
  | `events_ingested` | **Cumulative** count of stored `source='suricata'` events in the database — not a per-cycle delta and not a promise that new data arrived. |
  | `last_run_at` | Wall-clock time of the last completed poll (set even on an idle cycle), which is how you tell "polling but nothing new" from "not running". |
* `POST /api/v1/suricata/collect` — triggers a single collection cycle. Useful
  for ad-hoc collection and verification. Returns `records_seen`,
  `events_ingested`, `alerts` (Greywatch alerts raised this cycle — each a
  `SURICATA_ALERT` for new incidents, or `[]` when events only aggregated into
  an existing open alert), `fallback_used`, and `errors`. Returns HTTP 200 even
  when the EVE file is missing; the error is reported in the `errors` array.

The checkpoint (byte offset + counters) lives in the database
(`collector_state` table) alongside the journal collector, so it survives
restarts and follows the same backup/restore story as your events.

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `POST /api/v1/suricata/collect` returns `events_ingested: 0, errors: [...]` | The EVE file path is wrong or the service user cannot read it. Check `eve_path` from `GET /api/v1/suricata/status`, set `GREYWATCH_SURICATA_EVE_PATH`, and verify with `head -n 1 <path>`. |
| `EVE file not found` after a Suricata log rotation | Expected on the first cycle after rotation: the offset is reset and records are re-read and de-duplicated (you may briefly see `fallback_used: true`). |
| Duplicates appear after a crash | Not expected by design — the offset advances inside the insert transaction. If you see duplicates, two *concurrent* collector instances are running against the same file (e.g. a manually-started loop + a systemd unit). Run a single instance. |
| `database is locked` (rare, under concurrent API + collector load) | Both the API and the collector write the same SQLite file. Either (a) run them against separate databases, or (b) enable WAL mode once: `python -c "import sqlite3; c=sqlite3.connect('$DB'); c.execute('PRAGMA journal_mode=WAL'); c.commit()"`. WAL lets readers and the writer run concurrently with far fewer lock errors. |
| Collector runs but `events_ingested` stays 0 | Either no new lines were appended since the last offset, or all new lines were malformed/unrecognized `event_type` values. `tail -n 5 <eve_path>` to confirm new records arrive; check that `event_type` is one of `alert`, `dns`, `tls`, `http`, `flow`. |
| Suricata `alert` records don't appear as Greywatch alerts | Expected: each Suricata `alert` raises a `SURICATA_ALERT` (not `SSH_BRUTE_FORCE`). If none appear, (a) confirm `events_ingested > 0` on `POST /api/v1/suricata/collect`, (b) check `GET /api/v1/events` shows `suricata_alert` rows with `source="suricata"`, and (c) check `GET /api/v1/alerts` — identical alerts within the 60-minute window aggregate rather than duplicate. Repeated detections of the same signature + 5-tuple collapse into one open alert (`event_count` grows) by design; see §1. |
| `python -m backend.app.suricata` says disabled / "no module" | Use the venv interpreter (`python -m backend.app.suricata` from the repo root with `.venv` active) and set `GREYWATCH_SURICATA_ENABLED=1` for the loop. |

---

## 9. Reliability & recovery reference

Each row states the behavior the implementation actually has. Every row is
covered by a hermetic test in `backend/tests/test_suricata.py` (see §10).

| Situation | Behavior | Checkpoint effect |
|---|---|---|
| File exists but is empty | Clean no-op: `records_seen=0, events_ingested=0, errors=[]` | Offset `0`, `last_run_at` recorded |
| File missing | Reported, never raised: `errors=["EVE file not found: …"]`, HTTP 200 on the collect endpoint | Unchanged |
| File exists but unreadable (permissions) | Reported, never raised: `errors=["[Errno 13] Permission denied: …"]` | Unchanged |
| Trailing record mid-write (no newline yet) | The partial line is **held back**; the batch is processed without it | Not advanced past the partial line |
| Truncated to 0 bytes (or any shrink below the offset) | Detected as rotation: `fallback_used=true`, offset resets to `0`, the file is re-read from the start and content-deduplicated | Reset to `0`, then advances normally |
| Log rotation (new file, different inodes) | Same as truncation — the size comparison is what triggers the reset | Reset to `0`, then advances |
| Restart (new process, same database) | Resumes from the persisted offset; already-collected bytes are not re-ingested | Read from the stored value |
| Crash mid-cycle | The offset advances in the **same transaction** as the inserts, so the run either commits both or neither; the retry re-reads the bytes and de-duplicates them | All-or-nothing |
| Malformed / non-object / unrecognized records | Skipped individually (non-JSON text and JSON scalars never reach the classifier); the surrounding valid records are still stored | Advances past the whole processed block |
| More records than `max_records` | The cycle stops at the cap and commits what it read; the remainder is picked up next cycle ("no loss, just latency") | Advances only to the last **complete** line processed |
| Duplicate lines inside one batch | De-duplicated by raw JSON line | Advances normally |

Two safety properties worth stating explicitly, because they are easy to
mis-assume:

* **No silent enablement.** Nothing starts the loop for you. `enabled=false`
  means an ordinary process start collects nothing (CLI exit code `2`);
  collection happens only via `--once` or `POST /api/v1/suricata/collect`.
* **No privileged work.** The collector reads one file and writes one SQLite
  database; it needs no root, no network access, and never invokes Suricata.

---

## 10. Running the tests safely

The whole suite is hermetic: EVE input is written to pytest's `tmp_path` and
every test points `GREYWATCH_DB` at a per-test temporary database. **No test
reads or writes `data/greywatch.db`.**

```bash
# from the repository root
. .venv/bin/activate

# Suricata collector suite only
python -m pytest backend/tests/test_suricata.py -q

# Everything (backend)
python -m pytest backend/tests -q
```

Expected: `121 passed` for the full backend suite; the Suricata module alone is
61 cases. Two honest notes:

* `test_collect_reports_unreadable_file` is **skipped when running as root**,
  because root bypasses file permissions and the unreadable condition cannot be
  reproduced. A skip there is expected, not a failure.
* `test_sample_eve_produces_four_distinct_suricata_alerts` uses
  `sample-logs/eve.json`. The test skips (rather than fails) when that fixture
  is absent from the checkout — so if the fixture is not committed, CI stays
  green while this one case never runs. Confirm it is tracked before relying on
  it as coverage.

To inspect what a run did without touching your real data, use a throwaway
database explicitly:

```bash
rm -f /tmp/gw-suricata.db*
GREYWATCH_DB=/tmp/gw-suricata.db \
GREYWATCH_SURICATA_EVE_PATH=$(pwd)/sample-logs/eve.json \
  python -m backend.app.suricata --once
GREYWATCH_DB=/tmp/gw-suricata.db python -m backend.app.suricata --status
rm -f /tmp/gw-suricata.db*
```

---

## 11. Experimental / limited areas

Read this before treating any part of the integration as production-grade.

* **No live Suricata install is tested in CI.** Unit and API tests use synthetic
  EVE records; the collector's wire-level assumptions (real `eve.json` framing,
  Suricata's own rotation via `eve-log` file rotation) are validated by fixture,
  not against a running Suricata.
* **Continuous mode has no process supervision of its own.** The module exposes
  a foreground loop; supervising it (systemd unit in §5, `Restart=on-failure`)
  is left to you. Restarting the loop is safe — the checkpoint recovers.
* **The aggregation window is a fixed 60-minute constant**
  (`siem.SURICATA_ALERT_WINDOW_MINUTES`), deliberately not environment
  configurable: a tunable window with no per-signature semantics would change
  alert identity between deployments without a migration story.
* **Unknown-signature keying is best effort.** Two records with no signature,
  no signature_id, no category and identical network fields are
  indistinguishable and therefore aggregate (§2).
* **Only `alert` records raise alerts.** `dns`/`tls`/`http`/`flow` are stored as
  contextual events and never alert.
* **Concurrency is not coordinated.** Two collector instances against the same
  EVE file and database will duplicate work; SQLite `database is locked` is
  possible under concurrent API + collector load (WAL mode mitigates, §8).
* **API authentication is absent** — the status and collect endpoints are
  unauthenticated, so do not expose them to untrusted networks.
