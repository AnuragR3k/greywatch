# Linux Authentication Journal Collector

Greywatch can collect **real PAM/SSH/sudo authentication events** directly from
the systemd journal on Linux hosts (developed and verified on **Fedora 44,
systemd 259**). The collector reads structured journal fields with
`journalctl -o json`, normalizes them into the same event shape used by the
line-based parser, and feeds them straight into the SIEM — so journal-sourced
SSH failures trigger the existing `SSH_BRUTE_FORCE` rule identically to
hand-posted log lines.

> The dashboard redesign lives on `feat/dashboard-redesign` and is intentionally
> left untouched by this work. The collector is a **backend-only** feature.

---

## 1. How it works

```
                      systemd Journal (journald)
                                 │  journalctl --output=json
                                 ▼
            ┌──────────────────────────────────────┐
            │  backend/app/collector.py            │
            │  - run_journalctl()  : reads journal │
            │  - parse_journal_record(): classify  │
            │  - collect_once()    : dedup + store │
            │    checkpoint cursor in DB          │
            └�───────────────┬─────────────────────┘
                            │  siem.ingest_events / _store_events_and_detect
                            ▼
            ┌──────────────────────────────────────┐
            │  backend/app/siem.py                  │
            │  events / alerts tables + SSH_BRUTE_  │
            │  FORCE sliding-window detection      │
            └───────────────┬─────────────────────┘
                            │
               GET /api/v1/events , /api/v1/alerts
```

Key properties:

* **Incremental.** A cursor is persisted in the `collector_state` table after
  every successful cycle. The next cycle calls `journalctl --after-cursor`,
  which returns only entries strictly after the last ingested one — the whole
  journal is never re-read.
* **Safe restart.** The cursor is advanced **inside the same transaction** as
  the event inserts, so a crash either keeps the old cursor (re-read is
  de-duplicated) or advances it past already-ingested rows. No partial writes.
* **Duplicate protection.** Two layers: (1) within a batch, records are
  de-duplicated by journal cursor; (2) when a cursor becomes invalid (journal
  rotation/vacuum), the collector falls back to a `--since` window and
  de-duplicates against events already stored in the recent window.
* **No root required.** `journalctl` reads the journal; the API does **not**
  have to run as root. See §3.
* **Genuine vs. synthetic.** Genuine journal records always carry a `__CURSOR`;
  they are stored with `events.source = 'journal'`. Hand-crafted / test
  records (no cursor) are tagged `source = 'test'`. Events ingested through the
  line-based API keep `source = NULL` (legacy). This provenance column lets you
  always tell real journal events apart from test or synthetic data.
* **Detection parity.** SSH journal messages are classified with the **same
  regular expressions** as `parse_auth_line`, so `ssh_login_failed`,
  `ssh_invalid_user`, and `ssh_login_success` are produced identically and the
  `SSH_BRUTE_FORCE` rule fires exactly as for line-based ingestion.

Collection is **optional and off by default**. Set `GREYWATCH_JOURNAL_ENABLED=1`
to enable automatic polling; `python -m backend.app.collector --once` always
runs one cycle regardless of that flag.

---

## 2. Supported event types

| journal `MESSAGE` pattern | `event_type` | `severity` | notes |
|---|---|---|---|
| sshd: `Failed password … from <ip> …` | `ssh_login_failed` | medium | feeds `SSH_BRUTE_FORCE` |
| sshd: `Accepted … for <user> from <ip> …` | `ssh_login_success` | low | |
| sshd: `Invalid user <user> from <ip>` | `ssh_invalid_user` | medium | |
| `pam_unix(sudo:session): session opened for user <user> … by <invoking>` | `sudo_session_opened` | info | |
| `pam_unix(sudo:session): session closed for user <user>` | `sudo_session_closed` | info | |
| `… : TTY=… ; USER=<user> ; COMMAND=…` | `sudo_command` | low | |
| `pam_unix(sudo:auth): authentication failure … user=<user>` | `pam_auth_failed` | high | |
| `…: authentication failure … user=<user>` | `pam_auth_failed` | high | generic PAM failure (login/gdm/…) |

Unrecognized or non-auth records (e.g. kernel messages, audit housekeeping)
are silently skipped — they do not reach the event store.

### Source metadata preserved
For every ingested event the collector preserves the **exact journal timestamp**
(`__REALTIME_TIMESTAMP`, converted to UTC ISO 8601), the **hostname**
(`_HOSTNAME`), the **raw journal `MESSAGE`** verbatim, and the **`source`**
provenance. The journal `SYSLOG_IDENTIFIER`, `_UID`, and `_PID` are not
promoted to dedicated columns today (the schema is stable), but the raw message
retains them in the journal's own wording so they remain searchable in
`raw_message`.

---

## 3. Prerequisites & least-privilege access

The collector reads the journal through `journalctl`. It does **not** need to
run as root, and it does **not** enable or reconfigure SSH.

* Fedora (and most systemd distributions): journald exposes the system journal
  to members of one of a few UNIX groups. Make the service account a member of
  the **canonical** group `systemd-journal`:

  ```bash
  sudo usermod -aG systemd-journal greywatch
  # then re-login / restart the service so the new group takes effect
  ```

  On **Fedora**, membership in the `wheel` group also grants read access to
  `/var/log/journal` via an ACL (`group:wheel:r-x`); this is how interactive
  administrators can read the journal by default.

* Verify access before installing the service:

  ```bash
  journalctl --no-pager -n 2 --output=json
  ```

  If the command returns records and exits 0, the account can read the journal.

* **Do not** run the collector (or the API) as root unless you specifically
  need to. The collector only calls `journalctl` (read) and writes to the
  SQLite database (configurable path). The database directory must be writable
  by the service account.

### What the collector does **not** do
* It does **not** start, enable, or modify `sshd` or any network service.
* It does **not** write to the journal — it only reads.
* It does **not** need the API to be running. It can write directly to the
  shared SQLite database, so it may run on the same host as the API with no
  inter-process dependency.

---

## 4. Installation & configuration

The collector ships with the backend (no extra dependencies — it uses only the
Python standard library plus `backend.app.siem`).

```bash
# from the repository root, with the venv active
. .venv/bin/activate
python -m backend.app.collector --once        # one cycle now
python -m backend.app.collector               # continuous loop (see §5)
python -m backend.app.collector --status      # print checkpoint state
```

### Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `GREYWATCH_JOURNAL_ENABLED` | `0` | `1`/`true`/`yes` to enable the continuous loop. `--once` runs a cycle regardless. |
| `GREYWATCH_JOURNAL_POLL_INTERVAL` | `5` | Seconds between polls in continuous mode. |
| `GREYWATCH_JOURNAL_LOOKBACK_MINUTES` | `1440` | First-run / fallback window size (minutes). |
| `GREYWATCH_JOURNAL_MAX_RECORDS` | `1000` | Cap on events stored per cycle. If more are available, the cursor still advances and the remainder is picked up next cycle (no loss, just latency). |
| `GREYWATCH_JOURNAL_IDENTIFIERS` | `sshd,sudo` | Comma-separated `SYSLOG_IDENTIFIER`s to collect (repeated `-t` filters). Add `login`, `gdm-password`, etc. for broader PAM coverage. |
| `GREYWATCH_JOURNAL_COMMAND` | `journalctl` | Path/name of the journalctl binary. Override for tests or alternate installations. |
| `GREYWATCH_DB` | `data/greywatch.db` | SQLite database path (shared with the API). Use a writable directory. |

Example: collect only SSH + sudo, polling every 10 seconds:

```bash
export GREYWATCH_JOURNAL_ENABLED=1
export GREYWATCH_JOURNAL_POLL_INTERVAL=10
export GREYWATCH_JOURNAL_IDENTIFIERS=sshd,sudo
python -m backend.app.collector
```

---

## 5. Startup

### One-shot / cron
```bash
. .venv/bin/activate
GREYWATCH_JOURNAL_ENABLED=1 python -m backend.app.collector --once
```

### Continuous (foreground)
```bash
. .venv/bin/activate
GREYWATCH_JOURNAL_ENABLED=1 python -m backend.app.collector
```

### systemd service (recommended)
Save as `/etc/systemd/system/greywatch-collector.service`:

```ini
[Unit]
Description=Greywatch authentication journal collector
After=network.target

[Service]
Type=simple
User=greywatch
Group=greywatch
WorkingDirectory=/opt/greywatch
Environment=GREYWATCH_JOURNAL_ENABLED=1
Environment=GREYWATCH_DB=/var/lib/greywatch/greywatch.db
Environment=GREYWATCH_JOURNAL_POLL_INTERVAL=5
Environment=GREYWATCH_JOURNAL_IDENTIFIERS=sshd,sudo
ExecStart=/opt/greywatch/.venv/bin/python -m backend.app.collector
Restart=on-failure
RestartSec=5

# Least-privilege: the service account must read the journal but run as an
# unprivileged user (do NOT set User=root here).
#   sudo usermod -aG systemd-journal greywatch

[Install]
WantedBy=multi-user.target
```

Make sure the `data/` (or configured) directory is owned by the service user:

```bash
sudo mkdir -p /var/lib/greywatch
sudo chown greywatch:greywatch /var/lib/greywatch
sudo systemctl daemon-reload
sudo systemctl enable --now greywatch-collector
```

> The collector writes to the **same SQLite database** the API reads. If the API
> and collector run concurrently against the same file and you see lock errors,
> consider enabling WAL mode on that database (see §8). The API itself does not
> need to be running for the collector to work.

---

## 6. Verifying real events on Fedora

This is the acceptance check: a controlled journal event is collected and
queried through Greywatch.

1. **Start Greywatch** (API) against a throwaway test database:

   ```bash
   export GREYWATCH_DB=/tmp/gw-verify.db
   uvicorn backend.app.main:app --port 8000 &
   ```

2. **Inject a controlled, uniquely-marked event** into the real journal with
   `logger` (no SSH changes required). This is a genuine journal record that
   the collector will read just like any other:

   ```bash
   logger -t sudo "pam_unix(sudo:session): session opened for user root(uid=0) by testcollector(uid=1000)"
   ```

3. **Collect it** with the real `journalctl`:

   ```bash
   export GREYWATCH_JOURNAL_ENABLED=1
   GREYWATCH_JOURNAL_LOOKBACK_MINUTES=5 python -m backend.app.collector --once
   # expected: collected: records_seen=N ingested=N ...
   ```

4. **Query it through the API**:

   ```bash
   curl -s "http://127.0.0.1:8000/api/v1/events?limit=50" | python -m json.tool | grep testcollector
   curl -s http://127.0.0.1:8000/api/v1/journal/status
   ```

   You should see an event with `"source": "journal"`, the correct UTC
   timestamp, `"host": "<your-host>"`, and the raw message verbatim.

5. **Verify restart safety** — run `--once` again immediately; it should report
   `records_seen=0 ingested=0` and the database should not have grown:

   ```bash
   python -m backend.app.collector --once
   ```

6. **Verify SSH brute-force via the journal** — inject 5 failures from one IP:

   ```bash
   for i in 0 1 2 3 4; do logger -t sshd "Failed password for invalid user tf$i from 198.51.100.77 port 4000$i ssh2"; done
   python -m backend.app.collector --once
   curl -s http://127.0.0.1:8000/api/v1/alerts | python -m json.tool
   # expect an open SSH_BRUTE_FORCE alert for 198.51.100.77, count 5
   ```

7. **Tear down** the test data:

   ```bash
   rm -f /tmp/gw-verify.db /tmp/gw-verify.db-*
   ```

The `logger`-injected records are genuine journal events (they carry real
`__CURSOR` / `__REALTIME_TIMESTAMP` values), so this exercise validates the
full production read path — not a synthetic stand-in.

---

## 7. Monitoring & operational endpoints

* `GET /api/v1/journal/status` — returns `enabled`, `last_cursor`,
  `last_event_ts`, `events_ingested`, and `last_run_at`. Use this to confirm
  the collector is making progress.
* `POST /api/v1/journal/collect` — triggers a single collection cycle. Useful
  for ad-hoc collection and for the verification steps above. Returns
  `records_seen`, `events_ingested`, `alerts`, `fallback_used`, and `errors`.

The checkpoint lives in the database (`collector_state` table), so it survives
restarts and follows the same backup/restore story as your events.

---

## 8. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `journalctl binary not found` | `journalctl` isn't on `PATH`. Install `systemd` or set `GREYWATCH_JOURNAL_COMMAND=/path/to/journalctl`. |
| `(journal) Failed to seek to cursor: Invalid argument` (then fallback) | The stored cursor is stale (journal was rotated/vacuumed). This is handled automatically: the collector falls back to `--since` from the last event time and re-establishes a fresh cursor. |
| "permission denied" running `journalctl` | The service user cannot read the journal. Add it to `systemd-journal` (or `wheel`/`adm` on Fedora) and restart the service. Verify with `journalctl --no-pager -n 2 --output=json` as that user. |
| `database is locked` (rare, under concurrent API + collector load) | Both the API and the collector write the same SQLite file. Either (a) run them against separate databases, or (b) enable WAL mode on the database once: `python -c "import sqlite3; c=sqlite3.connect('$DB'); c.execute('PRAGMA journal_mode=WAL'); c.commit()"`. WAL lets readers and the writer run concurrently with far fewer lock errors. |
| Collector runs but `events_ingested` stays 0 | Either no new journal entries match the configured `SYSLOG_IDENTIFIER`s, or all matched records were unrecognized. Check `journalctl -t sshd -t sudo --since "-5min"` to confirm events exist and inspect their `MESSAGE`. |
| Duplicate events after a crash | Should not happen by design (atomic cursor+insert). If you see duplicates, they were inserted by two *concurrent* collector instances — run a single instance (the systemd unit with `Restart=on-failure` enforces one). |

---

## 9. Security notes

* **Read-only journal access.** The collector only ever calls `journalctl
  --output=json …` (read). It never writes to the journal and never starts a
  network service.
* **No SSH changes.** Collection does not require, start, or modify an SSH
  server. The host's SSH configuration is irrelevant to journal collection.
* **Least privilege.** The service account needs only group membership for
  journal read access and a writable database directory — not root.
* **No secrets committed.** The collector stores no credentials. The database
  path and the journal cursor are operational state, not secrets.
* **Input is never `eval`'d.** Journal `MESSAGE` values are treated as opaque
  text and matched with regular expressions; they are never executed or
  interpreted as code.
