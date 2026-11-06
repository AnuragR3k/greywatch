# Greywatch

A small, self-hosted SIEM for Linux. It pulls in SSH/sudo logs and Suricata alerts, runs detection rules on them, and gives you a dashboard to investigate what fired.

I built it to learn how a SIEM works end to end: ingestion, normalization, detection, and triage. It's a learning project that runs well on a single host, not a replacement for Wazuh or Splunk.

> **Status:** early development. Don't expose it to the internet.

<img width="1911" height="968" alt="image" src="https://github.com/user-attachments/assets/d23135f7-7e05-484b-8115-85a9264d6334" />

<!-- TODO: add a dashboard screenshot or GIF here. This is the single most useful thing you can add. -->
<!-- ![Greywatch dashboard](docs/images/dashboard.png) -->

## What it does

- Ingests log lines over an HTTP API and normalizes them into events
- Detects SSH brute-force attempts and raises alerts with the evidence attached
- Reads authentication events (SSH, PAM, sudo) from the systemd journal
- Reads Suricata `eve.json` (alerts, DNS, HTTP, TLS, flow)
- Lets you search events, open an alert, see the raw logs behind it, and resolve it

## How it fits together

```
journal / eve.json / HTTP  ->  collectors  ->  normalize  ->  SQLite
                                                               |
                                              detection rules -> alerts -> React dashboard
```

Backend is FastAPI + SQLite, frontend is React + Vite. Everything runs on one machine.

## Quick start

You need Linux, Python 3.10+ and Node 18+. <!-- TODO: confirm the real minimum versions -->

```bash
git clone https://github.com/AnuragR3k/greywatch.git
cd greywatch

# backend
python3 -m venv .venv
source .venv/bin/activate
pip install -e .          # TODO: confirm this is the right command for pyproject.toml
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000

# frontend (second terminal)
cd frontend
npm install
npm run dev
```

Check the API is up:

```bash
curl http://127.0.0.1:8000/health
```

Then open the URL Vite prints.

### Try it with sample data

No Suricata needed. There's a sample `eve.json` in `sample-logs/`:

```bash
GREYWATCH_SURICATA_EVE_PATH=$(pwd)/sample-logs/eve.json \
  python -m backend.app.suricata --once
```

The events show up in the dashboard, and the Suricata alerts appear in the alert list.

## Collectors

Both collectors are off by default.

| Collector | Reads | Enable | Docs |
|---|---|---|---|
| Journal | PAM, SSH, sudo events from systemd | see docs | [docs/JOURNAL_COLLECTOR.md](docs/JOURNAL_COLLECTOR.md) |
| Suricata | `eve.json` | `GREYWATCH_SURICATA_ENABLED=1` | [docs/SURICATA.md](docs/SURICATA.md) |

## Detection rules

| Rule | Triggers on |
|---|---|
| `SSH_BRUTE_FORCE` | Repeated failed SSH logins from one source |
| `SURICATA_ALERT` | Any Suricata alert; repeats of the same signature and 5-tuple within 60 minutes are grouped into one alert |

More rules are planned (see below). Rule definitions live in `rules/`.

## Security

By default, only `/` and `/health` are public. Everything else only accepts connections from localhost.

To reach the API from another machine, set a token and send it with each request:

```bash
export GREYWATCH_API_TOKEN="a-long-random-string"
curl -H "Authorization: Bearer $GREYWATCH_API_TOKEN" http://HOST:8000/api/v1/events
```

The dashboard is a static JS app and can't safely hold that token. For remote use, put it behind a reverse proxy that handles login.

## Tests

```bash
python -m pytest backend/tests -q     # backend
cd frontend && npm run lint && npm run build
```

CI runs the same checks on every push. The tests use synthetic Suricata records. I haven't yet run it against a live Suricata instance.

## Known limitations

- Only one hand-written detection rule so far
- SQLite can throw `database is locked` if the API and a collector write at the same time (WAL mode helps)
- Only Suricata `alert` records create alerts; DNS/HTTP/TLS/flow are stored as context
- Tested on Fedora so far

## Roadmap

- [ ] More Linux detection rules (sudo abuse, new user created, port scans) mapped to MITRE ATT&CK
- [ ] End-to-end test against live Suricata traffic
- [ ] Docker Compose setup
- [ ] GeoIP / IP reputation on source addresses
- [ ] Collector health in the dashboard

## Contributing

Issues and PRs are welcome. For anything big, open an issue first. Please run the tests before sending a PR.

