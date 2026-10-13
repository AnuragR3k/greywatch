# Greywatch

Open-source security monitoring and SIEM platform.

Greywatch collects security events, detects suspicious activity,
and helps analysts investigate threats through a unified dashboard.

## Initial Features

- Linux security log ingestion
- Event normalization
- Rule-based threat detection
- Security alerts and severity levels
- Event search and investigation
- SOC dashboard

## Journal Collection (Linux)

Greywatch can collect **real PAM/SSH/sudo authentication events** from the
systemd journal on Linux hosts (developed on Fedora) without enabling or
reconfiguring SSH. The collector is optional and off by default. See
[`docs/JOURNAL_COLLECTOR.md`](docs/JOURNAL_COLLECTOR.md) for installation,
least-privilege permissions, configuration, and how to verify real events.

```bash
GREYWATCH_JOURNAL_ENABLED=1 python -m backend.app.collector --once   # one cycle
python -m backend.app.collector                                    # continuous loop
curl http://127.0.0.1:8000/api/v1/journal/status                   # checkpoint state
```

## Technology

- Python and FastAPI
- React and Vite
- PostgreSQL
- Docker

## Status

🚧 Under active development.

Greywatch is an experimental project intended for learning,
security research, and open-source development.
