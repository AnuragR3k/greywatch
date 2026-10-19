#!/usr/bin/env bash
#
# e2e_servers.sh — start Greywatch backend (isolated temp DB) + frontend dev
# server for Playwright end-to-end smoke tests.
#
# The backend runs on 127.0.0.1:8000 against /tmp/gw-e2e.db (never
# data/greywatch.db). The frontend dev server runs on :5173 and proxies
# /api and /health to the backend via frontend/vite.config.js.
#
# Exits nonzero if either server fails to become healthy.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export GREYWATCH_DB="${GREYWATCH_DB:-/tmp/gw-e2e.db}"
# Start from a clean, isolated database so e2e runs are deterministic and never
# touch production data/greywatch.db.
rm -f "$GREYWATCH_DB"

LOG_DIR="$(mktemp -d)"
BACKEND_LOG="$LOG_DIR/backend.log"

.venv/bin/uvicorn backend.app.main:app \
    --host 127.0.0.1 --port 8000 --log-level warning \
    >"$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!

cleanup() {
    kill "$BACKEND_PID" >/dev/null 2>&1 || true
    wait "$BACKEND_PID" >/dev/null 2>&1 || true
    rm -rf "$LOG_DIR"
    rm -f "$GREYWATCH_DB"
}
trap cleanup EXIT INT TERM

# Wait for the backend to become healthy.
for _ in $(seq 1 80); do
    if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
if ! curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
    echo "ERROR: backend did not become healthy on :8000. Log:" >&2
    cat "$BACKEND_LOG" >&2 || true
    exit 1
fi

echo "Backend healthy on :8000 (DB=$GREYWATCH_DB)"

# Start the frontend dev server in the foreground (playwright webServer manages
# the process lifecycle). It proxies /api and /health to the backend.
cd frontend
exec npm run dev -- --port 5173 --host
