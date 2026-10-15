#!/usr/bin/env bash
#
# live_ssh_brute_force_test.sh — a safe, repeatable, end-to-end *live* detection
# test for Greywatch's existing SSH_BRUTE_FORCE rule.
#
# WHAT IT DOES (synthetic, reserved IPs, isolated DB):
#   1. Starts a throwaway Greywatch API (uvicorn) on a TEMPORARY SQLite database
#      (GREYWATCH_DB -> a fresh /tmp file). It NEVER touches data/greywatch.db.
#   2. Injects exactly five synthetic "Failed password" SSH log lines from the
#      reserved documentation IP 203.0.113.10 (RFC 5737) via the EXISTING
#      /api/v1/events/ingest HTTP endpoint — no real SSH, no real accounts.
#   3. Reads the alert back through the EXISTING /api/v1/alerts and
#      /api/v1/alerts/{id} endpoints and asserts the detection contract.
#   4. Prints a PASS/FAIL report.
#   5. Cleans up: stops uvicorn and removes ONLY its own temp database.
#
# This exercises the real HTTP path end to end: HTTP ingest -> parse_auth_line
# -> ssh_login_failed -> SSH_BRUTE_FORCE (threshold 5, 5-min window, per-IP) ->
# alerts table -> alert-detail evidence. No code is mocked.
#
# NOTE: This does NOT prove real network-intrusion detection. It proves the
# detection *pipeline* works on synthetic data. See docs/LIVE_THREAT_TEST.md.
#
set -euo pipefail

# --------------------------------------------------------------------------- #
# Config (all overrides via env for repeatability)
# --------------------------------------------------------------------------- #
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

VENV_PY="${VENV_PY:-$REPO_ROOT/.venv/bin/python}"
VENV_UVICORN="${VENV_UVICORN:-$REPO_ROOT/.venv/bin/uvicorn}"
HOST="127.0.0.1"
PORT="${LIVE_TEST_PORT:-8010}"          # avoids the dev server on :5173 / stale :8000
BASE="http://${HOST}:${PORT}"
ATTACK_IP="${LIVE_TEST_ATTACK_IP:-203.0.113.10}"   # RFC 5737 documentation address

# A fresh temp DB per run -> fully repeatable; no duplicate alerts / events
# accumulate across runs. Production data/greywatch.db is NEVER touched.
TEMP_DB="$(mktemp -u "${LIVE_TEST_DB_DIR:-/tmp}/gw-live-XXXXXXXX.db")"
export GREYWATCH_DB="$TEMP_DB"

# Temp file holding the synthetic log lines (safe JSON construction).
TMP_LINES="$(mktemp -u "${LIVE_TEST_DB_DIR:-/tmp}/gw-live-lines.XXXXXX")"

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
log() { printf '%b\n' "$*"; }

# jget <json-string> <dot.path>  -> prints a scalar from the JSON.
# Path supports dot notation and [n] indexing, e.g. alerts[0].rule_id
jget() {
  "$VENV_PY" -c '
import json, sys, re
d = json.loads(sys.argv[1]); v = d
for tok in re.findall(r"[^\.\[\]]+|\[\d+\]", sys.argv[2]):
    v = v[int(tok[1:-1])] if tok.startswith("[") else v[tok]
import json as _j
if v is None:
    print("")
elif isinstance(v, str):
    print(v)
elif isinstance(v, bool):
    print("true" if v else "false")
elif isinstance(v, (int, float)):
    print(v)
else:
    print(_j.dumps(v))
' "$1" "$2"
}

pass=0
fail=0
check() { # check <description> <got> <expected>
    if [[ "$2" == "$3" ]]; then
        log "  OK   : $1 = '$2'"
        pass=$((pass + 1))
    else
        log "  FAIL : $1 — expected '$3', got '$2'"
        fail=$((fail + 1))
    fi
}

cleanup() {
    local rc=$?
    if [[ -n "${API_PID:-}" ]]; then
        kill "$API_PID" >/dev/null 2>&1 || true
        wait "$API_PID" >/dev/null 2>&1 || true
    fi
    rm -f "$TMP_LINES"
    # Remove ONLY this run's temp database (path guard prevents mishaps).
    if [[ "$TEMP_DB" == /tmp/gw-live-*.db ]]; then
        rm -f "$TEMP_DB"
    fi
    log ""
    log "Cleanup: stopped test API on :${PORT}; removed temp DB ${TEMP_DB}."
    exit "$rc"
}
trap cleanup EXIT INT TERM

# --------------------------------------------------------------------------- #
# Preconditions
# --------------------------------------------------------------------------- #
log "== Greywatch live SSH brute-force detection test =="
log "Repo root : $REPO_ROOT"
log "API       : $VENV_UVICORN on ${HOST}:${PORT} (temp DB)"
log "Temp DB   : $TEMP_DB (production data/greywatch.db is NEVER touched)"
log "Attack IP : $ATTACK_IP (RFC 5737 documentation — not routable)"
log ""

for dep in "$VENV_UVICORN" "$VENV_PY" curl; do
    if ! command -v "$dep" >/dev/null 2>&1 && [[ ! -x "$dep" ]]; then
        log "ERROR: required tool '$dep' not found."
        exit 2
    fi
done

# --------------------------------------------------------------------------- #
# 1. Start an isolated API instance
# --------------------------------------------------------------------------- #
log "[1/5] Starting throwaway Greywatch API on ${HOST}:${PORT} ..."
"$VENV_UVICORN" backend.app.main:app \
    --host "$HOST" --port "$PORT" \
    --log-level warning >/tmp/gw-live-server.log 2>&1 &
API_PID=$!

ready=0
for _ in $(seq 1 40); do
    if curl -fsS "${BASE}/health" >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.5
done
if [[ $ready -ne 1 ]]; then
    log "ERROR: API did not become healthy at ${BASE}. Server log:"
    sed 's/^/    /' /tmp/gw-live-server.log 2>/dev/null || true
    exit 1
fi
log "    health: $(curl -fsS "${BASE}/health")"
log ""

# --------------------------------------------------------------------------- #
# 2. Inject exactly five synthetic failed SSH logins (the threshold) from one IP
# --------------------------------------------------------------------------- #
log "[2/5] Ingesting 5 synthetic 'Failed password' lines from $ATTACK_IP ..."
for i in 0 1 2 3 4; do
    printf 'sshd[600%d]: Failed password for attacker%d from %s port 540%d00 ssh2\n' \
        "$i" "$i" "$ATTACK_IP" "$i"
done > "$TMP_LINES"

payload="$("$VENV_PY" -c '
import json, sys
lines = open(sys.argv[1]).read().splitlines()
print(json.dumps({"lines": lines}))
' "$TMP_LINES")"

ingest_resp="$(curl -fsS -X POST "${BASE}/api/v1/events/ingest" \
    -H 'Content-Type: application/json' \
    -d "$payload")"
log "    ingest: $ingest_resp"
log ""

# --------------------------------------------------------------------------- #
# 3. Verify the detection contract
# --------------------------------------------------------------------------- #
log "[3/5] Verifying detection contract ..."

check "ingest parsed 5/5 lines" "$(jget "$ingest_resp" parsed)" "5"
check "0 lines ignored" "$(jget "$ingest_resp" ignored)" "0"

events_resp="$(curl -fsS "${BASE}/api/v1/events?limit=100")"
check "5 events stored & queryable via GET /api/v1/events" "$(jget "$events_resp" count)" "5"

# Count events whose source_ip matches the attack IP.
ev_match="$("$VENV_PY" -c '
import json, sys
d = json.loads(sys.argv[1])
n = sum(1 for e in d.get("events", []) if e.get("source_ip") == sys.argv[2])
print(n)
' "$events_resp" "$ATTACK_IP")"
check "all 5 events carry $ATTACK_IP" "$ev_match" "5"

alerts_resp="$(curl -fsS "${BASE}/api/v1/alerts?status=all&limit=100")"
check "exactly one alert raised" "$(jget "$alerts_resp" count)" "1"

alert_json="$(jget "$alerts_resp" alerts[0])"
check "alert rule_id == SSH_BRUTE_FORCE" "$(jget "$alert_json" rule_id)" "SSH_BRUTE_FORCE"
check "alert severity == high" "$(jget "$alert_json" severity)" "high"
check "alert status == open" "$(jget "$alert_json" status)" "open"
check "alert source_ip == $ATTACK_IP" "$(jget "$alert_json" source_ip)" "$ATTACK_IP"
check "alert event_count == 5" "$(jget "$alert_json" event_count)" "5"

alert_id="$(jget "$alert_json" id)"
log ""

# --------------------------------------------------------------------------- #
# 4. Verify alert evidence points at the relevant events
# --------------------------------------------------------------------------- #
log "[4/5] Verifying alert evidence (GET /api/v1/alerts/${alert_id}) ..."
detail="$(curl -fsS "${BASE}/api/v1/alerts/${alert_id}")"

win_start="$(jget "$detail" evidence_window_start)"
win_end="$(jget "$detail" evidence_window_end)"
check "evidence window_start present" "$([ -n "$win_start" ] && echo yes)" "yes"
check "evidence window_end present" "$([ -n "$win_end" ] && echo yes)" "yes"

ev_count="$("$VENV_PY" -c '
import json, sys
d = json.loads(sys.argv[1])
print(len(d.get("evidence_events", [])))
' "$detail")"
check "evidence_events length == 5" "$ev_count" "5"

ev_sources="$("$VENV_PY" -c '
import json, sys
d = json.loads(sys.argv[1])
ips = {e.get("source_ip") for e in d.get("evidence_events", [])}
print(",".join(sorted(ips)))
' "$detail")"
check "all evidence events from $ATTACK_IP" "$ev_sources" "$ATTACK_IP"

ev_types="$("$VENV_PY" -c '
import json, sys
d = json.loads(sys.argv[1])
types = {e.get("event_type") for e in d.get("evidence_events", [])}
print(",".join(sorted(types)))
' "$detail")"
check "evidence events are ssh_login_failed" "$ev_types" "ssh_login_failed"
log ""

# --------------------------------------------------------------------------- #
# 5. Distinguish simulated vs real telemetry
# --------------------------------------------------------------------------- #
log "[5/5] Provenance distinction ..."
src_val="$("$VENV_PY" -c '
import json, sys
d = json.loads(sys.argv[1])
s = d["events"][0].get("source")
print("null" if s is None else s)
' "$events_resp")"
check "synthetic HTTP events have source=NULL (HTTP ingest line)" "$src_val" "null"
log "    -> dashboard maps provenance: NULL='HTTP ingest'(grey), 'journal'='systemd journal'(teal), 'suricata'='Suricata'(purple)"
log ""

# --------------------------------------------------------------------------- #
log "== RESULT: $pass passed, $fail failed =="
if [[ $fail -ne 0 ]]; then
    log "FAIL — see assertions above."
    exit 1
fi
log "PASS — SSH_BRUTE_FORCE fired end-to-end on synthetic data."
log "Simulated only: no real SSH login, no real accounts, no production DB touched."
