#!/usr/bin/env bash
#
# scripts/generate_staging_token.sh
#
# Generates a stable GREYWATCH_API_TOKEN and writes it to a protected file
# under /etc/greywatch/.
#
# The token is NEVER printed to stdout and NEVER committed to version control.
# It is consumed in two places:
#   1. Backend: via systemd EnvironmentFile=/etc/greywatch/greywatch.env
#      (mode 0600, root readable only). The backend validates this token on
#      every non-public API endpoint (token mode).
#   2. Caddy: via Caddy's own environment (systemd EnvironmentFile or caddy
#      service env). Caddy injects this token server-side as the
#      Authorization header when proxying /api/* to the backend. The browser
#      never sees the token.
#
# Usage:
#   sudo ./scripts/generate_staging_token.sh
#
# Outputs only confirmation paths; the raw token is written to disk only.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

ETC_DIR="/etc/greywatch"
ENV_FILE="${ETC_DIR}/greywatch.env"

# Require root so we can write protected files.
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: run as root (sudo)." >&2
    exit 1
fi

mkdir -p "${ETC_DIR}"
chmod 0700 "${ETC_DIR}"

# Generate a 32-byte (256-bit) URL-safe token.
TOKEN="$(head -c 32 /dev/urandom | base64 | tr -d '\n' | head -c 43)"
if [ -z "${TOKEN}" ]; then
    echo "ERROR: failed to generate token." >&2
    exit 1
fi

# Backend environment file (mode 0600, root only).
cat > "${ENV_FILE}" <<EOF
# Greywatch backend environment — generated $(date -u +%Y-%m-%dT%H:%M:%SZ)
# DO NOT COMMIT. Mode 0600, root readable only.
GREYWATCH_API_TOKEN="${TOKEN}"
GREYWATCH_DB=/var/lib/greywatch/greywatch.db
GREYWATCH_API_LOOPBACK_ONLY=1
GREYWATCH_RATE_LIMIT_ENABLED=1
GREYWATCH_MAX_REQUEST_BYTES=1048576
EOF
chmod 0600 "${ENV_FILE}"

echo "Staging token generated."
echo "  Backend env : ${ENV_FILE}   (0600, root)"
echo ""
echo "Next steps:"
echo "  1. Set the same GREYWATCH_API_TOKEN in Caddy's environment (systemd"
echo "     EnvironmentFile or caddy service env) so Caddy can inject it"
echo "     server-side when proxying /api/* to the backend."
echo "  2. Configure Caddy basicauth dashboard user + bcrypt hash"
echo "     (caddy hash-password)."
echo "  3. Reload Caddy and the GreyWatch API; see docs/DEPLOYMENT.md."
echo ""
echo "The raw token is written above to ${ENV_FILE} only — it is not shown here."
echo "The browser never receives the API token."
