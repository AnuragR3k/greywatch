#!/usr/bin/env bash
#
# scripts/gw_retention.sh
#
# Greywatch event-retention and SQLite maintenance wrapper.
#
# Usage:
#   ./scripts/gw_retention.sh dry-run          Preview eligible/protected/deletable counts
#   ./scripts/gw_retention.sh execute          Delete eligible events (requires
#                                              GREYWATCH_EVENT_RETENTION_DAYS to be set)
#   ./scripts/gw_retention.sh vacuum           Compact the database (STOP THE SERVICE FIRST)
#
# Configuration (environment variables):
#   GREYWATCH_DB                   Database path
#                                    (default: /var/lib/greywatch/greywatch.db)
#   GREYWATCH_EVENT_RETENTION_DAYS Event retention period in days
#                                    (default: unset = DISABLED / non-destructive)
#   GREYWATCH_RETENTION_BATCH_SIZE Deletion batch size (default: 1000)
#   GREYWATCH_PYTHON               Python interpreter (default: python3)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_PATH="${GREYWATCH_DB:-/var/lib/greywatch/greywatch.db}"
RETENTION_DAYS="${GREYWATCH_EVENT_RETENTION_DAYS:-}"
BATCH_SIZE="${GREYWATCH_RETENTION_BATCH_SIZE:-1000}"
PYTHON="${GREYWATCH_PYTHON:-python3}"

usage() {
    cat <<'EOF'
Usage: gw_retention.sh <command>

  dry-run          Preview what would be deleted (safe, read-only)
  execute          Delete events older than GREYWATCH_EVENT_RETENTION_DAYS
  vacuum           VACUUM the database (REQUIRES SERVICE DOWNTIME)

Environment: GREYWATCH_DB, GREYWATCH_EVENT_RETENTION_DAYS,
             GREYWATCH_RETENTION_BATCH_SIZE, GREYWATCH_PYTHON.
EOF
}

if [ ! -d "${REPO_ROOT}/backend/app" ]; then
    echo "ERROR: backend/app not found at ${REPO_ROOT}/backend/app" >&2
    exit 1
fi

command="${1:-}"
shift || true

case "${command}" in
    dry-run)
        exec "${PYTHON}" -m backend.app.retention --dry-run --batch-size "${BATCH_SIZE}"
        ;;
    execute)
        if [ -z "${RETENTION_DAYS}" ]; then
            echo "ERROR: GREYWATCH_EVENT_RETENTION_DAYS is not set." >&2
            echo "       Set it to a positive integer (e.g. 90) to enable retention." >&2
            echo "       To preview what would be deleted, use 'dry-run' instead." >&2
            exit 1
        fi
        exec "${PYTHON}" -m backend.app.retention --execute --batch-size "${BATCH_SIZE}"
        ;;
    vacuum)
        echo "WARNING: VACUUM requires exclusive database access." >&2
        echo "         Stop greywatch-api and all collectors before proceeding." >&2
        echo "         sudo systemctl stop greywatch-api" >&2
        echo -n "Proceed? [y/N] "
        read -r confirm
        case "${confirm,,}" in
            y|yes)
                exec "${PYTHON}" -m backend.app.retention --vacuum
                ;;
            *)
                echo "Aborted."
                exit 2
                ;;
        esac
        ;;
    ""|-h|--help|help)
        usage
        exit 0
        ;;
    *)
        echo "ERROR: unknown command: ${command}" >&2
        usage >&2
        exit 1
        ;;
esac
