#!/usr/bin/env bash
#
# scripts/gw_db_backup.sh
#
# Greywatch SQLite backup/restore wrapper.
#
# Delegates to scripts/gw_db_backup.py, which uses SQLite's online backup API
# (sqlite3.Connection.backup) for consistent, non-destructive backups of a live
# WAL-mode database. The live database file is never copied or written to.
#
# Configuration (environment variables):
#   GREYWATCH_DB                    live database path
#                                   (default: /var/lib/greywatch/greywatch.db)
#   GREYWATCH_BACKUP_DIR            backup directory
#                                   (default: /var/backups/greywatch)
#   GREYWATCH_BACKUP_RETENTION_DAYS retention window for `backup` (default: 30)
#   GREYWATCH_DB_OWNER              optional "user[:group]" to chown a restored
#                                   database to; unresolved owners are reported
#                                   and existing ownership is preserved
#   GREYWATCH_PYTHON                Python interpreter (default: python3)
#
# Usage:
#   ./scripts/gw_db_backup.sh backup
#   ./scripts/gw_db_backup.sh verify   <backup-file>
#   ./scripts/gw_db_backup.sh retain   <days>
#   ./scripts/gw_db_backup.sh restore  <backup-file> --yes
#
# Restore requires `--yes`. The script never stops or starts greywatch-api:
# stop the service yourself before restoring (see docs/DEPLOYMENT.md).
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_ENGINE="${REPO_ROOT}/scripts/gw_db_backup.py"

DB_PATH="${GREYWATCH_DB:-/var/lib/greywatch/greywatch.db}"
BACKUP_DIR="${GREYWATCH_BACKUP_DIR:-/var/backups/greywatch}"
RETENTION_DAYS="${GREYWATCH_BACKUP_RETENTION_DAYS:-30}"
DB_OWNER="${GREYWATCH_DB_OWNER:-}"
PYTHON="${GREYWATCH_PYTHON:-python3}"

usage() {
    cat <<'EOF'
Usage: gw_db_backup.sh <command> [args]

  backup                          Create a verified online backup of GREYWATCH_DB
  verify <backup-file>            Verify a backup's integrity and foreign keys
  retain <days>                   Prune backups older than <days>
  restore <backup-file> --yes     Replace GREYWATCH_DB with a verified backup

Environment: GREYWATCH_DB, GREYWATCH_BACKUP_DIR,
             GREYWATCH_BACKUP_RETENTION_DAYS, GREYWATCH_DB_OWNER,
             GREYWATCH_PYTHON.
EOF
}

if [ ! -f "${PY_ENGINE}" ]; then
    echo "ERROR: backup engine not found: ${PY_ENGINE}" >&2
    exit 1
fi

command="${1:-}"
shift || true

case "${command}" in
    backup)
        exec "${PYTHON}" "${PY_ENGINE}" backup \
            "${DB_PATH}" "${BACKUP_DIR}" \
            --retention-days "${RETENTION_DAYS}"
        ;;
    verify)
        if [ -z "${1:-}" ]; then
            echo "ERROR: verify requires a <backup-file>" >&2
            exit 1
        fi
        exec "${PYTHON}" "${PY_ENGINE}" verify "$1"
        ;;
    retain)
        days="${1:-${RETENTION_DAYS}}"
        exec "${PYTHON}" "${PY_ENGINE}" retain "${BACKUP_DIR}" "${days}"
        ;;
    restore)
        if [ -z "${1:-}" ]; then
            echo "ERROR: restore requires a <backup-file>" >&2
            exit 1
        fi
        if [ "${2:-}" != "--yes" ]; then
            echo "ERROR: restore replaces the database and requires --yes." >&2
            echo "       Stop greywatch-api first, then re-run with --yes." >&2
            exit 1
        fi
        owner_args=()
        if [ -n "${DB_OWNER}" ]; then
            owner_args=(--owner "${DB_OWNER}")
        fi
        exec "${PYTHON}" "${PY_ENGINE}" restore "$1" "${DB_PATH}" \
            --yes "${owner_args[@]}"
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