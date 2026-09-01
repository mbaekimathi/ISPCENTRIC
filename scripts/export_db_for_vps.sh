#!/usr/bin/env bash
# Export local ISPCENTRIC MySQL database for VPS import.
# Run on Windows (Git Bash) or Linux from project root:
#   bash scripts/export_db_for_vps.sh
# Upload result:
#   scp deploy/ispcentric_dump.sql root@isp.richcom.co.ke:/tmp/
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/deploy/ispcentric_dump.sql"

# Read from .env when present.
ENV_FILE="$ROOT/.env"
DB_HOST="127.0.0.1"
DB_USER="root"
DB_PASS=""
DB_NAME="ISPCENTRIC"

if [[ -f "$ENV_FILE" ]]; then
  _val() { grep -E "^$1=" "$ENV_FILE" 2>/dev/null | tail -n1 | cut -d= -f2- | tr -d '\r' || true; }
  DB_HOST="$(_val MYSQL_HOST; echo "$DB_HOST")"
  DB_USER="$(_val MYSQL_USER; echo "$DB_USER")"
  DB_PASS="$(_val MYSQL_PASSWORD)"
  DB_NAME="$(_val MYSQL_DATABASE; echo "$DB_NAME")"
fi

mkdir -p "$(dirname "$OUT")"
echo "==> Dumping $DB_NAME from $DB_HOST to $OUT"

if [[ -n "$DB_PASS" ]]; then
  MYSQL_PWD="$DB_PASS" mysqldump -h "$DB_HOST" -u "$DB_USER" \
    --single-transaction --routines --triggers "$DB_NAME" >"$OUT"
else
  mysqldump -h "$DB_HOST" -u "$DB_USER" \
    --single-transaction --routines --triggers "$DB_NAME" >"$OUT"
fi

echo "==> Done ($(wc -c <"$OUT") bytes)"
echo "    Upload: scp $OUT root@isp.richcom.co.ke:/tmp/"
echo "    Import: ssh root@isp.richcom.co.ke 'mysql ispcentric < /tmp/ispcentric_dump.sql'"
