#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

log() { printf '[restore] %s\n' "$*"; }
warn() { printf '[restore][warn] %s\n' "$*" >&2; }
fail() { printf '[restore][error] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<USAGE
Usage: $0 [--restore-env] [--yes] backups/runs/<YYYYMMDD-HHMMSS>

Options:
  --restore-env   Restore backup .env to project root .env (explicit only).
  --yes           Skip interactive confirmation.
USAGE
}

RESTORE_ENV=0
ASSUME_YES=0
BACKUP_DIR=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    --restore-env) RESTORE_ENV=1 ;;
    --yes) ASSUME_YES=1 ;;
    -h|--help) usage; exit 0 ;;
    -*) fail "unknown option: $1" ;;
    *)
      if [ -n "$BACKUP_DIR" ]; then
        fail "backup directory provided multiple times"
      fi
      BACKUP_DIR="$1"
      ;;
  esac
  shift
done

[ -n "$BACKUP_DIR" ] || { usage; fail "backup directory argument is required"; }
[ -d "$BACKUP_DIR" ] || fail "backup directory not found: $BACKUP_DIR"

./scripts/verify_backup.sh "$BACKUP_DIR"

docker compose version >/dev/null 2>&1 || fail "docker compose is not available"
DB_CID="$(docker compose ps -q db 2>/dev/null || true)"
WEB_CID="$(docker compose ps -q web 2>/dev/null || true)"
[ -n "$DB_CID" ] || fail "db container not found (is stack running?)"
[ -n "$WEB_CID" ] || fail "web container not found (is stack running?)"

DB_NAME="$(docker compose exec -T db sh -lc 'printf %s "${POSTGRES_DB:-}"' | tr -d '\r')"
DB_USER="$(docker compose exec -T db sh -lc 'printf %s "${POSTGRES_USER:-}"' | tr -d '\r')"
[ -n "$DB_NAME" ] || fail "POSTGRES_DB is empty in db container env"
[ -n "$DB_USER" ] || fail "POSTGRES_USER is empty in db container env"
MEDIA_VOL="$(docker inspect "$WEB_CID" --format '{{range .Mounts}}{{if eq .Destination "/data/media"}}{{.Name}}{{end}}{{end}}')"
[ -n "$MEDIA_VOL" ] || fail "failed to detect media volume mounted to /data/media"

warn "Destructive action: PostgreSQL database '$DB_NAME' will be replaced from backup."
warn "Destructive action: media volume '$MEDIA_VOL' contents will be replaced from backup."
if [ "$RESTORE_ENV" -eq 1 ]; then
  warn "Explicit env restore enabled: project .env WILL be overwritten."
else
  warn "Env restore disabled: project .env will remain unchanged."
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  printf 'Type "restore" to continue: '
  read -r answer
  [ "$answer" = "restore" ] || fail "restore cancelled"
fi

log "restoring PostgreSQL database: $DB_NAME"
zcat "$BACKUP_DIR/postgres.sql.gz" | docker compose exec -T db sh -lc 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;" >/dev/null && psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'

log "restoring media volume: $MEDIA_VOL"
docker run --rm -v "$MEDIA_VOL":/target -v "$BACKUP_DIR":/backup busybox sh -c 'rm -rf /target/* /target/.[!.]* /target/..?* 2>/dev/null || true; tar -xzf /backup/media.tar.gz -C /target'

if [ "$RESTORE_ENV" -eq 1 ]; then
  log "restoring .env"
  cp "$BACKUP_DIR/.env" "$PROJECT_ROOT/.env"
else
  log "skipping .env restore (use --restore-env to enable)"
fi

log "restore completed"
cat <<NEXT
Next steps:
  docker compose up -d --build
  docker compose exec web python manage.py migrate
  ./scripts/post_deploy_smoke.sh
NEXT
