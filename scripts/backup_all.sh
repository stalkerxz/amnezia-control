#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

RUN_TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_ROOT="$PROJECT_ROOT/backups/runs"
RUN_DIR="$BACKUP_ROOT/$RUN_TS"

log() { printf '[backup] %s\n' "$*"; }
fail() { printf '[backup][error] %s\n' "$*" >&2; exit 1; }

require_cmds=(docker gzip tar sha256sum df awk sed date hostname mktemp)
for cmd in "${require_cmds[@]}"; do
  command -v "$cmd" >/dev/null 2>&1 || fail "required command not found: $cmd"
done

[ -f .env ] || fail "missing .env in project root"

docker compose version >/dev/null 2>&1 || fail "docker compose is not available"

DB_CID="$(docker compose ps -q db 2>/dev/null || true)"
WEB_CID="$(docker compose ps -q web 2>/dev/null || true)"
[ -n "$DB_CID" ] || fail "db container not found (is stack running?)"
[ -n "$WEB_CID" ] || fail "web container not found (is stack running?)"

docker compose exec -T db true >/dev/null 2>&1 || fail "db service is not reachable"
docker compose exec -T web true >/dev/null 2>&1 || fail "web service is not reachable"

DB_NAME="$(docker compose exec -T db sh -lc 'printf %s "${POSTGRES_DB:-}"' | tr -d '\r')"
DB_USER="$(docker compose exec -T db sh -lc 'printf %s "${POSTGRES_USER:-}"' | tr -d '\r')"
[ -n "$DB_NAME" ] || fail "POSTGRES_DB is empty in db container env"
[ -n "$DB_USER" ] || fail "POSTGRES_USER is empty in db container env"

MEDIA_VOL="$(docker inspect "$WEB_CID" --format '{{range .Mounts}}{{if eq .Destination "/data/media"}}{{.Name}}{{end}}{{end}}')"
[ -n "$MEDIA_VOL" ] || fail "failed to detect media volume mounted to /data/media"

log "collecting size estimates"
DB_BYTES_RAW="$(docker compose exec -T db sh -lc 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "SELECT pg_database_size(current_database());"' 2>/dev/null | tr -d '\r' || true)"
if [[ "$DB_BYTES_RAW" =~ ^[0-9]+$ ]]; then
  DB_BYTES="$DB_BYTES_RAW"
else
  DB_BYTES=0
fi
MEDIA_BYTES_RAW="$(docker run --rm -v "$MEDIA_VOL":/data busybox sh -c 'du -sb /data 2>/dev/null | awk "{print \$1}"' 2>/dev/null || true)"
if [[ "$MEDIA_BYTES_RAW" =~ ^[0-9]+$ ]]; then
  MEDIA_BYTES="$MEDIA_BYTES_RAW"
else
  MEDIA_BYTES=0
fi
REQUIRED_BYTES=$(( DB_BYTES * 2 + MEDIA_BYTES + 200 * 1024 * 1024 ))
AVAIL_BYTES="$(df -Pk "$PROJECT_ROOT" | awk 'NR==2{print $4*1024}')"
if [ "$AVAIL_BYTES" -lt "$REQUIRED_BYTES" ]; then
  fail "insufficient disk space: need ~${REQUIRED_BYTES} bytes, available ${AVAIL_BYTES} bytes"
fi

mkdir -p "$RUN_DIR"
log "backup destination: $RUN_DIR"

log "dumping PostgreSQL database $DB_NAME"
TMP_SQL="$RUN_DIR/postgres.sql"
docker compose exec -T db sh -lc 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB"' > "$TMP_SQL"
gzip -9 "$TMP_SQL"

log "archiving media volume: $MEDIA_VOL"
docker run --rm -v "$MEDIA_VOL":/source:ro -v "$RUN_DIR":/backup busybox sh -c 'tar -czf /backup/media.tar.gz -C /source .'

log "copying runtime .env"
cp .env "$RUN_DIR/.env"

log "writing metadata"
{
  echo "timestamp=$RUN_TS"
  echo "hostname=$(hostname)"
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "git_commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  else
    echo "git_commit=unavailable"
  fi
  echo "project_path=$PROJECT_ROOT"
  echo "compose_project=${COMPOSE_PROJECT_NAME:-$(basename "$PROJECT_ROOT")}" 
  echo "db_service=db"
  echo "web_service=web"
  echo "db_container=$DB_CID"
  echo "web_container=$WEB_CID"
  echo "media_volume=$MEDIA_VOL"
  echo "db_name=$DB_NAME"
  echo "db_user=$DB_USER"
} > "$RUN_DIR/meta.txt"

log "generating checksums"
(
  cd "$RUN_DIR"
  sha256sum postgres.sql.gz media.tar.gz .env meta.txt > SHA256SUMS
)

log "validating artifacts"
gzip -t "$RUN_DIR/postgres.sql.gz"
tar -tzf "$RUN_DIR/media.tar.gz" >/dev/null

log "backup complete"
log "files:"
ls -lh "$RUN_DIR"
