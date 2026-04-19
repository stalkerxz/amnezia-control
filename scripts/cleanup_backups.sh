#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_ROOT="$PROJECT_ROOT/backups/runs"
KEEP_COUNT=14

log() { printf '[cleanup] %s\n' "$*"; }
fail() { printf '[cleanup][error] %s\n' "$*" >&2; exit 1; }

[ -d "$BACKUP_ROOT" ] || {
  log "nothing to cleanup: $BACKUP_ROOT does not exist"
  exit 0
}

mapfile -t RUN_DIRS < <(find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -r)
COUNT="${#RUN_DIRS[@]}"
if [ "$COUNT" -le "$KEEP_COUNT" ]; then
  log "nothing to cleanup: found $COUNT backups (policy keeps last $KEEP_COUNT)"
  exit 0
fi

log "cleanup policy: keep last $KEEP_COUNT backups in backups/runs/"
for idx in "${!RUN_DIRS[@]}"; do
  if [ "$idx" -ge "$KEEP_COUNT" ]; then
    target="$BACKUP_ROOT/${RUN_DIRS[$idx]}"
    log "removing $target"
    rm -rf -- "$target"
  fi
done

log "cleanup complete"
