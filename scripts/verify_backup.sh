#!/usr/bin/env bash
set -euo pipefail

log() { printf '[verify] %s\n' "$*"; }
fail() { printf '[verify][error] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<USAGE
Usage: $0 backups/runs/<YYYYMMDD-HHMMSS>
USAGE
}

[ "${1:-}" != "" ] || { usage; fail "backup directory argument is required"; }
BACKUP_DIR="$1"
[ -d "$BACKUP_DIR" ] || fail "backup directory not found: $BACKUP_DIR"

for f in postgres.sql.gz media.tar.gz .env SHA256SUMS meta.txt; do
  [ -f "$BACKUP_DIR/$f" ] || fail "missing required file: $BACKUP_DIR/$f"
done

log "verifying checksums"
(
  cd "$BACKUP_DIR"
  sha256sum -c SHA256SUMS
)

log "verifying postgres.sql.gz integrity"
gzip -t "$BACKUP_DIR/postgres.sql.gz"

log "verifying media.tar.gz readability"
tar -tzf "$BACKUP_DIR/media.tar.gz" >/dev/null

log "backup verification passed: $BACKUP_DIR"
