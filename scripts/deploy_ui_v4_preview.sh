#!/usr/bin/env bash
set -Eeuo pipefail

TARGET_BRANCH="${UI_V4_BRANCH:-feature/ui-v4-amnezia-inspired}"
STATE_FILE=".git/ui-v4-preview-state"
COMPOSE=(docker compose)

log() { printf '\n[%s] %s\n' "ui-v4" "$*"; }
die() { printf '\n[ui-v4] ERROR: %s\n' "$*" >&2; exit 1; }

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || true)"
[[ -n "$repo_root" ]] || die "run this from the amnezia-control git repository"
cd "$repo_root"

restore_previous_revision() {
  local previous_head="$1"
  local previous_branch="$2"

  log "Restoring previous source revision $previous_head"
  if [[ -n "$previous_branch" ]]; then
    git switch "$previous_branch"
    [[ "$(git rev-parse HEAD)" == "$previous_head" ]] || die "previous branch moved; refusing automatic reset"
  else
    git switch --detach "$previous_head"
  fi

  log "Rebuilding previous application revision"
  "${COMPOSE[@]}" up -d --build

  log "Running post-rollback smoke checks"
  bash scripts/post_deploy_smoke.sh
}

rollback_from_state() {
  [[ -f "$STATE_FILE" ]] || die "preview state file not found: $STATE_FILE"

  local previous_head previous_branch target_head
  previous_head="$(sed -n 's/^PREVIOUS_HEAD=//p' "$STATE_FILE" | tail -1)"
  previous_branch="$(sed -n 's/^PREVIOUS_BRANCH=//p' "$STATE_FILE" | tail -1)"
  target_head="$(sed -n 's/^TARGET_HEAD=//p' "$STATE_FILE" | tail -1)"

  [[ "$previous_head" =~ ^[0-9a-f]{40}$ ]] || die "invalid PREVIOUS_HEAD in state file"
  [[ -z "$target_head" || "$target_head" =~ ^[0-9a-f]{40}$ ]] || die "invalid TARGET_HEAD in state file"
  [[ -z "$(git status --porcelain)" ]] || die "working tree is dirty; rollback aborted"

  restore_previous_revision "$previous_head" "$previous_branch"
  rm -f "$STATE_FILE"
  log "Rollback completed"
}

if [[ "${1:-}" == "rollback" ]]; then
  rollback_from_state
  exit 0
fi

command -v git >/dev/null || die "git is required"
command -v docker >/dev/null || die "docker is required"
docker compose version >/dev/null || die "docker compose plugin is required"
[[ -f .env ]] || die ".env is missing"
[[ -f docker-compose.yml ]] || die "docker-compose.yml is missing"
[[ -z "$(git status --porcelain)" ]] || die "working tree is dirty; commit/stash server changes first"

PREVIOUS_HEAD="$(git rev-parse HEAD)"
PREVIOUS_BRANCH="$(git symbolic-ref --quiet --short HEAD 2>/dev/null || true)"

log "Current revision"
echo "branch: ${PREVIOUS_BRANCH:-DETACHED}"
echo "HEAD:   $PREVIOUS_HEAD"

log "Fetching $TARGET_BRANCH"
git fetch --no-tags origin "$TARGET_BRANCH"
TARGET_HEAD="$(git rev-parse FETCH_HEAD)"
echo "target: $TARGET_HEAD"

[[ "$PREVIOUS_HEAD" != "$TARGET_HEAD" ]] || die "target UI v4 revision is already deployed"

log "Verifying that UI v4 contains the currently deployed revision"
if ! git merge-base --is-ancestor "$PREVIOUS_HEAD" "$TARGET_HEAD"; then
  die "current HEAD is not an ancestor of UI v4. Rebase/update the UI branch before deployment; nothing was changed"
fi

log "Verifying preview scope"
changed_files="$(git diff --name-only "$PREVIOUS_HEAD" "$TARGET_HEAD")"
printf '%s\n' "$changed_files"

while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  case "$path" in
    amnezia_control/templates/*|amnezia_control/static/css/*|scripts/ui_v4_check.sh|scripts/deploy_ui_v4_preview.sh)
      ;;
    *)
      die "non-UI change detected in preview range: $path"
      ;;
  esac
done <<< "$changed_files"

log "Validating current Docker Compose configuration"
"${COMPOSE[@]}" config --quiet
"${COMPOSE[@]}" ps

log "Creating full pre-preview backup"
bash scripts/backup_all.sh
BACKUP_DIR="$(ls -1dt backups/runs/*/ 2>/dev/null | head -1 | sed 's:/$::' || true)"
[[ -n "$BACKUP_DIR" ]] || die "backup completed but latest backup directory could not be determined"
bash scripts/verify_backup.sh "$BACKUP_DIR"
echo "backup: $BACKUP_DIR"

cat > "$STATE_FILE" <<STATE
PREVIOUS_HEAD=$PREVIOUS_HEAD
PREVIOUS_BRANCH=$PREVIOUS_BRANCH
TARGET_HEAD=$TARGET_HEAD
BACKUP_DIR=$BACKUP_DIR
STATE

rollback_on_error() {
  local rc=$?
  trap - ERR INT TERM
  printf '\n[ui-v4] Deployment failed (exit %s). Starting automatic source rollback.\n' "$rc" >&2
  if restore_previous_revision "$PREVIOUS_HEAD" "$PREVIOUS_BRANCH"; then
    printf '\n[ui-v4] Previous revision restored successfully. Backup remains at %s\n' "$BACKUP_DIR" >&2
    rm -f "$STATE_FILE"
  else
    printf '\n[ui-v4] AUTOMATIC ROLLBACK FAILED. Backup: %s; previous HEAD: %s\n' "$BACKUP_DIR" "$PREVIOUS_HEAD" >&2
  fi
  exit "$rc"
}
trap rollback_on_error ERR INT TERM

log "Switching source tree to UI v4 preview (detached HEAD)"
git switch --detach "$TARGET_HEAD"

log "Running structural checks before container restart"
bash scripts/ui_v4_check.sh

log "Building and starting UI v4"
"${COMPOSE[@]}" up -d --build

log "Waiting for web service"
ready=0
for _ in $(seq 1 45); do
  if "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx web; then
    if "${COMPOSE[@]}" exec -T web python manage.py check >/dev/null 2>&1; then
      ready=1
      break
    fi
  fi
  sleep 2
done
[[ "$ready" == "1" ]] || die "web service did not become ready"

log "Running UI v4 checks on rebuilt containers"
bash scripts/ui_v4_check.sh

log "Running repository post-deploy smoke checks"
bash scripts/post_deploy_smoke.sh

trap - ERR INT TERM

log "UI v4 preview deployed successfully"
echo "previous: $PREVIOUS_HEAD (${PREVIOUS_BRANCH:-DETACHED})"
echo "current:  $TARGET_HEAD"
echo "backup:   $BACKUP_DIR"
echo
echo "Rollback command:"
echo "  bash scripts/deploy_ui_v4_preview.sh rollback"
