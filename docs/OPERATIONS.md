# Operations / deploy safety notes

## 1) Hotfix parity (repo vs production)
Use this short checklist after any urgent production hotfix:

1. Capture exact changes in git (code + config + compose).
2. Rebuild and run from repository (`docker compose up -d --build`) instead of patching running containers manually.
3. Verify no pending migration generation:
   - `python manage.py makemigrations --check --dry-run`
4. Verify migration plan is empty on target environment:
   - `python manage.py migrate --plan`
5. Run `scripts/post_deploy_smoke.sh` after deploy.

This prevents long-lived "server-only" fixes that are not represented in source control.

## 2) Migration hygiene
Minimum checks per release:

- `python manage.py makemigrations --check --dry-run` must report `No changes detected`.
- `python manage.py migrate --plan` should show no unapplied migrations on a fully migrated target.
- Never edit already applied migration files in-place; add a new migration instead.

## 3) Renewal attachment storage
- Renewal request uploads use Django `FileField` in `portal.ClientRenewalRequest.attachment`.
- Storage root is controlled by `MEDIA_ROOT` (default `/data/media` in compose env).
- `docker-compose.yml` mounts named volume `media_data` to `/data/media` for `web`, `worker`, and `beat`.

Result: attachments are persisted in Docker volume storage and survive container rebuild/restart.

## 4) Backup and restore (production runbook)
### Scope
Every backup run includes only recoverable runtime state:

1. PostgreSQL dump (`postgres.sql.gz`).
2. Media volume archive (`media.tar.gz`, includes renewal attachments).
3. Runtime `.env` (contains secrets, including `CONFIG_ENCRYPTION_KEY`).
4. Integrity metadata (`SHA256SUMS` + `meta.txt`).

If `CONFIG_ENCRYPTION_KEY` is lost, encrypted portal tokens/config values cannot be decrypted.

### Backup location and layout
Backups are written to sortable paths:

- `backups/runs/<YYYYMMDD-HHMMSS>/`

Expected files per run:

- `postgres.sql.gz`
- `media.tar.gz`
- `.env`
- `SHA256SUMS`
- `meta.txt`

### Create backup
Run from project root:

```bash
./scripts/backup_all.sh
```

Script behavior:
- checks required commands;
- checks compose services (`db`, `web`) are reachable;
- auto-detects DB name/user from container env;
- auto-detects media volume from `web` mount to `/data/media`;
- checks free disk space before starting;
- validates generated archives (`gzip -t`, `tar -tzf`);
- exits non-zero on any failure.

### Verify backup
Run before transfer and before restore:

```bash
./scripts/verify_backup.sh backups/runs/<YYYYMMDD-HHMMSS>
```

Verification includes required files, checksum validation, gzip test, and tar readability test.

### Restore backup
Default restore (DB + media only):

```bash
./scripts/restore_all.sh backups/runs/<YYYYMMDD-HHMMSS>
```

Restore with explicit `.env` overwrite:

```bash
./scripts/restore_all.sh --restore-env backups/runs/<YYYYMMDD-HHMMSS>
```

Non-interactive confirmation (automation):

```bash
./scripts/restore_all.sh --yes backups/runs/<YYYYMMDD-HHMMSS>
```

Safety rules:
- restore validates backup first via `verify_backup.sh`;
- restore is destructive for DB/media and warns clearly;
- interactive confirmation is required unless `--yes` is passed;
- `.env` is **never** overwritten unless `--restore-env` is explicitly set.

### Mandatory post-restore steps
After any restore run:

```bash
docker compose up -d --build
docker compose exec web python manage.py migrate
./scripts/post_deploy_smoke.sh
```

## 5) Backup retention cleanup
Policy: keep the latest **14** backup runs in `backups/runs/`.

Cleanup command:

```bash
./scripts/cleanup_backups.sh
```

Behavior:
- only touches `backups/runs/`;
- removes oldest directories after the most recent 14;
- does nothing when there are 14 or fewer runs.

## 6) Attachment access safety
- Attachments are served only through authenticated operator endpoint `/clients/renewal-requests/<id>/attachment/`.
- There is no direct reverse-proxy alias for `/media`; Caddy forwards requests to Django.
- Keep it this way unless you add explicit signed/private media handling.
