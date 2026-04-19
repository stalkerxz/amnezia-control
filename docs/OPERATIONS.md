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

## 4) Backup scope
Backups must include:

1. PostgreSQL database (`postgres_data` or logical dump).
2. Media files (`media_data` volume, especially `portal/renewal_attachments/...`).
3. Runtime configuration (`.env`, Caddy/Django settings overrides, encryption key `CONFIG_ENCRYPTION_KEY`).

If `CONFIG_ENCRYPTION_KEY` is lost, encrypted portal tokens cannot be decrypted.

## 5) Restore notes (concise)
1. Restore DB.
2. Restore media volume contents to `MEDIA_ROOT`.
3. Restore `.env` with the original `CONFIG_ENCRYPTION_KEY` and DB credentials.
4. Start stack and run `python manage.py migrate`.
5. Run `scripts/post_deploy_smoke.sh`.

## 6) Attachment access safety
- Attachments are served only through authenticated operator endpoint `/clients/renewal-requests/<id>/attachment/`.
- There is no direct reverse-proxy alias for `/media`; Caddy forwards requests to Django.
- Keep it this way unless you add explicit signed/private media handling.
