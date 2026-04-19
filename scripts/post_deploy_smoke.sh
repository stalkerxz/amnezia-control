#!/usr/bin/env bash
set -euo pipefail

echo "[smoke] Django system check"
docker compose exec web python manage.py check

echo "[smoke] Migration generation drift check"
docker compose exec web python manage.py makemigrations --check --dry-run

echo "[smoke] Migration plan"
docker compose exec web python manage.py migrate --plan

echo "[smoke] Verify attachment endpoint requires auth"
code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:${APP_PORT:-8090}/clients/renewal-requests/1/attachment/)"
if [[ "$code" != "302" ]]; then
  echo "Unexpected HTTP code for anonymous attachment access: $code"
  exit 1
fi

echo "[smoke] Done"
