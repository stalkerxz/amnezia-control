#!/usr/bin/env bash
set -euo pipefail
python manage.py migrate --noinput
python manage.py collectstatic --noinput
python manage.py seed_demo || true
exec gunicorn amnezia_control.wsgi:application --bind 0.0.0.0:8000 --workers 3
