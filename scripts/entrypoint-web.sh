#!/usr/bin/env bash
set -euo pipefail
python manage.py wait_for_db
python manage.py migrate --noinput
python manage.py collectstatic --noinput
exec gunicorn amnezia_control.wsgi:application --bind 0.0.0.0:8000 --workers 3
