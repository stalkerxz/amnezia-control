#!/usr/bin/env bash
set -euo pipefail

COMPOSE=(docker compose)

if ! "${COMPOSE[@]}" ps --status running web >/dev/null 2>&1; then
  echo "ERROR: web service is not running"
  exit 1
fi

echo "[ui-v4] Django system check"
"${COMPOSE[@]}" exec -T web python manage.py check

echo "[ui-v4] Migration drift check"
"${COMPOSE[@]}" exec -T web python manage.py makemigrations --check --dry-run

echo "[ui-v4] Template and static asset load check"
"${COMPOSE[@]}" exec -T web python manage.py shell <<'PY'
from django.contrib.staticfiles import finders
from django.template.loader import get_template
from django.urls import reverse

TEMPLATES = [
    "partials/base.html",
    "core/dashboard.html",
    "core/settings.html",
    "customers/customers_list.html",
    "customers/customer_detail.html",
    "customers/_operator_workspace.html",
    "customer_portal/base.html",
    "customer_portal/home.html",
    "customer_portal/_connections_workspace.html",
    "servers/list.html",
    "servers/detail.html",
    "jobs/list.html",
    "jobs/detail.html",
    "audit/list.html",
]

STATIC_ASSETS = [
    "css/app-v4.css",
    "css/app-v4-layout.css",
    "css/app-v4-customers.css",
    "css/app-v4-detail.css",
    "css/app-v4-system.css",
]

for template_name in TEMPLATES:
    get_template(template_name)
    print(f"template OK: {template_name}")

for asset in STATIC_ASSETS:
    found = finders.find(asset)
    if not found:
        raise RuntimeError(f"static asset not found: {asset}")
    print(f"static OK: {asset}")

URLS = [
    ("customers-list", (), {}),
    ("customers-onboarding", (), {}),
    ("customer-portal-home", (), {}),
    ("servers-list", (), {}),
    ("servers-detail", (1,), {}),
    ("servers-sync-runtime", (1,), {}),
    ("jobs-list", (), {}),
    ("audit-list", (), {}),
]

for name, args, kwargs in URLS:
    value = reverse(name, args=args, kwargs=kwargs)
    print(f"url OK: {name} -> {value}")

print("UI v4 structural checks passed")
PY

echo "[ui-v4] Migration plan"
"${COMPOSE[@]}" exec -T web python manage.py migrate --plan

echo "[ui-v4] OK"
