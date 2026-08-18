#!/usr/bin/env bash
set -euo pipefail

COMPOSE=(docker compose)

if ! "${COMPOSE[@]}" ps --status running --services 2>/dev/null | grep -qx web; then
  echo "ERROR: web service is not running"
  exit 1
fi

echo "[ui-v4] Django system check"
"${COMPOSE[@]}" exec -T web python manage.py check

echo "[ui-v4] Migration drift check"
"${COMPOSE[@]}" exec -T web python manage.py makemigrations --check --dry-run

echo "[ui-v4] Template and static asset load check"
"${COMPOSE[@]}" exec -T web python manage.py shell <<'PY'
from types import SimpleNamespace

from django.contrib.staticfiles import finders
from django.template.loader import get_template
from django.test import RequestFactory
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
    "css/app-v4-system-detail.css",
    "css/app-v4-polish.css",
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

# Modern operator routes must not load the transitional v2/v3 bundles.
base = get_template("partials/base.html")
rf = RequestFactory()
auth_user = SimpleNamespace(is_authenticated=True, username="ui-v4-check")
anon_user = SimpleNamespace(is_authenticated=False, username="")
legacy_assets = ("app-v2.css", "app-v3.css", "app-v3-pages.css")

for path in ("/", "/customers/", "/servers/", "/jobs/", "/audit/", "/settings/"):
    html = base.render({"request": rf.get(path), "user": auth_user})
    leaked = [asset for asset in legacy_assets if asset in html]
    if leaked:
        raise RuntimeError(f"legacy CSS leaked into modern route {path}: {', '.join(leaked)}")
    print(f"modern CSS isolation OK: {path}")

for path in ("/clients/", "/clients/renewal-requests/", "/xhttp/"):
    html = base.render({"request": rf.get(path), "user": auth_user})
    missing = [asset for asset in legacy_assets if asset not in html]
    if missing:
        raise RuntimeError(f"legacy fallback missing on {path}: {', '.join(missing)}")
    print(f"legacy CSS fallback OK: {path}")

login_html = base.render({"request": rf.get("/login/"), "user": anon_user})
missing = [asset for asset in legacy_assets if asset not in login_html]
if missing:
    raise RuntimeError(f"auth fallback missing: {', '.join(missing)}")
print("auth CSS fallback OK: /login/")

print("UI v4 structural checks passed")
PY

echo "[ui-v4] Migration plan"
"${COMPOSE[@]}" exec -T web python manage.py migrate --plan

echo "[ui-v4] OK"
