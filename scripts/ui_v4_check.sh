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
from pathlib import Path
from types import SimpleNamespace

from django.conf import settings
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
    "customers/customer_onboarding_form.html",
    "customers/customer_form.html",
    "customers/customer_edit_form.html",
    "customers/device_form.html",
    "customers/device_edit_form.html",
    "customers/connection_product_select.html",
    "customers/vpn_connection_form.html",
    "customers/xhttp_connection_form.html",
    "customers/access_form.html",
    "customers/access_manage.html",
    "customer_portal/base.html",
    "customer_portal/login.html",
    "customer_portal/home.html",
    "customer_portal/_connections_workspace.html",
    "vpn/renewal_requests_list.html",
    "servers/list.html",
    "servers/detail.html",
    "jobs/list.html",
    "jobs/detail.html",
    "audit/list.html",
]

STATIC_ASSETS = [
    "css/app-v4.css",
    "css/app-v4-shell.css",
    "css/app-v4-layout.css",
    "css/app-v4-customers.css",
    "css/app-v4-detail.css",
    "css/app-v4-system.css",
    "css/app-v4-system-detail.css",
    "css/app-v4-renewals.css",
    "css/app-v4-forms.css",
    "css/app-v4-access.css",
    "css/app-v4-portal.css",
    "css/app-v4-portal-polish.css",
    "css/app-v4-polish.css",
]

for template_name in TEMPLATES:
    get_template(template_name)
    print(f"template OK: {template_name}")

static_paths = {}
for asset in STATIC_ASSETS:
    found = finders.find(asset)
    if not found:
        raise RuntimeError(f"static asset not found: {asset}")
    static_paths[asset] = Path(found)
    print(f"static OK: {asset}")

URLS = [
    ("customers-list", (), {}),
    ("customers-onboarding", (), {}),
    ("customers-access-create", (1,), {}),
    ("customers-access-manage", (1,), {}),
    ("customers-device-access-update", (1,), {}),
    ("customers-device-status", (1,), {}),
    ("customers-device-move", (1,), {}),
    ("customers-device-connection-create", (1,), {}),
    ("customers-device-vpn-create", (1,), {}),
    ("customers-device-xhttp-create", (1,), {}),
    ("customers-xhttp-action", (1, "check"), {}),
    ("clients-detail", (1,), {}),
    ("clients-download-native", (1,), {}),
    ("xhttp-device-download", (1,), {}),
    ("customer-portal-login", (), {}),
    ("customer-portal-logout", (), {}),
    ("customer-portal-home", (), {}),
    ("customer-portal-renewal-request", (), {}),
    ("customer-portal-vpn-download", (1,), {}),
    ("customer-portal-vpn-qr", (1,), {}),
    ("customer-portal-xhttp-download", (1,), {}),
    ("renewal-requests-list", (), {}),
    ("servers-list", (), {}),
    ("servers-detail", (1,), {}),
    ("servers-sync-runtime", (1,), {}),
    ("jobs-list", (), {}),
    ("audit-list", (), {}),
]

for name, args, kwargs in URLS:
    value = reverse(name, args=args, kwargs=kwargs)
    print(f"url OK: {name} -> {value}")

# The operator shell owns core v4 + shell geometry only. Composition belongs to individual pages.
base = get_template("partials/base.html")
rf = RequestFactory()
auth_user = SimpleNamespace(is_authenticated=True, username="ui-v4-check")
anon_user = SimpleNamespace(is_authenticated=False, username="")
legacy_assets = ("app-v2.css", "app-v3.css", "app-v3-pages.css")
composition_assets = (
    "app-v4-layout.css",
    "app-v4-customers.css",
    "app-v4-detail.css",
    "app-v4-system.css",
    "app-v4-system-detail.css",
    "app-v4-renewals.css",
    "app-v4-forms.css",
    "app-v4-access.css",
    "app-v4-portal.css",
    "app-v4-portal-polish.css",
)

for path in (
    "/",
    "/customers/",
    "/clients/renewal-requests/",
    "/servers/",
    "/jobs/",
    "/audit/",
    "/settings/",
):
    html = base.render({"request": rf.get(path), "user": auth_user})
    leaked_legacy = [asset for asset in legacy_assets if asset in html]
    if leaked_legacy:
        raise RuntimeError(
            f"legacy CSS leaked into modern route {path}: "
            + ", ".join(leaked_legacy)
        )
    leaked_composition = [asset for asset in composition_assets if asset in html]
    if leaked_composition:
        raise RuntimeError(
            f"page composition CSS leaked into base shell on {path}: "
            + ", ".join(leaked_composition)
        )
    for required_core in ("app-v4.css", "app-v4-shell.css", "app-v4-polish.css"):
        if required_core not in html:
            raise RuntimeError(
                f"core v4 stylesheet missing from shell on {path}: {required_core}"
            )
    print(f"modern shell CSS isolation OK: {path}")

for path in ("/clients/", "/xhttp/"):
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

# Every modern operator screen must own exactly one copy of its composition layers.
template_root = Path(settings.BASE_DIR) / "templates"
TEMPLATE_STYLE_REQUIREMENTS = {
    "core/dashboard.html": ("app-v4-layout.css",),
    "core/settings.html": ("app-v4-layout.css", "app-v4-system.css"),
    "customers/customers_list.html": ("app-v4-layout.css", "app-v4-customers.css"),
    "customers/customer_detail.html": ("app-v4-layout.css", "app-v4-detail.css"),
    "customers/customer_onboarding_form.html": ("app-v4-forms.css",),
    "customers/customer_form.html": ("app-v4-forms.css",),
    "customers/customer_edit_form.html": ("app-v4-forms.css",),
    "customers/device_form.html": ("app-v4-forms.css",),
    "customers/device_edit_form.html": ("app-v4-forms.css",),
    "customers/connection_product_select.html": ("app-v4-forms.css",),
    "customers/vpn_connection_form.html": ("app-v4-forms.css",),
    "customers/xhttp_connection_form.html": ("app-v4-forms.css",),
    "customers/access_form.html": ("app-v4-forms.css", "app-v4-access.css"),
    "customers/access_manage.html": ("app-v4-forms.css", "app-v4-access.css"),
    "vpn/renewal_requests_list.html": (
        "app-v4-layout.css",
        "app-v4-system.css",
        "app-v4-renewals.css",
    ),
    "servers/list.html": ("app-v4-layout.css", "app-v4-system.css"),
    "servers/detail.html": (
        "app-v4-layout.css",
        "app-v4-system.css",
        "app-v4-system-detail.css",
    ),
    "jobs/list.html": ("app-v4-layout.css", "app-v4-system.css"),
    "jobs/detail.html": (
        "app-v4-layout.css",
        "app-v4-system.css",
        "app-v4-system-detail.css",
    ),
    "audit/list.html": ("app-v4-layout.css", "app-v4-system.css"),
}

for template_name, required_assets in TEMPLATE_STYLE_REQUIREMENTS.items():
    source = (template_root / template_name).read_text(encoding="utf-8")
    for asset in required_assets:
        count = source.count(asset)
        if count != 1:
            raise RuntimeError(
                f"stylesheet ownership error in {template_name}: "
                f"{asset} occurs {count} times, expected exactly 1"
            )
    print(f"page CSS ownership OK: {template_name}")

# The customer portal is a separate consumer shell and must not inherit legacy/operator CSS.
portal_base = get_template("customer_portal/base.html")
portal_base_source = (template_root / "customer_portal/base.html").read_text(encoding="utf-8")
for forbidden in (*legacy_assets, *composition_assets[:-2], "app-v4-shell.css", "app-v4-polish.css"):
    if forbidden in portal_base_source:
        raise RuntimeError(f"operator/legacy stylesheet leaked into customer portal: {forbidden}")
for required in ("app.css", "app-v4.css", "app-v4-portal.css", "app-v4-portal-polish.css"):
    if portal_base_source.count(required) != 1:
        raise RuntimeError(
            f"customer portal stylesheet ownership error: {required} "
            f"occurs {portal_base_source.count(required)} times"
        )
print("customer portal CSS isolation OK")

portal_login_html = portal_base.render(
    {"request": rf.get("/cabinet/login/"), "user": auth_user}
)
if "portal-shell-user" in portal_login_html:
    raise RuntimeError("authenticated session controls leaked into customer portal login")
print("customer portal login shell OK")

portal_home_source = (template_root / "customer_portal/home.html").read_text(encoding="utf-8")
if "app-v4-layout.css" in portal_home_source or "app-v2.css" in portal_home_source:
    raise RuntimeError("customer portal home still depends on operator/legacy CSS")
print("customer portal home composition OK")

# Self-contained page layers must retain the shared primitives they use.
CSS_MARKERS = {
    "css/app-v4-shell.css": (
        ".nav-icon svg",
        ".sidebar-account-avatar",
        ".topbar-user-avatar",
        ".sidebar-toggle svg",
    ),
    "css/app-v4-forms.css": (
        ".v4-form-page .v4-back-link",
        ".v4-form-page .v4-status-pill",
    ),
    "css/app-v4-system-detail.css": (
        ".v4-system-page > .v4-back-link",
    ),
    "css/app-v4-portal.css": (
        ".portal-shell-header",
        ".portal-v4-status-card",
        ".portal-device-card",
        ".portal-login-card",
    ),
    "css/app-v4-portal-polish.css": (
        ".portal-v4-account-chip",
        ".portal-login-shell",
        ".portal-connection-actions",
    ),
}
for asset, markers in CSS_MARKERS.items():
    css = static_paths[asset].read_text(encoding="utf-8")
    missing_markers = [marker for marker in markers if marker not in css]
    if missing_markers:
        raise RuntimeError(
            f"self-contained CSS primitives missing from {asset}: "
            + ", ".join(missing_markers)
        )
    print(f"self-contained CSS OK: {asset}")

print("UI v4 structural checks passed")
PY

echo "[ui-v4] Migration plan"
"${COMPOSE[@]}" exec -T web python manage.py migrate --plan

echo "[ui-v4] OK"