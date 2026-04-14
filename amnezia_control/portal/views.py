from django.contrib import messages
from django.http import Http404, HttpResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from audit.services import AuditService
from vpn.models import VPNClient
from vpn.services import VPNClientService

from .services import PortalAccessService


def _fmt_bytes(value: int | None):
    if value is None:
        return "—"
    units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
    size = float(max(value, 0))
    unit = units[0]
    for item in units:
        unit = item
        if size < 1024.0:
            break
        if item != units[-1]:
            size /= 1024.0
    if unit == "Б":
        return f"{int(size)} {unit}"
    return f"{size:.2f} {unit}"


def _resolve_access(token: str):
    access = PortalAccessService.resolve_token(token)
    if not access:
        raise Http404("Portal access not found")
    PortalAccessService.mark_accessed(access)
    return access


@require_http_methods(["GET"])
def portal_home_view(request, token: str):
    access = _resolve_access(token)
    client = access.client
    limit_state = VPNClientService.get_limit_state(client)
    blocked = client.status != VPNClient.Status.ACTIVE or limit_state != VPNClient.LimitState.ACTIVE
    return render(
        request,
        "portal/home.html",
        {
            "token": token,
            "access": access,
            "client": client,
            "limit_state": limit_state,
            "blocked": blocked,
            "traffic_used_display": _fmt_bytes(client.traffic_used_bytes),
            "traffic_limit_display": _fmt_bytes(client.traffic_limit_bytes),
        },
    )


@require_http_methods(["GET"])
def portal_download_config_view(request, token: str):
    access = _resolve_access(token)
    client = access.client
    if not client.revisions.exists():
        raise Http404("Config is not issued yet")
    config = VPNClientService.latest_config(client)
    response = HttpResponse(config, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{client.name}-{client.protocol_type}-amneziavpn.conf"'
    return response


@require_http_methods(["GET"])
def portal_qr_view(request, token: str):
    access = _resolve_access(token)
    client = access.client
    qr_base64 = VPNClientService.qr_png_base64(client) if client.revisions.exists() else ""
    return render(request, "portal/qr.html", {"token": token, "client": client, "qr_base64": qr_base64})


@require_http_methods(["POST"])
def portal_request_renewal_view(request, token: str):
    access = _resolve_access(token)
    client = access.client
    AuditService.log(
        actor=None,
        action="portal.renewal.request",
        entity_type="VPNClient",
        entity_id=str(client.id),
        details={
            "portal_access_id": access.id,
            "requested_at": timezone.now().isoformat(),
            "ip": request.META.get("REMOTE_ADDR", ""),
            "user_agent": request.META.get("HTTP_USER_AGENT", "")[:255],
        },
    )
    messages.success(request, "Запрос на продление отправлен оператору. Ожидайте обратной связи.")
    return redirect("portal-home", token=token)
