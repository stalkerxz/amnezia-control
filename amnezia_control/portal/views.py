from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from audit.services import AuditService
from vpn.models import VPNClient
from vpn.services import VPNClientService

from .models import ClientRenewalRequest
from .services import PortalAccessService, PortalReissuePolicyService, PortalResolveReason, RenewalRequestService

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


def _render_access_error(request, reason: str, *, status: int = 404):
    reason_map = {
        PortalResolveReason.INVALID: {
            "title": "Ссылка недействительна",
            "message": "Ссылка на кабинет клиента некорректна или устарела.",
        },
        PortalResolveReason.REVOKED: {
            "title": "Ссылка отозвана",
            "message": "Доступ по этой ссылке был отозван оператором.",
        },
        PortalResolveReason.EXPIRED: {
            "title": "Срок действия ссылки истёк",
            "message": "Срок действия ссылки завершён. Запросите новую ссылку у оператора.",
        },
    }
    context = reason_map.get(reason, reason_map[PortalResolveReason.INVALID])
    context["reason"] = reason
    return render(request, "portal/access_error.html", context, status=status)


def _resolve_access_or_error(request, token: str):
    access, reason = PortalAccessService.resolve_token(token)
    if reason:
        return None, _render_access_error(request, reason)
    PortalAccessService.mark_accessed(access)
    return access, None


@require_http_methods(["GET"])
def portal_home_view(request, token: str):
    access, error_response = _resolve_access_or_error(request, token)
    if error_response:
        return error_response

    client = access.client
    limit_state = VPNClientService.get_limit_state(client)
    blocked = client.status != VPNClient.Status.ACTIVE or limit_state != VPNClient.LimitState.ACTIVE
    open_renewal_request = RenewalRequestService.get_open_for_client(client=client)
    latest_renewal_request = RenewalRequestService.get_latest_for_client(client=client)
    can_selfservice_reissue, reissue_block_message = PortalReissuePolicyService.can_selfservice_reissue(access=access)
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
            "open_renewal_request": open_renewal_request,
            "latest_renewal_request": latest_renewal_request,
            "can_selfservice_reissue": can_selfservice_reissue,
            "reissue_block_message": reissue_block_message,
            "reissue_cooldown_hours": PortalReissuePolicyService.COOLDOWN_HOURS,
        },
    )


@require_http_methods(["GET"])
def portal_download_config_view(request, token: str):
    access, error_response = _resolve_access_or_error(request, token)
    if error_response:
        return error_response

    client = access.client
    if not client.revisions.exists():
        messages.warning(request, "Конфигурация ещё не выпущена оператором.")
        return redirect("portal-home", token=token)

    config = VPNClientService.portal_export_config(client)
    response = HttpResponse(config, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{client.name}-{client.protocol_type}-amneziawg.conf"'
    return response


@require_http_methods(["GET"])
def portal_qr_view(request, token: str):
    access, error_response = _resolve_access_or_error(request, token)
    if error_response:
        return error_response

    client = access.client
    qr_base64 = VPNClientService.portal_qr_png_base64(client) if client.revisions.exists() else ""
    return render(request, "portal/qr.html", {"token": token, "client": client, "qr_base64": qr_base64, "access": access})


@require_http_methods(["POST"])
def portal_request_renewal_view(request, token: str):
    access, error_response = _resolve_access_or_error(request, token)
    if error_response:
        return error_response

    client = access.client
    open_request, created = RenewalRequestService.create_or_get_open_from_portal(client=client)

    if created:
        AuditService.log(
            actor=None,
            action="portal.renewal.request",
            entity_type="VPNClient",
            entity_id=str(client.id),
            details={
                "portal_access_id": access.id,
                "renewal_request_id": open_request.id,
                "requested_at": timezone.now().isoformat(),
                "ip": request.META.get("REMOTE_ADDR", ""),
                "user_agent": request.META.get("HTTP_USER_AGENT", "")[:255],
            },
        )
        messages.success(request, "Заявка на продление отправлена. Мы уже передали её оператору.")
    else:
        if open_request.status == ClientRenewalRequest.Status.NEW:
            messages.info(request, "Заявка уже отправлена и ожидает обработки.")
        else:
            messages.info(request, "Заявка уже в работе у оператора.")

    return redirect("portal-home", token=token)


@require_http_methods(["POST"])
def portal_reissue_config_view(request, token: str):
    access, error_response = _resolve_access_or_error(request, token)
    if error_response:
        return error_response

    if (request.POST.get("confirm_reissue") or "") != "1":
        messages.warning(request, "Подтвердите переиздание конфигурации.")
        return redirect("portal-home", token=token)

    can_selfservice_reissue, block_message = PortalReissuePolicyService.can_selfservice_reissue(access=access)
    if not can_selfservice_reissue:
        messages.warning(request, block_message)
        return redirect("portal-home", token=token)

    client = access.client
    try:
        VPNClientService.reissue_config(client=client, actor=None)
    except Exception:
        messages.error(request, "Не удалось переиздать конфигурацию. Попробуйте позже или обратитесь к оператору.")
        return redirect("portal-home", token=token)

    access.last_selfservice_reissue_at = timezone.now()
    access.save(update_fields=["last_selfservice_reissue_at"])
    AuditService.log(
        actor=None,
        action="portal.config.reissue",
        entity_type="VPNClient",
        entity_id=str(client.id),
        details={
            "portal_access_id": access.id,
            "performed_at": timezone.now().isoformat(),
            "ip": request.META.get("REMOTE_ADDR", ""),
            "user_agent": request.META.get("HTTP_USER_AGENT", "")[:255],
            "cooldown_hours": PortalReissuePolicyService.COOLDOWN_HOURS,
        },
    )
    messages.success(
        request,
        "Готово. Новая конфигурация уже выпущена. Скачайте её заново или откройте новый QR-код. Предыдущая конфигурация больше не действует.",
    )
    return redirect("portal-home", token=token)
