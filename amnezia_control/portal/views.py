from datetime import datetime

from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from audit.models import AuditLog
from audit.services import AuditService
from vpn.models import VPNClient
from vpn.services import VPNClientService

from .forms import PortalRenewalRequestForm
from .models import ClientRenewalRequest
from .services import PortalAccessService, PortalReissuePolicyService, PortalResolveReason, RenewalRequestService

PORTAL_TARGET_AMNEZIAWG = "amneziawg"
PORTAL_TARGET_AMNEZIAVPN = "amneziavpn"
PORTAL_TARGETS = {
    PORTAL_TARGET_AMNEZIAWG: {"label": "AmneziaWG", "suffix": "amneziawg"},
    PORTAL_TARGET_AMNEZIAVPN: {"label": "AmneziaVPN", "suffix": "amneziavpn"},
}


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


def _build_portal_status_block(*, open_renewal_request, latest_renewal_request):
    if open_renewal_request:
        if open_renewal_request.status == ClientRenewalRequest.Status.NEW:
            return {
                "title": "Заявка отправлена",
                "text": "Мы получили ваш запрос на продление. Оператор скоро начнёт обработку.",
                "variant": "info",
                "badge": "Ожидает обработки",
                "updated_at": open_renewal_request.created_at,
                "operator_note": (open_renewal_request.operator_note or "").strip(),
            }
        return {
            "title": "Заявка в работе",
            "text": "Оператор уже обрабатывает ваш запрос на продление.",
            "variant": "primary",
            "badge": "В работе",
            "updated_at": open_renewal_request.updated_at,
            "operator_note": (open_renewal_request.operator_note or "").strip(),
        }

    if not latest_renewal_request:
        return None

    if latest_renewal_request.status == ClientRenewalRequest.Status.DONE:
        return {
            "title": "Последняя заявка выполнена",
            "text": "Продление по последнему обращению уже завершено.",
            "variant": "success",
            "badge": "Выполнено",
            "updated_at": latest_renewal_request.processed_at or latest_renewal_request.updated_at,
            "operator_note": (latest_renewal_request.operator_note or "").strip(),
        }

    if latest_renewal_request.status == ClientRenewalRequest.Status.DISMISSED:
        return {
            "title": "Последняя заявка отклонена",
            "text": "Последний запрос на продление закрыт без выполнения.",
            "variant": "secondary",
            "badge": "Отклонено",
            "updated_at": latest_renewal_request.processed_at or latest_renewal_request.updated_at,
            "operator_note": (latest_renewal_request.operator_note or "").strip(),
        }

    return None


def _build_portal_history(*, access, client, limit: int = 8):
    timeline = []
    seen = set()

    def push(when, title: str, text: str):
        if not when:
            return
        dedupe_key = (title, text.strip(), when.replace(second=0, microsecond=0))
        if dedupe_key in seen:
            return
        seen.add(dedupe_key)
        timeline.append({"at": when, "title": title, "text": text.strip()})

    push(access.created_at, "Доступ к кабинету выдан", "Ссылка на кабинет клиента была выпущена.")

    audit_actions = {
        "portal.renewal.request": "Заявка на продление отправлена",
        "portal.renewal.in_progress": "Заявка передана в работу",
        "portal.renewal.done": "Заявка выполнена",
        "portal.renewal.extend_and_close": "Заявка выполнена",
        "portal.renewal.dismissed": "Заявка отклонена",
        "portal.config.reissue": "Конфигурация переиздана",
    }

    recent_audits = (
        AuditLog.objects.filter(entity_type="VPNClient", entity_id=str(client.id), action__in=audit_actions.keys())
        .order_by("-created_at")[:20]
    )
    for event in recent_audits:
        title = audit_actions.get(event.action)
        if not title:
            continue
        text = ""
        event_details = event.details or {}
        operator_note = event_details.get("operator_note") or ""
        if operator_note.strip():
            text = f"Комментарий оператора: {operator_note.strip()}"
        elif event.action == "portal.renewal.request":
            text = "Запрос уже передан оператору."
        elif event.action == "portal.renewal.in_progress":
            text = "Оператор начал обработку вашего обращения."
        elif event.action in {"portal.renewal.done", "portal.renewal.extend_and_close"}:
            text = "Продление по заявке завершено."
            new_expires_at = event_details.get("new_expires_at")
            if new_expires_at:
                try:
                    parsed = datetime.fromisoformat(new_expires_at)
                    if timezone.is_naive(parsed):
                        parsed = timezone.make_aware(parsed, timezone=timezone.get_current_timezone())
                    text = f"Доступ продлён до {timezone.localtime(parsed).strftime('%d.%m.%Y %H:%M')}."
                except ValueError:
                    text = "Продление по заявке завершено."
        elif event.action == "portal.renewal.dismissed":
            text = "По заявке принято решение об отклонении."
        elif event.action == "portal.config.reissue":
            text = "Конфигурация обновлена и готова к скачиванию."
        push(event.created_at, title, text)

    timeline.sort(key=lambda item: item["at"], reverse=True)
    return timeline[:limit]


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
    status_block = _build_portal_status_block(
        open_renewal_request=open_renewal_request,
        latest_renewal_request=latest_renewal_request,
    )
    if status_block and latest_renewal_request and latest_renewal_request.status == ClientRenewalRequest.Status.DONE and client.expires_at:
        status_block["expires_at"] = client.expires_at
    history_items = _build_portal_history(access=access, client=client)
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
            "status_block": status_block,
            "history_items": history_items,
            "can_selfservice_reissue": can_selfservice_reissue,
            "reissue_block_message": reissue_block_message,
            "reissue_cooldown_hours": PortalReissuePolicyService.COOLDOWN_HOURS,
            "renewal_form": PortalRenewalRequestForm(),
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

    target = request.GET.get("target", PORTAL_TARGET_AMNEZIAWG).strip().lower()
    if target not in PORTAL_TARGETS:
        target = PORTAL_TARGET_AMNEZIAWG

    config = VPNClientService.portal_export_config_for_target(client, target)
    response = HttpResponse(config, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = (
        f'attachment; filename="{client.name}-{client.protocol_type}-{PORTAL_TARGETS[target]["suffix"]}.conf"'
    )
    return response


@require_http_methods(["GET"])
def portal_qr_view(request, token: str):
    access, error_response = _resolve_access_or_error(request, token)
    if error_response:
        return error_response

    client = access.client
    target = request.GET.get("target", PORTAL_TARGET_AMNEZIAWG).strip().lower()
    if target not in PORTAL_TARGETS:
        target = PORTAL_TARGET_AMNEZIAWG
    qr_base64 = VPNClientService.portal_qr_png_base64_for_target(client, target) if client.revisions.exists() else ""
    return render(
        request,
        "portal/qr.html",
        {
            "token": token,
            "client": client,
            "qr_base64": qr_base64,
            "access": access,
            "target": target,
            "target_label": PORTAL_TARGETS[target]["label"],
        },
    )


@require_http_methods(["POST"])
def portal_request_renewal_view(request, token: str):
    access, error_response = _resolve_access_or_error(request, token)
    if error_response:
        return error_response

    form = PortalRenewalRequestForm(request.POST, request.FILES)
    if not form.is_valid():
        for errors in form.errors.values():
            for error in errors:
                messages.error(request, error)
        return redirect("portal-home", token=token)

    client = access.client
    open_request, created = RenewalRequestService.create_or_get_open_from_portal(
        client=client,
        attachment=form.cleaned_data.get("attachment"),
    )

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
            base_message = "Заявка уже отправлена и ожидает обработки."
        else:
            base_message = "Заявка уже в работе у оператора."

        submitted_attachment = form.cleaned_data.get("attachment")
        if submitted_attachment and open_request.attachment:
            messages.info(
                request,
                f"{base_message} В текущей заявке уже есть файл «{open_request.attachment_display_name}», новый файл не заменяет существующий.",
            )
        elif submitted_attachment and not open_request.attachment:
            messages.info(request, f"{base_message} Файл «{submitted_attachment.name}» добавлен к текущей заявке.")
        else:
            messages.info(request, base_message)

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
