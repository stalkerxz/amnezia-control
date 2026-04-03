from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Q
from django.db.models.functions import Coalesce
from django.http import HttpResponse
from django.urls import reverse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
import ipaddress

from audit.models import AuditLog
from jobs.models import Job
from servers.models import Server, ServerProtocol
from .forms import VPNClientBulkLimitsUpdateForm, VPNClientCreateForm, VPNClientLimitsUpdateForm, VPNClientListFilterForm
from .models import VPNClient
from .services import VPNClientService


def _admin_required(user):
    return user.is_authenticated and user.is_staff


def _limit_state_badge(limit_state: str):
    if limit_state == VPNClient.LimitState.EXPIRED:
        return "text-bg-warning", "Истек"
    if limit_state == VPNClient.LimitState.TRAFFIC_EXCEEDED:
        return "text-bg-danger", "Трафик превышен"
    return "text-bg-success", "Активен"


def _fmt_bytes(value: int | None):
    if value is None:
        return "—"
    units = ["Б", "КБ", "МБ", "ГБ", "ТБ"]
    size = float(max(value, 0))
    unit = units[0]
    for u in units:
        unit = u
        if size < 1024.0:
            break
        if u != units[-1]:
            size /= 1024.0
    if unit == "Б":
        return f"{int(size)} {unit}"
    return f"{size:.2f} {unit}"


def _normalize_runtime_address(value: str) -> str:
    if not value:
        return "—"
    normalized = []
    for token in value.split(","):
        part = token.strip()
        if not part:
            continue
        if "/" in part:
            normalized.append(part)
            continue
        try:
            normalized.append(f"{ipaddress.ip_address(part)}/32")
        except ValueError:
            normalized.append(part)
    return ", ".join(normalized) if normalized else "—"


def _is_awg2_degraded_telemetry(peer_source: str) -> bool:
    source = (peer_source or "").lower()
    return "config file fallback" in source and "degraded telemetry" in source


def _telemetry_view_state(*, client: VPNClient, peer_source: str):
    degraded_awg2 = client.protocol_type == VPNClient.ProtocolType.AWG2 and _is_awg2_degraded_telemetry(peer_source)
    if degraded_awg2:
        return {
            "is_unavailable": True,
            "is_degraded": True,
            "status_label": "Runtime-опрос недоступен",
            "status_class": "text-warning",
            "details": "Используется fallback. Peers читаются из конфигурации, поэтому live-счётчики трафика сейчас недоступны.",
            "badge_label": "Fallback-режим",
        }
    if client.traffic_sync_error:
        return {
            "is_unavailable": True,
            "is_degraded": False,
            "status_label": "Ошибка",
            "status_class": "text-danger",
            "details": client.traffic_sync_error,
            "badge_label": "Телеметрия недоступна",
        }
    if client.traffic_last_sync_at:
        return {
            "is_unavailable": False,
            "is_degraded": False,
            "status_label": "Успешно",
            "status_class": "text-success",
            "details": timezone.localtime(client.traffic_last_sync_at).strftime("%d.%m.%Y %H:%M"),
            "badge_label": "",
        }
    return {
        "is_unavailable": False,
        "is_degraded": False,
        "status_label": "Нет данных",
        "status_class": "text-secondary",
        "details": "Данные ещё не синхронизированы",
        "badge_label": "",
    }


@login_required
@user_passes_test(_admin_required)
def clients_list_view(request):
    filter_form = VPNClientListFilterForm(request.GET or None)
    clients = (
        VPNClient.objects.select_related("server", "created_by")
        .annotate(updated_at=Coalesce("last_runtime_sync_at", "created_at"))
        .order_by("-id")
    )

    if filter_form.is_valid():
        q = filter_form.cleaned_data["q"].strip()
        protocol = filter_form.cleaned_data["protocol"]
        status = filter_form.cleaned_data["status"]
        source = filter_form.cleaned_data["source"]
        quick = filter_form.cleaned_data["quick"]
        operator_scope = filter_form.cleaned_data["operator_scope"] or VPNClientListFilterForm.OPERATOR_SCOPE_ALL

        if q:
            clients = clients.filter(name__icontains=q)
        if protocol:
            clients = clients.filter(protocol_type=protocol)
        if status == VPNClientListFilterForm.STATUS_ALL:
            pass
        elif status:
            clients = clients.filter(status=status)
        else:
            clients = clients.exclude(status=VPNClient.Status.DELETED)
        if source == "imported":
            clients = clients.filter(imported_from_runtime=True)
        elif source == "manual":
            clients = clients.filter(imported_from_runtime=False)
        if operator_scope == VPNClientListFilterForm.OPERATOR_SCOPE_MINE:
            clients = clients.filter(created_by=request.user)

        if quick == VPNClientListFilterForm.QUICK_ACTIVE:
            clients = clients.filter(status=VPNClient.Status.ACTIVE)
        elif quick == VPNClientListFilterForm.QUICK_DISABLED:
            clients = clients.filter(status=VPNClient.Status.DISABLED)
        elif quick == VPNClientListFilterForm.QUICK_EXPIRED:
            clients = clients.filter(limit_state=VPNClient.LimitState.EXPIRED).exclude(status=VPNClient.Status.DELETED)
        elif quick == VPNClientListFilterForm.QUICK_TRAFFIC_EXCEEDED:
            clients = clients.filter(limit_state=VPNClient.LimitState.TRAFFIC_EXCEEDED).exclude(status=VPNClient.Status.DELETED)
        elif quick == VPNClientListFilterForm.QUICK_DELETED:
            clients = clients.filter(status=VPNClient.Status.DELETED)
    else:
        clients = clients.exclude(status=VPNClient.Status.DELETED)

    protocol_map = {
        (protocol.server_id, protocol.protocol_type): protocol
        for protocol in ServerProtocol.objects.filter(server_id__in={client.server_id for client in clients})
    }

    client_ids = [str(client.id) for client in clients]
    recent_client_logs = (
        AuditLog.objects.select_related("actor")
        .filter(entity_type="VPNClient", entity_id__in=client_ids)
        .order_by("entity_id", "-created_at")
    )
    latest_log_by_client_id = {}
    for log in recent_client_logs:
        latest_log_by_client_id.setdefault(log.entity_id, log)

    client_rows = []
    for client in clients:
        badge_class, badge_label = _limit_state_badge(client.limit_state)
        protocol = protocol_map.get((client.server_id, client.protocol_type))
        telemetry_state = _telemetry_view_state(client=client, peer_source=(protocol.runtime_metadata or {}).get("peer_source", "") if protocol else "")
        client_rows.append(
            {
                "client": client,
                "latest_audit_log": latest_log_by_client_id.get(str(client.id)),
                "limit_badge_class": badge_class,
                "limit_badge_label": badge_label,
                "expires_display": timezone.localtime(client.expires_at).strftime("%d.%m.%Y %H:%M") if client.expires_at else "—",
                "traffic_used_display": _fmt_bytes(client.traffic_used_bytes),
                "traffic_limit_display": _fmt_bytes(client.traffic_limit_bytes),
                "runtime_address_display": _normalize_runtime_address(client.runtime_address),
                "telemetry": telemetry_state,
            }
        )

    server = Server.objects.filter(is_enabled=True).first()
    quick_filters = [
        (VPNClientListFilterForm.QUICK_ACTIVE, "Активные"),
        (VPNClientListFilterForm.QUICK_DISABLED, "Отключённые"),
        (VPNClientListFilterForm.QUICK_EXPIRED, "Просроченные"),
        (VPNClientListFilterForm.QUICK_TRAFFIC_EXCEEDED, "Трафик превышен"),
        (VPNClientListFilterForm.QUICK_DELETED, "Удалённые"),
    ]
    current_quick = filter_form.cleaned_data["quick"] if filter_form.is_valid() else ""
    quick_filter_links = []
    for key, label in quick_filters:
        query = request.GET.copy()
        query["quick"] = key
        quick_filter_links.append(
            {
                "key": key,
                "label": label,
                "active": current_quick == key,
                "url": f'{reverse("clients-list")}?{query.urlencode()}',
            }
        )

    return render(
        request,
        "vpn/clients_list.html",
        {
            "client_rows": client_rows,
            "filter_form": filter_form,
            "server": server,
            "quick_filter_links": quick_filter_links,
        },
    )


@login_required
@user_passes_test(_admin_required)
def clients_import_view(request):
    server = Server.objects.filter(is_enabled=True).first()
    if not server:
        messages.error(request, "Сервер не настроен")
        return redirect("clients-list")
    if request.method == "POST":
        imported = VPNClientService.import_runtime_peers(server=server, actor=request.user)
        messages.success(request, f"Импортировано клиентов: {imported}")
    return redirect("clients-list")


@login_required
@user_passes_test(_admin_required)
def clients_create_view(request):
    server = Server.objects.filter(is_enabled=True).first()
    if not server:
        messages.error(request, "Сервер не настроен")
        return redirect("clients-list")

    if request.method == "POST":
        form = VPNClientCreateForm(request.POST)
        if form.is_valid():
            try:
                client = VPNClientService.create_client(
                    server=server,
                    name=form.cleaned_data["name"],
                    protocol_type=form.cleaned_data["protocol_type"],
                    expires_at=form.cleaned_data["expires_at"],
                    traffic_limit_bytes=form.cleaned_data["traffic_limit_bytes"],
                    actor=request.user,
                )
                messages.success(request, "Клиент создан")
                return redirect("clients-detail", pk=client.id)
            except Exception as exc:
                messages.error(request, f"Ошибка создания клиента: {exc}")
    else:
        form = VPNClientCreateForm()
    return render(request, "vpn/clients_create.html", {"form": form})


@login_required
@user_passes_test(_admin_required)
def clients_detail_view(request, pk: int):
    client = get_object_or_404(VPNClient.objects.select_related("server"), pk=pk)
    limits_form = VPNClientLimitsUpdateForm(client=client)
    revision = client.revisions.first()
    revision_count = client.revisions.count()
    qr_base64 = VPNClientService.qr_png_base64(client) if revision else ""

    protocol = client.server.protocols.filter(protocol_type=client.protocol_type).first()
    missing_endpoint = False
    missing_awg2_metadata = False
    if protocol:
        host_candidates = [
            client.server.public_endpoint_host,
            client.server.host,
            protocol.runtime_metadata.get("public_host", ""),
        ]
        host = next((h for h in host_candidates if VPNClientService._is_public_endpoint_host(h)), "")
        port = client.server.public_endpoint_port or protocol.runtime_metadata.get("udp_port")
        missing_endpoint = not (host and port)
        if client.protocol_type == VPNClient.ProtocolType.AWG2:
            required = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")
            awg2_metadata = protocol.runtime_metadata.get("awg2_metadata", {})
            missing_awg2_metadata = any(not awg2_metadata.get(k) for k in required)
    else:
        missing_endpoint = True
        missing_awg2_metadata = client.protocol_type == VPNClient.ProtocolType.AWG2

    telemetry_state = _telemetry_view_state(
        client=client,
        peer_source=(protocol.runtime_metadata or {}).get("peer_source", "") if protocol else "",
    )

    effective_limit_state = VPNClientService.get_limit_state(client)
    limit_badge_class, limit_badge_label = _limit_state_badge(effective_limit_state)
    reissue_blocked = effective_limit_state in {VPNClient.LimitState.EXPIRED, VPNClient.LimitState.TRAFFIC_EXCEEDED}
    reissue_block_reason = ""
    if effective_limit_state == VPNClient.LimitState.EXPIRED:
        reissue_block_reason = "Переиздание недоступно: срок действия клиента истек."
    elif effective_limit_state == VPNClient.LimitState.TRAFFIC_EXCEEDED:
        reissue_block_reason = "Переиздание недоступно: превышен лимит трафика."

    warning_items = []
    if effective_limit_state == VPNClient.LimitState.EXPIRED:
        warning_items.append("Срок действия клиента истёк.")
    if effective_limit_state == VPNClient.LimitState.TRAFFIC_EXCEEDED:
        warning_items.append("Клиент превысил лимит трафика.")
    if client.status == VPNClient.Status.DELETED:
        warning_items.append("Клиент находится в состоянии «Удалён» (soft delete).")
    if not client.runtime_peer_public_key:
        warning_items.append("В runtime не найден public key peer-клиента.")
    if telemetry_state["is_degraded"]:
        warning_items.append("Runtime-опрос недоступен. Используется fallback, peers читаются из конфигурации.")
    elif client.traffic_sync_error:
        warning_items.append("Телеметрия трафика недоступна.")
    if not revision:
        warning_items.append("Для клиента отсутствует выпущенная ревизия конфига.")

    recent_audit_logs = AuditLog.objects.select_related("actor").filter(entity_type="VPNClient", entity_id=str(client.id)).order_by("-created_at")[:5]
    latest_operator_action = recent_audit_logs[0] if recent_audit_logs else None

    client_job_filters = Q(action__icontains="client")
    if client.runtime_peer_public_key:
        client_job_filters |= Q(payload__command__icontains=client.runtime_peer_public_key)
    if client.runtime_address:
        client_job_filters |= Q(payload__command__icontains=client.runtime_address)

    recent_jobs = list(
        Job.objects.select_related("server", "actor")
        .filter(server=client.server)
        .filter(client_job_filters)
        .order_by("-created_at")[:5]
    )
    if not recent_jobs:
        recent_jobs = list(Job.objects.select_related("server", "actor").filter(server=client.server).order_by("-created_at")[:5])

    return render(
        request,
        "vpn/clients_detail.html",
        {
            "client": client,
            "revision": revision,
            "revision_count": revision_count,
            "qr_base64": qr_base64,
            "missing_endpoint": missing_endpoint,
            "missing_awg2_metadata": missing_awg2_metadata,
            "expires_display": timezone.localtime(client.expires_at).strftime("%d.%m.%Y %H:%M") if client.expires_at else "Не задано",
            "traffic_used_display": _fmt_bytes(client.traffic_used_bytes),
            "traffic_limit_display": _fmt_bytes(client.traffic_limit_bytes),
            "traffic_usage_unavailable": telemetry_state["is_unavailable"],
            "telemetry": telemetry_state,
            "runtime_address_display": _normalize_runtime_address(client.runtime_address),
            "limit_badge_class": limit_badge_class,
            "limit_badge_label": limit_badge_label,
            "reissue_blocked": reissue_blocked,
            "reissue_block_reason": reissue_block_reason,
            "limits_form": limits_form,
            "is_deleted": client.status == VPNClient.Status.DELETED,
            "warning_items": warning_items,
            "recent_audit_logs": recent_audit_logs,
            "latest_operator_action": latest_operator_action,
            "recent_jobs": recent_jobs,
        },
    )


@login_required
@user_passes_test(_admin_required)
def client_qr_modal_view(request, pk: int):
    client = get_object_or_404(VPNClient, pk=pk)
    revision = client.revisions.first()
    qr_base64 = VPNClientService.qr_png_base64(client) if revision else ""
    return render(
        request,
        "vpn/partials/client_qr_modal_body.html",
        {
            "client": client,
            "revision": revision,
            "qr_base64": qr_base64,
        },
    )


@login_required
@user_passes_test(_admin_required)
def client_action_view(request, pk: int, action: str):
    client = get_object_or_404(VPNClient, pk=pk)
    if request.method != "POST":
        return redirect("clients-detail", pk=client.id)

    next_url = request.POST.get("next")

    try:
        success_message = "Действие выполнено"
        if action == "disable":
            VPNClientService.set_status(client=client, status=VPNClient.Status.DISABLED, actor=request.user)
        elif action == "enable":
            VPNClientService.set_status(client=client, status=VPNClient.Status.ACTIVE, actor=request.user)
            success_message = "Клиент включен"
        elif action == "restore":
            if client.status != VPNClient.Status.DELETED:
                messages.warning(request, "Восстановление доступно только для удалённых клиентов.")
                return redirect("clients-detail", pk=client.id)
            VPNClientService.set_status(
                client=client,
                status=VPNClient.Status.DISABLED,
                actor=request.user,
                disable_reason=VPNClient.DisableReason.MANUAL,
            )
            success_message = "Клиент восстановлен в состояние «Отключён»"
        elif action == "delete":
            VPNClientService.set_status(client=client, status=VPNClient.Status.DELETED, actor=request.user)
            success_message = "Клиент помечен как удаленный и скрыт из основного списка"
        elif action == "reissue":
            VPNClientService.reissue_config(client=client, actor=request.user)
        messages.success(request, success_message)
    except Exception as exc:
        messages.error(request, f"Ошибка выполнения действия: {exc}")

    if next_url:
        return redirect(next_url)
    if action == "delete":
        return redirect("clients-list")
    return redirect("clients-detail", pk=client.id)


@login_required
@user_passes_test(_admin_required)
def clients_bulk_action_view(request):
    if request.method != "POST":
        return redirect("clients-list")

    action = request.POST.get("action", "")
    selected_ids = [int(value) for value in request.POST.getlist("client_ids") if str(value).isdigit()]
    next_url = request.POST.get("next") or reverse("clients-list")

    if not selected_ids:
        messages.warning(request, "Выберите хотя бы одного клиента.")
        return redirect(next_url)

    clients = list(VPNClient.objects.filter(id__in=selected_ids))
    if not clients:
        messages.warning(request, "Выбранные клиенты не найдены.")
        return redirect(next_url)

    if action == "limits":
        form = VPNClientBulkLimitsUpdateForm(request.POST)
        if not form.is_valid():
            messages.error(request, "Проверьте форму массового изменения лимитов.")
            return redirect(next_url)

        apply_expires = form.cleaned_data["apply_expires"]
        apply_traffic = form.cleaned_data["apply_traffic"]
        resolved_expires_at = form.cleaned_data.get("resolved_expires_at")
        resolved_traffic_limit_bytes = form.cleaned_data.get("resolved_traffic_limit_bytes")

        updated = 0
        skipped_deleted = 0
        for client in clients:
            if client.status == VPNClient.Status.DELETED:
                skipped_deleted += 1
                continue
            try:
                VPNClientService.update_limits(
                    client=client,
                    expires_at=(
                        resolved_expires_at
                        if apply_expires == VPNClientBulkLimitsUpdateForm.APPLY_SET
                        else None
                        if apply_expires == VPNClientBulkLimitsUpdateForm.APPLY_CLEAR
                        else client.expires_at
                    ),
                    traffic_limit_bytes=(
                        resolved_traffic_limit_bytes
                        if apply_traffic == VPNClientBulkLimitsUpdateForm.APPLY_SET
                        else None
                        if apply_traffic == VPNClientBulkLimitsUpdateForm.APPLY_CLEAR
                        else client.traffic_limit_bytes
                    ),
                    actor=request.user,
                )
                updated += 1
            except Exception:
                continue

        if updated:
            msg = f"Лимиты обновлены для {updated} клиент(ов) без переиздания конфига."
            if skipped_deleted:
                msg += f" Удалённые пропущены: {skipped_deleted}."
            messages.success(request, msg)
        else:
            messages.error(request, "Не удалось обновить лимиты для выбранных клиентов.")
        return redirect(next_url)

    applied = 0
    skipped = 0
    failed = 0
    for client in clients:
        try:
            if action == "disable":
                VPNClientService.set_status(client=client, status=VPNClient.Status.DISABLED, actor=request.user)
            elif action == "enable":
                VPNClientService.set_status(client=client, status=VPNClient.Status.ACTIVE, actor=request.user)
            elif action == "restore":
                if client.status != VPNClient.Status.DELETED:
                    skipped += 1
                    continue
                VPNClientService.set_status(
                    client=client,
                    status=VPNClient.Status.DISABLED,
                    actor=request.user,
                    disable_reason=VPNClient.DisableReason.MANUAL,
                )
            elif action == "delete":
                VPNClientService.set_status(client=client, status=VPNClient.Status.DELETED, actor=request.user)
            elif action == "reissue":
                VPNClientService.reissue_config(client=client, actor=request.user)
            else:
                messages.error(request, "Неизвестное массовое действие.")
                return redirect(next_url)
            applied += 1
        except Exception:
            failed += 1
            continue

    action_labels = {
        "disable": "отключено",
        "enable": "включено",
        "restore": "восстановлено",
        "delete": "помечено удалёнными",
        "reissue": "переиздано",
    }
    if applied:
        message = f"Массовое действие выполнено: {action_labels[action]} — {applied} шт."
        if action == "restore" and skipped:
            message += f" Пропущены не удалённые: {skipped}."
        if failed:
            message += f" Ошибки восстановления: {failed}." if action == "restore" else f" Ошибки: {failed}."
        messages.success(request, message)
    else:
        if action == "restore" and skipped:
            messages.warning(request, f"Нечего восстанавливать: выбраны только не удалённые клиенты ({skipped}).")
        else:
            messages.error(request, "Не удалось выполнить массовое действие для выбранных клиентов.")
    return redirect(next_url)


@login_required
@user_passes_test(_admin_required)
def client_download_config_view(request, pk: int):
    client = get_object_or_404(VPNClient, pk=pk)
    config = VPNClientService.latest_config(client)
    response = HttpResponse(config, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{client.name}-{client.protocol_type}-amneziavpn.conf"'
    return response


@login_required
@user_passes_test(_admin_required)
def client_download_native_config_view(request, pk: int):
    client = get_object_or_404(VPNClient, pk=pk)
    config = VPNClientService.build_native_client_config(client)
    response = HttpResponse(config, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{client.name}-{client.protocol_type}-amneziawg.conf"'
    return response


@login_required
@user_passes_test(_admin_required)
def client_update_limits_view(request, pk: int):
    client = get_object_or_404(VPNClient, pk=pk)
    if request.method != "POST":
        return redirect("clients-detail", pk=client.id)

    form = VPNClientLimitsUpdateForm(request.POST, client=client)
    if not form.is_valid():
        messages.error(request, "Проверьте форму изменения лимитов.")
        return redirect("clients-detail", pk=client.id)

    VPNClientService.update_limits(
        client=client,
        expires_at=form.cleaned_data["expires_at"],
        traffic_limit_bytes=form.cleaned_data["traffic_limit_bytes"],
        actor=request.user,
    )
    messages.success(request, "Лимиты клиента обновлены без переиздания конфига.")
    return redirect("clients-detail", pk=client.id)
