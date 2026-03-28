from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models.functions import Coalesce
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from servers.models import Server
from .forms import VPNClientCreateForm, VPNClientListFilterForm
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


@login_required
@user_passes_test(_admin_required)
def clients_list_view(request):
    filter_form = VPNClientListFilterForm(request.GET or None)
    clients = (
        VPNClient.objects.select_related("server")
        .annotate(updated_at=Coalesce("last_runtime_sync_at", "created_at"))
        .order_by("-id")
    )

    if filter_form.is_valid():
        q = filter_form.cleaned_data["q"].strip()
        protocol = filter_form.cleaned_data["protocol"]
        status = filter_form.cleaned_data["status"]
        source = filter_form.cleaned_data["source"]

        if q:
            clients = clients.filter(name__icontains=q)
        if protocol:
            clients = clients.filter(protocol_type=protocol)
        if status:
            clients = clients.filter(status=status)
        if source == "imported":
            clients = clients.filter(imported_from_runtime=True)
        elif source == "manual":
            clients = clients.filter(imported_from_runtime=False)

    client_rows = []
    for client in clients:
        badge_class, badge_label = _limit_state_badge(client.limit_state)
        client_rows.append(
            {
                "client": client,
                "limit_badge_class": badge_class,
                "limit_badge_label": badge_label,
                "expires_display": timezone.localtime(client.expires_at).strftime("%d.%m.%Y %H:%M") if client.expires_at else "—",
                "traffic_used_display": _fmt_bytes(client.traffic_used_bytes),
                "traffic_limit_display": _fmt_bytes(client.traffic_limit_bytes),
            }
        )

    server = Server.objects.filter(is_enabled=True).first()
    return render(
        request,
        "vpn/clients_list.html",
        {
            "client_rows": client_rows,
            "filter_form": filter_form,
            "server": server,
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

    limit_badge_class, limit_badge_label = _limit_state_badge(client.limit_state)
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
            "traffic_usage_unavailable": bool(client.traffic_sync_error),
            "limit_badge_class": limit_badge_class,
            "limit_badge_label": limit_badge_label,
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
        if action == "disable":
            VPNClientService.set_status(client=client, status=VPNClient.Status.DISABLED, actor=request.user)
        elif action == "enable":
            VPNClientService.set_status(client=client, status=VPNClient.Status.ACTIVE, actor=request.user)
        elif action == "delete":
            VPNClientService.set_status(client=client, status=VPNClient.Status.DELETED, actor=request.user)
        elif action == "reissue":
            VPNClientService.reissue_config(client=client, actor=request.user)
        messages.success(request, "Действие выполнено")
    except Exception as exc:
        messages.error(request, f"Ошибка выполнения действия: {exc}")

    if next_url:
        return redirect(next_url)
    return redirect("clients-detail", pk=client.id)


@login_required
@user_passes_test(_admin_required)
def client_download_config_view(request, pk: int):
    client = get_object_or_404(VPNClient, pk=pk)
    config = VPNClientService.latest_config(client)
    response = HttpResponse(config, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{client.name}-{client.protocol_type}.conf"'
    return response
