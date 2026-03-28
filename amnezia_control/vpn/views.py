from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Count, Max
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from servers.models import Server
from .forms import VPNClientCreateForm
from .models import VPNClient
from .services import VPNClientService


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def clients_list_view(request):
    q = request.GET.get("q", "").strip()
    protocol = request.GET.get("protocol", "").strip()
    status = request.GET.get("status", "").strip()
    source = request.GET.get("source", "").strip()

    clients = (
        VPNClient.objects.select_related("server")
        .annotate(last_revision_at=Max("revisions__created_at"), revisions_total=Count("revisions"))
        .order_by("-created_at")
    )
    if q:
        clients = clients.filter(name__icontains=q)
    if protocol in {choice[0] for choice in VPNClient.ProtocolType.choices}:
        clients = clients.filter(protocol_type=protocol)
    if status in {choice[0] for choice in VPNClient.Status.choices}:
        clients = clients.filter(status=status)
    if source == "imported":
        clients = clients.filter(imported_from_runtime=True)
    elif source == "manual":
        clients = clients.filter(imported_from_runtime=False)

    filters = {
        "q": q,
        "protocol": protocol,
        "status": status,
        "source": source,
    }

    return render(
        request,
        "vpn/clients_list.html",
        {
            "clients": clients,
            "filters": filters,
            "protocol_choices": VPNClient.ProtocolType.choices,
            "status_choices": VPNClient.Status.choices,
        },
    )


@login_required
@user_passes_test(_admin_required)
def clients_import_view(request):
    server_id = request.GET.get("server") or request.POST.get("server")
    server = None
    if server_id:
        server = Server.objects.filter(pk=server_id, is_enabled=True).first()
    if not server:
        server = Server.objects.filter(is_enabled=True).first()

    if not server:
        messages.error(request, "Нет доступного сервера для импорта peers.")
        return redirect("clients-list")

    if request.method == "POST":
        imported = VPNClientService.import_runtime_peers(server=server, actor=request.user)
        messages.success(request, f"Импорт runtime peers завершен. Добавлено клиентов: {imported}.")
    return redirect("clients-list")


@login_required
@user_passes_test(_admin_required)
def clients_create_view(request):
    servers_qs = Server.objects.filter(is_enabled=True).order_by("name")
    selected_server_id = request.GET.get("server") or request.POST.get("server")
    selected_server = servers_qs.filter(pk=selected_server_id).first() if selected_server_id else servers_qs.first()

    if not selected_server:
        messages.error(request, "Сначала добавьте и включите сервер.")
        return redirect("clients-list")

    initial_protocol = request.GET.get("protocol")

    if request.method == "POST":
        form = VPNClientCreateForm(request.POST)
        if form.is_valid():
            try:
                client = VPNClientService.create_client(
                    server=selected_server,
                    name=form.cleaned_data["name"],
                    protocol_type=form.cleaned_data["protocol_type"],
                    actor=request.user,
                )
                messages.success(request, "Клиент создан и конфиг выпущен.")
                return redirect("clients-detail", pk=client.id)
            except Exception as exc:
                messages.error(request, f"Не удалось создать клиента: {exc}")
    else:
        initial = {"protocol_type": initial_protocol} if initial_protocol else None
        form = VPNClientCreateForm(initial=initial)

    return render(
        request,
        "vpn/clients_create.html",
        {
            "form": form,
            "selected_server": selected_server,
            "servers": servers_qs,
            "selected_server_id": str(selected_server.id),
        },
    )


@login_required
@user_passes_test(_admin_required)
def clients_detail_view(request, pk: int):
    client = get_object_or_404(VPNClient.objects.select_related("server", "created_by"), pk=pk)
    revisions = client.revisions.all()
    revision = revisions.first()
    qr_base64 = VPNClientService.qr_png_base64(client) if revision else ""

    blockers = []
    if client.status == VPNClient.Status.DELETED:
        blockers.append("Клиент помечен как удаленный. Доступны только просмотр и аудит изменений.")
    if not client.runtime_address:
        blockers.append("Runtime address отсутствует. Выполните перевыпуск конфига.")
    if not revision:
        blockers.append("Конфиг еще не выпущен. Нажмите «Перевыпустить конфиг».")
    protocol = client.server.protocols.filter(protocol_type=client.protocol_type).first()
    if protocol:
        if not protocol.runtime_metadata.get("endpoint_host_ready", False):
            blockers.append("Публичный endpoint host не готов. Проверьте сервер и выполните runtime sync.")
        if not protocol.runtime_metadata.get("endpoint_port_ready", False):
            blockers.append("UDP endpoint port не определен. Проверьте настройки endpoint и runtime sync.")
    if client.protocol_type == VPNClient.ProtocolType.AWG2:
        if protocol and not protocol.runtime_metadata.get("awg2_metadata_ready", False):
            blockers.append("AWG2 metadata неполная — runtime sync обязателен до выпуска AWG2 конфигов.")

    return render(
        request,
        "vpn/clients_detail.html",
        {
            "client": client,
            "revision": revision,
            "revisions_count": revisions.aggregate(total=Count("id")).get("total") or 0,
            "latest_revision_at": revision.created_at if revision else None,
            "qr_base64": qr_base64,
            "blockers": blockers,
        },
    )


@login_required
@user_passes_test(_admin_required)
def client_action_view(request, pk: int, action: str):
    client = get_object_or_404(VPNClient, pk=pk)
    if request.method != "POST":
        return redirect("clients-detail", pk=client.id)

    try:
        if action == "disable":
            VPNClientService.set_status(client=client, status=VPNClient.Status.DISABLED, actor=request.user)
            messages.success(request, "Клиент отключен.")
        elif action == "enable":
            VPNClientService.set_status(client=client, status=VPNClient.Status.ACTIVE, actor=request.user)
            messages.success(request, "Клиент снова активен.")
        elif action == "delete":
            VPNClientService.set_status(client=client, status=VPNClient.Status.DELETED, actor=request.user)
            messages.success(request, "Клиент помечен как удаленный.")
        elif action == "reissue":
            VPNClientService.reissue_config(client=client, actor=request.user)
            messages.success(request, "Конфиг успешно перевыпущен.")
        else:
            messages.error(request, "Неизвестное действие.")
    except Exception as exc:
        messages.error(request, f"Ошибка выполнения действия: {exc}")
    return redirect("clients-detail", pk=client.id)


@login_required
@user_passes_test(_admin_required)
def client_download_config_view(request, pk: int):
    client = get_object_or_404(VPNClient, pk=pk)
    config = VPNClientService.latest_config(client)
    response = HttpResponse(config, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{client.name}-{client.protocol_type}.conf"'
    return response
