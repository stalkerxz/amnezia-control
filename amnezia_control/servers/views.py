from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import get_object_or_404, redirect, render

from .models import Server
from .services import ServerService
from vpn.models import VPNClient
from vpn.services import VPNClientService


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def server_list_view(request):
    return render(request, "servers/list.html", {"servers": Server.objects.all()})


@login_required
@user_passes_test(_admin_required)
def server_detail_view(request, pk: int):
    server = get_object_or_404(Server, pk=pk)
    return render(request, "servers/detail.html", {"server": server, "protocols": server.protocols.all()})


@login_required
@user_passes_test(_admin_required)
def server_sync_runtime_view(request, pk: int):
    server = get_object_or_404(Server, pk=pk)
    if request.method == "POST":
        ServerService.sync_runtime_state(server=server, actor=request.user)
        messages.success(request, "Состояние контейнеров синхронизировано")
    return redirect("servers-detail", pk=pk)


@login_required
@user_passes_test(_admin_required)
def server_import_peers_view(request, pk: int):
    server = get_object_or_404(Server, pk=pk)
    if request.method == "POST":
        imported = VPNClientService.import_runtime_peers(server=server, actor=request.user)
        messages.success(request, f"Импортировано клиентов: {imported}")
    return redirect("servers-detail", pk=pk)


@login_required
@user_passes_test(_admin_required)
def server_create_client_view(request, pk: int, protocol_type: str):
    server = get_object_or_404(Server, pk=pk)
    if request.method != "POST":
        return redirect("servers-detail", pk=pk)

    if protocol_type not in {VPNClient.ProtocolType.AWG, VPNClient.ProtocolType.AWG2}:
        messages.error(request, "Неподдерживаемый протокол")
        return redirect("servers-detail", pk=pk)

    client_name = request.POST.get("name", "").strip()
    if not client_name:
        messages.error(request, "Введите имя клиента")
        return redirect("servers-detail", pk=pk)

    try:
        client = VPNClientService.create_client(
            server=server,
            name=client_name,
            protocol_type=protocol_type,
            actor=request.user,
        )
    except Exception as exc:
        messages.error(request, f"Ошибка создания клиента: {exc}")
        return redirect("servers-detail", pk=pk)

    messages.success(request, f"Клиент «{client.name}» создан ({client.protocol_type.upper()})")
    return redirect("clients-detail", pk=client.id)
