from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import get_object_or_404, redirect, render

from .models import Server
from .services import ServerService
from vpn.models import VPNClient
from vpn.services import VPNClientService


def _admin_required(user):
    return user.is_authenticated and user.is_staff


def _health_label(status: str) -> str:
    labels = {
        "healthy": "Здоров",
        "degraded": "Ограниченно работоспособен",
        "unhealthy": "Нездоров",
        "not_checked": "Не проверялся",
        "unknown": "Не проверялся",
    }
    return labels.get(status or "not_checked", "Не проверялся")


def _peer_source_view(peer_source: str):
    source = (peer_source or "").strip()
    if source == "runtime wg dump":
        return "Runtime-опрос", ""
    if source == "config file fallback (degraded telemetry)":
        return "Runtime-опрос недоступен", "Используется fallback. Peers читаются из конфигурации."
    if not source:
        return "Нет данных", ""
    return "Служебный источник", source


@login_required
@user_passes_test(_admin_required)
def server_list_view(request):
    servers_qs = Server.objects.prefetch_related("protocols").all()
    health_filter = request.GET.get("health", "").strip()
    if health_filter in {
        ServerService.HEALTH_HEALTHY,
        ServerService.HEALTH_DEGRADED,
        ServerService.HEALTH_UNHEALTHY,
        ServerService.HEALTH_NOT_CHECKED,
    }:
        servers_qs = servers_qs.filter(health_status=health_filter)
    else:
        health_filter = ""

    monitor_server_id = request.GET.get("monitor", "").strip()
    servers = []
    for server in servers_qs:
        item = {
            "obj": server,
            "health_label": _health_label(server.health_status),
            "health_reasons": ServerService.evaluate_health(server)["reasons"][:2],
            "metrics": None,
        }
        if monitor_server_id and monitor_server_id.isdigit() and int(monitor_server_id) == server.id:
            item["metrics"] = ServerService.collect_load_metrics(server, request.user)
        servers.append(item)
    health_filters = [
        {"key": "", "label": "Все"},
        {"key": ServerService.HEALTH_HEALTHY, "label": "Здоровы"},
        {"key": ServerService.HEALTH_DEGRADED, "label": "Ограничены"},
        {"key": ServerService.HEALTH_UNHEALTHY, "label": "Проблемы"},
        {"key": ServerService.HEALTH_NOT_CHECKED, "label": "Не проверялись"},
    ]
    for item in health_filters:
        item["active"] = item["key"] == health_filter
        item["url"] = "/servers/" if not item["key"] else f"/servers/?health={item['key']}"

    return render(
        request,
        "servers/list.html",
        {"servers": servers, "health_filters": health_filters, "health_filter": health_filter},
    )


@login_required
@user_passes_test(_admin_required)
def server_detail_view(request, pk: int):
    server = get_object_or_404(Server, pk=pk)
    protocols = list(server.protocols.all().order_by("protocol_type"))
    ready_protocols = sum(
        1
        for protocol in protocols
        if protocol.runtime_metadata.get("endpoint_host_ready")
        and protocol.runtime_metadata.get("endpoint_port_ready")
        and protocol.runtime_metadata.get("subnet_ready")
    )
    endpoint_display = "—"
    if server.public_endpoint_host and server.public_endpoint_port:
        endpoint_display = f"{server.public_endpoint_host}:{server.public_endpoint_port}"
    elif server.public_endpoint_host:
        endpoint_display = server.public_endpoint_host

    protocol_rows = []
    for protocol in protocols:
        peer_source_label, peer_source_hint = _peer_source_view((protocol.runtime_metadata or {}).get("peer_source", ""))
        protocol_rows.append(
            {
                "protocol": protocol,
                "peer_source_label": peer_source_label,
                "peer_source_hint": peer_source_hint,
            }
        )

    health_eval = ServerService.evaluate_health(server)
    context = {
        "server": server,
        "server_health_label": _health_label(server.health_status),
        "server_health_reasons": health_eval["reasons"],
        "protocol_rows": protocol_rows,
        "ready_protocols": ready_protocols,
        "total_protocols": len(protocols),
        "endpoint_display": endpoint_display,
    }
    return render(request, "servers/detail.html", context)


@login_required
@user_passes_test(_admin_required)
def server_sync_runtime_view(request, pk: int):
    server = get_object_or_404(Server, pk=pk)
    if request.method == "POST":
        try:
            ServerService.sync_runtime_state(server=server, actor=request.user)
            server.refresh_from_db(fields=["health_status"])
            messages.success(request, f"Состояние runtime синхронизировано. Итог здоровья: {_health_label(server.health_status)}.")
        except Exception as exc:
            ServerService.update_health(server, ServerService.HEALTH_UNHEALTHY)
            messages.error(request, f"Синхронизация runtime не выполнена: {exc}")
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
