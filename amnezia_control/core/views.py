from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Max
from django.db.models import Prefetch
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone

from audit.models import AuditLog
from jobs.models import Job, JobEvent
from servers.models import Server, ServerProtocol
from vpn.models import VPNClient


def _admin_required(user):
    return user.is_authenticated and user.is_staff


def _job_action_label(action: str) -> str:
    labels = {
        "server.sync_runtime": "Синхронизация состояния сервера",
        "server.import_runtime_peers": "Импорт клиентов из runtime",
        "client.create": "Создание клиента",
        "client.reissue": "Переиздание конфигурации клиента",
        "client.disable": "Отключение клиента",
        "client.enable": "Включение клиента",
        "client.delete": "Удаление клиента",
    }
    return labels.get(action, (action or "—").replace(".", " · "))


def _audit_action_label(action: str) -> str:
    labels = {
        "server.sync_runtime": "Сервер: синхронизация состояния",
        "server.import_runtime_peers": "Сервер: импорт клиентов из runtime",
        "client.create": "Клиент: создан",
        "client.reissue": "Клиент: конфигурация переиздана",
        "client.disable": "Клиент: отключён",
        "client.enable": "Клиент: включён",
        "client.delete": "Клиент: помечен удалённым",
    }
    return labels.get(action, (action or "—").replace(".", " · "))


@login_required
@user_passes_test(_admin_required)
def dashboard_view(request):
    protocols = list(ServerProtocol.objects.all())
    protocol_map = {(protocol.server_id, protocol.protocol_type): protocol for protocol in protocols}
    clients = list(VPNClient.objects.select_related("server").all())

    degraded_clients_count = 0
    for client in clients:
        protocol = protocol_map.get((client.server_id, client.protocol_type))
        peer_source = (protocol.runtime_metadata or {}).get("peer_source", "") if protocol else ""
        if (
            client.protocol_type == VPNClient.ProtocolType.AWG2
            and client.status != VPNClient.Status.DELETED
            and "config file fallback (degraded telemetry)" in peer_source
        ):
            degraded_clients_count += 1

    jobs_recent = list(
        Job.objects.select_related("server", "actor")
        .prefetch_related(Prefetch("events", queryset=JobEvent.objects.order_by("-created_at")))
        .order_by("-created_at")[:8]
    )
    jobs_recent_rows = []
    for job in jobs_recent:
        events = list(job.events.all())
        has_warning = any(event.level == "warning" for event in events)
        warning_event = next((event for event in events if event.level == "warning"), None)
        jobs_recent_rows.append(
            {
                "job": job,
                "action_label": _job_action_label(job.action),
                "has_warning": has_warning,
                "warning_hint": warning_event.message if warning_event else "",
            }
        )

    audit_recent_rows = [
        {
            "log": log,
            "action_label": _audit_action_label(log.action),
        }
        for log in AuditLog.objects.select_related("actor").order_by("-created_at")[:10]
    ]

    context = {
        "servers_count": Server.objects.count(),
        "clients_total_count": len(clients),
        "active_clients_count": sum(1 for client in clients if client.status == VPNClient.Status.ACTIVE),
        "disabled_clients_count": sum(1 for client in clients if client.status == VPNClient.Status.DISABLED),
        "deleted_clients_count": sum(1 for client in clients if client.status == VPNClient.Status.DELETED),
        "expired_clients_count": sum(
            1
            for client in clients
            if client.limit_state == VPNClient.LimitState.EXPIRED and client.status != VPNClient.Status.DELETED
        ),
        "traffic_exceeded_clients_count": sum(
            1
            for client in clients
            if client.limit_state == VPNClient.LimitState.TRAFFIC_EXCEEDED and client.status != VPNClient.Status.DELETED
        ),
        "degraded_clients_count": degraded_clients_count,
        "awg_available": any(protocol.protocol_type == ServerProtocol.ProtocolType.AWG and protocol.enabled for protocol in protocols),
        "awg2_available": any(
            protocol.protocol_type == ServerProtocol.ProtocolType.AWG2 and protocol.enabled for protocol in protocols
        ),
        "last_runtime_sync": Server.objects.aggregate(last=Max("last_runtime_sync_at")).get("last"),
        "failed_jobs_recent_count": Job.objects.filter(
            status=Job.Status.FAILED, created_at__gte=timezone.now() - timezone.timedelta(hours=24)
        ).count(),
        "jobs_recent_rows": jobs_recent_rows,
        "audit_recent_rows": audit_recent_rows,
    }
    return render(request, "core/dashboard.html", context)


def health_view(request):
    return JsonResponse({"status": "ok"})
