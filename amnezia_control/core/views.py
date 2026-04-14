from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Max
from django.db.models import Prefetch
from django.http import JsonResponse
from django.urls import reverse
from django.shortcuts import render
from django.utils import timezone

from audit.models import AuditLog
from jobs.models import Job, JobEvent
from jobs.services import classify_job_signal
from servers.models import Server, ServerProtocol
from servers.services import ServerService
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
    servers = list(Server.objects.prefetch_related("protocols").all())
    server_health_states = [ServerService.evaluate_health(server)["status"] for server in servers]
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
        job_signal = classify_job_signal(job, events)
        warning_event = next((event for event in events if event.level == "warning"), None)
        jobs_recent_rows.append(
            {
                "job": job,
                "action_label": _job_action_label(job.action),
                "job_signal": job_signal,
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

    failed_jobs_created_from = (timezone.localdate() - timezone.timedelta(days=1)).isoformat()
    renewal_24h_cutoff = timezone.now() - timezone.timedelta(hours=24)
    renewal_7d_cutoff = timezone.now() - timezone.timedelta(days=7)
    renewal_requests_last_24h = AuditLog.objects.filter(action="portal.renewal.request", created_at__gte=renewal_24h_cutoff).count()
    renewal_requests_last_7d = AuditLog.objects.filter(action="portal.renewal.request", created_at__gte=renewal_7d_cutoff).count()
    recent_renewal_requests = list(
        AuditLog.objects.filter(action="portal.renewal.request").order_by("-created_at")[:5]
    )

    jobs_last_24h = list(
        Job.objects.prefetch_related(Prefetch("events", queryset=JobEvent.objects.order_by("-created_at"))).filter(
            created_at__gte=timezone.now() - timezone.timedelta(hours=24)
        )
    )
    failed_jobs_recent_count = 0
    warning_jobs_recent_count = 0
    degraded_jobs_recent_count = 0
    for job in jobs_last_24h:
        signal = classify_job_signal(job, list(job.events.all()))
        if signal == "failed":
            failed_jobs_recent_count += 1
        elif signal == "warning":
            warning_jobs_recent_count += 1
        elif signal == "degraded_success":
            degraded_jobs_recent_count += 1

    attention_items = [
        {
            "title": "Серверы: ограниченно работоспособны",
            "count": sum(1 for state in server_health_states if state == ServerService.HEALTH_DEGRADED),
            "url": f"{reverse('servers-list')}?health=degraded",
            "tone": "warning",
        },
        {
            "title": "Серверы: проблемы",
            "count": sum(1 for state in server_health_states if state == ServerService.HEALTH_UNHEALTHY),
            "url": f"{reverse('servers-list')}?health=unhealthy",
            "tone": "danger",
        },
        {
            "title": "Клиенты: срок действия истёк",
            "count": sum(
                1
                for client in clients
                if client.limit_state == VPNClient.LimitState.EXPIRED and client.status != VPNClient.Status.DELETED
            ),
            "url": f"{reverse('clients-list')}?quick=expired",
            "tone": "warning",
        },
        {
            "title": "Клиенты: превышен лимит трафика",
            "count": sum(
                1
                for client in clients
                if client.limit_state == VPNClient.LimitState.TRAFFIC_EXCEEDED and client.status != VPNClient.Status.DELETED
            ),
            "url": f"{reverse('clients-list')}?quick=traffic_exceeded",
            "tone": "danger",
        },
        {
            "title": "Ошибки задач за последние 24 часа",
            "count": failed_jobs_recent_count,
            "url": f"{reverse('jobs-list')}?status=failed&created_from={failed_jobs_created_from}",
            "tone": "danger",
        },
        {
            "title": "Клиенты в soft delete",
            "count": sum(1 for client in clients if client.status == VPNClient.Status.DELETED),
            "url": f"{reverse('clients-list')}?quick=deleted",
            "tone": "neutral",
        },
    ]

    current_limitations = []
    if degraded_clients_count:
        current_limitations.append(f"AWG2 fallback-телеметрия используется для {degraded_clients_count} клиент(ов).")
    not_checked_servers_count = sum(1 for state in server_health_states if state == ServerService.HEALTH_NOT_CHECKED)
    if not_checked_servers_count:
        current_limitations.append(f"Не проверены серверы: {not_checked_servers_count}.")
    degraded_servers_count = sum(1 for state in server_health_states if state == ServerService.HEALTH_DEGRADED)
    if degraded_servers_count:
        current_limitations.append(f"Есть деградированные серверы: {degraded_servers_count}.")

    context = {
        "servers_count": len(servers),
        "healthy_servers_count": sum(1 for state in server_health_states if state == ServerService.HEALTH_HEALTHY),
        "degraded_servers_count": degraded_servers_count,
        "unhealthy_servers_count": sum(1 for state in server_health_states if state == ServerService.HEALTH_UNHEALTHY),
        "not_checked_servers_count": not_checked_servers_count,
        "clients_total_count": len(clients),
        "active_clients_count": sum(1 for client in clients if client.status == VPNClient.Status.ACTIVE),
        "disabled_clients_count": sum(1 for client in clients if client.status == VPNClient.Status.DISABLED),
        "deleted_clients_count": attention_items[5]["count"],
        "expired_clients_count": attention_items[2]["count"],
        "traffic_exceeded_clients_count": attention_items[3]["count"],
        "degraded_clients_count": degraded_clients_count,
        "awg_available": any(protocol.protocol_type == ServerProtocol.ProtocolType.AWG and protocol.enabled for protocol in protocols),
        "awg2_available": any(
            protocol.protocol_type == ServerProtocol.ProtocolType.AWG2 and protocol.enabled for protocol in protocols
        ),
        "last_runtime_sync": Server.objects.aggregate(last=Max("last_runtime_sync_at")).get("last"),
        "failed_jobs_recent_count": failed_jobs_recent_count,
        "warning_jobs_recent_count": warning_jobs_recent_count,
        "degraded_jobs_recent_count": degraded_jobs_recent_count,
        "jobs_recent_rows": jobs_recent_rows,
        "audit_recent_rows": audit_recent_rows,
        "attention_items": attention_items,
        "current_limitations": current_limitations,
        "renewal_requests_last_24h": renewal_requests_last_24h,
        "renewal_requests_last_7d": renewal_requests_last_7d,
        "recent_renewal_requests": recent_renewal_requests,
    }
    return render(request, "core/dashboard.html", context)


def health_view(request):
    return JsonResponse({"status": "ok"})
