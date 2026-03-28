from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models import Max
from django.http import JsonResponse
from django.shortcuts import render

from audit.models import AuditLog
from jobs.models import Job
from servers.models import Server, ServerProtocol
from vpn.models import VPNClient


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def dashboard_view(request):
    protocols = ServerProtocol.objects.all()
    servers = Server.objects.order_by("name")

    server_for_actions = servers.filter(is_enabled=True).first() or servers.first()
    system_health = {
        "web": True,
        "worker": Job.objects.filter(status=Job.Status.RUNNING).exists() or Job.objects.exists(),
        "db": True,
        "redis": Job.objects.exists(),
    }

    context = {
        "servers_count": servers.count(),
        "clients_count": VPNClient.objects.count(),
        "active_clients_count": VPNClient.objects.filter(status=VPNClient.Status.ACTIVE).count(),
        "awg_available": protocols.filter(protocol_type=ServerProtocol.ProtocolType.AWG, enabled=True).exists(),
        "awg2_available": protocols.filter(protocol_type=ServerProtocol.ProtocolType.AWG2, enabled=True).exists(),
        "last_runtime_sync": servers.aggregate(last=Max("last_runtime_sync_at")).get("last"),
        "jobs_recent": Job.objects.select_related("server", "actor").order_by("-created_at")[:5],
        "audit_recent": AuditLog.objects.select_related("actor").order_by("-created_at")[:10],
        "system_health": system_health,
        "server_for_actions": server_for_actions,
    }
    return render(request, "core/dashboard.html", context)


def health_view(request):
    return JsonResponse({"status": "ok"})
