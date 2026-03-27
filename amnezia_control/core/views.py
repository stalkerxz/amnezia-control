from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse
from django.shortcuts import render
from servers.models import Server
from vpn.models import VPNClient
from jobs.models import Job
from audit.models import AuditLog


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def dashboard_view(request):
    context = {
        "servers_count": Server.objects.count(),
        "clients_count": VPNClient.objects.count(),
        "active_clients_count": VPNClient.objects.filter(status=VPNClient.Status.ACTIVE).count(),
        "jobs_recent": Job.objects.order_by("-created_at")[:5],
        "audit_recent": AuditLog.objects.order_by("-created_at")[:10],
    }
    return render(request, "core/dashboard.html", context)


def health_view(request):
    return JsonResponse({"status": "ok"})
