from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import render
from .models import AuditLog


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def audit_list_view(request):
    q = request.GET.get("q", "").strip()
    logs = AuditLog.objects.all()
    if q:
        logs = logs.filter(action__icontains=q)
    return render(request, "audit/list.html", {"logs": logs[:200], "q": q})
