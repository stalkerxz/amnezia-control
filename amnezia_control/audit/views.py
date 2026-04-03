import json

from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.shortcuts import render
from django.utils.dateparse import parse_date

from .models import AuditLog


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def audit_list_view(request):
    q = request.GET.get("q", "").strip()
    entity_type = request.GET.get("entity_type", "").strip()
    created_from = request.GET.get("created_from", "").strip()
    operator_scope = request.GET.get("operator_scope", "all").strip() or "all"
    logs = AuditLog.objects.select_related("actor").all()
    if q:
        logs = logs.filter(action__icontains=q)
    if entity_type:
        logs = logs.filter(entity_type=entity_type)
    parsed_created_from = parse_date(created_from) if created_from else None
    if parsed_created_from:
        logs = logs.filter(created_at__date__gte=parsed_created_from)
    if operator_scope == "mine":
        logs = logs.filter(actor=request.user)

    paginator = Paginator(logs, 100)
    page_obj = paginator.get_page(request.GET.get("page"))
    log_rows = [
        {
            "log": log,
            "details_pretty": json.dumps(log.details, ensure_ascii=False, indent=2, sort_keys=True),
        }
        for log in page_obj.object_list
    ]
    entity_type_choices = AuditLog.objects.order_by("entity_type").values_list("entity_type", flat=True).distinct()
    return render(
        request,
        "audit/list.html",
        {
            "logs": page_obj.object_list,
            "log_rows": log_rows,
            "q": q,
            "entity_type_filter": entity_type,
            "created_from": created_from,
            "operator_scope": operator_scope,
            "entity_type_choices": entity_type_choices,
            "page_obj": page_obj,
        },
    )
