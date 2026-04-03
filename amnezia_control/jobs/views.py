import json

from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, render
from django.utils.dateparse import parse_date

from .models import Job
from .services import classify_job_signal


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def jobs_list_view(request):
    jobs_qs = Job.objects.select_related("server", "actor").order_by("-created_at")
    status = request.GET.get("status", "").strip()
    signal = request.GET.get("signal", "").strip()
    action = request.GET.get("action", "").strip()
    created_from = request.GET.get("created_from", "").strip()
    if status:
        jobs_qs = jobs_qs.filter(status=status)
    if action:
        jobs_qs = jobs_qs.filter(action__icontains=action)
    parsed_created_from = parse_date(created_from) if created_from else None
    if parsed_created_from:
        jobs_qs = jobs_qs.filter(created_at__date__gte=parsed_created_from)

    jobs_qs = jobs_qs.prefetch_related("events")
    all_job_rows = []
    for job in jobs_qs:
        ordered_events = list(job.events.all().order_by("-created_at"))
        latest_event = ordered_events[0] if ordered_events else None
        job_signal = classify_job_signal(job, ordered_events)
        all_job_rows.append(
            {
                "job": job,
                "payload_pretty": json.dumps(job.payload, ensure_ascii=False, indent=2, sort_keys=True),
                "latest_event": latest_event,
                "job_signal": job_signal,
            }
        )

    if signal:
        all_job_rows = [row for row in all_job_rows if row["job_signal"] == signal]

    paginator = Paginator(all_job_rows, 50)
    page_obj = paginator.get_page(request.GET.get("page"))
    job_rows = list(page_obj.object_list)

    return render(
        request,
        "jobs/list.html",
        {
            "job_rows": job_rows,
            "page_obj": page_obj,
            "status_filter": status,
            "signal_filter": signal,
            "action_filter": action,
            "created_from": created_from,
            "status_choices": Job.Status.choices,
        },
    )


@login_required
@user_passes_test(_admin_required)
def jobs_detail_view(request, pk: int):
    job = get_object_or_404(Job.objects.select_related("server", "actor"), pk=pk)
    events = list(job.events.order_by("created_at"))
    payload_pretty = json.dumps(job.payload, ensure_ascii=False, indent=2, sort_keys=True)
    job_signal = classify_job_signal(job, events)
    return render(
        request,
        "jobs/detail.html",
        {
            "job": job,
            "events": events,
            "payload_pretty": payload_pretty,
            "job_signal": job_signal,
        },
    )
