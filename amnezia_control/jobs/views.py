import json

from django.contrib.auth.decorators import (
    login_required,
    user_passes_test,
)
from django.core.paginator import Paginator
from django.db.models import (
    Exists,
    OuterRef,
    Prefetch,
    Q,
)
from django.shortcuts import (
    get_object_or_404,
    render,
)
from django.utils.dateparse import parse_date

from .models import Job, JobEvent
from .services import (
    DEGRADED_MARKERS,
    classify_job_signal,
)


def _admin_required(user):
    return (
        user.is_authenticated
        and user.is_staff
    )


def _with_signal_annotations(queryset):
    warning_events = JobEvent.objects.filter(
        job_id=OuterRef("pk"),
        level="warning",
    )

    degraded_condition = Q()

    for marker in DEGRADED_MARKERS:
        degraded_condition |= (
            Q(message__icontains=marker)
            | Q(stdout__icontains=marker)
            | Q(stderr__icontains=marker)
        )

    degraded_warning_events = (
        warning_events.filter(
            degraded_condition
        )
    )

    return queryset.annotate(
        has_warning_signal=Exists(
            warning_events
        ),
        has_degraded_warning_signal=Exists(
            degraded_warning_events
        ),
    )


def _filter_by_signal(queryset, signal):
    if not signal:
        return queryset

    if signal == "failed":
        return queryset.filter(
            status=Job.Status.FAILED
        )

    if signal == "degraded_success":
        return queryset.filter(
            status=Job.Status.SUCCESS,
            has_degraded_warning_signal=True,
        )

    if signal == "warning":
        return (
            queryset
            .exclude(
                status=Job.Status.FAILED
            )
            .filter(
                has_warning_signal=True
            )
            .exclude(
                status=Job.Status.SUCCESS,
                has_degraded_warning_signal=True,
            )
        )

    if signal == "success":
        return queryset.filter(
            status=Job.Status.SUCCESS,
            has_warning_signal=False,
        )

    if signal == "in_progress":
        return queryset.filter(
            status__in=(
                Job.Status.PENDING,
                Job.Status.RUNNING,
            ),
            has_warning_signal=False,
        )

    # Preserve previous behaviour for an
    # unknown signal value: no rows.
    return queryset.none()


@login_required
@user_passes_test(_admin_required)
def jobs_list_view(request):
    jobs_qs = (
        Job.objects
        .select_related(
            "server",
            "actor",
        )
        .order_by("-created_at")
    )

    status = (
        request.GET
        .get("status", "")
        .strip()
    )

    signal = (
        request.GET
        .get("signal", "")
        .strip()
    )

    action = (
        request.GET
        .get("action", "")
        .strip()
    )

    operator_scope = (
        request.GET
        .get(
            "operator_scope",
            "all",
        )
        .strip()
        or "all"
    )

    created_from = (
        request.GET
        .get("created_from", "")
        .strip()
    )

    if status:
        jobs_qs = jobs_qs.filter(
            status=status
        )

    if action:
        jobs_qs = jobs_qs.filter(
            action__icontains=action
        )

    if operator_scope == "mine":
        jobs_qs = jobs_qs.filter(
            actor=request.user
        )

    parsed_created_from = (
        parse_date(created_from)
        if created_from
        else None
    )

    if parsed_created_from:
        jobs_qs = jobs_qs.filter(
            created_at__date__gte=(
                parsed_created_from
            )
        )

    jobs_qs = _with_signal_annotations(
        jobs_qs
    )

    jobs_qs = _filter_by_signal(
        jobs_qs,
        signal,
    )

    # Pagination must happen in PostgreSQL.
    # Do not materialize the full Job table.
    paginator = Paginator(
        jobs_qs,
        50,
    )

    page_obj = paginator.get_page(
        request.GET.get("page")
    )

    # Only fetch events for the 50 jobs
    # actually displayed on this page.
    page_jobs = list(
        page_obj.object_list
        .prefetch_related(
            Prefetch(
                "events",
                queryset=(
                    JobEvent.objects
                    .order_by("-created_at")
                ),
                to_attr="ordered_events",
            )
        )
    )

    job_rows = []

    for job in page_jobs:
        ordered_events = (
            job.ordered_events
        )

        latest_event = (
            ordered_events[0]
            if ordered_events
            else None
        )

        job_rows.append(
            {
                "job": job,
                "payload_pretty": json.dumps(
                    job.payload,
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ),
                "latest_event": latest_event,
                "job_signal": (
                    classify_job_signal(
                        job,
                        ordered_events,
                    )
                ),
            }
        )

    return render(
        request,
        "jobs/list.html",
        {
            "job_rows": job_rows,
            "page_obj": page_obj,
            "status_filter": status,
            "signal_filter": signal,
            "action_filter": action,
            "operator_scope": (
                operator_scope
            ),
            "created_from": created_from,
            "status_choices": (
                Job.Status.choices
            ),
        },
    )


@login_required
@user_passes_test(_admin_required)
def jobs_detail_view(request, pk: int):
    job = get_object_or_404(
        Job.objects.select_related(
            "server",
            "actor",
        ),
        pk=pk,
    )

    events = list(
        job.events.order_by(
            "created_at"
        )
    )

    payload_pretty = json.dumps(
        job.payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )

    job_signal = classify_job_signal(
        job,
        events,
    )

    return render(
        request,
        "jobs/detail.html",
        {
            "job": job,
            "events": events,
            "payload_pretty": (
                payload_pretty
            ),
            "job_signal": job_signal,
        },
    )
