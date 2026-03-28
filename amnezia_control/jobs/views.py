import json

from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.shortcuts import get_object_or_404, render

from .models import Job


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def jobs_list_view(request):
    jobs_qs = Job.objects.select_related("server", "actor").order_by("-created_at")
    paginator = Paginator(jobs_qs, 50)
    page_obj = paginator.get_page(request.GET.get("page"))
    return render(request, "jobs/list.html", {"jobs": page_obj.object_list, "page_obj": page_obj})


@login_required
@user_passes_test(_admin_required)
def jobs_detail_view(request, pk: int):
    job = get_object_or_404(Job.objects.select_related("server", "actor"), pk=pk)
    payload_pretty = json.dumps(job.payload, ensure_ascii=False, indent=2, sort_keys=True)
    return render(
        request,
        "jobs/detail.html",
        {
            "job": job,
            "events": job.events.order_by("created_at"),
            "payload_pretty": payload_pretty,
        },
    )
