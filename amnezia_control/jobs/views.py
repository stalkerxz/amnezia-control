from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import get_object_or_404, render
from .models import Job


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def jobs_list_view(request):
    return render(request, "jobs/list.html", {"jobs": Job.objects.order_by("-created_at")[:200]})


@login_required
@user_passes_test(_admin_required)
def jobs_detail_view(request, pk: int):
    job = get_object_or_404(Job, pk=pk)
    return render(request, "jobs/detail.html", {"job": job, "events": job.events.order_by("created_at")})
