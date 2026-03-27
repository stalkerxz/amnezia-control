from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import get_object_or_404, render
from .models import Server


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def server_list_view(request):
    return render(request, "servers/list.html", {"servers": Server.objects.all()})


@login_required
@user_passes_test(_admin_required)
def server_detail_view(request, pk: int):
    server = get_object_or_404(Server, pk=pk)
    return render(request, "servers/detail.html", {"server": server, "protocols": server.protocols.all()})
