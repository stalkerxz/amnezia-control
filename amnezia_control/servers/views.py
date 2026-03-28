from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.shortcuts import get_object_or_404, redirect, render

from .models import Server
from .services import ServerService


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


@login_required
@user_passes_test(_admin_required)
def server_sync_runtime_view(request, pk: int):
    server = get_object_or_404(Server, pk=pk)
    if request.method == "POST":
        ServerService.sync_runtime_state(server=server, actor=request.user)
        messages.success(request, "Состояние контейнеров синхронизировано")
    return redirect("servers-detail", pk=pk)
