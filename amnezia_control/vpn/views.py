from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from servers.models import Server
from .forms import VPNClientCreateForm
from .models import VPNClient
from .services import VPNClientService


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def clients_list_view(request):
    q = request.GET.get("q", "").strip()
    clients = VPNClient.objects.select_related("server").order_by("-id")
    if q:
        clients = clients.filter(name__icontains=q)
    return render(request, "vpn/clients_list.html", {"clients": clients, "q": q})


@login_required
@user_passes_test(_admin_required)
def clients_create_view(request):
    server = Server.objects.filter(is_enabled=True).first()
    if not server:
        messages.error(request, "Сервер не настроен")
        return redirect("clients-list")

    if request.method == "POST":
        form = VPNClientCreateForm(request.POST)
        if form.is_valid():
            client = VPNClientService.create_client(
                server=server,
                name=form.cleaned_data["name"],
                protocol_type=form.cleaned_data["protocol_type"],
                actor=request.user,
            )
            messages.success(request, "Клиент создан")
            return redirect("clients-detail", pk=client.id)
    else:
        form = VPNClientCreateForm()
    return render(request, "vpn/clients_create.html", {"form": form})


@login_required
@user_passes_test(_admin_required)
def clients_detail_view(request, pk: int):
    client = get_object_or_404(VPNClient, pk=pk)
    qr_base64 = VPNClientService.qr_png_base64(client) if client.revisions.exists() else ""
    return render(request, "vpn/clients_detail.html", {"client": client, "revision": client.revisions.first(), "qr_base64": qr_base64})


@login_required
@user_passes_test(_admin_required)
def client_action_view(request, pk: int, action: str):
    client = get_object_or_404(VPNClient, pk=pk)
    if request.method != "POST":
        return redirect("clients-detail", pk=client.id)

    if action == "disable":
        VPNClientService.set_status(client=client, status=VPNClient.Status.DISABLED, actor=request.user)
    elif action == "enable":
        VPNClientService.set_status(client=client, status=VPNClient.Status.ACTIVE, actor=request.user)
    elif action == "delete":
        VPNClientService.set_status(client=client, status=VPNClient.Status.DELETED, actor=request.user)
    elif action == "reissue":
        VPNClientService.reissue_config(client=client, actor=request.user)
    messages.success(request, "Действие выполнено")
    return redirect("clients-detail", pk=client.id)


@login_required
@user_passes_test(_admin_required)
def client_download_config_view(request, pk: int):
    client = get_object_or_404(VPNClient, pk=pk)
    config = VPNClientService.latest_config(client)
    response = HttpResponse(config, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{client.name}-{client.protocol_type}.conf"'
    return response
