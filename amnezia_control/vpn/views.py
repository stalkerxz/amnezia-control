from django.contrib import messages
from django.contrib.auth.decorators import login_required, user_passes_test
from django.db.models.functions import Coalesce
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render

from servers.models import Server
from .forms import VPNClientCreateForm, VPNClientListFilterForm
from .models import VPNClient
from .services import VPNClientService


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def clients_list_view(request):
    filter_form = VPNClientListFilterForm(request.GET or None)
    clients = (
        VPNClient.objects.select_related("server")
        .annotate(updated_at=Coalesce("last_runtime_sync_at", "created_at"))
        .order_by("-id")
    )

    if filter_form.is_valid():
        q = filter_form.cleaned_data["q"].strip()
        protocol = filter_form.cleaned_data["protocol"]
        status = filter_form.cleaned_data["status"]
        source = filter_form.cleaned_data["source"]

        if q:
            clients = clients.filter(name__icontains=q)
        if protocol:
            clients = clients.filter(protocol_type=protocol)
        if status:
            clients = clients.filter(status=status)
        if source == "imported":
            clients = clients.filter(imported_from_runtime=True)
        elif source == "manual":
            clients = clients.filter(imported_from_runtime=False)

    server = Server.objects.filter(is_enabled=True).first()
    return render(
        request,
        "vpn/clients_list.html",
        {
            "clients": clients,
            "filter_form": filter_form,
            "server": server,
        },
    )


@login_required
@user_passes_test(_admin_required)
def clients_import_view(request):
    server = Server.objects.filter(is_enabled=True).first()
    if not server:
        messages.error(request, "Сервер не настроен")
        return redirect("clients-list")
    if request.method == "POST":
        imported = VPNClientService.import_runtime_peers(server=server, actor=request.user)
        messages.success(request, f"Импортировано клиентов: {imported}")
    return redirect("clients-list")


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
            try:
                client = VPNClientService.create_client(
                    server=server,
                    name=form.cleaned_data["name"],
                    protocol_type=form.cleaned_data["protocol_type"],
                    actor=request.user,
                )
                messages.success(request, "Клиент создан")
                return redirect("clients-detail", pk=client.id)
            except Exception as exc:
                messages.error(request, f"Ошибка создания клиента: {exc}")
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

    next_url = request.POST.get("next")

    try:
        if action == "disable":
            VPNClientService.set_status(client=client, status=VPNClient.Status.DISABLED, actor=request.user)
        elif action == "enable":
            VPNClientService.set_status(client=client, status=VPNClient.Status.ACTIVE, actor=request.user)
        elif action == "delete":
            VPNClientService.set_status(client=client, status=VPNClient.Status.DELETED, actor=request.user)
        elif action == "reissue":
            VPNClientService.reissue_config(client=client, actor=request.user)
        messages.success(request, "Действие выполнено")
    except Exception as exc:
        messages.error(request, f"Ошибка выполнения действия: {exc}")

    if next_url:
        return redirect(next_url)
    return redirect("clients-detail", pk=client.id)


@login_required
@user_passes_test(_admin_required)
def client_download_config_view(request, pk: int):
    client = get_object_or_404(VPNClient, pk=pk)
    config = VPNClientService.latest_config(client)
    response = HttpResponse(config, content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{client.name}-{client.protocol_type}.conf"'
    return response
