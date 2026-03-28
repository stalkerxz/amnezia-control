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
    client = get_object_or_404(VPNClient.objects.select_related("server"), pk=pk)
    revision = client.revisions.first()
    revision_count = client.revisions.count()
    qr_base64 = VPNClientService.qr_png_base64(client) if revision else ""

    protocol = client.server.protocols.filter(protocol_type=client.protocol_type).first()
    missing_endpoint = False
    missing_awg2_metadata = False
    if protocol:
        host_candidates = [
            client.server.public_endpoint_host,
            client.server.host,
            protocol.runtime_metadata.get("public_host", ""),
        ]
        host = next((h for h in host_candidates if VPNClientService._is_public_endpoint_host(h)), "")
        port = client.server.public_endpoint_port or protocol.runtime_metadata.get("udp_port")
        missing_endpoint = not (host and port)
        if client.protocol_type == VPNClient.ProtocolType.AWG2:
            required = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")
            awg2_metadata = protocol.runtime_metadata.get("awg2_metadata", {})
            missing_awg2_metadata = any(not awg2_metadata.get(k) for k in required)
    else:
        missing_endpoint = True
        missing_awg2_metadata = client.protocol_type == VPNClient.ProtocolType.AWG2

    return render(
        request,
        "vpn/clients_detail.html",
        {
            "client": client,
            "revision": revision,
            "revision_count": revision_count,
            "qr_base64": qr_base64,
            "missing_endpoint": missing_endpoint,
            "missing_awg2_metadata": missing_awg2_metadata,
        },
    )


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
