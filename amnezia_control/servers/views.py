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
    servers = Server.objects.prefetch_related("protocols").order_by("name")
    return render(request, "servers/list.html", {"servers": servers})


@login_required
@user_passes_test(_admin_required)
def server_detail_view(request, pk: int):
    server = get_object_or_404(Server.objects.prefetch_related("protocols"), pk=pk)
    protocols = list(server.protocols.all())

    protocol_by_type = {protocol.protocol_type: protocol for protocol in protocols}
    awg = protocol_by_type.get("awg")
    awg2 = protocol_by_type.get("awg2")

    warnings = []
    if not server.public_endpoint_host and not (awg and awg.runtime_metadata.get("public_host")) and not server.host:
        warnings.append("Не определен публичный endpoint host. Экспорт конфигов и QR может быть заблокирован.")
    if awg2 and not awg2.runtime_metadata.get("awg2_metadata_ready", False):
        warnings.append("AWG2 metadata неполная. Создание AWG2 клиентов будет недоступно до runtime sync.")
    if awg2 and not awg2.runtime_metadata.get("endpoint_port_ready", False):
        warnings.append("Не определен UDP endpoint port. Проверьте public endpoint port и повторите sync.")

    return render(
        request,
        "servers/detail.html",
        {
            "server": server,
            "protocols": protocols,
            "awg": awg,
            "awg2": awg2,
            "warnings": warnings,
        },
    )


@login_required
@user_passes_test(_admin_required)
def server_sync_runtime_view(request, pk: int):
    server = get_object_or_404(Server, pk=pk)
    if request.method == "POST":
        ServerService.sync_runtime_state(server=server, actor=request.user)
        messages.success(request, "Runtime успешно синхронизирован. Диагностика обновлена.")
    return redirect("servers-detail", pk=pk)
