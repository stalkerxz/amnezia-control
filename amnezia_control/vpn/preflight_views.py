from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse

from servers.models import Server

from .models import VPNClient
from .preflight import ClientCreationPreflightService


def _admin_required(user):
    return user.is_authenticated and user.is_staff


@login_required
@user_passes_test(_admin_required)
def client_creation_preflight_view(request):
    protocol_type = (request.GET.get("protocol") or VPNClient.ProtocolType.AWG2).strip().lower()
    if protocol_type not in {VPNClient.ProtocolType.AWG, VPNClient.ProtocolType.AWG2}:
        return JsonResponse({"ready": False, "error": "Неподдерживаемый протокол."}, status=400)

    server_id = (request.GET.get("server_id") or "").strip()
    servers = Server.objects.filter(is_enabled=True)
    if server_id.isdigit():
        servers = servers.filter(pk=int(server_id))
    server = servers.first()
    if not server:
        return JsonResponse({"ready": False, "error": "Включённый сервер не найден.", "checks": []}, status=404)

    try:
        result = ClientCreationPreflightService.check(
            server=server,
            protocol_type=protocol_type,
            include_live=True,
        )
    except Exception as exc:
        return JsonResponse(
            {
                "ready": False,
                "server": server.name,
                "protocol_type": protocol_type,
                "checks": [],
                "error": f"Проверка готовности не выполнена: {exc}",
            },
            status=200,
        )
    return JsonResponse(result)
