import re

from django.contrib import messages
from django.shortcuts import redirect

from servers.models import Server

from .models import VPNClient
from .preflight import ClientCreationPreflightService


class ClientCreationPreflightMiddleware:
    """Fail closed for operator-side client creation when runtime is not ready."""

    server_create_pattern = re.compile(r"^/servers/(?P<server_id>\d+)/create-client/(?P<protocol>awg2?)/$")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method == "POST" and request.user.is_authenticated and request.user.is_staff:
            target = self._creation_target(request)
            if target:
                server, protocol_type, fallback_name, fallback_kwargs = target
                try:
                    result = ClientCreationPreflightService.check(
                        server=server,
                        protocol_type=protocol_type,
                        include_live=True,
                    )
                except Exception as exc:
                    messages.error(request, f"Создание клиента заблокировано: проверка готовности не выполнена ({exc}).")
                    return redirect(fallback_name, **fallback_kwargs)

                if not result["ready"]:
                    failed = [item["label"] for item in result["checks"] if item["blocking"] and not item["ok"]]
                    details = ", ".join(failed[:5]) or "неизвестная ошибка готовности"
                    messages.error(request, f"Создание клиента заблокировано. Не пройдены проверки: {details}.")
                    return redirect(fallback_name, **fallback_kwargs)

        return self.get_response(request)

    @classmethod
    def _creation_target(cls, request):
        if request.path == "/clients/new/":
            servers = (
                Server.objects
                .filter(is_enabled=True)
                .order_by(
                    "-is_default_for_new_clients",
                    "name",
                    "id",
                )
            )

            raw_server_id = (
                request.POST.get("server")
                or ""
            ).strip()

            server = None

            if raw_server_id.isdigit():
                server = servers.filter(
                    pk=int(raw_server_id)
                ).first()

            if server is None:
                server = servers.first()

            protocol_type = (
                request.POST.get("protocol_type")
                or VPNClient.ProtocolType.AWG2
            ).strip().lower()

            if (
                not server
                or protocol_type not in {
                    VPNClient.ProtocolType.AWG,
                    VPNClient.ProtocolType.AWG2,
                }
            ):
                return None

            return (
                server,
                protocol_type,
                "clients-create",
                {},
            )

        match = cls.server_create_pattern.match(request.path)
        if not match:
            return None
        server = Server.objects.filter(pk=int(match.group("server_id")), is_enabled=True).first()
        if not server:
            return None
        return server, match.group("protocol"), "servers-detail", {"pk": server.pk}
