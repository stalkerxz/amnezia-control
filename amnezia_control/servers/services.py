from django.utils import timezone

from audit.services import AuditService
from jobs.services import JobService
from vpn.services import RuntimeCommandService

from .models import Server, ServerProtocol


class ServerService:
    CONTAINERS = {
        ServerProtocol.ProtocolType.AWG: "amnezia-awg",
        ServerProtocol.ProtocolType.AWG2: "amnezia-awg2",
    }

    @staticmethod
    def update_health(server: Server, status: str) -> Server:
        server.health_status = status
        server.save(update_fields=["health_status", "updated_at"])
        return server

    @staticmethod
    def refresh_health_with_job(server: Server, actor):
        return JobService.create_job(
            server=server,
            actor=actor,
            action="server.health_check",
            payload={"server_id": server.id},
        )

    @staticmethod
    def _parse_udp_port(inspect_data):
        ports = inspect_data[0].get("NetworkSettings", {}).get("Ports", {}) if inspect_data else {}
        for container_port, host_bindings in ports.items():
            if container_port.endswith("/udp") and host_bindings:
                return int(host_bindings[0].get("HostPort", 0))
        return None

    @classmethod
    def sync_runtime_state(cls, *, server: Server, actor):
        names = RuntimeCommandService.run(server, actor, "runtime.ps", "docker ps --format '{{.Names}}'").stdout.splitlines()
        for protocol_type, container_name in cls.CONTAINERS.items():
            protocol, _ = ServerProtocol.objects.get_or_create(server=server, protocol_type=protocol_type)
            protocol.container_name = container_name
            if container_name in names:
                inspect_raw = RuntimeCommandService.run(server, actor, f"runtime.inspect.{protocol_type}", f"docker inspect {container_name}").stdout
                import json

                inspect_data = json.loads(inspect_raw)
                protocol.container_status = inspect_data[0].get("State", {}).get("Status", "unknown")
                protocol.runtime_metadata = {
                    "udp_port": cls._parse_udp_port(inspect_data),
                    "image": inspect_data[0].get("Config", {}).get("Image", ""),
                    "mounts": [m.get("Destination", "") for m in inspect_data[0].get("Mounts", [])],
                }
                protocol.enabled = protocol.container_status == "running"
            else:
                protocol.container_status = "missing"
                protocol.runtime_metadata = {}
                protocol.enabled = False
            protocol.last_sync_at = timezone.now()
            protocol.save(update_fields=["container_name", "container_status", "runtime_metadata", "enabled", "last_sync_at"])

        server.last_runtime_sync_at = timezone.now()
        server.save(update_fields=["last_runtime_sync_at"])
        AuditService.log(actor, "server.runtime.sync", "Server", server.id)
        return server
