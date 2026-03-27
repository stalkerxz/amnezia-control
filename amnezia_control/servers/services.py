import ipaddress
import json
import re

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
    AWG2_CANONICAL_KEYS = [
        "I1", "I2", "I3", "I4", "I5",
        "S1", "S2", "S3", "S4",
        "Jc", "Jmin", "Jmax",
        "H1", "H2", "H3", "H4",
    ]

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

    @staticmethod
    def _parse_public_host(inspect_data):
        ports = inspect_data[0].get("NetworkSettings", {}).get("Ports", {}) if inspect_data else {}
        for container_port, host_bindings in ports.items():
            if container_port.endswith("/udp") and host_bindings:
                host_ip = host_bindings[0].get("HostIp", "")
                if host_ip and host_ip not in {"0.0.0.0", "127.0.0.1"}:
                    return host_ip
        return ""

    @staticmethod
    def _parse_interface_metadata(raw_conf: str):
        subnet = ""
        listen_port = None
        for line in raw_conf.splitlines():
            text = line.strip()
            if text.lower().startswith("address") and "=" in text:
                value = text.split("=", 1)[1].strip().split(",")[0].strip()
                try:
                    subnet = str(ipaddress.ip_interface(value).network)
                except ValueError:
                    subnet = ""
            if text.lower().startswith("listenport") and "=" in text:
                try:
                    listen_port = int(text.split("=", 1)[1].strip())
                except ValueError:
                    listen_port = None
        return subnet, listen_port

    @classmethod
    def _normalize_awg2_key(cls, key: str) -> str:
        compact = re.sub(r"[^A-Za-z0-9]", "", key).upper().replace("AWG2", "")
        mapping = {
            "JC": "Jc",
            "JMIN": "Jmin",
            "JMAX": "Jmax",
        }
        if compact in mapping:
            return mapping[compact]
        if compact and compact[0] in {"I", "S", "H"}:
            return compact
        return ""

    @classmethod
    def _parse_awg2_metadata(cls, env_list, conf_text: str):
        discovered = {}

        for item in env_list:
            if "=" not in item:
                continue
            k, v = item.split("=", 1)
            norm = cls._normalize_awg2_key(k)
            if norm in cls.AWG2_CANONICAL_KEYS:
                discovered[norm] = v.strip()

        for line in conf_text.splitlines():
            text = line.strip()
            if "=" not in text:
                continue
            k, v = text.split("=", 1)
            norm = cls._normalize_awg2_key(k)
            if norm in cls.AWG2_CANONICAL_KEYS:
                discovered[norm] = v.strip()

        missing = [k for k in cls.AWG2_CANONICAL_KEYS if not discovered.get(k)]
        return discovered, missing

    @classmethod
    def sync_runtime_state(cls, *, server: Server, actor):
        all_names = RuntimeCommandService.run(server, actor, "runtime.ps_all", "docker ps -a --format '{{.Names}}'").stdout.splitlines()
        running_names = RuntimeCommandService.run(server, actor, "runtime.ps_running", "docker ps --format '{{.Names}}'").stdout.splitlines()

        for protocol_type, container_name in cls.CONTAINERS.items():
            protocol, _ = ServerProtocol.objects.get_or_create(server=server, protocol_type=protocol_type)
            protocol.container_name = container_name

            if container_name in all_names:
                inspect_raw = RuntimeCommandService.run(server, actor, f"runtime.inspect.{protocol_type}", f"docker inspect {container_name}").stdout
                inspect_data = json.loads(inspect_raw)
                config_env = inspect_data[0].get("Config", {}).get("Env", [])
                command_bin = "awg" if protocol_type == ServerProtocol.ProtocolType.AWG else "wg"

                iface = ""
                peer_count = 0
                raw_iface_conf = ""
                if container_name in running_names:
                    try:
                        iface = RuntimeCommandService.run(server, actor, f"runtime.iface.{protocol_type}", f"docker exec {container_name} {command_bin} show interfaces").stdout.strip().split()[0]
                        dump = RuntimeCommandService.run(server, actor, f"runtime.peers.{protocol_type}", f"docker exec {container_name} {command_bin} show dump").stdout
                        peer_count = sum(1 for line in dump.splitlines() if len(line.split("\t")) >= 8)
                    except Exception:
                        iface = ""
                        peer_count = 0

                    if iface:
                        for path in (f"/etc/wireguard/{iface}.conf", f"/etc/amnezia/{iface}.conf", "/etc/amnezia/awg2.conf"):
                            try:
                                raw_iface_conf = RuntimeCommandService.run(server, actor, f"runtime.conf.{protocol_type}", f"docker exec {container_name} cat {path}").stdout
                                if raw_iface_conf:
                                    break
                            except Exception:
                                continue

                subnet, listen_port = cls._parse_interface_metadata(raw_iface_conf)
                awg2_meta, awg2_missing = ({}, [])
                if protocol_type == ServerProtocol.ProtocolType.AWG2:
                    awg2_meta, awg2_missing = cls._parse_awg2_metadata(config_env, raw_iface_conf)

                protocol.container_status = inspect_data[0].get("State", {}).get("Status", "unknown")
                protocol.runtime_metadata = {
                    "udp_port": cls._parse_udp_port(inspect_data) or listen_port,
                    "public_host": cls._parse_public_host(inspect_data),
                    "image": inspect_data[0].get("Config", {}).get("Image", ""),
                    "mounts": [m.get("Destination", "") for m in inspect_data[0].get("Mounts", [])],
                    "env": config_env,
                    "interface": iface,
                    "peer_count": peer_count,
                    "subnet": subnet,
                    "awg2_metadata": awg2_meta,
                    "awg2_missing_keys": awg2_missing,
                    "awg2_metadata_ready": not awg2_missing if protocol_type == ServerProtocol.ProtocolType.AWG2 else True,
                }
                protocol.enabled = container_name in running_names
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
