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
    AWG2_REQUIRED_KEYS = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"]
    AWG2_OPTIONAL_KEYS = ["I1", "I2", "I3", "I4", "I5"]

    @staticmethod
    def update_health(server: Server, status: str) -> Server:
        server.health_status = status
        server.save(update_fields=["health_status", "updated_at"])
        return server

    @staticmethod
    def refresh_health_with_job(server: Server, actor):
        return JobService.create_job(server=server, actor=actor, action="server.health_check", payload={"server_id": server.id})

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
            if not text or text.startswith("#"):
                continue
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

    @staticmethod
    def _is_public_host(value: str) -> bool:
        if not value:
            return False
        value = value.strip().lower()
        if value in {"localhost", "127.0.0.1", "0.0.0.0"}:
            return False
        try:
            return ipaddress.ip_address(value).is_global
        except ValueError:
            return bool(re.fullmatch(r"[a-z0-9.-]+", value))

    @classmethod
    def _normalize_awg2_key(cls, key: str) -> str:
        compact = re.sub(r"[^A-Za-z0-9]", "", key).upper().replace("AWG2", "")
        mapping = {"JC": "Jc", "JMIN": "Jmin", "JMAX": "Jmax"}
        if compact in mapping:
            return mapping[compact]
        if compact and compact[0] in {"I", "S", "H"}:
            return compact
        return ""

    @classmethod
    def _parse_awg2_metadata(cls, env_list, conf_text: str):
        discovered = {}
        allowed = set(cls.AWG2_REQUIRED_KEYS + cls.AWG2_OPTIONAL_KEYS)

        for item in env_list:
            if "=" not in item:
                continue
            k, v = item.split("=", 1)
            norm = cls._normalize_awg2_key(k)
            if norm in allowed:
                discovered[norm] = v.strip()

        for line in conf_text.splitlines():
            text = line.strip()
            if not text or text.startswith("#") or "=" not in text:
                continue
            k, v = text.split("=", 1)
            norm = cls._normalize_awg2_key(k)
            if norm in allowed:
                discovered[norm] = v.strip()

        required_missing = [k for k in cls.AWG2_REQUIRED_KEYS if not discovered.get(k)]
        optional_missing = [k for k in cls.AWG2_OPTIONAL_KEYS if not discovered.get(k)]
        return discovered, required_missing, optional_missing

    @staticmethod
    def _candidate_config_paths(iface: str):
        return [
            "/opt/amnezia/awg/awg0.conf",
            "/opt/amnezia/awg/wg0.conf",
            f"/opt/amnezia/awg/{iface}.conf",
            "/etc/amnezia/awg0.conf",
            "/etc/amnezia/wg0.conf",
            f"/etc/amnezia/{iface}.conf",
            "/etc/wireguard/awg0.conf",
            "/etc/wireguard/wg0.conf",
            f"/etc/wireguard/{iface}.conf",
        ]

    @staticmethod
    def _parse_peers_from_config_text(raw_conf: str):
        peers = []
        section = ""
        current = {}
        for line in raw_conf.splitlines():
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            if text.startswith("[") and text.endswith("]"):
                if section.lower() == "[peer]" and current.get("PublicKey") and current.get("AllowedIPs"):
                    peers.append({"public_key": current["PublicKey"], "allowed_ips": current["AllowedIPs"]})
                section = text
                current = {}
                continue
            if "=" not in text or section.lower() != "[peer]":
                continue
            k, v = text.split("=", 1)
            current[k.strip()] = v.strip()
        if section.lower() == "[peer]" and current.get("PublicKey") and current.get("AllowedIPs"):
            peers.append({"public_key": current["PublicKey"], "allowed_ips": current["AllowedIPs"]})
        return peers

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

                iface = ""
                peer_count = 0
                peer_source = "none"
                raw_iface_conf = ""
                config_path = ""
                if container_name in running_names:
                    try:
                        iface = RuntimeCommandService.run(server, actor, f"runtime.iface.{protocol_type}", f"docker exec {container_name} wg show interfaces").stdout.strip().split()[0]
                        dump = RuntimeCommandService.run(server, actor, f"runtime.peers.{protocol_type}", f"docker exec {container_name} wg show dump").stdout
                        peer_count = sum(1 for line in dump.splitlines() if len(line.split("\t")) >= 8)
                        peer_source = "runtime_wg_dump"
                    except Exception:
                        iface = ""
                        peer_count = 0
                        peer_source = "runtime_wg_dump_failed"

                    for path in cls._candidate_config_paths(iface or "wg0"):
                        try:
                            raw_iface_conf = RuntimeCommandService.run(server, actor, f"runtime.conf.{protocol_type}", f"docker exec {container_name} cat {path}").stdout
                            if raw_iface_conf:
                                config_path = path
                                break
                        except Exception:
                            continue
                    if protocol_type == ServerProtocol.ProtocolType.AWG2 and raw_iface_conf:
                        if peer_source != "runtime_wg_dump":
                            peer_count = len(cls._parse_peers_from_config_text(raw_iface_conf))
                            peer_source = "config_file_fallback"

                subnet, listen_port = cls._parse_interface_metadata(raw_iface_conf)
                awg2_meta, awg2_required_missing, awg2_optional_missing = ({}, [], [])
                if protocol_type == ServerProtocol.ProtocolType.AWG2:
                    awg2_meta, awg2_required_missing, awg2_optional_missing = cls._parse_awg2_metadata(config_env, raw_iface_conf)

                udp_port = cls._parse_udp_port(inspect_data) or listen_port
                discovered_public_host = cls._parse_public_host(inspect_data)
                endpoint_host_ready = cls._is_public_host(server.public_endpoint_host) or cls._is_public_host(server.host) or cls._is_public_host(discovered_public_host)
                endpoint_port_ready = bool(server.public_endpoint_port or udp_port)
                subnet_ready = bool(subnet)

                protocol.container_status = inspect_data[0].get("State", {}).get("Status", "unknown")
                protocol.runtime_metadata = {
                    "config_path": config_path,
                    "udp_port": udp_port,
                    "public_host": discovered_public_host,
                    "image": inspect_data[0].get("Config", {}).get("Image", ""),
                    "mounts": [m.get("Destination", "") for m in inspect_data[0].get("Mounts", [])],
                    "env": config_env,
                    "interface": iface,
                    "peer_count": peer_count,
                    "peer_source": peer_source,
                    "subnet": subnet,
                    "subnet_ready": subnet_ready,
                    "endpoint_host_ready": endpoint_host_ready,
                    "endpoint_port_ready": endpoint_port_ready,
                    "awg2_metadata": awg2_meta,
                    "awg2_active_keys": sorted(awg2_meta.keys()),
                    "awg2_missing_keys": awg2_required_missing,
                    "awg2_optional_missing_keys": awg2_optional_missing,
                    "awg2_metadata_ready": not awg2_required_missing if protocol_type == ServerProtocol.ProtocolType.AWG2 else True,
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
