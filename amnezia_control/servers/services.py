import ipaddress
import json
import re
import shlex

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
    HEALTH_NOT_CHECKED = "not_checked"
    HEALTH_HEALTHY = "healthy"
    HEALTH_DEGRADED = "degraded"
    HEALTH_UNHEALTHY = "unhealthy"

    @staticmethod
    def _parse_load_average(uptime_text: str):
        match = re.search(r"load average[s]?:\s*([0-9.,]+)\s*,\s*([0-9.,]+)\s*,\s*([0-9.,]+)", uptime_text)
        if not match:
            return None
        return {
            "1": float(match.group(1).replace(",", ".")),
            "5": float(match.group(2).replace(",", ".")),
            "15": float(match.group(3).replace(",", ".")),
        }

    @staticmethod
    def _parse_free_bytes(free_output: str):
        lines = [line.strip() for line in free_output.splitlines() if line.strip()]
        mem_line = next((line for line in lines if line.lower().startswith("mem:")), "")
        if not mem_line:
            return None
        parts = mem_line.split()
        if len(parts) < 4:
            return None
        total = int(parts[1])
        used = int(parts[2])
        free = int(parts[3])
        return {
            "total": total,
            "used": used,
            "free": free,
            "used_percent": round((used / total * 100), 2) if total else 0,
        }

    @staticmethod
    def _parse_disk_root(df_output: str):
        lines = [line.strip() for line in df_output.splitlines() if line.strip()]
        if len(lines) < 2:
            return None
        parts = lines[-1].split()
        if len(parts) < 6:
            return None
        total = int(parts[1])
        used = int(parts[2])
        free = int(parts[3])
        return {
            "total": total,
            "used": used,
            "free": free,
            "used_percent": round((used / total * 100), 2) if total else 0,
        }

    @staticmethod
    def _parse_main_interface(ip_route_output: str):
        match = re.search(r"\bdev\s+(\S+)", ip_route_output)
        return match.group(1) if match else ""

    @staticmethod
    def _parse_net_dev_counters(proc_net_dev_output: str, iface: str):
        for line in proc_net_dev_output.splitlines():
            if ":" not in line:
                continue
            name, data = line.split(":", 1)
            if name.strip() != iface:
                continue
            cols = data.split()
            if len(cols) < 16:
                return None
            return {"rx_bytes": int(cols[0]), "tx_bytes": int(cols[8])}
        return None

    @staticmethod
    def _parse_docker_ps_statuses(docker_ps_output: str):
        containers = []
        for line in docker_ps_output.splitlines():
            if "\t" not in line:
                continue
            name, status = line.split("\t", 1)
            containers.append({"name": name.strip(), "status": status.strip()})
        return containers

    @staticmethod
    def _parse_labeled_sections(raw: str):
        sections = {}
        current = None
        for line in raw.splitlines():
            if line.startswith("__") and line.endswith("__"):
                current = line.strip("_").lower()
                sections[current] = []
                continue
            if current:
                sections[current].append(line)
        return {k: "\n".join(v).strip() for k, v in sections.items()}

    @classmethod
    def collect_load_metrics(cls, server: Server, actor):
        enabled_protocols = list(server.protocols.filter(enabled=True).order_by("protocol_type"))
        metrics = {
            "hostname": server.host,
            "uptime": "",
            "load_average": None,
            "cpu_cores": None,
            "memory": None,
            "disk_root": None,
            "main_interface": "",
            "network": None,
            "docker": {"available": True, "containers": []},
            "protocols": [],
            "errors": [],
        }
        try:
            host_bundle_cmd = (
                "sh -lc 'echo __HOSTNAME__; hostname; "
                "echo __UPTIME__; uptime; "
                "echo __NPROC__; nproc; "
                "echo __FREE__; free -b; "
                "echo __DF__; df -B1 /; "
                "echo __ROUTE__; ip route get 1.1.1.1; "
                "echo __NETDEV__; cat /proc/net/dev'"
            )
            bundle_out = RuntimeCommandService.run(server, actor, "monitoring.host_bundle", host_bundle_cmd).stdout
            sections = cls._parse_labeled_sections(bundle_out)
            metrics["hostname"] = sections.get("hostname", "").strip() or server.host
            uptime_out = sections.get("uptime", "")
            metrics["uptime"] = uptime_out
            metrics["load_average"] = cls._parse_load_average(uptime_out)
            metrics["cpu_cores"] = int((sections.get("nproc", "0").splitlines() or ["0"])[0].strip())
            metrics["memory"] = cls._parse_free_bytes(sections.get("free", ""))
            metrics["disk_root"] = cls._parse_disk_root(sections.get("df", ""))
            route_out = sections.get("route", "").strip()
            iface = cls._parse_main_interface(route_out)
            metrics["main_interface"] = iface
            if iface:
                netdev_out = sections.get("netdev", "")
                metrics["network"] = cls._parse_net_dev_counters(netdev_out, iface)
        except Exception as exc:
            metrics["errors"].append(f"SSH monitoring failed: {exc}")
            return metrics

        protocol_container_names = {p.container_name for p in enabled_protocols if p.container_name}
        try:
            docker_out = RuntimeCommandService.run(server, actor, "monitoring.docker", "docker ps --format '{{.Names}}	{{.Status}}'").stdout
            containers = cls._parse_docker_ps_statuses(docker_out)
            for row in containers:
                row["is_protocol_container"] = row["name"] in protocol_container_names
            metrics["docker"]["containers"] = containers
        except Exception as exc:
            metrics["docker"] = {"available": False, "containers": []}
            metrics["errors"].append(f"Docker metrics unavailable: {exc}")

        for protocol in enabled_protocols:
            protocol_row = {
                "protocol_type": protocol.protocol_type,
                "container_name": protocol.container_name or "",
                "interface": (protocol.runtime_metadata or {}).get("interface", ""),
                "config_path": (protocol.runtime_metadata or {}).get("config_path", ""),
                "peer_counts": None,
                "available": False,
                "error": "",
            }
            if not protocol_row["container_name"] or not protocol_row["interface"] or not protocol_row["config_path"]:
                protocol_row["error"] = "Недостаточно данных runtime (container/interface/config_path)."
                metrics["protocols"].append(protocol_row)
                continue
            try:
                peer_cmd = "docker exec {container} sh -lc 'grep -c \"^\\[Peer\\]\" {config}; wg show {iface} peers | wc -l'".format(
                    container=shlex.quote(protocol_row["container_name"]),
                    config=shlex.quote(protocol_row["config_path"]),
                    iface=shlex.quote(protocol_row["interface"]),
                )
                peer_out = RuntimeCommandService.run(
                    server,
                    actor,
                    f"monitoring.protocol.peers.{protocol.protocol_type}",
                    peer_cmd,
                ).stdout.splitlines()
                if len(peer_out) >= 2:
                    protocol_row["peer_counts"] = {
                        "file_peers": int(peer_out[0].strip() or 0),
                        "live_peers": int(peer_out[1].strip() or 0),
                    }
                    protocol_row["available"] = True
                else:
                    protocol_row["error"] = "Некорректный ответ команды peers."
            except Exception as exc:
                protocol_row["error"] = str(exc)
            metrics["protocols"].append(protocol_row)

        return metrics

    @staticmethod
    def update_health(server: Server, status: str) -> Server:
        server.health_status = status
        server.save(update_fields=["health_status", "updated_at"])
        return server

    @staticmethod
    def refresh_health_with_job(server: Server, actor):
        return JobService.create_job(server=server, actor=actor, action="server.health_check", payload={"server_id": server.id})

    @classmethod
    def evaluate_health(cls, server: Server) -> dict:
        if not server.last_runtime_sync_at:
            return {
                "status": cls.HEALTH_NOT_CHECKED,
                "reasons": ["Проверка не запускалась. Выполните синхронизацию runtime."],
            }

        protocols = list(server.protocols.all())
        protocol_map = {protocol.protocol_type: protocol for protocol in protocols}

        reasons = []
        blocking_issues = []
        degraded_issues = []
        usable_protocols = 0

        for protocol_type, container_name in cls.CONTAINERS.items():
            protocol = protocol_map.get(protocol_type)
            if not protocol:
                blocking_issues.append(f"{protocol_type.upper()}: протокол не обнаружен после синхронизации")
                continue

            metadata = protocol.runtime_metadata or {}
            status = (protocol.container_status or "").lower().strip()
            running = status == "running"
            subnet_ready = bool(metadata.get("subnet_ready"))
            endpoint_host_ready = bool(metadata.get("endpoint_host_ready"))
            endpoint_port_ready = bool(metadata.get("endpoint_port_ready"))
            protocol_ready = running and subnet_ready and endpoint_host_ready and endpoint_port_ready

            if status == "missing":
                blocking_issues.append(f"{protocol_type.upper()}: контейнер {container_name} отсутствует")
                continue
            if not running:
                blocking_issues.append(f"{protocol_type.upper()}: контейнер не запущен (статус: {status or 'unknown'})")
            if not subnet_ready:
                blocking_issues.append(f"{protocol_type.upper()}: не определена подсеть")
            if not endpoint_host_ready:
                blocking_issues.append(f"{protocol_type.upper()}: не готов endpoint host")
            if not endpoint_port_ready:
                blocking_issues.append(f"{protocol_type.upper()}: не готов endpoint port")

            if protocol_type == ServerProtocol.ProtocolType.AWG2:
                awg2_metadata_ready = metadata.get("awg2_metadata_ready", True)
                if not awg2_metadata_ready:
                    missing = ", ".join(metadata.get("awg2_missing_keys", [])) or "обязательные параметры"
                    blocking_issues.append(f"AWG2: отсутствуют обязательные параметры ({missing})")

                peer_source = (metadata.get("peer_source", "") or "").lower()
                if "degraded telemetry" in peer_source or "fallback" in peer_source:
                    degraded_issues.append("AWG2: runtime-телеметрия недоступна, используется fallback из конфигурации")

            if protocol_ready:
                if protocol_type != ServerProtocol.ProtocolType.AWG2 or metadata.get("awg2_metadata_ready", True):
                    usable_protocols += 1

        if not usable_protocols:
            reasons.extend(blocking_issues or ["Нет рабочего протокольного пути для клиентов"])
            return {
                "status": cls.HEALTH_UNHEALTHY,
                "reasons": reasons,
            }

        if blocking_issues or degraded_issues:
            reasons.extend(blocking_issues)
            reasons.extend(degraded_issues)
            return {
                "status": cls.HEALTH_DEGRADED,
                "reasons": reasons,
            }

        return {
            "status": cls.HEALTH_HEALTHY,
            "reasons": ["SSH-команды, контейнеры и базовая готовность протоколов подтверждены."],
        }

    @classmethod
    def evaluate_and_update_health(cls, server: Server) -> dict:
        result = cls.evaluate_health(server)
        cls.update_health(server, result["status"])
        return result

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
            protocol, created = ServerProtocol.objects.get_or_create(server=server, protocol_type=protocol_type)
            original_enabled = protocol.enabled
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
                        if protocol_type == ServerProtocol.ProtocolType.AWG2:
                            dump_result = RuntimeCommandService.run_with_expected_failure(
                                server,
                                actor,
                                f"runtime.peers.{protocol_type}.all",
                                f"docker exec {container_name} wg show all dump",
                                expected_error_patterns=RuntimeCommandService.AWG2_EXPECTED_RUNTIME_DUMP_ERRORS,
                                fallback_message="AWG2 runtime telemetry unavailable: using config fallback (degraded mode).",
                                warn_on_expected_failure=False,
                            )
                            if dump_result is None:
                                dump_result = RuntimeCommandService.run_with_expected_failure(
                                    server,
                                    actor,
                                    f"runtime.peers.{protocol_type}",
                                    f"docker exec {container_name} wg show dump",
                                    expected_error_patterns=RuntimeCommandService.AWG2_EXPECTED_RUNTIME_DUMP_ERRORS,
                                    fallback_message="AWG2 runtime telemetry unavailable: using config fallback (degraded mode).",
                                )
                                if dump_result is None:
                                    peer_source = "runtime telemetry unavailable; config fallback"
                                else:
                                    peer_count = sum(1 for line in dump_result.stdout.splitlines() if len(line.split("\t")) >= 8)
                                    peer_source = "runtime wg dump"
                            else:
                                peer_count = sum(1 for line in dump_result.stdout.splitlines() if len(line.split("\t")) >= 8)
                                peer_source = "runtime wg dump"
                        else:
                            dump = RuntimeCommandService.run(server, actor, f"runtime.peers.{protocol_type}", f"docker exec {container_name} wg show dump").stdout
                            peer_count = sum(1 for line in dump.splitlines() if len(line.split("\t")) >= 8)
                            peer_source = "runtime wg dump"
                    except Exception:
                        iface = ""
                        peer_count = 0
                        peer_source = "runtime wg dump failed"

                    for path in cls._candidate_config_paths(iface or "wg0"):
                        try:
                            raw_iface_conf = RuntimeCommandService.run(server, actor, f"runtime.conf.{protocol_type}", f"docker exec {container_name} cat {path}").stdout
                            if raw_iface_conf:
                                config_path = path
                                break
                        except Exception:
                            continue
                    if protocol_type == ServerProtocol.ProtocolType.AWG2 and raw_iface_conf:
                        if peer_source != "runtime wg dump":
                            peer_count = len(cls._parse_peers_from_config_text(raw_iface_conf))
                            peer_source = "config file fallback (degraded telemetry)"

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
            else:
                protocol.container_status = "missing"
                protocol.runtime_metadata = {}

            protocol.enabled = (container_name in running_names) if created else original_enabled
            protocol.last_sync_at = timezone.now()
            protocol.save(update_fields=["container_name", "container_status", "runtime_metadata", "enabled", "last_sync_at"])

        server.last_runtime_sync_at = timezone.now()
        server.save(update_fields=["last_runtime_sync_at"])
        cls.evaluate_and_update_health(server)
        AuditService.log(actor, "server.runtime.sync", "Server", server.id)
        return server
