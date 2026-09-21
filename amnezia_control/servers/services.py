import ipaddress
import json
import re
import shlex

from django.utils import timezone

from audit.services import AuditService
from jobs.services import JobService
from vpn.services import ConfigCryptoService, RuntimeCommandService

from .models import Server, ServerProtocol


class ServerService:
    CONTAINERS = {
        ServerProtocol.ProtocolType.AWG: "amnezia-awg",
        ServerProtocol.ProtocolType.AWG2: "amnezia-awg2",
    }
    AWG2_REQUIRED_KEYS = ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"]
    AWG2_OPTIONAL_KEYS = ["I1", "I2", "I3", "I4", "I5"]
    AWG3_KEYS = [
        "HeaderProtectionKey",
        "ContentPaddingAddition",
        "RekeyAfterTime",
        "RekeyTimeout",
        "RejectAfterTime",
        "KeepaliveTimeout",
        "MaxHandshakeAttempts",
        "RandomTrailers",
        "DisableCookies",
    ]
    AWG_SENSITIVE_KEYS = {"HeaderProtectionKey"}
    AWG_STANDARD_INTERFACE_KEYS = {
        "PrivateKey", "Address", "ListenPort", "DNS", "MTU", "Table",
        "PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig", "FwMark",
    }
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
                "command_bin": (protocol.runtime_metadata or {}).get("command_bin", "wg"),
                "peer_counts": None,
                "available": False,
                "error": "",
            }
            if not protocol_row["container_name"] or not protocol_row["interface"] or not protocol_row["config_path"]:
                protocol_row["error"] = "Недостаточно данных runtime (container/interface/config_path)."
                metrics["protocols"].append(protocol_row)
                continue
            try:
                command_bin = str(protocol_row["command_bin"] or "wg").strip()
                if command_bin not in {"wg", "awg"}:
                    raise RuntimeError(f"Unsupported runtime command binary: {command_bin}")
                peer_cmd = "docker exec {container} sh -lc 'grep -c \"^\\[Peer\\]\" {config}; {command_bin} show {iface} peers | wc -l'".format(
                    container=shlex.quote(protocol_row["container_name"]),
                    config=shlex.quote(protocol_row["config_path"]),
                    command_bin=command_bin,
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
                continue
            if not protocol.enabled:
                continue

            metadata = protocol.runtime_metadata or {}
            status = (protocol.container_status or "").lower().strip()
            running = status == "running"
            subnet_ready = bool(metadata.get("subnet_ready"))
            endpoint_host_ready = bool(metadata.get("endpoint_host_ready"))
            endpoint_port_ready = bool(metadata.get("endpoint_port_ready"))
            runtime_interface_ready = metadata.get("runtime_interface_ready", True)
            runtime_listener_ready = metadata.get("runtime_listener_ready", True)
            protocol_ready = (
                running
                and subnet_ready
                and endpoint_host_ready
                and endpoint_port_ready
                and runtime_interface_ready
                and runtime_listener_ready
            )

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

                if metadata.get("runtime_interface_ready") is False:
                    blocking_issues.append("AWG2: runtime-интерфейс не обнаружен")
                if metadata.get("runtime_listener_ready") is False:
                    blocking_issues.append("AWG2: runtime listen-port не подтвержден")

                peer_source = (metadata.get("peer_source", "") or "").lower()
                if "degraded telemetry" in peer_source or "fallback" in peer_source:
                    degraded_issues.append("AWG2: runtime-телеметрия недоступна, используется fallback из конфигурации")
                elif metadata.get("runtime_command_ready") is False:
                    degraded_issues.append("AWG2: runtime-команды недоступны")

                unsupported_keys = metadata.get("awg_unsupported_keys", [])
                if unsupported_keys:
                    degraded_issues.append(
                        "AWG2: обнаружены неподдерживаемые runtime-параметры; переиздание заблокировано: "
                        + ", ".join(unsupported_keys)
                    )
                if metadata.get("mtu_mismatch"):
                    degraded_issues.append(
                        f"AWG2: MTU mismatch config={metadata.get('config_mtu')} runtime={metadata.get('runtime_mtu')}"
                    )

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
        mtu = None
        section = ""
        for line in raw_conf.splitlines():
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            if text.startswith("[") and text.endswith("]"):
                section = text.strip("[]").lower()
                continue
            if section and section != "interface":
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
            if text.lower().startswith("mtu") and "=" in text:
                try:
                    mtu = int(text.split("=", 1)[1].strip())
                except ValueError:
                    mtu = None
        return subnet, listen_port, mtu

    @staticmethod
    def _parse_runtime_mtu(ip_link_output: str):
        match = re.search(r"\bmtu\s+(\d+)\b", ip_link_output or "")
        return int(match.group(1)) if match else None

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
        compact = re.sub(r"[^A-Za-z0-9]", "", key).upper().replace("AWG2", "").replace("AWG3", "")
        mapping = {
            "JC": "Jc",
            "JMIN": "Jmin",
            "JMAX": "Jmax",
            "HEADERPROTECTIONKEY": "HeaderProtectionKey",
            "CONTENTPADDINGADDITION": "ContentPaddingAddition",
            "REKEYAFTERTIME": "RekeyAfterTime",
            "REKEYTIMEOUT": "RekeyTimeout",
            "REJECTAFTERTIME": "RejectAfterTime",
            "KEEPALIVETIMEOUT": "KeepaliveTimeout",
            "MAXHANDSHAKEATTEMPTS": "MaxHandshakeAttempts",
            "RANDOMTRAILERS": "RandomTrailers",
            "DISABLECOOKIES": "DisableCookies",
        }
        if compact in mapping:
            return mapping[compact]
        if re.fullmatch(r"I[1-5]|S[1-4]|H[1-4]", compact):
            return compact
        return ""

    @classmethod
    def _parse_awg2_metadata(cls, env_list, conf_text: str):
        discovered = {}
        allowed = set(cls.AWG2_REQUIRED_KEYS + cls.AWG2_OPTIONAL_KEYS + cls.AWG3_KEYS)

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

    @classmethod
    def _protect_awg_metadata(cls, metadata: dict) -> tuple[dict, dict]:
        public_metadata = dict(metadata)
        encrypted_metadata = {}
        for key in cls.AWG_SENSITIVE_KEYS:
            value = public_metadata.pop(key, "")
            if value:
                encrypted_metadata[key] = ConfigCryptoService.encrypt(str(value))
        return public_metadata, encrypted_metadata

    @classmethod
    def _awg_generation(cls, metadata: dict) -> str:
        if any(str(metadata.get(key, "")).strip() for key in cls.AWG3_KEYS):
            return "3.1"
        if any(str(metadata.get(key, "")).strip() for key in cls.AWG2_REQUIRED_KEYS):
            return "2"
        if any(str(metadata.get(key, "")).strip() for key in cls.AWG2_OPTIONAL_KEYS):
            return "1.5"
        return "unknown"

    @classmethod
    def _awg_capabilities(cls, metadata: dict) -> list[str]:
        capabilities = []
        if any(metadata.get(key) for key in cls.AWG2_REQUIRED_KEYS + cls.AWG2_OPTIONAL_KEYS):
            capabilities.append("legacy_obfuscation")
        capability_keys = {
            "HeaderProtectionKey": "header_protection",
            "ContentPaddingAddition": "content_padding",
            "RekeyAfterTime": "configurable_rekey",
            "RekeyTimeout": "configurable_rekey",
            "RejectAfterTime": "configurable_reject",
            "KeepaliveTimeout": "configurable_keepalive",
            "MaxHandshakeAttempts": "configurable_handshake_attempts",
            "RandomTrailers": "random_trailers",
            "DisableCookies": "disable_cookies",
        }
        for key, capability in capability_keys.items():
            if metadata.get(key) and capability not in capabilities:
                capabilities.append(capability)
        return capabilities

    @classmethod
    def _unsupported_awg_interface_keys(cls, conf_text: str) -> list[str]:
        known = set(cls.AWG2_REQUIRED_KEYS + cls.AWG2_OPTIONAL_KEYS + cls.AWG3_KEYS)
        section = ""
        unsupported = []
        for line in conf_text.splitlines():
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            if text.startswith("[") and text.endswith("]"):
                section = text.strip("[]").lower()
                continue
            if section != "interface" or "=" not in text:
                continue
            key = text.split("=", 1)[0].strip()
            if key in known or key in cls.AWG_STANDARD_INTERFACE_KEYS:
                continue
            if re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", key):
                unsupported.append(key)
        return sorted(set(unsupported))

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
            previous_metadata = protocol.runtime_metadata or {}
            protocol.container_name = container_name

            if container_name in all_names:
                inspect_raw = RuntimeCommandService.run(server, actor, f"runtime.inspect.{protocol_type}", f"docker inspect {container_name}").stdout
                inspect_data = json.loads(inspect_raw)
                config_env = inspect_data[0].get("Config", {}).get("Env", [])

                iface = ""
                command_bin = str(previous_metadata.get("command_bin") or "wg").strip()
                if command_bin not in {"wg", "awg"}:
                    command_bin = "wg"
                peer_count = 0
                peer_source = "none"
                raw_iface_conf = ""
                config_path = ""
                runtime_mtu = None
                runtime_listener_port = None

                if container_name in running_names:
                    candidates = [command_bin] + [item for item in ("wg", "awg") if item != command_bin]
                    for candidate in candidates:
                        try:
                            iface_out = RuntimeCommandService.run(
                                server,
                                actor,
                                f"runtime.iface.{protocol_type}",
                                f"docker exec {container_name} {candidate} show interfaces",
                            ).stdout.strip()
                            if iface_out:
                                iface = iface_out.split()[0]
                                command_bin = candidate
                                break
                        except Exception:
                            continue

                    if iface:
                        try:
                            if protocol_type == ServerProtocol.ProtocolType.AWG2:
                                dump_result = RuntimeCommandService.run_with_expected_failure(
                                    server,
                                    actor,
                                    f"runtime.peers.{protocol_type}.all",
                                    f"docker exec {container_name} {command_bin} show all dump",
                                    expected_error_patterns=RuntimeCommandService.AWG2_EXPECTED_RUNTIME_DUMP_ERRORS,
                                    fallback_message="AWG2 runtime telemetry unavailable: using config fallback (degraded mode).",
                                    warn_on_expected_failure=False,
                                )
                                if dump_result is None:
                                    dump_result = RuntimeCommandService.run_with_expected_failure(
                                        server,
                                        actor,
                                        f"runtime.peers.{protocol_type}",
                                        f"docker exec {container_name} {command_bin} show dump",
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
                                dump = RuntimeCommandService.run(
                                    server,
                                    actor,
                                    f"runtime.peers.{protocol_type}",
                                    f"docker exec {container_name} {command_bin} show dump",
                                ).stdout
                                peer_count = sum(1 for line in dump.splitlines() if len(line.split("\t")) >= 8)
                                peer_source = "runtime wg dump"
                        except Exception:
                            peer_count = 0
                            peer_source = "runtime wg dump failed"

                        if protocol_type == ServerProtocol.ProtocolType.AWG2:
                            try:
                                mtu_out = RuntimeCommandService.run(
                                    server,
                                    actor,
                                    f"runtime.mtu.{protocol_type}",
                                    f"docker exec {container_name} ip -o link show {iface}",
                                ).stdout
                                runtime_mtu = cls._parse_runtime_mtu(mtu_out)
                            except Exception:
                                runtime_mtu = None
                            try:
                                listener_out = RuntimeCommandService.run(
                                    server,
                                    actor,
                                    f"runtime.listen_port.{protocol_type}",
                                    f"docker exec {container_name} {command_bin} show {iface} listen-port",
                                ).stdout.strip()
                                runtime_listener_port = int(listener_out) if listener_out.isdigit() else None
                            except Exception:
                                runtime_listener_port = None

                    for path in cls._candidate_config_paths(iface or "wg0"):
                        try:
                            raw_iface_conf = RuntimeCommandService.run(
                                server,
                                actor,
                                f"runtime.conf.{protocol_type}",
                                f"docker exec {container_name} cat {path}",
                            ).stdout
                            if raw_iface_conf:
                                config_path = path
                                break
                        except Exception:
                            continue
                    if protocol_type == ServerProtocol.ProtocolType.AWG2 and raw_iface_conf:
                        if peer_source != "runtime wg dump":
                            peer_count = len(cls._parse_peers_from_config_text(raw_iface_conf))
                            peer_source = "config file fallback (degraded telemetry)"

                subnet, listen_port, config_mtu = cls._parse_interface_metadata(raw_iface_conf)
                awg2_meta, awg2_required_missing, awg2_optional_missing = ({}, [], [])
                awg2_meta_for_storage = {}
                awg_sensitive_metadata_encrypted = {}
                awg_generation = ""
                awg_capabilities = []
                awg_unsupported_keys = []
                if protocol_type == ServerProtocol.ProtocolType.AWG2:
                    awg2_meta, awg2_required_missing, awg2_optional_missing = cls._parse_awg2_metadata(config_env, raw_iface_conf)
                    awg_generation = cls._awg_generation(awg2_meta)
                    awg_capabilities = cls._awg_capabilities(awg2_meta)
                    awg_unsupported_keys = cls._unsupported_awg_interface_keys(raw_iface_conf)
                    awg2_meta_for_storage, awg_sensitive_metadata_encrypted = cls._protect_awg_metadata(awg2_meta)

                udp_port = cls._parse_udp_port(inspect_data) or listen_port or runtime_listener_port
                discovered_public_host = cls._parse_public_host(inspect_data)
                endpoint_host_ready = cls._is_public_host(server.public_endpoint_host) or cls._is_public_host(server.host) or cls._is_public_host(discovered_public_host)
                endpoint_port_ready = bool(server.public_endpoint_port or udp_port)
                subnet_ready = bool(subnet)
                runtime_interface_ready = bool(iface)
                runtime_command_ready = peer_source == "runtime wg dump"
                runtime_listener_ready = bool(runtime_listener_port) if protocol_type == ServerProtocol.ProtocolType.AWG2 else runtime_interface_ready
                mtu_mismatch = bool(config_mtu and runtime_mtu and config_mtu != runtime_mtu)

                protocol.container_status = inspect_data[0].get("State", {}).get("Status", "unknown")
                protocol.runtime_metadata = {
                    "config_path": config_path,
                    "udp_port": udp_port,
                    "public_host": discovered_public_host,
                    "image": inspect_data[0].get("Config", {}).get("Image", ""),
                    "mounts": [m.get("Destination", "") for m in inspect_data[0].get("Mounts", [])],
                    "env_keys": sorted(item.split("=", 1)[0] for item in config_env if "=" in item),
                    "interface": iface,
                    "command_bin": command_bin,
                    "quick_bin": "awg-quick" if protocol_type == ServerProtocol.ProtocolType.AWG2 else "",
                    "peer_count": peer_count,
                    "peer_source": peer_source,
                    "subnet": subnet,
                    "subnet_ready": subnet_ready,
                    "endpoint_host_ready": endpoint_host_ready,
                    "endpoint_port_ready": endpoint_port_ready,
                    "runtime_interface_ready": runtime_interface_ready,
                    "runtime_command_ready": runtime_command_ready,
                    "runtime_listener_ready": runtime_listener_ready,
                    "config_mtu": config_mtu,
                    "runtime_mtu": runtime_mtu,
                    "mtu_mismatch": mtu_mismatch,
                    "awg_generation": awg_generation,
                    "awg_capabilities": awg_capabilities,
                    "awg_unsupported_keys": awg_unsupported_keys,
                    "awg_config_supported": not awg_unsupported_keys,
                    "awg2_metadata": awg2_meta_for_storage,
                    "awg_sensitive_metadata_encrypted": awg_sensitive_metadata_encrypted,
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
