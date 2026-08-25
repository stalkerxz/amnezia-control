from __future__ import annotations

import base64
import json
import uuid

from django.utils import timezone

from audit.services import AuditService
from jobs.executors import SafeSSHExecutor
from servers.models import Server, ServerProtocol
from vpn.services import AdapterFactory, PeerState, RuntimeCommandService


BRIDGE_PATH = "/usr/local/sbin/amnezia-control-agent-call"
BRIDGE_PATTERN = (
    r"^/usr/local/sbin/amnezia-control-agent-call "
    r"(?:awg3|awg4) [A-Za-z0-9_-]+$"
)
AGENT_AWG3_SENTINEL = "awg-agent:awg3"
AGENT_AWG4_SENTINEL = "awg-agent:awg4"
AWG2_REQUIRED_KEYS = (
    "Jc",
    "Jmin",
    "Jmax",
    "S1",
    "S2",
    "S3",
    "S4",
    "H1",
    "H2",
    "H3",
    "H4",
)
AWG2_OPTIONAL_KEYS = ("I1", "I2", "I3", "I4", "I5")

_installed = False
_original_sync_runtime_state = None
_original_collect_load_metrics = None
_original_adapter_for_server = None


def _encode_payload(operation: str, **payload) -> str:
    raw = json.dumps(
        {"op": operation, **payload},
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _agent_call(
    server: Server,
    actor,
    agent: str,
    operation: str,
    *,
    sensitive_output: bool = False,
    **payload,
) -> dict:
    if agent not in {"awg3", "awg4"}:
        raise ValueError("Unsupported AWG agent")

    token = _encode_payload(operation, **payload)
    command = f"{BRIDGE_PATH} {agent} {token}"
    result = RuntimeCommandService.run(
        server,
        actor,
        f"agent.{agent}.{operation}",
        command,
        sensitive_output=sensitive_output,
    )
    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid {agent} agent bridge response"
        ) from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"Invalid {agent} agent bridge result")
    return parsed


def _parse_config_sections(config: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    current = ""
    for raw_line in (config or "").splitlines():
        text = raw_line.strip()
        if not text or text.startswith("#"):
            continue
        if text.startswith("[") and text.endswith("]"):
            current = text[1:-1].strip()
            sections.setdefault(current, {})
            continue
        if "=" not in text or not current:
            continue
        key, value = [part.strip() for part in text.split("=", 1)]
        sections[current][key] = value
    return sections


def _stable_client_id(server: Server, public_key: str) -> str:
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"amnezia-control://server/{server.pk}/peer/{public_key}",
        )
    )


class RemoteAWG2AgentAdapter:
    """AWG2 adapter backed by the remote AWG4 host agent.

    The central application still stores its canonical client config and
    lifecycle state. Runtime mutations are delegated to the already-installed
    AWG4 agent through the restricted SSH bridge.
    """

    protocol_type = "awg2"

    def __init__(self, server: Server):
        self.server = server
        self.protocol = ServerProtocol.objects.filter(
            server=server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
        ).first()
        if not self.protocol:
            raise ValueError("AWG2 agent runtime is not discovered")
        metadata = self.protocol.runtime_metadata or {}
        if metadata.get("backend") != Server.RuntimeBackend.AWG_AGENT:
            raise ValueError("AWG2 protocol is not backed by an AWG agent")
        if metadata.get("agent") != "awg4":
            raise ValueError("Unsupported AWG2 agent mapping")

    def _call(
        self,
        actor,
        operation: str,
        *,
        sensitive_output: bool = False,
        **payload,
    ) -> dict:
        return _agent_call(
            self.server,
            actor,
            "awg4",
            operation,
            sensitive_output=sensitive_output,
            **payload,
        )

    def create_peer(self, actor):
        result = self._call(
            actor,
            "create_peer",
            sensitive_output=True,
            client_id=str(uuid.uuid4()),
            client_name="central-awg2",
            mode="full",
            allowed_ips=["0.0.0.0/0"],
        )
        sections = _parse_config_sections(result.get("conf", ""))
        interface = sections.get("Interface", {})
        peer = sections.get("Peer", {})

        private_key = interface.get("PrivateKey", "")
        server_public_key = peer.get("PublicKey", "")
        public_key = str(result.get("public_key", "")).strip()
        address = str(result.get("address", "")).strip().split("/", 1)[0]

        if not private_key or not server_public_key or not public_key or not address:
            if public_key:
                try:
                    self._call(
                        actor,
                        "revoke_peer",
                        sensitive_output=True,
                        public_key=public_key,
                    )
                except Exception:
                    pass
            raise RuntimeError("AWG4 agent returned incomplete peer material")

        return {
            "private_key": private_key,
            "public_key": public_key,
            "preshared_key": "",
            "address": address,
            "iface": (self.protocol.runtime_metadata or {}).get(
                "interface",
                "awg4",
            ),
            "server_public_key": server_public_key,
        }

    def discover_peers(self, actor):
        listed = self._call(actor, "list_peers")
        telemetry = self._call(actor, "peer_statuses")
        status_map = telemetry.get("peers", {})
        if not isinstance(status_map, dict):
            status_map = {}

        peers = []
        for item in listed.get("peers", []):
            if not isinstance(item, dict):
                continue
            public_key = str(item.get("public_key", "")).strip()
            allowed_ips = str(item.get("allowed_ips", "")).strip()
            if not public_key or not allowed_ips:
                continue
            status = status_map.get(public_key, {})
            if not isinstance(status, dict):
                status = {}
            peers.append(
                PeerState(
                    public_key=public_key,
                    allowed_ips=allowed_ips,
                    transfer_rx=int(status.get("rx_bytes") or 0),
                    transfer_tx=int(status.get("tx_bytes") or 0),
                    telemetry_state=PeerState.TELEMETRY_AVAILABLE,
                )
            )
        return peers

    def list_peers(self, actor):
        return self.discover_peers(actor)

    def peer_transfer_map(self, actor) -> dict[str, int] | None:
        try:
            result = self._call(actor, "peer_statuses")
        except Exception:
            return None
        peers = result.get("peers", {})
        if not isinstance(peers, dict):
            return None
        transfers = {}
        for public_key, status in peers.items():
            if not isinstance(status, dict):
                continue
            transfers[str(public_key)] = int(status.get("rx_bytes") or 0) + int(
                status.get("tx_bytes") or 0
            )
        return transfers

    def disable_peer(self, actor, peer_public_key: str):
        # Docker-backed clients are disabled by removing the runtime peer while
        # retaining central config. Revoke has the same runtime semantics here;
        # add_existing_peer restores the peer on re-enable.
        self.remove_peer(actor, peer_public_key)

    def remove_peer(self, actor, peer_public_key: str):
        self._call(
            actor,
            "revoke_peer",
            sensitive_output=True,
            public_key=peer_public_key,
        )

    def add_existing_peer(
        self,
        actor,
        *,
        peer_public_key: str,
        allowed_ips: str,
        preshared_key: str = "",
    ):
        if preshared_key:
            raise RuntimeError(
                "AWG4 agent restore does not support preshared keys"
            )
        address = str(allowed_ips).split(",", 1)[0].strip()
        self._call(
            actor,
            "activate_peer",
            sensitive_output=True,
            public_key=peer_public_key,
            address=address,
            client_id=_stable_client_id(self.server, peer_public_key),
            client_name=f"central-{peer_public_key[:10]}",
        )


def _protocol_metadata(server: Server, info: dict, *, agent: str) -> dict:
    public_host_ready = bool(
        server.public_endpoint_host
        or server.host
    )
    udp_port = info.get("udp_port") or info.get("listen_port")
    metadata = {
        "backend": Server.RuntimeBackend.AWG_AGENT,
        "agent": agent,
        "config_path": info.get("config_path", ""),
        "udp_port": int(udp_port) if udp_port else None,
        "public_host": "",
        "image": "",
        "mounts": [],
        "env": [],
        "interface": info.get("interface", ""),
        "interface_addresses": info.get("interface_addresses", []),
        "peer_count": int(info.get("peer_count") or 0),
        "peer_source": f"{agent} agent",
        "subnet": info.get("subnet", ""),
        "subnet_ready": bool(info.get("subnet")),
        "endpoint_host_ready": public_host_ready,
        "endpoint_port_ready": bool(server.public_endpoint_port or udp_port),
        "reservation_count": int(info.get("reservation_count") or 0),
    }
    return metadata


def _sync_agent_runtime(server: Server, actor):
    from servers.services import ServerService

    awg3_info = _agent_call(server, actor, "awg3", "runtime_info")
    awg4_info = _agent_call(server, actor, "awg4", "runtime_info")
    now = timezone.now()

    legacy, _ = ServerProtocol.objects.get_or_create(
        server=server,
        protocol_type=ServerProtocol.ProtocolType.AWG,
    )
    legacy.container_name = AGENT_AWG3_SENTINEL
    legacy.container_status = (
        "running" if awg3_info.get("interface_up") else "exited"
    )
    legacy.runtime_metadata = {
        **_protocol_metadata(server, awg3_info, agent="awg3"),
        "central_protocol_supported": False,
    }
    legacy.enabled = False
    legacy.last_sync_at = now
    legacy.save(
        update_fields=[
            "container_name",
            "container_status",
            "runtime_metadata",
            "enabled",
            "last_sync_at",
        ]
    )

    awg2, _ = ServerProtocol.objects.get_or_create(
        server=server,
        protocol_type=ServerProtocol.ProtocolType.AWG2,
    )
    awg2_meta = dict(awg4_info.get("awg2_metadata") or {})
    required_missing = [
        key for key in AWG2_REQUIRED_KEYS if not awg2_meta.get(key)
    ]
    optional_missing = [
        key for key in AWG2_OPTIONAL_KEYS if not awg2_meta.get(key)
    ]
    awg31_required_missing = [
        key
        for key in ServerService.AWG31_REQUIRED_KEYS
        if not awg2_meta.get(key)
    ]
    awg2.container_name = AGENT_AWG4_SENTINEL
    awg2.container_status = (
        "running" if awg4_info.get("interface_up") else "exited"
    )
    awg2.runtime_metadata = {
        **_protocol_metadata(server, awg4_info, agent="awg4"),
        "awg2_metadata": awg2_meta,
        "awg2_active_keys": sorted(awg2_meta),
        "awg2_missing_keys": required_missing,
        "awg2_optional_missing_keys": optional_missing,
        "awg2_metadata_ready": not required_missing,
        "awg31_metadata_ready": not awg31_required_missing,
        "awg31_missing_keys": awg31_required_missing,
        "central_protocol_supported": True,
    }
    awg2.enabled = bool(awg4_info.get("interface_up"))
    awg2.last_sync_at = now
    awg2.save(
        update_fields=[
            "container_name",
            "container_status",
            "runtime_metadata",
            "enabled",
            "last_sync_at",
        ]
    )

    server.last_runtime_sync_at = now
    server.save(update_fields=["last_runtime_sync_at"])
    ServerService.evaluate_and_update_health(server)
    AuditService.log(
        actor,
        "server.runtime.sync",
        "Server",
        server.id,
        {"backend": Server.RuntimeBackend.AWG_AGENT},
    )
    return server


def _collect_agent_metrics(server: Server, actor):
    from servers.services import ServerService

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
        bundle = RuntimeCommandService.run(
            server,
            actor,
            "monitoring.host_bundle",
            host_bundle_cmd,
        ).stdout
        sections = ServerService._parse_labeled_sections(bundle)
        metrics["hostname"] = sections.get("hostname", "").strip() or server.host
        uptime = sections.get("uptime", "")
        metrics["uptime"] = uptime
        metrics["load_average"] = ServerService._parse_load_average(uptime)
        metrics["cpu_cores"] = int(
            (sections.get("nproc", "0").splitlines() or ["0"])[0].strip()
        )
        metrics["memory"] = ServerService._parse_free_bytes(
            sections.get("free", "")
        )
        metrics["disk_root"] = ServerService._parse_disk_root(
            sections.get("df", "")
        )
        iface = ServerService._parse_main_interface(
            sections.get("route", "").strip()
        )
        metrics["main_interface"] = iface
        if iface:
            metrics["network"] = ServerService._parse_net_dev_counters(
                sections.get("netdev", ""),
                iface,
            )
    except Exception as exc:
        metrics["errors"].append(f"SSH monitoring failed: {exc}")
        return metrics

    try:
        docker_out = RuntimeCommandService.run(
            server,
            actor,
            "monitoring.docker",
            "docker ps --format '{{.Names}}\t{{.Status}}'",
        ).stdout
        metrics["docker"]["containers"] = ServerService._parse_docker_ps_statuses(
            docker_out
        )
    except Exception as exc:
        metrics["docker"] = {"available": False, "containers": []}
        metrics["errors"].append(f"Docker metrics unavailable: {exc}")

    for protocol in server.protocols.filter(enabled=True).order_by("protocol_type"):
        metadata = protocol.runtime_metadata or {}
        if metadata.get("backend") != Server.RuntimeBackend.AWG_AGENT:
            continue
        agent = metadata.get("agent", "")
        row = {
            "protocol_type": protocol.protocol_type,
            "container_name": protocol.container_name or "",
            "interface": metadata.get("interface", ""),
            "config_path": metadata.get("config_path", ""),
            "peer_counts": None,
            "available": False,
            "error": "",
        }
        try:
            info = _agent_call(server, actor, agent, "runtime_info")
            statuses = _agent_call(server, actor, agent, "peer_statuses")
            peers = statuses.get("peers", {})
            row["peer_counts"] = {
                "file_peers": int(info.get("peer_count") or 0),
                "live_peers": len(peers) if isinstance(peers, dict) else 0,
            }
            row["available"] = bool(info.get("interface_up"))
        except Exception as exc:
            row["error"] = str(exc)
        metrics["protocols"].append(row)

    return metrics


def install_agent_backend() -> None:
    global _installed
    global _original_sync_runtime_state
    global _original_collect_load_metrics
    global _original_adapter_for_server

    if _installed:
        return

    if BRIDGE_PATTERN not in SafeSSHExecutor.ALLOWED_PATTERNS:
        SafeSSHExecutor.ALLOWED_PATTERNS.append(BRIDGE_PATTERN)

    from servers.services import ServerService

    _original_sync_runtime_state = ServerService.sync_runtime_state
    _original_collect_load_metrics = ServerService.collect_load_metrics
    _original_adapter_for_server = AdapterFactory.get_for_server

    def sync_runtime_state(cls, *, server: Server, actor):
        if server.runtime_backend == Server.RuntimeBackend.AWG_AGENT:
            return _sync_agent_runtime(server, actor)
        return _original_sync_runtime_state(server=server, actor=actor)

    def collect_load_metrics(cls, server: Server, actor):
        if server.runtime_backend == Server.RuntimeBackend.AWG_AGENT:
            return _collect_agent_metrics(server, actor)
        return _original_collect_load_metrics(server, actor)

    def get_for_server(server: Server, protocol_type: str):
        if (
            server.runtime_backend == Server.RuntimeBackend.AWG_AGENT
            and protocol_type == ServerProtocol.ProtocolType.AWG2
        ):
            return RemoteAWG2AgentAdapter(server)
        return _original_adapter_for_server(server, protocol_type)

    ServerService.sync_runtime_state = classmethod(sync_runtime_state)
    ServerService.collect_load_metrics = classmethod(collect_load_metrics)
    AdapterFactory.get_for_server = staticmethod(get_for_server)

    _installed = True
