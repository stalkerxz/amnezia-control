import base64
import hashlib
import io
import ipaddress
import re
import shlex
from collections import defaultdict
from dataclasses import dataclass

import qrcode
from cryptography.fernet import Fernet
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from audit.services import AuditService
from jobs.executors import SafeSSHExecutor
from jobs.services import JobService
from servers.models import ProtocolProfile, Server, ServerProtocol
from .models import ClientConfigRevision, VPNClient


class ConfigCryptoService:
    @staticmethod
    def _fernet() -> Fernet:
        key = settings.CONFIG_ENCRYPTION_KEY
        if not key:
            raise ValueError("CONFIG_ENCRYPTION_KEY is required")
        return Fernet(key.encode())

    @classmethod
    def encrypt(cls, plaintext: str) -> str:
        return cls._fernet().encrypt(plaintext.encode()).decode()

    @classmethod
    def decrypt(cls, encrypted: str) -> str:
        return cls._fernet().decrypt(encrypted.encode()).decode()


@dataclass
class PeerState:
    public_key: str
    allowed_ips: str
    transfer_rx: int = 0
    transfer_tx: int = 0
    telemetry_available: bool = True

    @property
    def transfer_total(self) -> int:
        return self.transfer_rx + self.transfer_tx


class RuntimeCommandService:
    @staticmethod
    def executor_for_server(server: Server):
        return SafeSSHExecutor(
            host=server.host,
            username=server.ssh_username,
            port=server.port,
            key_path=server.ssh_private_key_path or None,
        )

    @staticmethod
    def run(server: Server, actor, action: str, command: str, sensitive_output: bool = False):
        job = JobService.create_job(server=server, actor=actor, action=action, payload={"command": command if not sensitive_output else "[REDACTED]"})
        JobService.mark_running(job)
        result = RuntimeCommandService.executor_for_server(server).run(command)
        JobService.event(
            job,
            f"Executed {action}",
            stdout="" if sensitive_output else result.stdout,
            stderr="" if sensitive_output else result.stderr,
            exit_code=result.exit_code,
            level="info" if result.exit_code == 0 else "error",
        )
        JobService.mark_done(job, ok=result.exit_code == 0)
        if result.exit_code != 0:
            raise RuntimeError(result.stderr or f"command failed: {action}")
        return result


class BaseProtocolAdapter:
    protocol_type = ""
    command_bin = "wg"

    def __init__(self, server: Server):
        self.server = server
        self.protocol = ServerProtocol.objects.filter(server=self.server, protocol_type=self.protocol_type).first()
        if not self.protocol or not self.protocol.container_name:
            raise ValueError(f"Container for {self.protocol_type} not detected")

    @property
    def container(self):
        return self.protocol.container_name

    def _run(self, actor, action, command, sensitive_output=False):
        return RuntimeCommandService.run(self.server, actor, action, command, sensitive_output=sensitive_output)

    def _wg_cmd(self, subcommand: str) -> str:
        return f"docker exec {self.container} {self.command_bin} {subcommand}"

    def interface_name(self, actor) -> str:
        out = self._run(actor, f"{self.protocol_type}.iface", self._wg_cmd("show interfaces")).stdout.strip()
        if not out:
            raise RuntimeError("WireGuard interface not detected")
        return out.split()[0]

    def server_public_key(self, actor, iface: str) -> str:
        return self._run(actor, f"{self.protocol_type}.server_pub", self._wg_cmd(f"show {iface} public-key")).stdout.strip()

    def list_peers(self, actor):
        try:
            out = self._run(actor, f"{self.protocol_type}.list", self._wg_cmd("show dump")).stdout
            peers = []
            for line in out.splitlines():
                cols = line.split("\t")
                if len(cols) >= 8:
                    public_key = cols[0].strip()
                    allowed_ips = cols[3].strip()
                    transfer_rx = int(cols[5].strip()) if len(cols) > 5 and cols[5].strip().isdigit() else 0
                    transfer_tx = int(cols[6].strip()) if len(cols) > 6 and cols[6].strip().isdigit() else 0
                    if public_key:
                        peers.append(
                            PeerState(
                                public_key=public_key,
                                allowed_ips=allowed_ips,
                                transfer_rx=transfer_rx,
                                transfer_tx=transfer_tx,
                            )
                        )
            return peers
        except RuntimeError:
            if self.protocol_type != VPNClient.ProtocolType.AWG2:
                raise
            return self._list_peers_from_config(actor)

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
                    peers.append(
                        PeerState(
                            public_key=current["PublicKey"],
                            allowed_ips=current["AllowedIPs"],
                            transfer_rx=0,
                            transfer_tx=0,
                            telemetry_available=False,
                        )
                    )
                section = text
                current = {}
                continue
            if "=" not in text or section.lower() != "[peer]":
                continue
            k, v = text.split("=", 1)
            current[k.strip()] = v.strip()
        if section.lower() == "[peer]" and current.get("PublicKey") and current.get("AllowedIPs"):
            peers.append(
                PeerState(
                    public_key=current["PublicKey"],
                    allowed_ips=current["AllowedIPs"],
                    transfer_rx=0,
                    transfer_tx=0,
                    telemetry_available=False,
                )
            )
        return peers

    def _list_peers_from_config(self, actor):
        config_path = self.protocol.runtime_metadata.get("config_path", "")
        if not config_path:
            return []
        raw_conf = self._run(actor, f"{self.protocol_type}.list_fallback_conf", f"docker exec {self.container} cat {config_path}").stdout
        return self._parse_peers_from_config_text(raw_conf)

    def peer_transfer_map(self, actor) -> dict[str, int] | None:
        try:
            peers = self.list_peers(actor)
        except Exception:
            return None
        if peers is None:
            return None
        if not peers:
            return {}
        if any(not peer.telemetry_available for peer in peers):
            return None
        return {peer.public_key: peer.transfer_total for peer in peers}

    def _next_address(self, actor) -> str:
        subnet_text = self.protocol.runtime_metadata.get("subnet", "")
        if not subnet_text:
            raise RuntimeError(f"Address pool for {self.protocol_type} is not discovered. Run runtime sync first.")
        try:
            subnet = ipaddress.ip_network(subnet_text, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"Invalid discovered subnet: {subnet_text}") from exc

        used = set()
        for peer in self.list_peers(actor):
            for token in peer.allowed_ips.split(","):
                value = token.strip()
                if not value:
                    continue
                try:
                    iface = ipaddress.ip_interface(value if "/" in value else f"{value}/32")
                    used.add(iface.ip)
                except ValueError:
                    continue

        for host in subnet.hosts():
            if host not in used:
                return str(host)
        raise RuntimeError(f"No free addresses in discovered subnet {subnet}")

    def generate_keypair(self, actor):
        private_key = self._run(actor, f"{self.protocol_type}.genkey", self._wg_cmd("genkey"), sensitive_output=True).stdout.strip()
        quoted = shlex.quote(private_key)
        cmd = f"printf %s {quoted} | docker exec -i {self.container} {self.command_bin} pubkey"
        public_key = self._run(actor, f"{self.protocol_type}.pubkey", cmd, sensitive_output=True).stdout.strip()
        return private_key, public_key

    def create_peer(self, actor):
        iface = self.interface_name(actor)
        private_key, public_key = self.generate_keypair(actor)
        address = self._next_address(actor)
        self._run(actor, f"{self.protocol_type}.add_peer", self._wg_cmd(f"set {iface} peer {public_key} allowed-ips {address}/32"))
        return {
            "private_key": private_key,
            "public_key": public_key,
            "address": address,
            "iface": iface,
            "server_public_key": self.server_public_key(actor, iface),
        }

    def disable_peer(self, actor, peer_public_key: str):
        self.remove_peer(actor, peer_public_key)

    def remove_peer(self, actor, peer_public_key: str):
        iface = self.interface_name(actor)
        self._run(actor, f"{self.protocol_type}.remove_peer", self._wg_cmd(f"set {iface} peer {peer_public_key} remove"))


class AWGLegacyAdapter(BaseProtocolAdapter):
    protocol_type = VPNClient.ProtocolType.AWG
    command_bin = "wg"


class AWG2Adapter(BaseProtocolAdapter):
    protocol_type = VPNClient.ProtocolType.AWG2
    command_bin = "wg"


class AdapterFactory:
    @staticmethod
    def get_for_client(client: VPNClient):
        return AdapterFactory.get_for_server(client.server, client.protocol_type)

    @staticmethod
    def get_for_server(server: Server, protocol_type: str):
        if protocol_type == VPNClient.ProtocolType.AWG:
            return AWGLegacyAdapter(server)
        if protocol_type == VPNClient.ProtocolType.AWG2:
            return AWG2Adapter(server)
        raise ValueError("Unsupported protocol")


class VPNClientService:
    @staticmethod
    def get_limit_state(client: VPNClient, now=None):
        current_time = now or timezone.now()
        if client.expires_at and client.expires_at <= current_time:
            return VPNClient.LimitState.EXPIRED
        if client.traffic_limit_bytes and client.traffic_used_bytes >= client.traffic_limit_bytes:
            return VPNClient.LimitState.TRAFFIC_EXCEEDED
        return VPNClient.LimitState.ACTIVE

    @staticmethod
    def _is_public_endpoint_host(value: str) -> bool:
        if not value:
            return False
        value = value.strip().lower()
        if value in {"localhost", "127.0.0.1", "0.0.0.0"}:
            return False
        try:
            ip = ipaddress.ip_address(value)
            return ip.is_global
        except ValueError:
            return bool(re.fullmatch(r"[a-z0-9.-]+", value))

    @classmethod
    def resolve_endpoint(cls, server: Server, protocol: ServerProtocol) -> str:
        host_candidates = [server.public_endpoint_host, server.host, protocol.runtime_metadata.get("public_host", "")]
        host = next((h for h in host_candidates if cls._is_public_endpoint_host(h)), "")
        if not host:
            raise RuntimeError("Public endpoint is not configured. Set public_endpoint_host in Server (Django admin) or provide public server.host, then run runtime sync.")

        port = server.public_endpoint_port or protocol.runtime_metadata.get("udp_port")
        if not port:
            raise RuntimeError("Public endpoint UDP port is not discovered.")
        return f"{host}:{int(port)}"

    @staticmethod
    def build_awg_legacy_client_config(*, private_key: str, address: str, endpoint: str, server_public_key: str) -> str:
        return (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {address}/32\n"
            "DNS = 1.1.1.1\n\n"
            "[Peer]\n"
            f"PublicKey = {server_public_key}\n"
            f"Endpoint = {endpoint}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
        )

    @staticmethod
    def build_awg2_client_config(*, private_key: str, address: str, endpoint: str, server_public_key: str, awg2_metadata: dict) -> str:
        required = ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")
        optional = ("I1", "I2", "I3", "I4", "I5")
        missing = [k for k in required if not awg2_metadata.get(k)]
        if missing:
            raise RuntimeError(f"AWG2 metadata is incomplete: missing {', '.join(missing)}. Run runtime sync and verify live AWG2 config.")

        awg2_lines = [f"{k} = {awg2_metadata[k]}" for k in required]
        awg2_lines.extend(f"{k} = {awg2_metadata[k]}" for k in optional if awg2_metadata.get(k))
        return (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {address}/32\n"
            "DNS = 1.1.1.1\n\n"
            "[Peer]\n"
            f"PublicKey = {server_public_key}\n"
            f"Endpoint = {endpoint}\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
            + "\n".join(awg2_lines)
            + "\n"
        )

    @staticmethod
    def _store_revision(client: VPNClient, config: str):
        hash_value = hashlib.sha256(config.encode()).hexdigest()
        next_rev = (client.revisions.first().revision_number + 1) if client.revisions.exists() else 1
        encrypted = ConfigCryptoService.encrypt(config)
        ClientConfigRevision.objects.create(
            client=client,
            revision_number=next_rev,
            protocol_type=client.protocol_type,
            config_blob_encrypted=encrypted,
            config_hash=hash_value,
        )
        return next_rev

    @staticmethod
    @transaction.atomic
    def create_client(*, server, name: str, protocol_type: str, actor, expires_at=None, traffic_limit_bytes=None):
        profile = ProtocolProfile.objects.filter(
            server_protocol__server=server,
            protocol_type=protocol_type,
            status=ProtocolProfile.ProfileStatus.ACTIVE,
        ).first()
        if not profile:
            raise ValueError("No active profile for protocol")

        client = VPNClient.objects.create(
            server=server,
            name=name,
            protocol_type=protocol_type,
            profile=profile,
            created_by=actor,
            expires_at=expires_at,
            traffic_limit_bytes=traffic_limit_bytes,
        )
        VPNClientService.reissue_config(client=client, actor=actor)
        AuditService.log(actor, "client.create", "VPNClient", client.id, {"protocol_type": protocol_type})
        return client

    @staticmethod
    @transaction.atomic
    def reissue_config(*, client: VPNClient, actor):
        limit_state = VPNClientService.get_limit_state(client)
        if limit_state == VPNClient.LimitState.EXPIRED:
            raise RuntimeError("Переиздание запрещено: срок действия клиента истек.")
        if limit_state == VPNClient.LimitState.TRAFFIC_EXCEEDED:
            raise RuntimeError("Переиздание запрещено: превышен лимит трафика клиента.")

        adapter = AdapterFactory.get_for_client(client)
        if client.runtime_peer_public_key:
            adapter.remove_peer(actor, client.runtime_peer_public_key)
        generated = adapter.create_peer(actor)
        endpoint = VPNClientService.resolve_endpoint(client.server, adapter.protocol)

        if client.protocol_type == VPNClient.ProtocolType.AWG:
            config = VPNClientService.build_awg_legacy_client_config(
                private_key=generated["private_key"],
                address=generated["address"],
                endpoint=endpoint,
                server_public_key=generated["server_public_key"],
            )
        else:
            config = VPNClientService.build_awg2_client_config(
                private_key=generated["private_key"],
                address=generated["address"],
                endpoint=endpoint,
                server_public_key=generated["server_public_key"],
                awg2_metadata=adapter.protocol.runtime_metadata.get("awg2_metadata", {}),
            )

        rev = VPNClientService._store_revision(client, config)
        client.runtime_peer_public_key = generated["public_key"]
        client.runtime_address = generated["address"]
        client.last_runtime_sync_at = timezone.now()
        client.save(update_fields=["runtime_peer_public_key", "runtime_address", "last_runtime_sync_at"])
        AuditService.log(actor, "client.reissue", "VPNClient", client.id, {"revision": rev})

    @staticmethod
    @transaction.atomic
    def update_limits(*, client: VPNClient, expires_at, traffic_limit_bytes, actor):
        old_expires_at = client.expires_at.isoformat() if client.expires_at else None
        old_traffic_limit_bytes = client.traffic_limit_bytes

        client.expires_at = expires_at
        client.traffic_limit_bytes = traffic_limit_bytes
        client.limit_state = VPNClientService.get_limit_state(client)
        client.save(update_fields=["expires_at", "traffic_limit_bytes", "limit_state"])

        AuditService.log(
            actor,
            "client.limits.update",
            "VPNClient",
            client.id,
            {
                "old_expires_at": old_expires_at,
                "new_expires_at": client.expires_at.isoformat() if client.expires_at else None,
                "old_traffic_limit_bytes": old_traffic_limit_bytes,
                "new_traffic_limit_bytes": client.traffic_limit_bytes,
            },
        )

    @staticmethod
    @transaction.atomic
    def set_status(*, client: VPNClient, status: str, actor, disable_reason: str | None = None):
        if status in {VPNClient.Status.DISABLED, VPNClient.Status.DELETED} and client.runtime_peer_public_key:
            adapter = AdapterFactory.get_for_client(client)
            if status == VPNClient.Status.DISABLED:
                adapter.disable_peer(actor, client.runtime_peer_public_key)
            else:
                adapter.remove_peer(actor, client.runtime_peer_public_key)

        update_fields = ["status"]
        client.status = status

        if status == VPNClient.Status.DISABLED:
            client.disable_reason = disable_reason or VPNClient.DisableReason.MANUAL
            update_fields.append("disable_reason")
            if client.disable_reason == VPNClient.DisableReason.EXPIRED:
                client.limit_state = VPNClient.LimitState.EXPIRED
                update_fields.append("limit_state")
            elif client.disable_reason == VPNClient.DisableReason.TRAFFIC_EXCEEDED:
                client.limit_state = VPNClient.LimitState.TRAFFIC_EXCEEDED
                update_fields.append("limit_state")
        elif status == VPNClient.Status.ACTIVE:
            resolved_state = VPNClientService.get_limit_state(client)
            if resolved_state == VPNClient.LimitState.ACTIVE:
                client.disable_reason = VPNClient.DisableReason.NONE
                client.limit_state = VPNClient.LimitState.ACTIVE
                update_fields.extend(["disable_reason", "limit_state"])
            else:
                client.status = VPNClient.Status.DISABLED
                client.limit_state = resolved_state
                client.disable_reason = (
                    VPNClient.DisableReason.EXPIRED
                    if resolved_state == VPNClient.LimitState.EXPIRED
                    else VPNClient.DisableReason.TRAFFIC_EXCEEDED
                )
                update_fields.extend(["disable_reason", "limit_state"])

        client.save(update_fields=update_fields)
        details = {"disable_reason": client.disable_reason} if client.status == VPNClient.Status.DISABLED else None
        AuditService.log(actor, f"client.{client.status}", "VPNClient", client.id, details=details)

    @staticmethod
    def latest_config(client: VPNClient) -> str:
        rev = client.revisions.first()
        return ConfigCryptoService.decrypt(rev.config_blob_encrypted)

    @staticmethod
    def qr_png_bytes(client: VPNClient) -> bytes:
        payload = VPNClientService.latest_config(client)
        img = qrcode.make(payload)
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        return buffer.getvalue()

    @staticmethod
    def qr_png_base64(client: VPNClient) -> str:
        return base64.b64encode(VPNClientService.qr_png_bytes(client)).decode()

    @staticmethod
    @transaction.atomic
    def import_runtime_peers(*, server, actor):
        imported = 0
        for protocol_type in (VPNClient.ProtocolType.AWG, VPNClient.ProtocolType.AWG2):
            profile = ProtocolProfile.objects.filter(
                server_protocol__server=server,
                protocol_type=protocol_type,
                status=ProtocolProfile.ProfileStatus.ACTIVE,
            ).first()
            if not profile:
                continue
            try:
                adapter = AdapterFactory.get_for_server(server, protocol_type)
                peers = adapter.list_peers(actor)
            except Exception:
                continue
            for idx, peer in enumerate(peers, start=1):
                _, created = VPNClient.objects.get_or_create(
                    server=server,
                    protocol_type=protocol_type,
                    runtime_peer_public_key=peer.public_key,
                    defaults={
                        "name": f"imported-{protocol_type}-{idx}",
                        "profile": profile,
                        "created_by": actor,
                        "imported_from_runtime": True,
                        "runtime_address": peer.allowed_ips,
                        "last_runtime_sync_at": timezone.now(),
                    },
                )
                if created:
                    imported += 1
        AuditService.log(actor, "client.import", "Server", server.id, {"imported": imported})
        return imported


class VPNClientLimitsService:
    @staticmethod
    def _set_limit_state(client: VPNClient):
        return VPNClientService.get_limit_state(client)

    @staticmethod
    def sync_traffic_usage(*, actor=None):
        active_clients = VPNClient.objects.filter(status=VPNClient.Status.ACTIVE).exclude(runtime_peer_public_key="")
        grouped = defaultdict(list)
        for client in active_clients.select_related("server"):
            grouped[(client.server_id, client.protocol_type)].append(client)

        synced = 0
        unavailable = 0
        now = timezone.now()

        for (_, protocol_type), clients in grouped.items():
            server = clients[0].server
            try:
                adapter = AdapterFactory.get_for_server(server, protocol_type)
            except Exception:
                for client in clients:
                    client.traffic_sync_error = "Телеметрия недоступна для runtime"
                    client.traffic_last_sync_at = now
                    client.save(update_fields=["traffic_sync_error", "traffic_last_sync_at"])
                    unavailable += 1
                continue

            transfer_map = adapter.peer_transfer_map(actor)
            if transfer_map is None:
                for client in clients:
                    client.traffic_sync_error = "Счетчики трафика недоступны"
                    client.traffic_last_sync_at = now
                    client.save(update_fields=["traffic_sync_error", "traffic_last_sync_at"])
                    unavailable += 1
                continue

            for client in clients:
                if client.runtime_peer_public_key in transfer_map:
                    used = transfer_map[client.runtime_peer_public_key]
                    update_fields = []
                    if used != client.traffic_used_bytes:
                        client.traffic_used_bytes = used
                        update_fields.append("traffic_used_bytes")
                    client.traffic_sync_error = ""
                    client.traffic_last_sync_at = now
                    update_fields.extend(["traffic_sync_error", "traffic_last_sync_at"])
                    if update_fields:
                        client.save(update_fields=update_fields)
                    synced += 1
                else:
                    client.traffic_sync_error = "Peer отсутствует в runtime"
                    client.traffic_last_sync_at = now
                    client.save(update_fields=["traffic_sync_error", "traffic_last_sync_at"])
                    unavailable += 1

        AuditService.log(actor, "client.limit.traffic_sync", "VPNClient", "bulk", details={"synced": synced, "unavailable": unavailable})
        return {"synced": synced, "unavailable": unavailable}

    @staticmethod
    def enforce_limits(*, actor=None):
        now = timezone.now()
        processed = 0
        expired = 0
        traffic_exceeded = 0

        clients = VPNClient.objects.select_related("server").filter(status=VPNClient.Status.ACTIVE)
        for client in clients:
            processed += 1
            if client.expires_at and client.expires_at <= now:
                VPNClientService.set_status(
                    client=client,
                    status=VPNClient.Status.DISABLED,
                    actor=actor,
                    disable_reason=VPNClient.DisableReason.EXPIRED,
                )
                expired += 1
                continue

            if client.traffic_limit_bytes and client.traffic_used_bytes >= client.traffic_limit_bytes:
                VPNClientService.set_status(
                    client=client,
                    status=VPNClient.Status.DISABLED,
                    actor=actor,
                    disable_reason=VPNClient.DisableReason.TRAFFIC_EXCEEDED,
                )
                traffic_exceeded += 1
                continue

            state = VPNClientLimitsService._set_limit_state(client)
            if state != client.limit_state:
                client.limit_state = state
                client.save(update_fields=["limit_state"])

        details = {"processed": processed, "expired": expired, "traffic_exceeded": traffic_exceeded}
        AuditService.log(actor, "client.limit.enforce", "VPNClient", "bulk", details=details)
        return details
