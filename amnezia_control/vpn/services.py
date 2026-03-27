import base64
import hashlib
import io
import ipaddress
import shlex
from dataclasses import dataclass

import qrcode
from cryptography.fernet import Fernet
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from audit.services import AuditService
from jobs.executors import SafeSSHExecutor
from jobs.services import JobService
from servers.models import ProtocolProfile, ServerProtocol
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


class RuntimeCommandService:
    @staticmethod
    def executor_for_server(server):
        return SafeSSHExecutor(
            host=server.host,
            username=server.ssh_username,
            port=server.port,
            key_path=server.ssh_private_key_path or None,
        )

    @staticmethod
    def run(server, actor, action: str, command: str, sensitive_output: bool = False):
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

    def __init__(self, client_or_server):
        self.server = client_or_server.server if hasattr(client_or_server, "server") else client_or_server
        self.protocol = ServerProtocol.objects.filter(server=self.server, protocol_type=self.protocol_type).first()
        if not self.protocol or not self.protocol.container_name:
            raise ValueError(f"Container for {self.protocol_type} not detected")

    @property
    def container(self):
        return self.protocol.container_name

    def _run(self, actor, action, command, sensitive_output=False):
        return RuntimeCommandService.run(self.server, actor, action, command, sensitive_output=sensitive_output)

    def interface_name(self, actor) -> str:
        out = self._run(actor, f"{self.protocol_type}.iface", f"docker exec {self.container} wg show interfaces").stdout.strip()
        if not out:
            raise RuntimeError("WireGuard interface not detected")
        return out.split()[0]

    def server_public_key(self, actor, iface: str) -> str:
        return self._run(actor, f"{self.protocol_type}.server_pub", f"docker exec {self.container} wg show {iface} public-key").stdout.strip()

    def list_peers(self, actor):
        out = self._run(actor, f"{self.protocol_type}.list", f"docker exec {self.container} wg show dump").stdout
        peers = []
        for line in out.splitlines():
            cols = line.split("\t")
            if len(cols) >= 8:
                # peer line in wg dump
                public_key = cols[0]
                allowed_ips = cols[3]
                if public_key and public_key != "public_key":
                    peers.append(PeerState(public_key=public_key, allowed_ips=allowed_ips))
        return peers

    def _next_address(self, actor) -> str:
        used = set()
        for peer in self.list_peers(actor):
            try:
                ip = peer.allowed_ips.split(",")[0].split("/")[0]
                used.add(ipaddress.ip_address(ip))
            except ValueError:
                continue
        subnet = ipaddress.ip_network("10.8.0.0/24")
        for host in subnet.hosts():
            if int(host) <= int(ipaddress.ip_address("10.8.0.1")):
                continue
            if host not in used:
                return str(host)
        raise RuntimeError("No free addresses")

    def generate_keypair(self, actor):
        private_key = self._run(actor, f"{self.protocol_type}.genkey", f"docker exec {self.container} wg genkey", sensitive_output=True).stdout.strip()
        quoted = shlex.quote(private_key)
        cmd = f"printf %s {quoted} | docker exec -i {self.container} wg pubkey"
        public_key = self._run(actor, f"{self.protocol_type}.pubkey", cmd, sensitive_output=True).stdout.strip()
        return private_key, public_key

    def create_peer(self, actor):
        iface = self.interface_name(actor)
        private_key, public_key = self.generate_keypair(actor)
        address = self._next_address(actor)
        self._run(actor, f"{self.protocol_type}.add_peer", f"docker exec {self.container} wg set {iface} peer {public_key} allowed-ips {address}/32")
        return {
            "private_key": private_key,
            "public_key": public_key,
            "address": address,
            "iface": iface,
            "server_public_key": self.server_public_key(actor, iface),
        }

    def remove_peer(self, actor, peer_public_key: str):
        iface = self.interface_name(actor)
        self._run(actor, f"{self.protocol_type}.remove_peer", f"docker exec {self.container} wg set {iface} peer {peer_public_key} remove")


class AWGLegacyAdapter(BaseProtocolAdapter):
    protocol_type = VPNClient.ProtocolType.AWG


class AWG2Adapter(BaseProtocolAdapter):
    protocol_type = VPNClient.ProtocolType.AWG2


class AdapterFactory:
    @staticmethod
    def get(target):
        protocol_type = target.protocol_type if hasattr(target, "protocol_type") else target
        if protocol_type == VPNClient.ProtocolType.AWG:
            return AWGLegacyAdapter(target)
        if protocol_type == VPNClient.ProtocolType.AWG2:
            return AWG2Adapter(target)
        raise ValueError("Unsupported protocol")


class VPNClientService:
    @staticmethod
    def _endpoint_for_server(server, protocol: ServerProtocol) -> str:
        host = server.host if server.host not in {"127.0.0.1", "localhost"} else "YOUR_VPS_IP"
        port = protocol.runtime_metadata.get("udp_port") or 51820
        return f"{host}:{port}"

    @staticmethod
    def _build_client_config(*, private_key: str, address: str, endpoint: str, server_public_key: str) -> str:
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
    def create_client(*, server, name: str, protocol_type: str, actor):
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
        )
        VPNClientService.reissue_config(client=client, actor=actor)
        AuditService.log(actor, "client.create", "VPNClient", client.id, {"protocol_type": protocol_type})
        return client

    @staticmethod
    @transaction.atomic
    def reissue_config(*, client: VPNClient, actor):
        adapter = AdapterFactory.get(client)
        if client.runtime_peer_public_key:
            adapter.remove_peer(actor, client.runtime_peer_public_key)
        generated = adapter.create_peer(actor)
        endpoint = VPNClientService._endpoint_for_server(client.server, adapter.protocol)
        config = VPNClientService._build_client_config(
            private_key=generated["private_key"],
            address=generated["address"],
            endpoint=endpoint,
            server_public_key=generated["server_public_key"],
        )
        rev = VPNClientService._store_revision(client, config)
        client.runtime_peer_public_key = generated["public_key"]
        client.runtime_address = generated["address"]
        client.last_runtime_sync_at = timezone.now()
        client.save(update_fields=["runtime_peer_public_key", "runtime_address", "last_runtime_sync_at"])
        AuditService.log(actor, "client.reissue", "VPNClient", client.id, {"revision": rev})

    @staticmethod
    @transaction.atomic
    def set_status(*, client: VPNClient, status: str, actor):
        if status in {VPNClient.Status.DISABLED, VPNClient.Status.DELETED} and client.runtime_peer_public_key:
            adapter = AdapterFactory.get(client)
            adapter.remove_peer(actor, client.runtime_peer_public_key)
        client.status = status
        client.save(update_fields=["status"])
        AuditService.log(actor, f"client.{status}", "VPNClient", client.id)

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
                adapter = AdapterFactory.get(protocol_type)
                peers = adapter.list_peers(actor)
            except Exception:
                continue
            for idx, peer in enumerate(peers, start=1):
                obj, created = VPNClient.objects.get_or_create(
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
