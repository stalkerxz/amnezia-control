import base64
import hashlib
import io
import qrcode
from cryptography.fernet import Fernet
from django.conf import settings
from django.db import transaction
from audit.services import AuditService
from servers.models import ProtocolProfile
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


class ProtocolConfigGenerator:
    def generate(self, client: VPNClient) -> str:
        raise NotImplementedError


class AWGGenerator(ProtocolConfigGenerator):
    def generate(self, client: VPNClient) -> str:
        template = client.profile.config_template
        return template.format(client_name=client.name, protocol="AWG")


class AWG2Generator(ProtocolConfigGenerator):
    def generate(self, client: VPNClient) -> str:
        template = client.profile.config_template
        return template.format(client_name=client.name, protocol="AWG2")


class GeneratorFactory:
    @staticmethod
    def get(protocol_type: str) -> ProtocolConfigGenerator:
        if protocol_type == VPNClient.ProtocolType.AWG:
            return AWGGenerator()
        if protocol_type == VPNClient.ProtocolType.AWG2:
            return AWG2Generator()
        raise ValueError("Unsupported protocol")


class VPNClientService:
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
        generator = GeneratorFactory.get(client.protocol_type)
        config = generator.generate(client)
        hash_value = hashlib.sha256(config.encode()).hexdigest()
        next_rev = (client.revisions.first().revision_number + 1) if client.revisions.exists() else 1
        encrypted = ConfigCryptoService.encrypt(config)
        ClientConfigRevision.objects.create(
            client=client,
            revision_number=next_rev,
            protocol_type=client.protocol_type,
            config_blob_encrypted=encrypted,
            config_hash=hash_value,
            qr_payload=config,
        )
        AuditService.log(actor, "client.reissue", "VPNClient", client.id, {"revision": next_rev})

    @staticmethod
    def set_status(*, client: VPNClient, status: str, actor):
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
