from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)
from vpn.models import VPNClient
from vpn.services import (
    ConfigCryptoService,
    VPNClientService,
)


def _legacy_metadata():
    return {
        "Jc": "6",
        "Jmin": "10",
        "Jmax": "50",
        "S1": "76",
        "S2": "56",
        "S3": "63",
        "S4": "12",
        "H1": "1",
        "H2": "2",
        "H3": "3",
        "H4": "4",
        "ContentPaddingAddition": "10-100",
        "RekeyAfterTime": "100-120",
        "RekeyTimeout": "3-7",
        "RejectAfterTime": "150-180",
        "KeepaliveTimeout": "5-15",
        "MaxHandshakeAttempts": "15-20",
        "RandomTrailers": "on",
        "DisableCookies": "on",
    }


@override_settings(
    CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode()
)
class AWGRuntimeSecretExportTest(TestCase):
    def setUp(self):
        self.user = (
            get_user_model()
            .objects
            .create_user(
                username="secret-test-admin",
                password="test",
                is_staff=True,
            )
        )
        self.server = Server.objects.create(
            name="secret-export-server",
            public_endpoint_host="vpn.example.com",
        )
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="full",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="[Interface]",
        )

    def test_runtime_metadata_decrypts_header_protection_key(self):
        encrypted = ConfigCryptoService.encrypt(
            "header-secret"
        )
        self.protocol.runtime_metadata = {
            "awg2_metadata": _legacy_metadata(),
            "awg2_secret_metadata": {
                "HeaderProtectionKey": encrypted,
            },
            "awg31_metadata_ready": True,
        }
        self.protocol.save(
            update_fields=[
                "runtime_metadata"
            ]
        )

        metadata = (
            VPNClientService
            ._runtime_awg_metadata(
                self.protocol
            )
        )

        self.assertEqual(
            metadata[
                "HeaderProtectionKey"
            ],
            "header-secret",
        )

    def test_reissue_missing_encrypted_secret_fails_before_peer_mutation(self):
        self.protocol.runtime_metadata = {
            "config_path": "/opt/amnezia/awg/awg0.conf",
            "interface": "awg0",
            "interface_ready": True,
            "subnet": "10.8.1.0/24",
            "subnet_ready": True,
            "endpoint_host_ready": True,
            "endpoint_port_ready": True,
            "awg_export_compatible": True,
            "awg2_metadata": _legacy_metadata(),
            "awg31_metadata_ready": True,
        }
        self.protocol.save(
            update_fields=[
                "runtime_metadata"
            ]
        )

        client = VPNClient.objects.create(
            server=self.server,
            name="protected-client",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=self.profile,
            created_by=self.user,
            status=VPNClient.Status.ACTIVE,
            runtime_peer_public_key="old-peer",
            runtime_address="10.8.1.20",
        )

        adapter = SimpleNamespace(
            protocol=self.protocol,
            remove_peer=Mock(),
            create_peer=Mock(),
        )

        with patch(
            "vpn.services.AdapterFactory.get_for_client",
            return_value=adapter,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "HeaderProtectionKey",
            ):
                VPNClientService.reissue_config(
                    client=client,
                    actor=self.user,
                )

        adapter.remove_peer.assert_not_called()
        adapter.create_peer.assert_not_called()

    def test_plaintext_metadata_remains_backward_compatible_until_scrub(self):
        metadata = _legacy_metadata()
        metadata[
            "HeaderProtectionKey"
        ] = "legacy-plaintext"
        self.protocol.runtime_metadata = {
            "awg2_metadata": metadata,
            "awg31_metadata_ready": True,
        }
        self.protocol.save(
            update_fields=[
                "runtime_metadata"
            ]
        )

        restored = (
            VPNClientService
            ._runtime_awg_metadata(
                self.protocol
            )
        )

        self.assertEqual(
            restored[
                "HeaderProtectionKey"
            ],
            "legacy-plaintext",
        )
