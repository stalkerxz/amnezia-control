from cryptography.fernet import Fernet

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)

from .models import VPNClient
from .services import VPNClientService


@override_settings(
    CONFIG_ENCRYPTION_KEY=(
        Fernet.generate_key().decode()
    )
)
class AmneziaVPNArtifactTest(TestCase):

    def setUp(self):
        self.user = (
            get_user_model()
            .objects
            .create_user(
                "artifact-admin",
                password="test",
                is_staff=True,
            )
        )

        self.server = Server.objects.create(
            name="agent-artifact",
            host="127.0.0.1",
            public_endpoint_host=(
                "vpn.example.com"
            ),
            public_endpoint_port=51831,
            runtime_backend=(
                Server.RuntimeBackend
                .AWG_AGENT
            ),
        )

        protocol = (
            ServerProtocol.objects.create(
                server=self.server,
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                enabled=True,
            )
        )

        profile = (
            ProtocolProfile.objects.create(
                server_protocol=protocol,
                name="full",
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                config_template=(
                    "# routing-mode: full"
                ),
            )
        )

        self.client_obj = (
            VPNClient.objects.create(
                server=self.server,
                name="agent-client",
                protocol_type=(
                    VPNClient
                    .ProtocolType
                    .AWG2
                ),
                profile=profile,
                created_by=self.user,
            )
        )

    def test_artifact_is_encrypted_and_returned(self):
        artifact = (
            "vpn://real-awg31-artifact"
        )

        VPNClientService._store_revision(
            self.client_obj,
            "[Interface]\n"
            "PrivateKey = test",
            amneziavpn_config=artifact,
        )

        revision = (
            self.client_obj
            .revisions
            .first()
        )

        self.assertTrue(
            revision
            .amneziavpn_blob_encrypted
        )

        self.assertNotEqual(
            revision
            .amneziavpn_blob_encrypted,
            artifact,
        )

        self.assertEqual(
            VPNClientService
            .latest_amneziavpn_config(
                self.client_obj
            ),
            artifact,
        )

        self.assertEqual(
            VPNClientService
            .portal_export_config_for_target(
                self.client_obj,
                "amneziavpn",
            ),
            artifact,
        )

    def test_old_agent_revision_fails_closed(self):
        VPNClientService._store_revision(
            self.client_obj,
            "[Interface]\n"
            "PrivateKey = old",
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "Переиздайте",
        ):
            (
                VPNClientService
                .portal_export_config_for_target(
                    self.client_obj,
                    "amneziavpn",
                )
            )
