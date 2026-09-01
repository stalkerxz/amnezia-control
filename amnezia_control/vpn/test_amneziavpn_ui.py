from cryptography.fernet import Fernet

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from portal.services import PortalAccessService

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
class AmneziaVPNAgentUITest(TestCase):

    def setUp(self):
        self.user = (
            get_user_model()
            .objects
            .create_user(
                "agent-ui-admin",
                password="test",
                is_staff=True,
            )
        )

        self.client.force_login(
            self.user
        )

        self.server = Server.objects.create(
            name="agent-ui",
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
                container_status="running",
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

        self.vpn_client = (
            VPNClient.objects.create(
                server=self.server,
                name="agent-ui-client",
                protocol_type=(
                    VPNClient
                    .ProtocolType
                    .AWG2
                ),
                profile=profile,
                created_by=self.user,
            )
        )

        self.conf = """[Interface]
PrivateKey = TEST
Address = 10.78.0.50/32

[Peer]
PublicKey = SERVER
Endpoint = vpn.example.com:51831
AllowedIPs = 0.0.0.0/0, ::/0
"""

    def test_old_agent_revision_requires_reissue_without_500(self):
        VPNClientService._store_revision(
            self.vpn_client,
            self.conf,
        )

        response = self.client.get(
            reverse(
                "clients-detail",
                args=[
                    self.vpn_client.pk,
                ],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Текущая ревизия создана до "
            "поддержки AmneziaVPN 3.1",
        )

        self.assertContains(
            response,
            "AmneziaVPN .vpn — "
            "требуется переиздание",
        )

        self.assertEqual(
            sum(
                "AmneziaVPN" in item
                for item in response.context[
                    "warning_items"
                ]
            ),
            1,
        )

        response = self.client.get(
            reverse(
                "clients-download",
                args=[
                    self.vpn_client.pk,
                ],
            )
        )

        self.assertEqual(
            response.status_code,
            302,
        )

    def test_old_agent_qr_views_do_not_500(self):
        VPNClientService._store_revision(
            self.vpn_client,
            self.conf,
        )

        response = self.client.get(
            reverse(
                "clients-qr-modal",
                args=[
                    self.vpn_client.pk,
                ],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        _, token = (
            PortalAccessService
            .issue_for_client(
                self.vpn_client
            )
        )

        response = self.client.get(
            reverse(
                "portal-qr",
                kwargs={
                    "token":
                        token,
                },
            ),
            {
                "target":
                    "amneziavpn",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Переиздайте конфигурацию",
        )

    def test_native_qr_remains_visible_without_vpn_artifact(self):
        from unittest.mock import patch

        VPNClientService._store_revision(
            self.vpn_client,
            self.conf,
        )

        def qr_for_target(
            client,
            target,
        ):
            if target == "amneziavpn":
                raise RuntimeError(
                    "Для этой ревизии отсутствует "
                    "профиль AmneziaVPN .vpn."
                )

            if target == "amneziawg":
                return "NATIVE-WG-QR"

            raise AssertionError(target)

        with patch(
            "vpn.views."
            "VPNClientService."
            "portal_qr_png_base64_for_target",
            side_effect=qr_for_target,
        ):
            response = self.client.get(
                reverse(
                    "clients-qr-modal",
                    args=[
                        self.vpn_client.pk,
                    ],
                )
            )

            self.assertEqual(
                response.status_code,
                200,
            )

            self.assertContains(
                response,
                "AmneziaWG .conf",
            )

            self.assertContains(
                response,
                "NATIVE-WG-QR",
            )

            self.assertNotContains(
                response,
                "Конфиг ещё не выпущен",
            )

            response = self.client.get(
                reverse(
                    "clients-detail",
                    args=[
                        self.vpn_client.pk,
                    ],
                )
            )

            self.assertEqual(
                response.status_code,
                200,
            )

            self.assertContains(
                response,
                "AmneziaWG .conf",
            )

            self.assertContains(
                response,
                "NATIVE-WG-QR",
            )

    def test_new_artifact_downloads_as_vpn(self):
        artifact = (
            "vpn://agent-awg31-profile"
        )

        VPNClientService._store_revision(
            self.vpn_client,
            self.conf,
            amneziavpn_config=artifact,
        )

        response = self.client.get(
            reverse(
                "clients-download",
                args=[
                    self.vpn_client.pk,
                ],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.content.decode(),
            artifact,
        )

        self.assertIn(
            "amneziavpn.vpn",
            response[
                "Content-Disposition"
            ],
        )

        _, token = (
            PortalAccessService
            .issue_for_client(
                self.vpn_client
            )
        )

        response = self.client.get(
            reverse(
                "portal-config",
                kwargs={
                    "token":
                        token,
                },
            ),
            {
                "target":
                    "amneziavpn",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.content.decode(),
            artifact,
        )

        self.assertIn(
            "amneziavpn.vpn",
            response[
                "Content-Disposition"
            ],
        )
