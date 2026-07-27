from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from servers.models import ProtocolProfile, Server, ServerProtocol

from .forms import VPNClientCreateForm
from .models import VPNClient
from .services import VPNClientService


class RoutingModeTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="routing-admin",
            password="test-password",
            is_staff=True,
        )

        self.server = Server.objects.create(
            name="routing-server",
            host="8.8.8.8",
            is_enabled=True,
        )

        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
        )

        self.full_profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="default-awg2",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            status=ProtocolProfile.ProfileStatus.ACTIVE,
            config_template="[Interface]",
        )

        self.selective_profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="AWG2 Selective — Mobile Core v1",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            status=ProtocolProfile.ProfileStatus.ACTIVE,
            config_template=(
                "# routing-mode: selective\n"
                "8.8.8.0/24\n"
                "8.8.8.128/25\n"
            ),
        )

    def test_form_contains_full_and_selective(self):
        form = VPNClientCreateForm(server=self.server)
        values = dict(form.fields["routing_mode"].choices)

        self.assertIn("full", values)
        self.assertIn("selective", values)

    def test_full_profile_uses_default_routes(self):
        self.assertEqual(
            VPNClientService.resolve_profile_allowed_ips(
                self.full_profile
            ),
            "0.0.0.0/0, ::/0",
        )

    def test_selective_routes_are_collapsed(self):
        self.assertEqual(
            VPNClientService.resolve_profile_allowed_ips(
                self.selective_profile
            ),
            "8.8.8.0/24",
        )

    @patch.object(VPNClientService, "reissue_config")
    def test_full_client_uses_full_profile(self, reissue):
        client = VPNClientService.create_client(
            server=self.server,
            name="full-device",
            protocol_type=VPNClient.ProtocolType.AWG2,
            routing_mode="full",
            actor=self.user,
        )

        self.assertEqual(client.profile, self.full_profile)
        reissue.assert_called_once()

    @patch.object(VPNClientService, "reissue_config")
    def test_selective_client_uses_selective_profile(self, reissue):
        client = VPNClientService.create_client(
            server=self.server,
            name="selective-device",
            protocol_type=VPNClient.ProtocolType.AWG2,
            routing_mode="selective",
            actor=self.user,
        )

        self.assertEqual(client.profile, self.selective_profile)
        reissue.assert_called_once()
