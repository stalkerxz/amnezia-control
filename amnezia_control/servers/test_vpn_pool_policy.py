from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)


class VPNPoolPolicyTests(TestCase):
    def setUp(self):
        self.user = (
            get_user_model()
            .objects.create_user(
                "pool-admin",
                password="123",
                is_staff=True,
            )
        )

        self.client.force_login(self.user)

    def _ready_server(
        self,
        *,
        name,
        locked=False,
        accepts=False,
    ):
        server = Server.objects.create(
            name=name,
            host="203.0.113.20",
            is_enabled=True,
            health_status="healthy",
            accepts_new_vpn_clients=accepts,
            vpn_pool_locked=locked,
            public_endpoint_host="203.0.113.20",
            public_endpoint_port=36784,
        )

        protocol = ServerProtocol.objects.create(
            server=server,
            protocol_type=(
                ServerProtocol.ProtocolType.AWG2
            ),
            enabled=True,
            container_name="awg",
            container_status="running",
            runtime_metadata={
                "awg31_metadata_ready": True,
                "subnet_ready": True,
                "endpoint_host_ready": True,
                "endpoint_port_ready": True,
                "subnet": "10.8.1.0/24",
                "peer_count": 0,
            },
        )

        ProtocolProfile.objects.create(
            server_protocol=protocol,
            name="FULL",
            protocol_type=(
                ServerProtocol.ProtocolType.AWG2
            ),
            config_template=(
                "# routing-mode: full"
            ),
            status=(
                ProtocolProfile
                .ProfileStatus
                .ACTIVE
            ),
        )

        return server

    def test_locked_server_cannot_be_enabled_by_post(
        self,
    ):
        server = self._ready_server(
            name="Legacy",
            locked=True,
        )

        response = self.client.post(
            reverse(
                "servers-toggle-vpn-pool",
                args=[server.id],
            ),
            {"enabled": "1"},
            follow=True,
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        server.refresh_from_db()

        self.assertFalse(
            server.accepts_new_vpn_clients
        )

        self.assertContains(
            response,
            "эксплуатационная политика",
        )

    def test_unlocked_ready_server_can_be_enabled(
        self,
    ):
        server = self._ready_server(
            name="Allowed",
        )

        response = self.client.post(
            reverse(
                "servers-toggle-vpn-pool",
                args=[server.id],
            ),
            {"enabled": "1"},
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        server.refresh_from_db()

        self.assertTrue(
            server.accepts_new_vpn_clients
        )

    def test_locked_server_list_shows_policy_label(
        self,
    ):
        self._ready_server(
            name="Legacy UI",
            locked=True,
        )

        response = self.client.get(
            reverse("servers-list")
        )

        self.assertContains(
            response,
            "Legacy · заблокирован",
        )
