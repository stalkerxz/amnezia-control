from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from customers.models import (
    ClientDevice,
    CustomerAccount,
)
from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)
from vpn.models import VPNClient


class CustomerVPNServerChoiceTests(
    TestCase
):
    def setUp(self):
        User = get_user_model()

        self.operator = (
            User.objects.create_user(
                username="pool-operator",
                password="test-password",
                is_staff=True,
                is_owner=True,
            )
        )

        self.client.force_login(
            self.operator
        )

        self.account = (
            CustomerAccount.objects.create(
                display_name="Test Customer",
                email="test@example.com",
                status=(
                    CustomerAccount
                    .Status
                    .ACTIVE
                ),
                created_by=self.operator,
            )
        )

        self.device = (
            ClientDevice.objects.create(
                account=self.account,
                name="iPhone",
                platform=(
                    ClientDevice
                    .Platform
                    .IOS
                ),
                status=(
                    ClientDevice
                    .Status
                    .ACTIVE
                ),
            )
        )

        self.server_a = (
            self.make_server(
                name="Pool A",
                host="203.0.113.10",
                peer_count=2,
            )
        )

        self.server_b = (
            self.make_server(
                name="Pool B",
                host="203.0.113.11",
                peer_count=20,
            )
        )

    def make_server(
        self,
        *,
        name,
        host,
        peer_count,
    ):
        server = Server.objects.create(
            name=name,
            host=host,
            is_enabled=True,
            is_default_for_new_clients=False,
            accepts_new_vpn_clients=True,
            health_status="healthy",
            public_endpoint_host=host,
            public_endpoint_port=36784,
        )

        protocol = (
            ServerProtocol.objects.create(
                server=server,
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
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
                    "peer_count": peer_count,
                    "public_host": host,
                    "udp_port": 36784,
                },
            )
        )

        ProtocolProfile.objects.create(
            server_protocol=protocol,
            name="FULL",
            protocol_type=(
                ServerProtocol
                .ProtocolType
                .AWG2
            ),
            config_template=(
                "# routing-mode: full\n"
            ),
            status=(
                ProtocolProfile
                .ProfileStatus
                .ACTIVE
            ),
        )

        return server

    def vpn_url(self):
        return reverse(
            "customers-device-vpn-create",
            args=[self.device.pk],
        )

    def test_get_shows_server_selector(
        self,
    ):
        response = self.client.get(
            self.vpn_url(),
            {
                "routing_mode": "full",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            'name="server_choice"',
        )

        self.assertContains(
            response,
            "Автоматически",
        )

        self.assertContains(
            response,
            self.server_a.name,
        )

        self.assertContains(
            response,
            self.server_b.name,
        )

        # Auto must choose the less loaded
        # eligible server.
        self.assertEqual(
            response.context["server"],
            self.server_a,
        )

        self.assertEqual(
            response.context[
                "server_choice"
            ],
            "auto",
        )

    def test_get_manual_server_choice(
        self,
    ):
        response = self.client.get(
            self.vpn_url(),
            {
                "routing_mode": "full",
                "server_choice": str(
                    self.server_b.pk
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.context["server"],
            self.server_b,
        )

        self.assertEqual(
            response.context[
                "server_choice"
            ],
            str(self.server_b.pk),
        )

    @patch(
        "customers.views."
        "VPNClientService.create_client"
    )
    def test_post_creates_on_manual_server(
        self,
        create_client,
    ):
        create_client.return_value = (
            SimpleNamespace(pk=999)
        )

        response = self.client.post(
            self.vpn_url(),
            {
                "routing_mode": "full",
                "server_choice": str(
                    self.server_b.pk
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        create_client.assert_called_once()

        kwargs = (
            create_client.call_args.kwargs
        )

        self.assertEqual(
            kwargs["server"],
            self.server_b,
        )

        self.assertEqual(
            kwargs["device"],
            self.device,
        )

        self.assertEqual(
            kwargs["routing_mode"],
            "full",
        )

        self.assertEqual(
            kwargs["protocol_type"],
            VPNClient.ProtocolType.AWG2,
        )

    def test_server_outside_pool_rejected(
        self,
    ):
        blocked = self.make_server(
            name="Blocked",
            host="203.0.113.12",
            peer_count=1,
        )

        blocked.accepts_new_vpn_clients = (
            False
        )

        blocked.save(
            update_fields=[
                "accepts_new_vpn_clients",
                "updated_at",
            ]
        )

        response = self.client.get(
            self.vpn_url(),
            {
                "routing_mode": "full",
                "server_choice": str(
                    blocked.pk
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            400,
        )
