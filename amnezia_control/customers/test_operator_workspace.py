from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)

from vpn.models import (
    VPNClient,
    XHTTPDevice,
)

from .models import (
    ClientDevice,
    CustomerAccount,
)

from .workspace import (
    build_customer_workspace,
)


class CustomerOperatorWorkspaceTest(
    TestCase
):
    def setUp(self):
        User = get_user_model()

        self.operator = (
            User.objects.create_user(
                username="workspace-operator",
                password="test-password",
                is_owner=True,
            )
        )

        self.account = (
            CustomerAccount.objects.create(
                display_name="Workspace Customer",
                email="workspace@example.com",
                created_by=self.operator,
            )
        )

        self.device = (
            ClientDevice.objects.create(
                account=self.account,
                name="MacBook",
                platform=(
                    ClientDevice.Platform.MACOS
                ),
            )
        )

        self.server = Server.objects.create(
            name="Workspace Server",
            public_endpoint_host=(
                "vpn.example.com"
            ),
        )

        self.protocol = (
            ServerProtocol.objects.create(
                server=self.server,
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                container_name="amnezia-awg2",
                enabled=True,
                runtime_metadata={
                    "udp_port": 51830,
                    "subnet": "10.77.0.0/24",
                },
            )
        )

        self.full_profile = (
            ProtocolProfile.objects.create(
                server_protocol=self.protocol,
                name="FULL",
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                config_template="[Interface]",
            )
        )

        self.select_profile = (
            ProtocolProfile.objects.create(
                server_protocol=self.protocol,
                name="SELECT",
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                config_template=(
                    "# routing-mode: selective\n"
                    "8.8.8.0/24\n"
                ),
            )
        )

        self.full = VPNClient.objects.create(
            server=self.server,
            name="workspace-full",
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            profile=self.full_profile,
            created_by=self.operator,
            device=self.device,
            runtime_address="10.77.0.10",
            runtime_peer_public_key=(
                "workspace-full-key"
            ),
        )

        self.selective = (
            VPNClient.objects.create(
                server=self.server,
                name="workspace-select",
                protocol_type=(
                    VPNClient.ProtocolType.AWG2
                ),
                profile=self.select_profile,
                created_by=self.operator,
                device=self.device,
                status=(
                    VPNClient.Status.DISABLED
                ),
                runtime_address="10.77.0.11",
                runtime_peer_public_key=(
                    "workspace-select-key"
                ),
            )
        )

        self.xhttp = (
            XHTTPDevice.objects.create(
                device=self.device,
                server=self.server,
                name="CDN",
                xray_email=(
                    "workspace@example.invalid"
                ),
                config_blob_encrypted=(
                    "encrypted"
                ),
                config_hash="hash",
            )
        )

    def test_workspace_groups_connections(
        self,
    ):
        workspace = (
            build_customer_workspace(
                self.account
            )
        )

        self.assertEqual(
            workspace["device_total"],
            1,
        )

        self.assertEqual(
            workspace["connection_total"],
            3,
        )

        self.assertEqual(
            workspace["full_total"],
            1,
        )

        self.assertEqual(
            workspace["selective_total"],
            1,
        )

        self.assertEqual(
            workspace["xhttp_total"],
            1,
        )

        self.assertEqual(
            workspace[
                "active_connection_total"
            ],
            2,
        )

        row = workspace["devices"][0]

        self.assertEqual(
            [item.pk for item in row["full"]],
            [self.full.pk],
        )

        self.assertEqual(
            [
                item.pk
                for item
                in row["selective"]
            ],
            [self.selective.pk],
        )

        self.assertEqual(
            [item.pk for item in row["xhttp"]],
            [self.xhttp.pk],
        )

        self.assertTrue(
            row["can_add_connections"]
        )

    def test_deleted_connections_are_hidden_from_workspace(
        self,
    ):
        VPNClient.objects.create(
            server=self.server,
            name="deleted-vpn",
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            profile=self.full_profile,
            created_by=self.operator,
            device=self.device,
            status=VPNClient.Status.DELETED,
            runtime_address="10.77.0.12",
            runtime_peer_public_key=(
                "deleted-key"
            ),
        )

        XHTTPDevice.objects.create(
            device=self.device,
            server=self.server,
            name="Deleted CDN",
            xray_email=(
                "deleted@example.invalid"
            ),
            status=XHTTPDevice.Status.DELETED,
            config_blob_encrypted="encrypted",
            config_hash="deleted-hash",
        )

        workspace = (
            build_customer_workspace(
                self.account
            )
        )

        self.assertEqual(
            workspace["connection_total"],
            3,
        )

        self.assertEqual(
            workspace["full_total"],
            1,
        )

        self.assertEqual(
            workspace["xhttp_total"],
            1,
        )

    def test_disabled_account_blocks_add_actions(
        self,
    ):
        self.account.status = (
            CustomerAccount.Status.DISABLED
        )

        self.account.save(
            update_fields=["status"]
        )

        workspace = (
            build_customer_workspace(
                self.account
            )
        )

        self.assertFalse(
            workspace["account_ready"]
        )

        self.assertFalse(
            workspace["devices"][0][
                "can_add_connections"
            ]
        )

    def test_detail_page_renders_workspace(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            reverse(
                "customers-detail",
                args=[self.account.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Рабочая область клиента",
        )

        self.assertContains(
            response,
            "AWG2 FULL",
        )

        self.assertContains(
            response,
            "AWG2 SELECTIVE",
        )

        self.assertContains(
            response,
            "VLESS / XHTTP",
        )

        self.assertContains(
            response,
            "?routing_mode=full",
        )

        self.assertContains(
            response,
            "?routing_mode=selective",
        )

        self.assertContains(
            response,
            "Расширенное управление",
        )

    def test_selective_create_link_preselects_mode(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        url = (
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            )
            + "?routing_mode=selective"
        )

        response = self.client.get(url)

        self.assertEqual(
            response.status_code,
            200,
        )

        form = response.context["form"]

        self.assertEqual(
            form.initial["routing_mode"],
            "selective",
        )

    def test_invalid_create_mode_falls_back_to_full(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        url = (
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            )
            + "?routing_mode=invalid"
        )

        response = self.client.get(url)

        self.assertEqual(
            response.status_code,
            200,
        )

        form = response.context["form"]

        self.assertEqual(
            form.initial["routing_mode"],
            "full",
        )
