from datetime import timedelta

from django.contrib.auth import (
    get_user_model,
)
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)

from .models import (
    ClientDevice,
    CustomerAccount,
)


class CustomerConnectionProductTest(
    TestCase
):
    def setUp(self):
        User = get_user_model()

        self.operator = (
            User.objects.create_user(
                username=(
                    "connection-product-operator"
                ),
                password="test-password",
                is_owner=True,
            )
        )

        self.regular_user = (
            User.objects.create_user(
                username=(
                    "connection-product-user"
                ),
                password="test-password",
                is_owner=False,
            )
        )

        self.account = (
            CustomerAccount.objects.create(
                display_name=(
                    "Connection Product Customer"
                ),
                email=(
                    "products@example.com"
                ),
                created_by=self.operator,
            )
        )

        self.device = (
            ClientDevice.objects.create(
                account=self.account,
                name="Product iPhone",
                platform=(
                    ClientDevice.Platform.IOS
                ),
            )
        )

        self.server = Server.objects.create(
            name="Product Server",
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
                container_name=(
                    "amnezia-awg2"
                ),
                enabled=True,
                runtime_metadata={
                    "udp_port": 51830,
                    "subnet": (
                        "10.88.0.0/24"
                    ),
                },
            )
        )

        ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="FULL",
            protocol_type=(
                ServerProtocol
                .ProtocolType
                .AWG2
            ),
            config_template=(
                "[Interface]"
            ),
        )

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

        self.client.force_login(
            self.operator
        )

    def test_product_selector_renders_three_connection_types(
        self,
    ):
        response = self.client.get(
            reverse(
                (
                    "customers-device-"
                    "connection-create"
                ),
                args=[self.device.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Весь интернет через VPN",
        )

        self.assertContains(
            response,
            "Только выбранные сервисы",
        )

        self.assertContains(
            response,
            "Альтернативное подключение",
        )

        self.assertContains(
            response,
            (
                reverse(
                    (
                        "customers-device-"
                        "vpn-create"
                    ),
                    args=[self.device.pk],
                )
                + "?routing_mode=full"
            ),
        )

        self.assertContains(
            response,
            (
                reverse(
                    (
                        "customers-device-"
                        "vpn-create"
                    ),
                    args=[self.device.pk],
                )
                + "?routing_mode=selective"
            ),
        )

        self.assertContains(
            response,
            reverse(
                (
                    "customers-device-"
                    "xhttp-create"
                ),
                args=[self.device.pk],
            ),
        )

    def test_workspace_has_one_product_connection_action(
        self,
    ):
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

        html = response.content.decode(
            "utf-8"
        )

        selector_url = reverse(
            (
                "customers-device-"
                "connection-create"
            ),
            args=[self.device.pk],
        )

        full_url = (
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            )
            + "?routing_mode=full"
        )

        selective_url = (
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            )
            + "?routing_mode=selective"
        )

        xhttp_url = reverse(
            "customers-device-xhttp-create",
            args=[self.device.pk],
        )

        self.assertIn(
            selector_url,
            html,
        )

        self.assertIn(
            "+ Подключение",
            html,
        )

        self.assertNotIn(
            full_url,
            html,
        )

        self.assertNotIn(
            selective_url,
            html,
        )

        self.assertNotIn(
            xhttp_url,
            html,
        )

    def test_full_form_is_product_specific(
        self,
    ):
        url = (
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            )
            + "?routing_mode=full"
        )

        response = self.client.get(url)

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Весь интернет через VPN",
        )

        self.assertContains(
            response,
            'name="routing_mode"',
        )

        self.assertContains(
            response,
            'value="full"',
        )

        self.assertNotContains(
            response,
            "Режим подключения",
        )

    def test_selective_form_is_product_specific(
        self,
    ):
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

        self.assertContains(
            response,
            "Только выбранные сервисы",
        )

        self.assertContains(
            response,
            'name="routing_mode"',
        )

        self.assertContains(
            response,
            'value="selective"',
        )

        self.assertNotContains(
            response,
            "Режим подключения",
        )

    def test_non_operator_cannot_open_product_selector(
        self,
    ):
        self.client.force_login(
            self.regular_user
        )

        response = self.client.get(
            reverse(
                (
                    "customers-device-"
                    "connection-create"
                ),
                args=[self.device.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_disabled_device_cannot_open_product_selector(
        self,
    ):
        self.device.status = (
            ClientDevice.Status.DISABLED
        )

        self.device.save(
            update_fields=["status"]
        )

        response = self.client.get(
            reverse(
                (
                    "customers-device-"
                    "connection-create"
                ),
                args=[self.device.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_expired_account_cannot_open_product_selector(
        self,
    ):
        self.account.expires_at = (
            timezone.now()
            - timedelta(minutes=1)
        )

        self.account.save(
            update_fields=[
                "expires_at",
            ]
        )

        response = self.client.get(
            reverse(
                (
                    "customers-device-"
                    "connection-create"
                ),
                args=[self.device.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )
