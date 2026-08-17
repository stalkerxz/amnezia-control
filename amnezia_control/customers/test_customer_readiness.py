from django.contrib.auth import (
    get_user_model,
)
from django.test import TestCase
from django.urls import reverse

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)
from vpn.models import VPNClient

from .models import (
    ClientDevice,
    CustomerAccount,
)


class CustomerReadinessWorkflowTest(
    TestCase
):
    def setUp(self):
        User = get_user_model()

        self.operator = (
            User.objects.create_user(
                username=(
                    "readiness-operator"
                ),
                password="test-password",
                is_owner=True,
            )
        )

        self.account = (
            CustomerAccount.objects.create(
                display_name=(
                    "Readiness Customer"
                ),
                email=(
                    "readiness@example.com"
                ),
                status=(
                    CustomerAccount.Status.ACTIVE
                ),
                created_by=self.operator,
            )
        )

        self.client.force_login(
            self.operator
        )

    def _detail(self):
        return self.client.get(
            reverse(
                "customers-detail",
                args=[self.account.pk],
            )
        )

    def _add_customer_login(self):
        User = get_user_model()

        user = User.objects.create_user(
            username=(
                "readiness-customer"
            ),
            password="test-password",
            is_owner=False,
            is_active=True,
        )

        self.account.user = user
        self.account.save(
            update_fields=["user"]
        )

        return user

    def _add_device(self):
        return ClientDevice.objects.create(
            account=self.account,
            name="Readiness iPhone",
            platform=(
                ClientDevice.Platform.IOS
            ),
            status=(
                ClientDevice.Status.ACTIVE
            ),
        )

    def _add_connection(
        self,
        device,
    ):
        server = Server.objects.create(
            name="Readiness Server",
            public_endpoint_host=(
                "vpn.example.com"
            ),
        )

        protocol = (
            ServerProtocol.objects.create(
                server=server,
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
                        "10.90.0.0/24"
                    ),
                },
            )
        )

        profile = (
            ProtocolProfile.objects.create(
                server_protocol=protocol,
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
        )

        return VPNClient.objects.create(
            server=server,
            name="Readiness VPN",
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            profile=profile,
            device=device,
            status=VPNClient.Status.ACTIVE,
        )

    def test_new_account_shows_readiness_chain_and_next_actions(
        self,
    ):
        response = self._detail()

        self.assertEqual(
            response.status_code,
            200,
        )

        for marker in (
            "Состояние клиента",
            "Шаг 1",
            "Шаг 2",
            "Шаг 3",
            "Шаг 4",
            "Клиент",
            "Личный кабинет",
            "Устройство",
            "Подключения",
            "Настройка не завершена",
            "Создать кабинет",
            "Добавить устройство",
        ):
            self.assertContains(
                response,
                marker,
            )

        self.assertNotContains(
            response,
            "VPN работает",
        )

    def test_customer_login_marks_cabinet_ready(
        self,
    ):
        self._add_customer_login()

        response = self._detail()

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Кабинет создан, вход разрешён.",
        )

        self.assertContains(
            response,
            "Управление кабинетом",
        )

        create_access_url = reverse(
            "customers-access-create",
            args=[self.account.pk],
        )

        self.assertNotContains(
            response,
            f'href="{create_access_url}"',
        )

    def test_active_device_without_connection_points_to_workspace(
        self,
    ):
        self._add_customer_login()
        self._add_device()

        response = self._detail()

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Активных устройств:",
        )

        self.assertContains(
            response,
            "Добавьте нужное подключение",
        )

        self.assertContains(
            response,
            "в карточке устройства ниже.",
        )

        self.assertContains(
            response,
            'href="#customer-connections"',
        )

        self.assertContains(
            response,
            'id="customer-connections"',
        )

        self.assertContains(
            response,
            "+ Подключение",
        )

    def test_complete_customer_is_marked_ready(
        self,
    ):
        self._add_customer_login()
        device = self._add_device()

        self._add_connection(
            device
        )

        response = self._detail()

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "VPN работает",
        )

        self.assertContains(
            response,
            "Активных устройств:",
        )

        self.assertContains(
            response,
            "Активных подключений:",
        )

        self.assertContains(
            response,
            "Рабочее состояние.",
        )

        self.assertNotContains(
            response,
            "Шаг 1",
        )

        self.assertNotContains(
            response,
            "Шаг 4",
        )

    def test_disabled_account_requires_attention(
        self,
    ):
        self._add_customer_login()
        self._add_device()

        self.account.status = (
            CustomerAccount.Status.DISABLED
        )

        self.account.save(
            update_fields=["status"]
        )

        response = self._detail()

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Аккаунт отключён.",
        )

        self.assertContains(
            response,
            "! Требует внимания",
        )

        self.assertNotContains(
            response,
            "VPN работает",
        )

    def test_operational_vpn_is_ready_without_cabinet(
        self,
    ):
        device = self._add_device()

        self._add_connection(
            device
        )

        response = self._detail()

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "VPN работает",
        )

        self.assertContains(
            response,
            "Кабинет не создан",
        )

        self.assertContains(
            response,
            "Личный кабинет не создан.",
        )

        self.assertNotContains(
            response,
            "Отдельная настройка",
        )

        self.assertContains(
            response,
            "Создать кабинет",
        )

        self.assertNotContains(
            response,
            "Настройка не завершена",
        )

        self.assertContains(
            response,
            "Рабочее состояние.",
        )

        self.assertNotContains(
            response,
            "Шаг 1",
        )

        self.assertNotContains(
            response,
            "Шаг 4",
        )
