from unittest.mock import patch

from django.contrib.auth import (
    get_user_model,
)
from django.test import TestCase
from django.urls import reverse

from .access_services import (
    CustomerAccessError,
)
from .models import (
    ClientDevice,
    CustomerAccount,
)


class CustomerOnboardingTest(TestCase):
    password = (
        "S3cure-Onboarding-Password!2026"
    )

    def setUp(self):
        User = get_user_model()

        self.operator = (
            User.objects.create_user(
                username="onboarding-operator",
                password="operator-password",
                is_owner=True,
            )
        )

        self.regular_user = (
            User.objects.create_user(
                username="onboarding-regular",
                password="regular-password",
                is_owner=False,
            )
        )

        self.client.force_login(
            self.operator
        )

    def _payload(
        self,
        **overrides,
    ):
        data = {
            "display_name": (
                "Onboarding Customer"
            ),
            "email": (
                "onboarding@example.com"
            ),
            "expires_at": "",
            "device_name": (
                "Onboarding iPhone"
            ),
            "device_platform": (
                ClientDevice.Platform.IOS
            ),
            "device_notes": (
                "Первое устройство"
            ),
            "create_login": "on",
            "username": "",
            "password1": self.password,
            "password2": self.password,
        }

        data.update(
            overrides
        )

        return data

    def test_onboarding_page_and_primary_list_action(
        self,
    ):
        response = self.client.get(
            reverse(
                "customers-onboarding"
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Создать клиента",
        )

        self.assertContains(
            response,
            "Первое устройство",
        )

        self.assertContains(
            response,
            "Личный кабинет",
        )

        self.assertContains(
            response,
            (
                "Подключения на этом этапе "
                "не создаются и не изменяются."
            ),
        )

        for technical_marker in (
            "FULL",
            "SELECTIVE",
            "VLESS/XHTTP",
            "AWG2",
            "runtime",
        ):
            self.assertNotContains(
                response,
                technical_marker,
            )

        list_response = self.client.get(
            reverse(
                "customers-list"
            )
        )

        self.assertEqual(
            list_response.status_code,
            200,
        )

        self.assertContains(
            list_response,
            reverse(
                "customers-onboarding"
            ),
        )

        self.assertContains(
            list_response,
            "Новый клиент",
        )

        self.assertContains(
            list_response,
            reverse(
                "customers-create"
            ),
        )

    @patch(
        "vpn.xhttp_services."
        "XHTTPDeviceService.create_device"
    )
    @patch(
        "vpn.services."
        "VPNClientService.create_client"
    )
    def test_full_onboarding_creates_account_device_and_login_without_runtime(
        self,
        vpn_create,
        xhttp_create,
    ):
        response = self.client.post(
            reverse(
                "customers-onboarding"
            ),
            self._payload(),
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        account = (
            CustomerAccount.objects.get(
                display_name=(
                    "Onboarding Customer"
                )
            )
        )

        self.assertEqual(
            account.status,
            CustomerAccount.Status.ACTIVE,
        )

        self.assertIsNotNone(
            account.user_id
        )

        self.assertEqual(
            account.user.username,
            "onboarding@example.com",
        )

        self.assertTrue(
            account.user.check_password(
                self.password
            )
        )

        device = (
            ClientDevice.objects.get(
                account=account
            )
        )

        self.assertEqual(
            device.name,
            "Onboarding iPhone",
        )

        self.assertEqual(
            device.status,
            ClientDevice.Status.ACTIVE,
        )

        self.assertRedirects(
            response,
            reverse(
                "customers-detail",
                args=[account.pk],
            ),
            fetch_redirect_response=False,
        )

        vpn_create.assert_not_called()
        xhttp_create.assert_not_called()

    def test_onboarding_can_skip_customer_login(
        self,
    ):
        payload = self._payload(
            create_login="",
            username="",
            password1="",
            password2="",
            email="no-login@example.com",
        )

        response = self.client.post(
            reverse(
                "customers-onboarding"
            ),
            payload,
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        account = (
            CustomerAccount.objects.get(
                email="no-login@example.com"
            )
        )

        self.assertIsNone(
            account.user_id
        )

        self.assertEqual(
            account.devices.count(),
            1,
        )

    @patch(
        "customers.onboarding_services."
        "create_customer_login"
    )
    def test_login_failure_rolls_back_account_and_device(
        self,
        create_login,
    ):
        create_login.side_effect = (
            CustomerAccessError(
                "Login creation failed"
            )
        )

        response = self.client.post(
            reverse(
                "customers-onboarding"
            ),
            self._payload(
                email=(
                    "rollback@example.com"
                ),
                username=(
                    "rollback@example.com"
                ),
            ),
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Login creation failed",
        )

        self.assertFalse(
            CustomerAccount.objects.filter(
                email="rollback@example.com"
            ).exists()
        )

        self.assertFalse(
            ClientDevice.objects.filter(
                name="Onboarding iPhone"
            ).exists()
        )

    def test_non_operator_cannot_use_onboarding(
        self,
    ):
        self.client.force_login(
            self.regular_user
        )

        response = self.client.get(
            reverse(
                "customers-onboarding"
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )
