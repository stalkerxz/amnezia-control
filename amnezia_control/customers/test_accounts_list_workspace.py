from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import (
    ClientDevice,
    CustomerAccount,
)


class CustomerAccountsListWorkspaceTest(
    TestCase
):

    def setUp(self):
        User = get_user_model()

        self.operator = User.objects.create_user(
            username="accounts-list-operator",
            password="test-password",
        )

        self.cabinet_user = (
            User.objects.create_user(
                username="accounts-list-customer",
                password="test-password",
                is_owner=False,
            )
        )

        self.no_device_user = (
            User.objects.create_user(
                username="accounts-no-device",
                password="test-password",
                is_owner=False,
            )
        )

        self.expiring_user = (
            User.objects.create_user(
                username="accounts-expiring",
                password="test-password",
                is_owner=False,
            )
        )

        self.alpha = (
            CustomerAccount.objects.create(
                display_name="Alpha Customer",
                email="alpha@example.com",
                status=(
                    CustomerAccount.Status.ACTIVE
                ),
                user=self.cabinet_user,
            )
        )

        self.alpha_device = (
            ClientDevice.objects.create(
                account=self.alpha,
                name="Alpha iPhone",
                platform=(
                    ClientDevice.Platform.IOS
                ),
                status=(
                    ClientDevice.Status.ACTIVE
                ),
            )
        )

        self.bravo = (
            CustomerAccount.objects.create(
                display_name="Bravo Customer",
                email="bravo@example.com",
                status=(
                    CustomerAccount.Status.ACTIVE
                ),
            )
        )

        ClientDevice.objects.create(
            account=self.bravo,
            name="Bravo MacBook",
            platform=(
                ClientDevice.Platform.MACOS
            ),
            status=(
                ClientDevice.Status.ACTIVE
            ),
        )

        self.charlie = (
            CustomerAccount.objects.create(
                display_name="Charlie Customer",
                email="charlie@example.com",
                status=(
                    CustomerAccount.Status.ACTIVE
                ),
                user=self.no_device_user,
            )
        )

        self.delta = (
            CustomerAccount.objects.create(
                display_name="Delta Customer",
                email="delta@example.com",
                status=(
                    CustomerAccount.Status.ACTIVE
                ),
                user=self.expiring_user,
                expires_at=(
                    timezone.now()
                    + timedelta(days=3)
                ),
            )
        )

        ClientDevice.objects.create(
            account=self.delta,
            name="Delta Windows",
            platform=(
                ClientDevice.Platform.WINDOWS
            ),
            status=(
                ClientDevice.Status.ACTIVE
            ),
        )

        self.disabled = (
            CustomerAccount.objects.create(
                display_name="Disabled Customer",
                status=(
                    CustomerAccount.Status.DISABLED
                ),
            )
        )

        self.deleted = (
            CustomerAccount.objects.create(
                display_name="Deleted Customer",
                status=(
                    CustomerAccount.Status.DELETED
                ),
            )
        )

        self.client.force_login(
            self.operator
        )

    def test_workspace_renders_kpis_and_filters(
        self,
    ):
        response = self.client.get(
            reverse("customers-list")
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Требуют внимания",
        )

        self.assertContains(
            response,
            "Кабинет создан",
        )

        self.assertContains(
            response,
            "Без кабинета",
        )

        self.assertContains(
            response,
            "Подключения",
        )

        self.assertContains(
            response,
            "Клиент, email или устройство",
        )

        metrics = response.context[
            "metrics"
        ]

        self.assertEqual(
            metrics["total"],
            6,
        )

        self.assertEqual(
            metrics["active"],
            4,
        )

        self.assertEqual(
            metrics["disabled"],
            1,
        )

        self.assertEqual(
            metrics["deleted"],
            1,
        )

        self.assertEqual(
            metrics["cabinet_missing"],
            1,
        )

        self.assertEqual(
            metrics["expires_soon"],
            1,
        )

    def test_search_matches_device_name(
        self,
    ):
        response = self.client.get(
            reverse("customers-list"),
            {
                "q": "Alpha iPhone",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        accounts = list(
            response.context["accounts"]
        )

        self.assertEqual(
            accounts,
            [self.alpha],
        )

    def test_status_filter(
        self,
    ):
        response = self.client.get(
            reverse("customers-list"),
            {
                "status": "disabled",
            },
        )

        accounts = list(
            response.context["accounts"]
        )

        self.assertEqual(
            accounts,
            [self.disabled],
        )

    def test_no_cabinet_filter(
        self,
    ):
        response = self.client.get(
            reverse("customers-list"),
            {
                "readiness": "no_cabinet",
            },
        )

        accounts = list(
            response.context["accounts"]
        )

        self.assertEqual(
            accounts,
            [self.bravo],
        )

    def test_no_devices_filter(
        self,
    ):
        response = self.client.get(
            reverse("customers-list"),
            {
                "readiness": "no_devices",
            },
        )

        accounts = list(
            response.context["accounts"]
        )

        self.assertEqual(
            accounts,
            [self.charlie],
        )

    def test_expiring_filter(
        self,
    ):
        response = self.client.get(
            reverse("customers-list"),
            {
                "readiness": "expiring",
            },
        )

        accounts = list(
            response.context["accounts"]
        )

        self.assertEqual(
            accounts,
            [self.delta],
        )

    def test_no_cabinet_does_not_override_operational_readiness(
        self,
    ):
        response = self.client.get(
            reverse("customers-list")
        )

        account = (
            response.context["accounts"]
            .get(pk=self.bravo.pk)
        )

        self.assertEqual(
            account.readiness_code,
            "no_connections",
        )

        self.assertNotEqual(
            account.readiness_code,
            "no_cabinet",
        )
