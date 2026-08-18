from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import CustomerAccount


class AccountExpiryUITest(TestCase):
    def setUp(self):
        User = get_user_model()

        self.operator = User.objects.create_user(
            username="expiry-ui-operator",
            password="operator-password",
            is_owner=True,
        )

        self.expired = CustomerAccount.objects.create(
            display_name="Expired UI Customer",
            email="expired-ui@example.com",
            status=CustomerAccount.Status.ACTIVE,
            expires_at=(
                timezone.now()
                - timedelta(days=1)
            ),
            created_by=self.operator,
        )

        self.valid = CustomerAccount.objects.create(
            display_name="Valid UI Customer",
            email="valid-ui@example.com",
            status=CustomerAccount.Status.ACTIVE,
            expires_at=(
                timezone.now()
                + timedelta(days=30)
            ),
            created_by=self.operator,
        )

        self.client.force_login(
            self.operator
        )

    def test_expired_account_is_not_in_active_filter(
        self,
    ):
        response = self.client.get(
            reverse("customers-list"),
            {
                "status": "active",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            self.valid.display_name,
        )

        self.assertNotContains(
            response,
            self.expired.display_name,
        )

    def test_expired_account_has_expired_badge_in_list(
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
            self.expired.display_name,
        )

        self.assertContains(
            response,
            "Срок истёк",
        )

        self.assertContains(
            response,
            "Доступ отключён",
        )

    def test_expired_account_detail_has_expired_status(
        self,
    ):
        response = self.client.get(
            reverse(
                "customers-detail",
                args=[self.expired.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Срок истёк",
        )

        self.assertContains(
            response,
            "Срок действия аккаунта истёк.",
        )
