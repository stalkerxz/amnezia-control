from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from audit.models import AuditLog

from .models import CustomerAccount


User = get_user_model()


class CustomerPortalPasswordChangeTest(TestCase):
    OLD_PASSWORD = "Old-Portal-Pass-481!"
    NEW_PASSWORD = "New-Portal-Pass-982!"

    def setUp(self):
        self.customer = User.objects.create_user(
            username="password-customer",
            password=self.OLD_PASSWORD,
            is_owner=False,
            is_staff=False,
            is_superuser=False,
        )

        self.account = CustomerAccount.objects.create(
            display_name="Password Customer",
            email="password@example.com",
            user=self.customer,
        )

        self.operator = User.objects.create_user(
            username="password-operator",
            password="Operator-Pass-481!",
            is_owner=True,
            is_staff=True,
        )

    def _payload(self, *, old_password=None):
        return {
            "old_password": (
                old_password
                if old_password is not None
                else self.OLD_PASSWORD
            ),
            "new_password1": self.NEW_PASSWORD,
            "new_password2": self.NEW_PASSWORD,
        }

    def test_anonymous_user_is_redirected_to_customer_login(self):
        response = self.client.get(
            reverse(
                "customer-portal-password-change"
            )
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.assertTrue(
            response.url.startswith(
                "/cabinet/login/"
            )
        )

    def test_operator_cannot_use_customer_password_screen(self):
        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            reverse(
                "customer-portal-password-change"
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_customer_changes_password_and_keeps_session(self):
        self.client.force_login(
            self.customer
        )

        response = self.client.post(
            reverse(
                "customer-portal-password-change"
            ),
            self._payload(),
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.assertEqual(
            response.url,
            reverse(
                "customer-portal-home"
            ),
        )

        self.customer.refresh_from_db()

        self.assertFalse(
            self.customer.check_password(
                self.OLD_PASSWORD
            )
        )

        self.assertTrue(
            self.customer.check_password(
                self.NEW_PASSWORD
            )
        )

        home = self.client.get(
            reverse(
                "customer-portal-home"
            )
        )

        self.assertEqual(
            home.status_code,
            200,
        )

        audit = AuditLog.objects.get(
            action=(
                "customer.login.password_change"
            ),
            entity_type="CustomerAccount",
            entity_id=str(
                self.account.pk
            ),
        )

        self.assertEqual(
            audit.actor_id,
            self.customer.pk,
        )

        self.assertEqual(
            audit.details["user_id"],
            self.customer.pk,
        )

        serialized_details = str(
            audit.details
        )

        self.assertNotIn(
            self.OLD_PASSWORD,
            serialized_details,
        )

        self.assertNotIn(
            self.NEW_PASSWORD,
            serialized_details,
        )

    def test_wrong_current_password_does_not_change_password(self):
        self.client.force_login(
            self.customer
        )

        response = self.client.post(
            reverse(
                "customer-portal-password-change"
            ),
            self._payload(
                old_password=(
                    "Wrong-Portal-Pass-481!"
                )
            ),
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertIn(
            "old_password",
            response.context["form"].errors,
        )

        self.customer.refresh_from_db()

        self.assertTrue(
            self.customer.check_password(
                self.OLD_PASSWORD
            )
        )

        self.assertFalse(
            AuditLog.objects.filter(
                action=(
                    "customer.login.password_change"
                ),
                entity_type="CustomerAccount",
                entity_id=str(
                    self.account.pk
                ),
            ).exists()
        )

    def test_deleted_customer_account_is_denied(self):
        self.account.status = (
            CustomerAccount.Status.DELETED
        )

        self.account.save(
            update_fields=["status"]
        )

        self.client.force_login(
            self.customer
        )

        response = self.client.get(
            reverse(
                "customer-portal-password-change"
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_disabled_customer_can_still_secure_own_login(self):
        self.account.status = (
            CustomerAccount.Status.DISABLED
        )

        self.account.save(
            update_fields=["status"]
        )

        self.client.force_login(
            self.customer
        )

        response = self.client.post(
            reverse(
                "customer-portal-password-change"
            ),
            self._payload(),
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.customer.refresh_from_db()

        self.assertTrue(
            self.customer.check_password(
                self.NEW_PASSWORD
            )
        )
