from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .access_services import (
    CustomerAccessError,
    create_customer_login,
)
from .models import ClientDevice, CustomerAccount


User = get_user_model()


class CustomerAccessCreationTest(TestCase):
    def setUp(self):
        self.operator = User.objects.create_user(
            username="phase5-operator",
            password="operator-password",
            is_owner=True,
            is_staff=True,
        )

        self.account = CustomerAccount.objects.create(
            display_name="Phase 5 Customer",
            email="phase5@example.com",
            created_by=self.operator,
        )

    def test_service_creates_non_operator_user(self):
        user = create_customer_login(
            account_id=self.account.pk,
            username="phase5-customer",
            password="Strong-Test-Pass-481!",
            actor=self.operator,
        )

        self.account.refresh_from_db()

        self.assertEqual(
            self.account.user_id,
            user.pk,
        )

        self.assertFalse(user.is_owner)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.is_active)

        self.assertTrue(
            user.check_password(
                "Strong-Test-Pass-481!"
            )
        )

    def test_operator_can_create_login_through_ui(self):
        self.client.force_login(
            self.operator
        )

        response = self.client.post(
            reverse(
                "customers-access-create",
                args=[self.account.pk],
            ),
            {
                "username": "customer-ui",
                "password1": "Strong-Ui-Pass-481!",
                "password2": "Strong-Ui-Pass-481!",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.account.refresh_from_db()

        self.assertIsNotNone(
            self.account.user_id
        )

        self.assertFalse(
            self.account.user.is_owner
        )

    def test_deleted_account_cannot_receive_login(self):
        self.account.status = (
            CustomerAccount.Status.DELETED
        )

        self.account.save(
            update_fields=["status"]
        )

        with self.assertRaises(
            CustomerAccessError
        ):
            create_customer_login(
                account_id=self.account.pk,
                username="deleted-customer",
                password="Strong-Deleted-481!",
                actor=self.operator,
            )

    def test_second_login_is_rejected(self):
        create_customer_login(
            account_id=self.account.pk,
            username="first-customer",
            password="Strong-First-481!",
            actor=self.operator,
        )

        with self.assertRaises(
            CustomerAccessError
        ):
            create_customer_login(
                account_id=self.account.pk,
                username="second-customer",
                password="Strong-Second-481!",
                actor=self.operator,
            )


class CustomerPortalAccessTest(TestCase):
    def setUp(self):
        self.operator = User.objects.create_user(
            username="phase5-staff",
            password="operator-password",
            is_owner=True,
            is_staff=True,
        )

        self.customer_user = User.objects.create_user(
            username="phase5-client",
            password="client-password",
            is_owner=False,
            is_staff=False,
            is_superuser=False,
        )

        self.account = CustomerAccount.objects.create(
            display_name="My VPN Account",
            email="client@example.com",
            user=self.customer_user,
        )

        self.device = ClientDevice.objects.create(
            account=self.account,
            name="My iPhone",
            platform=ClientDevice.Platform.IOS,
        )

        other_user = User.objects.create_user(
            username="other-client",
            password="other-password",
            is_owner=False,
        )

        other_account = CustomerAccount.objects.create(
            display_name="Other Secret Account",
            user=other_user,
        )

        ClientDevice.objects.create(
            account=other_account,
            name="Other Secret Device",
        )

    def test_anonymous_dashboard_redirects_to_customer_login(self):
        response = self.client.get(
            reverse(
                "customer-portal-home"
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

    def test_operator_cannot_use_customer_dashboard(self):
        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            reverse(
                "customer-portal-home"
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_operator_credentials_rejected_by_customer_login(self):
        response = self.client.post(
            reverse(
                "customer-portal-login"
            ),
            {
                "username": self.operator.username,
                "password": "operator-password",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertFalse(
            response.wsgi_request.user.is_authenticated
        )

        self.assertContains(
            response,
            "не имеет доступа",
        )

    def test_customer_can_login_and_only_see_own_account(self):
        response = self.client.post(
            reverse(
                "customer-portal-login"
            ),
            {
                "username": self.customer_user.username,
                "password": "client-password",
            },
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

        response = self.client.get(
            reverse(
                "customer-portal-home"
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "My VPN Account",
        )

        self.assertContains(
            response,
            "My iPhone",
        )

        self.assertNotContains(
            response,
            "Other Secret Account",
        )

        self.assertNotContains(
            response,
            "Other Secret Device",
        )
