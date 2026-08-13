from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import ClientDevice, CustomerAccount


class CustomerViewsTest(TestCase):
    def setUp(self):
        User = get_user_model()

        self.operator = User.objects.create_user(
            username="operator",
            password="test-password",
        )

        self.account = CustomerAccount.objects.create(
            display_name="Test Customer",
            email="customer@example.com",
        )

        self.device = ClientDevice.objects.create(
            account=self.account,
            name="Test iPhone",
            platform=ClientDevice.Platform.IOS,
        )

    def test_list_requires_login(self):
        response = self.client.get(reverse("customers-list"))

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_list_renders_account_and_counts(self):
        self.client.force_login(self.operator)

        response = self.client.get(reverse("customers-list"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response,
            "customers/customers_list.html",
        )
        self.assertContains(response, "Test Customer")

        account = response.context["accounts"].get(pk=self.account.pk)
        self.assertEqual(account.device_count, 1)
        self.assertEqual(account.vpn_config_count, 0)

    def test_detail_renders_device(self):
        self.client.force_login(self.operator)

        response = self.client.get(
            reverse(
                "customers-detail",
                args=[self.account.pk],
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response,
            "customers/customer_detail.html",
        )
        self.assertContains(response, "Test Customer")
        self.assertContains(response, "Test iPhone")
        self.assertContains(response, "iPhone / iPad")

    def test_unknown_account_returns_404(self):
        self.client.force_login(self.operator)

        response = self.client.get(
            reverse(
                "customers-detail",
                args=[999999],
            )
        )

        self.assertEqual(response.status_code, 404)

    def test_read_only_pages_reject_post(self):
        self.client.force_login(self.operator)

        list_response = self.client.post(reverse("customers-list"))
        detail_response = self.client.post(
            reverse(
                "customers-detail",
                args=[self.account.pk],
            )
        )

        self.assertEqual(list_response.status_code, 405)
        self.assertEqual(detail_response.status_code, 405)

    def test_read_only_pages_do_not_change_data(self):
        self.client.force_login(self.operator)

        before = (
            CustomerAccount.objects.count(),
            ClientDevice.objects.count(),
        )

        self.client.get(reverse("customers-list"))
        self.client.get(
            reverse(
                "customers-detail",
                args=[self.account.pk],
            )
        )

        after = (
            CustomerAccount.objects.count(),
            ClientDevice.objects.count(),
        )

        self.assertEqual(after, before)
