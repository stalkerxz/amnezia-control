from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from customers.models import (
    CustomerAccount,
)


class DashboardCustomerMetricsTests(TestCase):
    def setUp(self):
        User = get_user_model()

        self.operator = User.objects.create_user(
            username="dashboard-counter-operator",
            password="test-password",
            is_staff=True,
        )

        CustomerAccount.objects.create(
            display_name="Active attention",
            email="attention@example.test",
            status=CustomerAccount.Status.ACTIVE,
            created_by=self.operator,
        )

        CustomerAccount.objects.create(
            display_name="Disabled customer",
            email="disabled@example.test",
            status=CustomerAccount.Status.DISABLED,
            created_by=self.operator,
        )

        CustomerAccount.objects.create(
            display_name="Archived customer",
            email="archived@example.test",
            status=CustomerAccount.Status.DELETED,
            created_by=self.operator,
        )

        self.client.force_login(
            self.operator
        )

    def test_dashboard_matches_customer_list_metrics(self):
        customers_response = self.client.get(
            reverse("customers-list")
        )

        dashboard_response = self.client.get(
            reverse("dashboard")
        )

        self.assertEqual(
            customers_response.status_code,
            200,
        )

        self.assertEqual(
            dashboard_response.status_code,
            200,
        )

        customer_metrics = (
            customers_response.context[
                "metrics"
            ]
        )

        self.assertEqual(
            dashboard_response.context[
                "clients_total_count"
            ],
            customer_metrics["total"],
        )

        self.assertEqual(
            dashboard_response.context[
                "active_clients_count"
            ],
            customer_metrics["active"],
        )

        self.assertEqual(
            dashboard_response.context[
                "customer_attention_count"
            ],
            customer_metrics["attention"],
        )

    def test_deleted_accounts_are_not_dashboard_clients(self):
        response = self.client.get(
            reverse("dashboard")
        )

        self.assertEqual(
            response.context[
                "clients_total_count"
            ],
            2,
        )

        self.assertEqual(
            response.context[
                "active_clients_count"
            ],
            1,
        )

        self.assertEqual(
            response.context[
                "customer_attention_count"
            ],
            1,
        )
