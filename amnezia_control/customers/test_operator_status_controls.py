from unittest.mock import patch

from django.contrib.auth import (
    get_user_model,
)
from django.test import TestCase
from django.urls import reverse

from .models import (
    ClientDevice,
    CustomerAccount,
)
from .status_services import (
    CustomerStatusOperationError,
    set_customer_account_status,
)


User = get_user_model()


class OperatorStatusControlTest(
    TestCase
):
    def setUp(self):
        self.operator = (
            User.objects.create_user(
                username=(
                    "status-operator"
                ),
                password=(
                    "operator-password"
                ),
                is_owner=True,
                is_staff=True,
            )
        )

        self.customer_user = (
            User.objects.create_user(
                username=(
                    "status-customer"
                ),
                password=(
                    "customer-password"
                ),
                is_owner=False,
                is_staff=False,
            )
        )

        self.account = (
            CustomerAccount.objects.create(
                display_name=(
                    "Status Customer"
                ),
                status=(
                    CustomerAccount
                    .Status
                    .ACTIVE
                ),
                created_by=(
                    self.operator
                ),
            )
        )

        self.device = (
            ClientDevice.objects.create(
                account=(
                    self.account
                ),
                name=(
                    "Status Device"
                ),
                status=(
                    ClientDevice
                    .Status
                    .ACTIVE
                ),
            )
        )

    def success_result(self):
        return {
            "errors": [],
        }

    @patch(
        "customers.status_services."
        "reconcile_xhttp_account_task.run"
    )
    @patch(
        "customers.status_services."
        "reconcile_vpn_account_task.run"
    )
    def test_operator_can_disable_account(
        self,
        vpn_run,
        xhttp_run,
    ):
        vpn_run.return_value = (
            self.success_result()
        )

        xhttp_run.return_value = (
            self.success_result()
        )

        self.client.force_login(
            self.operator
        )

        response = self.client.post(
            reverse(
                "customers-status",
                args=[
                    self.account.pk
                ],
            ),
            {
                "status": (
                    CustomerAccount
                    .Status
                    .DISABLED
                )
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.account.refresh_from_db()

        self.assertEqual(
            self.account.status,
            (
                CustomerAccount
                .Status
                .DISABLED
            ),
        )

        vpn_run.assert_called_once_with(
            self.account.pk
        )

        xhttp_run.assert_called_once_with(
            self.account.pk
        )

    @patch(
        "customers.status_services."
        "reconcile_xhttp_account_task.run"
    )
    @patch(
        "customers.status_services."
        "reconcile_vpn_account_task.run"
    )
    def test_operator_can_enable_account(
        self,
        vpn_run,
        xhttp_run,
    ):
        self.account.status = (
            CustomerAccount
            .Status
            .DISABLED
        )

        self.account.save(
            update_fields=[
                "status",
            ]
        )

        vpn_run.return_value = (
            self.success_result()
        )

        xhttp_run.return_value = (
            self.success_result()
        )

        self.client.force_login(
            self.operator
        )

        response = self.client.post(
            reverse(
                "customers-status",
                args=[
                    self.account.pk
                ],
            ),
            {
                "status": (
                    CustomerAccount
                    .Status
                    .ACTIVE
                )
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.account.refresh_from_db()

        self.assertEqual(
            self.account.status,
            (
                CustomerAccount
                .Status
                .ACTIVE
            ),
        )

    @patch(
        "customers.status_services."
        "reconcile_xhttp_device_task.run"
    )
    @patch(
        "customers.status_services."
        "reconcile_vpn_device_task.run"
    )
    def test_operator_can_disable_device(
        self,
        vpn_run,
        xhttp_run,
    ):
        vpn_run.return_value = (
            self.success_result()
        )

        xhttp_run.return_value = (
            self.success_result()
        )

        self.client.force_login(
            self.operator
        )

        response = self.client.post(
            reverse(
                "customers-device-status",
                args=[
                    self.device.pk
                ],
            ),
            {
                "status": (
                    ClientDevice
                    .Status
                    .DISABLED
                )
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.device.refresh_from_db()

        self.assertEqual(
            self.device.status,
            (
                ClientDevice
                .Status
                .DISABLED
            ),
        )

        vpn_run.assert_called_once_with(
            self.device.pk
        )

        xhttp_run.assert_called_once_with(
            self.device.pk
        )

    @patch(
        "customers.status_services."
        "reconcile_xhttp_device_task.run"
    )
    @patch(
        "customers.status_services."
        "reconcile_vpn_device_task.run"
    )
    def test_operator_can_enable_device(
        self,
        vpn_run,
        xhttp_run,
    ):
        self.device.status = (
            ClientDevice
            .Status
            .DISABLED
        )

        self.device.save(
            update_fields=[
                "status",
            ]
        )

        vpn_run.return_value = (
            self.success_result()
        )

        xhttp_run.return_value = (
            self.success_result()
        )

        self.client.force_login(
            self.operator
        )

        response = self.client.post(
            reverse(
                "customers-device-status",
                args=[
                    self.device.pk
                ],
            ),
            {
                "status": (
                    ClientDevice
                    .Status
                    .ACTIVE
                )
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.device.refresh_from_db()

        self.assertEqual(
            self.device.status,
            (
                ClientDevice
                .Status
                .ACTIVE
            ),
        )

    def test_customer_cannot_change_account_status(
        self,
    ):
        self.client.force_login(
            self.customer_user
        )

        response = self.client.post(
            reverse(
                "customers-status",
                args=[
                    self.account.pk
                ],
            ),
            {
                "status": (
                    CustomerAccount
                    .Status
                    .DISABLED
                )
            },
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_status_routes_are_post_only(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        account_response = (
            self.client.get(
                reverse(
                    "customers-status",
                    args=[
                        self.account.pk
                    ],
                )
            )
        )

        device_response = (
            self.client.get(
                reverse(
                    "customers-device-status",
                    args=[
                        self.device.pk
                    ],
                )
            )
        )

        self.assertEqual(
            account_response.status_code,
            405,
        )

        self.assertEqual(
            device_response.status_code,
            405,
        )

    @patch(
        "customers.status_services."
        "reconcile_xhttp_account_task.run"
    )
    @patch(
        "customers.status_services."
        "reconcile_vpn_account_task.run"
    )
    def test_runtime_failure_restores_account_status(
        self,
        vpn_run,
        xhttp_run,
    ):
        vpn_run.return_value = (
            self.success_result()
        )

        xhttp_run.side_effect = [
            {
                "errors": [
                    {
                        "error": (
                            "simulated"
                        )
                    }
                ]
            },
            self.success_result(),
        ]

        with self.assertRaises(
            CustomerStatusOperationError
        ):
            set_customer_account_status(
                account_id=(
                    self.account.pk
                ),
                target_status=(
                    CustomerAccount
                    .Status
                    .DISABLED
                ),
                actor=(
                    self.operator
                ),
            )

        self.account.refresh_from_db()

        self.assertEqual(
            self.account.status,
            (
                CustomerAccount
                .Status
                .ACTIVE
            ),
        )

        self.assertGreaterEqual(
            vpn_run.call_count,
            2,
        )

    def test_detail_page_has_status_controls(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            reverse(
                "customers-detail",
                args=[
                    self.account.pk
                ],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            reverse(
                "customers-status",
                args=[
                    self.account.pk
                ],
            ),
        )

        self.assertContains(
            response,
            reverse(
                "customers-device-status",
                args=[
                    self.device.pk
                ],
            ),
        )

        self.assertContains(
            response,
            "Отключить аккаунт",
        )

        self.assertContains(
            response,
            "Отключить устройство",
        )
