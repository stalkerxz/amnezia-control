import uuid
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from servers.models import Server

from vpn.models import XHTTPDevice

from .models import (
    ClientDevice,
    CustomerAccount,
)


class OperatorXHTTPWorkspaceTest(
    TestCase
):
    def setUp(self):
        User = get_user_model()

        self.operator = (
            User.objects.create_user(
                username="xhttp-workspace-operator",
                password="operator-password",
                is_owner=True,
            )
        )

        self.customer_user = (
            User.objects.create_user(
                username="xhttp-workspace-customer",
                password="customer-password",
                is_owner=False,
            )
        )

        self.account = (
            CustomerAccount.objects.create(
                display_name="XHTTP Customer",
                email="xhttp@example.com",
                user=self.customer_user,
                created_by=self.operator,
            )
        )

        self.device = (
            ClientDevice.objects.create(
                account=self.account,
                name="XHTTP iPhone",
                platform=(
                    ClientDevice.Platform.IOS
                ),
            )
        )

        self.server = Server.objects.create(
            name="XHTTP Server",
            is_enabled=True,
        )

        self.xhttp = (
            XHTTPDevice.objects.create(
                device=self.device,
                server=self.server,
                name="CDN",
                client_uuid=uuid.uuid4(),
                xray_email=(
                    "xhttp-"
                    + uuid.uuid4().hex
                ),
                status=(
                    XHTTPDevice.Status.ACTIVE
                ),
                config_blob_encrypted="test",
                config_hash="0" * 64,
            )
        )

    def test_scoped_create_page(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            reverse(
                "customers-device-xhttp-create",
                args=[self.device.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Альтернативное подключение",
        )

        self.assertNotContains(
            response,
            "VLESS / XHTTP",
        )

        self.assertNotContains(
            response,
            "VLESS/XHTTP",
        )

        self.assertNotContains(
            response,
            "UUID",
        )

        self.assertContains(
            response,
            reverse(
                "customers-device-connection-create",
                args=[self.device.pk],
            ),
        )

        self.assertContains(
            response,
            self.account.display_name,
        )

        self.assertContains(
            response,
            self.device.name,
        )

        self.assertEqual(
            response.context[
                "device"
            ].pk,
            self.device.pk,
        )

        self.assertEqual(
            response.context[
                "form"
            ].initial["server"],
            self.server.pk,
        )

    @patch(
        "customers.views."
        "XHTTPDeviceService.create_device"
    )
    def test_scoped_create_uses_url_device(
        self,
        create_device,
    ):
        create_device.return_value = (
            SimpleNamespace(
                name="New CDN"
            )
        )

        self.client.force_login(
            self.operator
        )

        response = self.client.post(
            reverse(
                "customers-device-xhttp-create",
                args=[self.device.pk],
            ),
            {
                "device": "999999",
                "server": self.server.pk,
                "name": "New CDN",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.assertEqual(
            response.url,
            reverse(
                "customers-detail",
                args=[self.account.pk],
            ),
        )

        kwargs = (
            create_device
            .call_args
            .kwargs
        )

        self.assertEqual(
            kwargs["device"].pk,
            self.device.pk,
        )

        self.assertEqual(
            kwargs["server"].pk,
            self.server.pk,
        )

        self.assertEqual(
            kwargs["name"],
            "New CDN",
        )

    def test_customer_cannot_create_xhttp(
        self,
    ):
        self.client.force_login(
            self.customer_user
        )

        response = self.client.get(
            reverse(
                "customers-device-xhttp-create",
                args=[self.device.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_disabled_device_cannot_create_xhttp(
        self,
    ):
        self.device.status = (
            ClientDevice.Status.DISABLED
        )

        self.device.save(
            update_fields=["status"]
        )

        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            reverse(
                "customers-device-xhttp-create",
                args=[self.device.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    @patch(
        "customers.views."
        "XHTTPDeviceService.disable"
    )
    def test_device_workspace_action_dispatch(
        self,
        disable,
    ):
        self.client.force_login(
            self.operator
        )

        response = self.client.post(
            reverse(
                "customers-xhttp-action",
                args=[
                    self.xhttp.pk,
                    "disable",
                ],
            )
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.assertEqual(
            response.url,
            reverse(
                "customers-detail",
                args=[self.account.pk],
            ),
        )

        self.assertEqual(
            disable.call_count,
            1,
        )

        called_device = (
            disable
            .call_args
            .kwargs["device"]
        )

        self.assertEqual(
            called_device.pk,
            self.xhttp.pk,
        )

    def test_unknown_action_is_rejected(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        response = self.client.post(
            reverse(
                "customers-xhttp-action",
                args=[
                    self.xhttp.pk,
                    "unknown",
                ],
            )
        )

        self.assertEqual(
            response.status_code,
            400,
        )

    def test_workspace_contains_scoped_xhttp_controls(
        self,
    ):
        self.client.force_login(
            self.operator
        )

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

        self.assertContains(
            response,
            reverse(
                "customers-device-connection-create",
                args=[self.device.pk],
            ),
        )

        self.assertContains(
            response,
            "+ Подключение",
        )

        self.assertNotContains(
            response,
            reverse(
                "customers-device-xhttp-create",
                args=[self.device.pk],
            ),
        )

        for action in (
            "check",
            "disable",
            "rotate",
            "delete",
        ):
            self.assertContains(
                response,
                reverse(
                    "customers-xhttp-action",
                    args=[
                        self.xhttp.pk,
                        action,
                    ],
                ),
            )

        self.assertNotContains(
            response,
            "/xhttp/?device=",
        )

        self.assertContains(
            response,
            "Проверить",
        )

        self.assertContains(
            response,
            "Перевыпустить",
        )

        self.assertContains(
            response,
            "Удалить",
        )
