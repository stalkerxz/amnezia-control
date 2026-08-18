from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import (
    TestCase,
    override_settings,
)
from django.urls import reverse

from customers.models import (
    ClientDevice,
    CustomerAccount,
)
from servers.models import Server
from vpn.models import XHTTPDevice
from vpn.xhttp_services import (
    XHTTPDeviceService,
)


XHTTP_ADMIN_TEST_SETTINGS = {
    "CONFIG_ENCRYPTION_KEY": (
        Fernet.generate_key().decode()
    ),
    "XHTTP_CDN_DOMAIN": (
        "cdn.vpn.protopopov.pro"
    ),
    "XHTTP_PATH": (
        "/api/admin-test"
    ),
    "XHTTP_SC_MAX_EACH_POST_BYTES": 2048,
    "XHTTP_SC_MIN_POSTS_INTERVAL_MS": 30,
    "XHTTP_UPLINK_CHUNK_SIZE": 1800,
    "XHTTP_SERVER_MAX_HEADER_BYTES": 65536,
}


@override_settings(
    **XHTTP_ADMIN_TEST_SETTINGS
)
class XHTTPAdminLifecycleTest(TestCase):
    def setUp(self):
        self.user = (
            get_user_model()
            .objects.create_superuser(
                username="xhttp-admin",
                email="admin@example.com",
                password="admin-password",
            )
        )

        self.server = Server.objects.create(
            name="admin-xhttp-server",
            host="203.0.113.30",
            ssh_username="amnezia",
            is_enabled=True,
        )

        self.account = (
            CustomerAccount.objects.create(
                display_name=(
                    "Admin XHTTP Customer"
                ),
                created_by=self.user,
            )
        )

        self.client_device = (
            ClientDevice.objects.create(
                account=self.account,
                name="Admin iPhone",
                platform=(
                    ClientDevice.Platform.IOS
                ),
            )
        )

        with patch(
            "vpn.xhttp_services."
            "XHTTPRuntimeAdapter.add"
        ):
            self.xhttp = (
                XHTTPDeviceService
                .create_device(
                    device=self.client_device,
                    server=self.server,
                    name="Existing XHTTP",
                    actor=self.user,
                )
            )

        self.client.force_login(
            self.user
        )

    def test_admin_changelist_has_add_link(
        self,
    ):
        response = self.client.get(
            reverse(
                "admin:"
                "vpn_xhttpdevice_changelist"
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            reverse(
                "admin:"
                "vpn_xhttpdevice_add"
            ),
        )

    @patch(
        "vpn.xhttp_services."
        "XHTTPRuntimeAdapter.add"
    )
    def test_admin_add_uses_runtime_service(
        self,
        add_mock,
    ):
        response = self.client.post(
            reverse(
                "admin:"
                "vpn_xhttpdevice_add"
            ),
            {
                "device": (
                    self.client_device.pk
                ),
                "server": self.server.pk,
                "name": "Created in admin",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.assertTrue(
            XHTTPDevice.objects.filter(
                device=self.client_device,
                name="Created in admin",
            ).exists()
        )

        add_mock.assert_called_once()

    @patch(
        "vpn.xhttp_services."
        "XHTTPRuntimeAdapter.remove"
    )
    def test_admin_disable_uses_service(
        self,
        remove_mock,
    ):
        response = self.client.post(
            reverse(
                "admin:"
                "vpn_xhttpdevice_lifecycle",
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

        self.xhttp.refresh_from_db()

        self.assertEqual(
            self.xhttp.status,
            XHTTPDevice.Status.DISABLED,
        )

        self.assertEqual(
            self.xhttp.disable_reason,
            (
                XHTTPDevice
                .DisableReason
                .MANUAL
            ),
        )

        remove_mock.assert_called_once()

    @patch(
        "vpn.xhttp_services."
        "XHTTPRuntimeAdapter.add"
    )
    def test_admin_enable_uses_service(
        self,
        add_mock,
    ):
        self.xhttp.status = (
            XHTTPDevice.Status.DISABLED
        )

        self.xhttp.disable_reason = (
            XHTTPDevice
            .DisableReason
            .MANUAL
        )

        self.xhttp.save(
            update_fields=[
                "status",
                "disable_reason",
                "updated_at",
            ]
        )

        response = self.client.post(
            reverse(
                "admin:"
                "vpn_xhttpdevice_lifecycle",
                args=[
                    self.xhttp.pk,
                    "enable",
                ],
            )
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.xhttp.refresh_from_db()

        self.assertEqual(
            self.xhttp.status,
            XHTTPDevice.Status.ACTIVE,
        )

        add_mock.assert_called_once()

    @patch(
        "vpn.xhttp_services."
        "XHTTPRuntimeAdapter.check"
    )
    def test_admin_runtime_check_uses_service(
        self,
        check_mock,
    ):
        response = self.client.post(
            reverse(
                "admin:"
                "vpn_xhttpdevice_lifecycle",
                args=[
                    self.xhttp.pk,
                    "check",
                ],
            )
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        check_mock.assert_called_once()

    @patch(
        "vpn.xhttp_services."
        "XHTTPRuntimeAdapter.remove"
    )
    def test_admin_delete_is_soft_delete(
        self,
        remove_mock,
    ):
        delete_url = reverse(
            "admin:"
            "vpn_xhttpdevice_delete",
            args=[
                self.xhttp.pk
            ],
        )

        confirm = self.client.get(
            delete_url
        )

        self.assertEqual(
            confirm.status_code,
            200,
        )

        response = self.client.post(
            delete_url,
            {
                "post": "yes",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.assertTrue(
            XHTTPDevice.objects.filter(
                pk=self.xhttp.pk
            ).exists()
        )

        self.xhttp.refresh_from_db()

        self.assertEqual(
            self.xhttp.status,
            XHTTPDevice.Status.DELETED,
        )

        remove_mock.assert_called_once()
