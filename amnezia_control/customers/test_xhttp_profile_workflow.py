import json
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from customers.models import ClientDevice, CustomerAccount
from servers.models import Server
from vpn.models import XHTTPDevice
from vpn.xhttp_services import XHTTPDeviceService


XHTTP_TEST_SETTINGS = {
    "CONFIG_ENCRYPTION_KEY": Fernet.generate_key().decode(),
    "XHTTP_CDN_DOMAIN": "cdn.vpn.protopopov.pro",
    "XHTTP_PATH": "/api/ad4f850643d5e660f09d31f9",
    "XHTTP_SC_MAX_EACH_POST_BYTES": 2048,
    "XHTTP_SC_MIN_POSTS_INTERVAL_MS": 30,
    "XHTTP_UPLINK_CHUNK_SIZE": 1800,
    "XHTTP_SERVER_MAX_HEADER_BYTES": 65536,
}


def transport(device):
    payload = json.loads(
        XHTTPDeviceService.latest_config(device)
    )
    outbound = next(
        item
        for item in payload["outbounds"]
        if item.get("tag") == "xhttp-cdn"
    )
    xhttp = outbound["streamSettings"]["xhttpSettings"]
    return (
        xhttp.get("scMaxEachPostBytes"),
        xhttp.get("scMinPostsIntervalMs"),
        xhttp.get("uplinkChunkSize"),
        xhttp.get("xmux"),
    )


@override_settings(**XHTTP_TEST_SETTINGS)
class CustomerXHTTPProfileWorkflowTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            "xhttp-workspace-owner",
            password="123",
            is_owner=True,
            is_staff=True,
        )
        self.server = Server.objects.create(
            name="workspace-xhttp-server",
            host="203.0.113.70",
            ssh_username="amnezia",
            is_enabled=True,
        )
        self.account = CustomerAccount.objects.create(
            display_name="Workspace Client",
            created_by=self.user,
        )
        self.device = ClientDevice.objects.create(
            account=self.account,
            name="iPhone",
            platform=ClientDevice.Platform.IOS,
        )
        self.client.force_login(self.user)

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    def test_customer_create_can_issue_turbo(self, add_mock):
        response = self.client.post(
            reverse(
                "customers-device-xhttp-create",
                args=[self.device.pk],
            ),
            {
                "server": self.server.pk,
                "name": "Customer Turbo",
                "performance_profile": "turbo",
            },
        )

        self.assertRedirects(
            response,
            reverse("customers-detail", args=[self.account.pk]),
        )
        add_mock.assert_called_once()

        created = XHTTPDevice.objects.get(name="Customer Turbo")
        self.assertEqual(
            created.performance_profile,
            XHTTPDevice.PerformanceProfile.TURBO,
        )
        self.assertEqual(
            transport(created),
            (4096, 5, 3500, None),
        )

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.remove")
    def test_customer_reissue_can_switch_standard_to_turbo(
        self,
        remove_mock,
        add_mock,
    ):
        device = XHTTPDeviceService.create_device(
            device=self.device,
            server=self.server,
            name="Switch profile",
            performance_profile=XHTTPDevice.PerformanceProfile.STANDARD,
            actor=self.user,
        )
        old_uuid = device.client_uuid
        add_mock.reset_mock()

        response = self.client.post(
            reverse(
                "customers-xhttp-action",
                args=[device.pk, "rotate"],
            ),
            {"performance_profile": "turbo"},
        )

        self.assertRedirects(
            response,
            reverse("customers-detail", args=[self.account.pk]),
        )
        device.refresh_from_db()

        self.assertNotEqual(device.client_uuid, old_uuid)
        self.assertEqual(
            device.performance_profile,
            XHTTPDevice.PerformanceProfile.TURBO,
        )
        self.assertEqual(
            transport(device),
            (4096, 5, 3500, None),
        )
        add_mock.assert_called_once()
        remove_mock.assert_called()

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.remove")
    def test_customer_reissue_without_profile_preserves_turbo(
        self,
        remove_mock,
        add_mock,
    ):
        device = XHTTPDeviceService.create_device(
            device=self.device,
            server=self.server,
            name="Preserve Turbo",
            performance_profile=XHTTPDevice.PerformanceProfile.TURBO,
            actor=self.user,
        )
        add_mock.reset_mock()

        response = self.client.post(
            reverse(
                "customers-xhttp-action",
                args=[device.pk, "rotate"],
            ),
        )

        self.assertEqual(response.status_code, 302)
        device.refresh_from_db()

        self.assertEqual(
            device.performance_profile,
            XHTTPDevice.PerformanceProfile.TURBO,
        )
        self.assertEqual(
            transport(device),
            (4096, 5, 3500, None),
        )
