import json
import uuid
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


def xhttp_settings(payload):
    outbound = next(item for item in payload["outbounds"] if item.get("tag") == "xhttp-cdn")
    return outbound["streamSettings"]["xhttpSettings"]


@override_settings(**XHTTP_TEST_SETTINGS)
class XHTTPPerformanceProfileTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            "profile-operator",
            password="123",
            is_staff=True,
        )
        self.server = Server.objects.create(
            name="profile-server",
            host="203.0.113.50",
            ssh_username="amnezia",
        )
        self.account = CustomerAccount.objects.create(
            display_name="Profile Client",
            created_by=self.user,
        )
        self.client_device = ClientDevice.objects.create(
            account=self.account,
            name="iPhone",
            platform=ClientDevice.Platform.IOS,
        )

    def test_standard_profile_keeps_legacy_transport_values(self):
        payload = json.loads(
            XHTTPDeviceService.build_happ_config(
                client_uuid=uuid.uuid4(),
                device_name="Standard",
                performance_profile=XHTTPDevice.PerformanceProfile.STANDARD,
            )
        )
        xhttp = xhttp_settings(payload)
        self.assertEqual(xhttp["scMaxEachPostBytes"], 2048)
        self.assertEqual(xhttp["scMinPostsIntervalMs"], 30)
        self.assertEqual(xhttp["uplinkChunkSize"], 1800)
        self.assertNotIn("xmux", xhttp)
        self.assertEqual(payload["meta"]["performanceProfile"], "standard")

    def test_turbo_profile_uses_measured_transport_values(self):
        payload = json.loads(
            XHTTPDeviceService.build_happ_config(
                client_uuid=uuid.uuid4(),
                device_name="Turbo",
                performance_profile=XHTTPDevice.PerformanceProfile.TURBO,
            )
        )
        xhttp = xhttp_settings(payload)
        self.assertEqual(xhttp["scMaxEachPostBytes"], 4096)
        self.assertEqual(xhttp["scMinPostsIntervalMs"], 5)
        self.assertEqual(xhttp["uplinkChunkSize"], 3500)
        self.assertNotIn("xmux", xhttp)
        self.assertEqual(payload["meta"]["performanceProfile"], "turbo")

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    def test_create_persists_turbo_profile(self, add_mock):
        device = XHTTPDeviceService.create_device(
            device=self.client_device,
            server=self.server,
            name="Yandex CDN Turbo",
            performance_profile=XHTTPDevice.PerformanceProfile.TURBO,
            actor=self.user,
        )
        add_mock.assert_called_once()
        self.assertEqual(device.performance_profile, XHTTPDevice.PerformanceProfile.TURBO)
        payload = json.loads(XHTTPDeviceService.latest_config(device))
        self.assertEqual(xhttp_settings(payload)["scMinPostsIntervalMs"], 5)

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.remove")
    def test_rotate_preserves_turbo_profile(self, remove_mock, add_mock):
        device = XHTTPDeviceService.create_device(
            device=self.client_device,
            server=self.server,
            name="Yandex CDN Turbo",
            performance_profile=XHTTPDevice.PerformanceProfile.TURBO,
            actor=self.user,
        )
        old_uuid = device.client_uuid
        add_mock.reset_mock()

        XHTTPDeviceService.rotate(device=device, actor=self.user)
        device.refresh_from_db()

        self.assertNotEqual(device.client_uuid, old_uuid)
        self.assertEqual(device.performance_profile, XHTTPDevice.PerformanceProfile.TURBO)
        payload = json.loads(XHTTPDeviceService.latest_config(device))
        xhttp = xhttp_settings(payload)
        self.assertEqual(xhttp["scMaxEachPostBytes"], 4096)
        self.assertEqual(xhttp["scMinPostsIntervalMs"], 5)
        self.assertEqual(xhttp["uplinkChunkSize"], 3500)
        remove_mock.assert_called()
        add_mock.assert_called_once()

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    def test_view_can_create_turbo_profile(self, add_mock):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("xhttp-devices"),
            {
                "device": self.client_device.pk,
                "server": self.server.pk,
                "name": "Turbo UI",
                "performance_profile": XHTTPDevice.PerformanceProfile.TURBO,
            },
        )
        self.assertEqual(response.status_code, 302)
        created = XHTTPDevice.objects.get(name="Turbo UI")
        self.assertEqual(created.performance_profile, XHTTPDevice.PerformanceProfile.TURBO)
        payload = json.loads(XHTTPDeviceService.latest_config(created))
        self.assertEqual(xhttp_settings(payload)["scMinPostsIntervalMs"], 5)

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    def test_view_without_profile_defaults_to_standard(self, add_mock):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("xhttp-devices"),
            {
                "device": self.client_device.pk,
                "server": self.server.pk,
                "name": "Legacy POST",
            },
        )
        self.assertEqual(response.status_code, 302)
        created = XHTTPDevice.objects.get(name="Legacy POST")
        self.assertEqual(
            created.performance_profile,
            XHTTPDevice.PerformanceProfile.STANDARD,
        )

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.remove")
    def test_rotate_can_switch_standard_to_turbo(self, remove_mock, add_mock):
        device = XHTTPDeviceService.create_device(
            device=self.client_device,
            server=self.server,
            name="Switchable",
            actor=self.user,
        )
        add_mock.reset_mock()

        XHTTPDeviceService.rotate(
            device=device,
            actor=self.user,
            performance_profile=XHTTPDevice.PerformanceProfile.TURBO,
        )
        device.refresh_from_db()

        self.assertEqual(
            device.performance_profile,
            XHTTPDevice.PerformanceProfile.TURBO,
        )
        payload = json.loads(XHTTPDeviceService.latest_config(device))
        self.assertEqual(xhttp_settings(payload)["scMinPostsIntervalMs"], 5)
        remove_mock.assert_called()
        add_mock.assert_called_once()
