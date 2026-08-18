import importlib.util
import json
from importlib.machinery import SourceFileLoader
from pathlib import Path
import uuid
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from customers.models import (
    ClientDevice,
    CustomerAccount,
)
from jobs.executors import SafeSSHExecutor
from servers.models import ProtocolProfile, Server, ServerProtocol
from vpn.models import VPNClient, XHTTPDevice
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


def load_xhttp_helper_module():
    path = Path(__file__).resolve().parents[2] / "scripts" / "amnezia-control-xhttp"
    loader = SourceFileLoader("amnezia_control_xhttp_helper", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@override_settings(**XHTTP_TEST_SETTINGS)
class XHTTPDeviceServiceTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("operator", password="123", is_staff=True)
        self.server = Server.objects.create(
            name="xhttp-server",
            host="203.0.113.10",
            ssh_username="amnezia",
        )
        self.account = CustomerAccount.objects.create(
            display_name="Alexey",
            created_by=self.user,
        )
        self.client_device = ClientDevice.objects.create(
            account=self.account,
            name="iPhone",
            platform=ClientDevice.Platform.IOS,
        )

    def test_happ_config_contains_working_packet_up_profile(self):
        client_uuid = uuid.UUID("12345678-1234-4234-9234-1234567890ab")
        payload = json.loads(
            XHTTPDeviceService.build_happ_config(
                client_uuid=client_uuid,
                device_name="iPhone",
            )
        )
        outbound = payload["outbounds"][0]
        stream = outbound["streamSettings"]
        xhttp = stream["xhttpSettings"]
        self.assertEqual(outbound["settings"]["vnext"][0]["address"], "cdn.vpn.protopopov.pro")
        self.assertEqual(outbound["settings"]["vnext"][0]["users"][0]["id"], str(client_uuid))
        self.assertEqual(stream["network"], "xhttp")
        self.assertEqual(stream["security"], "tls")
        self.assertEqual(stream["tlsSettings"]["alpn"], ["h2"])
        self.assertFalse(stream["tlsSettings"]["allowInsecure"])
        self.assertEqual(xhttp["path"], "/api/ad4f850643d5e660f09d31f9")
        self.assertEqual(xhttp["mode"], "packet-up")
        self.assertEqual(xhttp["uplinkHTTPMethod"], "GET")
        self.assertEqual(xhttp["uplinkDataPlacement"], "header")
        self.assertEqual(xhttp["uplinkDataKey"], "X-Data")
        self.assertEqual(xhttp["scMaxEachPostBytes"], 2048)
        self.assertEqual(xhttp["scMinPostsIntervalMs"], 30)
        self.assertEqual(xhttp["uplinkChunkSize"], 1800)
        self.assertFalse(outbound["mux"]["enabled"])

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    def test_create_device_persists_encrypted_config(self, add_mock):
        device = XHTTPDeviceService.create_device(
            device=self.client_device,
            server=self.server,
            name="iPhone",
            actor=self.user,
        )
        add_mock.assert_called_once()
        self.assertEqual(device.status, XHTTPDevice.Status.ACTIVE)
        self.assertEqual(device.disable_reason, XHTTPDevice.DisableReason.NONE)
        self.assertRegex(device.xray_email, r"^xhttp-[0-9a-f]{32}$")
        self.assertNotIn(str(device.client_uuid), device.config_blob_encrypted)
        plaintext = XHTTPDeviceService.latest_config(device)
        self.assertIn(str(device.client_uuid), plaintext)
        self.assertEqual(len(device.config_hash), 64)

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.remove")
    def test_rotate_revokes_old_uuid_and_updates_config(self, remove_mock, add_mock):
        device = XHTTPDeviceService.create_device(
            device=self.client_device,
            server=self.server,
            name="MacBook",
            actor=self.user,
        )
        old_uuid = device.client_uuid
        old_email = device.xray_email
        add_mock.reset_mock()

        XHTTPDeviceService.rotate(device=device, actor=self.user)
        device.refresh_from_db()

        remove_mock.assert_called_with(
            client_uuid=old_uuid,
            xray_email=old_email,
            actor=self.user,
        )
        add_mock.assert_called_once()
        self.assertNotEqual(device.client_uuid, old_uuid)
        self.assertIn(str(device.client_uuid), XHTTPDeviceService.latest_config(device))

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    def test_create_rejected_for_disabled_parent_account(
        self,
        add_mock,
    ):
        self.account.status = (
            CustomerAccount.Status.DISABLED
        )

        self.account.save(
            update_fields=["status"]
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "активного аккаунта",
        ):
            XHTTPDeviceService.create_device(
                device=self.client_device,
                server=self.server,
                name="Blocked",
                actor=self.user,
            )

        add_mock.assert_not_called()

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.remove")
    def test_parent_reconciliation_preserves_manual_disable(self, remove_mock, add_mock):
        device = XHTTPDeviceService.create_device(
            device=self.client_device,
            server=self.server,
            name="Manual off",
            actor=self.user,
        )
        XHTTPDeviceService.disable(device=device, actor=self.user)
        device.refresh_from_db()
        self.assertEqual(device.disable_reason, XHTTPDevice.DisableReason.MANUAL)

        XHTTPDeviceService.enable_for_device(
            client_device=self.client_device,
            actor=None,
        )
        device.refresh_from_db()
        self.assertEqual(device.status, XHTTPDevice.Status.DISABLED)
        add_mock.assert_called_once()


class XHTTPHelperMutationTest(SimpleTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.helper = load_xhttp_helper_module()
        cls.client_uuid = "12345678-1234-4234-9234-1234567890ab"
        cls.email = "xhttp-123456781234423492341234567890ab"

    def config(self):
        return {
            "inbounds": [
                {
                    "tag": "vless-xhttp-yandex",
                    "protocol": "vless",
                    "listen": "127.0.0.1",
                    "port": 8080,
                    "settings": {"clients": []},
                    "streamSettings": {
                        "network": "xhttp",
                        "xhttpSettings": {"path": "/api/ad4f850643d5e660f09d31f9"},
                    },
                }
            ]
        }

    def test_add_check_remove_are_idempotent(self):
        config = self.config()
        self.assertTrue(self.helper.mutate(config, "add", self.client_uuid, self.email))
        self.assertFalse(self.helper.mutate(config, "add", self.client_uuid, self.email))
        self.assertFalse(self.helper.mutate(config, "check", self.client_uuid, self.email))
        self.assertTrue(self.helper.mutate(config, "remove", self.client_uuid, self.email))
        self.assertFalse(self.helper.mutate(config, "remove", self.client_uuid, self.email))

    def test_conflicting_email_is_rejected(self):
        config = self.config()
        config["inbounds"][0]["settings"]["clients"].append(
            {"id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "email": self.email}
        )
        with self.assertRaises(self.helper.ManagedError):
            self.helper.mutate(config, "add", self.client_uuid, self.email)


class XHTTPCommandAllowlistTest(SimpleTestCase):
    def setUp(self):
        self.executor = SafeSSHExecutor("example.com", "amnezia")

    def test_valid_helper_command_is_allowed(self):
        self.executor._validate(
            "sudo -n /usr/local/sbin/amnezia-control-xhttp add "
            "12345678-1234-4234-9234-1234567890ab "
            "xhttp-123456781234423492341234567890ab"
        )

    def test_shell_injection_is_rejected(self):
        with self.assertRaises(ValueError):
            self.executor._validate(
                "sudo -n /usr/local/sbin/amnezia-control-xhttp add "
                "12345678-1234-4234-9234-1234567890ab "
                "xhttp-123456781234423492341234567890ab; id"
            )


@override_settings(**XHTTP_TEST_SETTINGS)
class XHTTPDeviceViewTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("staff", password="123", is_staff=True)
        self.server = Server.objects.create(name="view-server", host="203.0.113.11")
        self.account = CustomerAccount.objects.create(
            display_name="Portal client",
            created_by=self.user,
        )
        self.client_device = ClientDevice.objects.create(
            account=self.account,
            name="Portal iPhone",
            platform=ClientDevice.Platform.IOS,
        )
        self.client.login(
            username="staff",
            password="123",
        )

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    def test_create_and_download_happ_json(self, add_mock):
        response = self.client.post(
            reverse("xhttp-devices"),
            {
                "device": self.client_device.pk,
                "server": self.server.pk,
                "name": "iPhone",
            },
        )
        self.assertRedirects(response, reverse("xhttp-devices"))
        device = XHTTPDevice.objects.get()

        download = self.client.get(reverse("xhttp-device-download", args=[device.id]))
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download["X-Content-Type-Options"], "nosniff")
        payload = json.loads(download.content.decode())
        self.assertEqual(
            payload["outbounds"][0]["settings"]["vnext"][0]["users"][0]["id"],
            str(device.client_uuid),
        )


@override_settings(**XHTTP_TEST_SETTINGS)
class XHTTPClientDeviceOwnershipTest(TestCase):
    def setUp(self):
        from customers.models import (
            ClientDevice,
            CustomerAccount,
        )

        self.user = (
            get_user_model()
            .objects.create_user(
                "xhttp-device-owner",
                password="123",
                is_staff=True,
            )
        )

        self.server = Server.objects.create(
            name="xhttp-device-server",
            host="203.0.113.20",
            ssh_username="amnezia",
            is_enabled=True,
        )

        self.account = CustomerAccount.objects.create(
            display_name="Device Owner",
            email="owner@example.com",
            created_by=self.user,
        )

        self.client_device = ClientDevice.objects.create(
            account=self.account,
            name="iPhone 15 Pro",
            platform=ClientDevice.Platform.IOS,
        )

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    def test_create_xhttp_directly_for_client_device(
        self,
        add_mock,
    ):
        device = XHTTPDeviceService.create_device(
            device=self.client_device,
            server=self.server,
            name="VLESS CDN",
            actor=self.user,
        )

        add_mock.assert_called_once()

        self.assertEqual(
            device.device_id,
            self.client_device.pk,
        )

        self.assertEqual(
            device.server_id,
            self.server.pk,
        )

        self.assertFalse(
            XHTTPDevice._meta
            .get_field("device")
            .null
        )

        self.assertFalse(
            XHTTPDevice._meta
            .get_field("server")
            .null
        )

        self.assertEqual(
            device.status,
            XHTTPDevice.Status.ACTIVE,
        )

        plaintext = (
            XHTTPDeviceService.latest_config(
                device
            )
        )

        self.assertIn(
            str(device.client_uuid),
            plaintext,
        )

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    def test_disabled_account_rejects_new_xhttp(
        self,
        add_mock,
    ):
        from customers.models import CustomerAccount

        self.account.status = (
            CustomerAccount.Status.DISABLED
        )

        self.account.save(
            update_fields=["status"]
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "активного аккаунта",
        ):
            XHTTPDeviceService.create_device(
                device=self.client_device,
                server=self.server,
                name="Blocked",
                actor=self.user,
            )

        add_mock.assert_not_called()

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    def test_disabled_device_rejects_new_xhttp(
        self,
        add_mock,
    ):
        from customers.models import ClientDevice

        self.client_device.status = (
            ClientDevice.Status.DISABLED
        )

        self.client_device.save(
            update_fields=["status"]
        )

        with self.assertRaisesRegex(
            RuntimeError,
            "активного устройства",
        ):
            XHTTPDeviceService.create_device(
                device=self.client_device,
                server=self.server,
                name="Blocked",
                actor=self.user,
            )

        add_mock.assert_not_called()

    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    def test_xhttp_view_creates_device_owned_connection(
        self,
        add_mock,
    ):
        self.client.force_login(
            self.user
        )

        response = self.client.post(
            reverse("xhttp-devices"),
            {
                "device": self.client_device.pk,
                "server": self.server.pk,
                "name": "CDN Reserve",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        created = XHTTPDevice.objects.get(
            name="CDN Reserve",
        )

        self.assertEqual(
            created.device_id,
            self.client_device.pk,
        )

        self.assertEqual(
            created.server_id,
            self.server.pk,
        )


    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.add")
    @patch("vpn.xhttp_services.XHTTPRuntimeAdapter.remove")
    def test_device_reconciliation_preserves_manual_disable(
        self,
        remove_mock,
        add_mock,
    ):
        device = XHTTPDeviceService.create_device(
            device=self.client_device,
            server=self.server,
            name="Manual Device",
            actor=self.user,
        )

        XHTTPDeviceService.disable(
            device=device,
            actor=self.user,
        )

        device.refresh_from_db()

        self.assertEqual(
            device.disable_reason,
            XHTTPDevice.DisableReason.MANUAL,
        )

        XHTTPDeviceService.enable_for_device(
            client_device=self.client_device,
            actor=None,
        )

        device.refresh_from_db()

        self.assertEqual(
            device.status,
            XHTTPDevice.Status.DISABLED,
        )


class XHTTPOwnerOperatorAccessTest(TestCase):
    def test_owner_can_open_xhttp_without_staff_flag(self):
        User = get_user_model()

        operator = User.objects.create_user(
            username="xhttp-owner-operator",
            password="test-password",
            is_owner=True,
            is_staff=False,
        )

        self.client.force_login(
            operator
        )

        response = self.client.get(
            reverse("xhttp-devices")
        )

        self.assertEqual(
            response.status_code,
            200,
        )
