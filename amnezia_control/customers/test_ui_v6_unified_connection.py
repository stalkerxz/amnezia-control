from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from customers.forms import DeviceAccessUpdateForm
from customers.models import ClientDevice, CustomerAccount
from servers.models import ProtocolProfile, Server, ServerProtocol
from vpn.models import VPNClient, XHTTPDevice


class UnifiedConnectionCreateTests(TestCase):
    def setUp(self):
        User = get_user_model()

        self.operator = User.objects.create_user(
            username="unified-connection-owner",
            password="test-password",
            is_staff=True,
            is_owner=True,
        )

        self.account = CustomerAccount.objects.create(
            display_name="Unified Customer",
            email="unified@example.com",
            status=CustomerAccount.Status.ACTIVE,
            expires_at=timezone.now() + timedelta(days=30),
            created_by=self.operator,
        )

        self.device = ClientDevice.objects.create(
            account=self.account,
            name="Unified iPhone",
            platform=ClientDevice.Platform.IOS,
            status=ClientDevice.Status.ACTIVE,
        )

        self.server = Server.objects.create(
            name="Unified VPN",
            host="203.0.113.90",
            is_enabled=True,
            accepts_new_vpn_clients=True,
            health_status="healthy",
            public_endpoint_host="203.0.113.90",
            public_endpoint_port=49561,
        )

        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
            runtime_metadata={
                "awg31_metadata_ready": True,
                "subnet_ready": True,
                "endpoint_host_ready": True,
                "endpoint_port_ready": True,
                "subnet": "10.8.90.0/24",
                "peer_count": 0,
                "public_host": "203.0.113.90",
                "udp_port": 49561,
            },
        )

        self.full_profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="FULL",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="# routing-mode: full\n0.0.0.0/0",
            status=ProtocolProfile.ProfileStatus.ACTIVE,
        )

        self.selective_profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="SELECT",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="# routing-mode: selective\n8.8.8.8/32",
            status=ProtocolProfile.ProfileStatus.ACTIVE,
        )

        self.client.force_login(self.operator)

    def url(self):
        return reverse(
            "customers-device-connection-create",
            args=[self.device.pk],
        )

    def access_payload(
        self,
        *,
        apply=DeviceAccessUpdateForm.APPLY_KEEP,
        preset="10gb",
        value="",
        unit="gb",
        expires_at="",
    ):
        return {
            "access-expires_at": expires_at,
            "access-apply_traffic": apply,
            "access-traffic_limit_preset": preset,
            "access-traffic_custom_value": value,
            "access-traffic_custom_unit": unit,
        }

    def test_get_is_single_screen_workflow(self):
        response = self.client.get(self.url())

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response,
            "customers/connection_product_select.html",
        )

        self.assertContains(
            response,
            'name="product_type"',
        )
        self.assertContains(
            response,
            'value="full"',
        )
        self.assertContains(
            response,
            'value="selective"',
        )
        self.assertContains(
            response,
            'value="alt"',
        )
        self.assertContains(
            response,
            'name="access-apply_traffic"',
        )
        self.assertContains(
            response,
            "Срок и лимиты",
        )
        self.assertContains(
            response,
            "Политика всего устройства",
        )
        self.assertContains(
            response,
            (
                "Если вы измените срок или VPN-лимит, "
                "новое значение применится и к существующим "
                "FULL/SELECT-подключениям."
            ),
        )
        self.assertContains(
            response,
            "Не создано",
        )
        self.assertContains(
            response,
            "Создать подключение",
        )

        self.assertNotContains(
            response,
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            ),
        )
        self.assertNotContains(
            response,
            reverse(
                "customers-device-xhttp-create",
                args=[self.device.pk],
            ),
        )

    @patch(
        "customers.views.VPNClientService.create_client"
    )
    def test_full_creation_applies_device_limit_before_issue(
        self,
        create_client,
    ):
        create_client.return_value = SimpleNamespace(pk=9001)

        device_expiry = (
            timezone.localtime(
                timezone.now() + timedelta(days=7)
            )
            .replace(second=0, microsecond=0)
        )

        payload = {
            "product_type": "full",
            "full_server_choice": "auto",
            **self.access_payload(
                apply=DeviceAccessUpdateForm.APPLY_SET,
                preset="10gb",
                expires_at=device_expiry.strftime(
                    "%Y-%m-%dT%H:%M"
                ),
            ),
        }

        response = self.client.post(
            self.url(),
            payload,
        )

        self.assertRedirects(
            response,
            reverse(
                "customers-detail",
                args=[self.account.pk],
            ),
        )

        self.device.refresh_from_db()

        self.assertEqual(
            self.device.vpn_traffic_limit_bytes,
            10 * 1024**3,
        )
        self.assertEqual(
            timezone.localtime(
                self.device.expires_at
            ).replace(second=0, microsecond=0),
            device_expiry,
        )

        create_client.assert_called_once()
        kwargs = create_client.call_args.kwargs

        self.assertEqual(
            kwargs["routing_mode"],
            "full",
        )
        self.assertEqual(
            kwargs["device"].pk,
            self.device.pk,
        )
        self.assertEqual(
            kwargs["traffic_limit_bytes"],
            10 * 1024**3,
        )
        self.assertEqual(
            timezone.localtime(
                kwargs["expires_at"]
            ).replace(second=0, microsecond=0),
            device_expiry,
        )

    @patch(
        "customers.views.VPNClientService.create_client"
    )
    def test_selective_creation_uses_same_screen(
        self,
        create_client,
    ):
        create_client.return_value = SimpleNamespace(pk=9002)

        response = self.client.post(
            self.url(),
            {
                "product_type": "selective",
                "selective_server_choice": "auto",
                **self.access_payload(),
            },
        )

        self.assertRedirects(
            response,
            reverse(
                "customers-detail",
                args=[self.account.pk],
            ),
        )

        self.assertEqual(
            create_client.call_args.kwargs[
                "routing_mode"
            ],
            "selective",
        )

    @patch(
        "customers.views.XHTTPDeviceService.create_device"
    )
    def test_alt_creation_uses_same_screen_and_profile(
        self,
        create_device,
    ):
        create_device.return_value = SimpleNamespace(
            name="Unified ALT",
        )

        response = self.client.post(
            self.url(),
            {
                "product_type": "alt",
                "alt-server": str(self.server.pk),
                "alt-name": "Unified ALT",
                "alt-performance_profile": (
                    XHTTPDevice.PerformanceProfile.TURBO
                ),
                **self.access_payload(),
            },
        )

        self.assertRedirects(
            response,
            reverse(
                "customers-detail",
                args=[self.account.pk],
            ),
        )

        create_device.assert_called_once()

        kwargs = create_device.call_args.kwargs

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
            "Unified ALT",
        )
        self.assertEqual(
            kwargs["performance_profile"],
            XHTTPDevice.PerformanceProfile.TURBO,
        )

    @patch(
        "customers.views.VPNClientService.create_client"
    )
    def test_invalid_custom_limit_creates_nothing(
        self,
        create_client,
    ):
        response = self.client.post(
            self.url(),
            {
                "product_type": "full",
                "full_server_choice": "auto",
                **self.access_payload(
                    apply=DeviceAccessUpdateForm.APPLY_SET,
                    preset="custom",
                    value="",
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )
        self.assertContains(
            response,
            "Укажите объём лимита.",
        )

        create_client.assert_not_called()

        self.device.refresh_from_db()
        self.assertIsNone(
            self.device.vpn_traffic_limit_bytes
        )

    @patch(
        "customers.views.update_customer_device_access"
    )
    @patch(
        "customers.views.VPNClientService.create_client"
    )
    def test_duplicate_product_has_no_policy_side_effect(
        self,
        create_client,
        update_access,
    ):
        VPNClient.objects.create(
            server=self.server,
            name="Existing-FULL",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=self.full_profile,
            created_by=self.operator,
            device=self.device,
        )

        response = self.client.post(
            self.url(),
            {
                "product_type": "full",
                "full_server_choice": "auto",
                **self.access_payload(
                    apply=DeviceAccessUpdateForm.APPLY_SET,
                    preset="10gb",
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )
        self.assertContains(
            response,
            "уже есть FULL-подключение",
        )

        create_client.assert_not_called()
        update_access.assert_not_called()

    @patch(
        "customers.views.VPNClientService.create_client",
        side_effect=RuntimeError("runtime failed"),
    )
    def test_issue_failure_restores_previous_device_policy(
        self,
        create_client,
    ):
        self.device.vpn_traffic_limit_bytes = (
            5 * 1024**3
        )
        self.device.save(
            update_fields=[
                "vpn_traffic_limit_bytes",
                "updated_at",
            ]
        )

        response = self.client.post(
            self.url(),
            {
                "product_type": "full",
                "full_server_choice": "auto",
                **self.access_payload(
                    apply=DeviceAccessUpdateForm.APPLY_SET,
                    preset="10gb",
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )
        self.assertContains(
            response,
            "runtime failed",
        )

        self.device.refresh_from_db()

        self.assertEqual(
            self.device.vpn_traffic_limit_bytes,
            5 * 1024**3,
        )
        create_client.assert_called_once()

    def test_non_owner_is_forbidden(self):
        User = get_user_model()
        customer = User.objects.create_user(
            username="unified-non-owner",
            password="test-password",
            is_owner=False,
        )

        self.client.force_login(customer)

        response = self.client.get(
            self.url()
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_inactive_device_is_forbidden(self):
        self.device.status = (
            ClientDevice.Status.DISABLED
        )
        self.device.save(
            update_fields=[
                "status",
                "updated_at",
            ]
        )

        response = self.client.get(
            self.url()
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_legacy_vpn_full_get_redirects_to_unified(self):
        response = self.client.get(
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            )
            + "?routing_mode=full"
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            self.url() + "?product=full",
        )

    def test_legacy_vpn_selective_get_redirects_to_unified(self):
        response = self.client.get(
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            )
            + "?routing_mode=selective"
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            self.url() + "?product=selective",
        )

    def test_legacy_vpn_invalid_get_redirects_to_full(self):
        response = self.client.get(
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            )
            + "?routing_mode=invalid"
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            self.url() + "?product=full",
        )

    def test_legacy_xhttp_get_redirects_to_unified(self):
        response = self.client.get(
            reverse(
                "customers-device-xhttp-create",
                args=[self.device.pk],
            )
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            self.url() + "?product=alt",
        )

