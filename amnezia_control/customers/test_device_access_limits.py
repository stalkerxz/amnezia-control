from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)
from vpn.models import VPNClient
from vpn.xhttp_services import XHTTPDeviceService

from .edit_services import (
    update_customer_account_metadata,
    update_customer_device_access,
)
from .models import (
    ClientDevice,
    CustomerAccount,
)
from .workspace import (
    build_customer_workspace,
)


class DeviceAccessLimitsTest(TestCase):
    def setUp(self):
        User = get_user_model()

        self.operator = User.objects.create_user(
            username="device-limit-operator",
            password="operator-password",
            is_owner=True,
        )

        self.customer_user = User.objects.create_user(
            username="device-limit-customer",
            password="customer-password",
            is_owner=False,
        )

        self.account_expiry = (
            timezone.now()
            + timedelta(days=90)
        )

        self.account = (
            CustomerAccount.objects.create(
                display_name="Device Limit Customer",
                email="device-limit@example.com",
                status=(
                    CustomerAccount.Status.ACTIVE
                ),
                expires_at=self.account_expiry,
                user=self.customer_user,
                created_by=self.operator,
            )
        )

        self.device = (
            ClientDevice.objects.create(
                account=self.account,
                name="iPhone",
                platform=(
                    ClientDevice.Platform.IOS
                ),
                status=(
                    ClientDevice.Status.ACTIVE
                ),
            )
        )

        self.server = Server.objects.create(
            name="Device Limit Server",
        )

        self.server_protocol = (
            ServerProtocol.objects.create(
                server=self.server,
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                enabled=True,
            )
        )

        self.profile = (
            ProtocolProfile.objects.create(
                server_protocol=(
                    self.server_protocol
                ),
                name="FULL",
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                config_template=(
                    "[Interface]\n"
                ),
            )
        )

        self.vpn = VPNClient.objects.create(
            server=self.server,
            device=self.device,
            name="device-limit-vpn",
            contact_email=(
                self.account.email
            ),
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            status=(
                VPNClient.Status.ACTIVE
            ),
            profile=self.profile,
            expires_at=(
                self.account.expires_at
            ),
            runtime_peer_public_key=(
                "STABLE-DEVICE-LIMIT-KEY"
            ),
            runtime_address="10.77.9.10",
        )

    def identity_snapshot(self):
        self.vpn.refresh_from_db()

        return {
            "public_key": (
                self.vpn
                .runtime_peer_public_key
            ),
            "address": (
                self.vpn.runtime_address
            ),
            "revision_count": (
                self.vpn.revisions.count()
            ),
        }

    def test_effective_expiry_uses_earliest_boundary(
        self,
    ):
        device_expiry = (
            timezone.now()
            + timedelta(days=30)
        )

        self.device.expires_at = (
            device_expiry
        )

        self.assertEqual(
            self.device.effective_expires_at,
            device_expiry,
        )

        earlier_account_expiry = (
            timezone.now()
            + timedelta(days=10)
        )

        self.account.expires_at = (
            earlier_account_expiry
        )

        self.assertEqual(
            self.device.effective_expires_at,
            earlier_account_expiry,
        )

    def test_device_update_syncs_vpn_without_reissue(
        self,
    ):
        before = (
            self.identity_snapshot()
        )

        device_expiry = (
            timezone.now()
            + timedelta(days=30)
        )

        limit = 25 * 1024**3

        update_customer_device_access(
            device_id=self.device.pk,
            expires_at=device_expiry,
            apply_traffic="set",
            traffic_limit_bytes=limit,
            actor=self.operator,
        )

        self.device.refresh_from_db()
        self.vpn.refresh_from_db()

        self.assertEqual(
            self.device.expires_at,
            device_expiry,
        )

        self.assertEqual(
            self.device.vpn_traffic_limit_bytes,
            limit,
        )

        self.assertEqual(
            self.vpn.expires_at,
            device_expiry,
        )

        self.assertEqual(
            self.vpn.traffic_limit_bytes,
            limit,
        )

        self.assertEqual(
            before,
            self.identity_snapshot(),
        )

    def test_keep_traffic_does_not_change_existing_limit(
        self,
    ):
        old_limit = 5 * 1024**3

        self.vpn.traffic_limit_bytes = (
            old_limit
        )

        self.vpn.save(
            update_fields=[
                "traffic_limit_bytes",
            ]
        )

        new_expiry = (
            timezone.now()
            + timedelta(days=20)
        )

        update_customer_device_access(
            device_id=self.device.pk,
            expires_at=new_expiry,
            apply_traffic="keep",
            traffic_limit_bytes=None,
            actor=self.operator,
        )

        self.vpn.refresh_from_db()

        self.assertEqual(
            self.vpn.traffic_limit_bytes,
            old_limit,
        )

        self.assertEqual(
            self.vpn.expires_at,
            new_expiry,
        )

    def test_clear_device_policy_clears_vpn_limit(
        self,
    ):
        limit = 10 * 1024**3

        self.device.vpn_traffic_limit_bytes = (
            limit
        )

        self.device.save(
            update_fields=[
                "vpn_traffic_limit_bytes",
            ]
        )

        self.vpn.traffic_limit_bytes = (
            limit
        )

        self.vpn.save(
            update_fields=[
                "traffic_limit_bytes",
            ]
        )

        update_customer_device_access(
            device_id=self.device.pk,
            expires_at=None,
            apply_traffic="clear",
            traffic_limit_bytes=None,
            actor=self.operator,
        )

        self.device.refresh_from_db()
        self.vpn.refresh_from_db()

        self.assertIsNone(
            self.device
            .vpn_traffic_limit_bytes
        )

        self.assertIsNone(
            self.vpn.traffic_limit_bytes
        )

        self.assertEqual(
            self.vpn.expires_at,
            self.account.expires_at,
        )

    def test_account_edit_respects_earlier_device_expiry(
        self,
    ):
        device_expiry = (
            timezone.now()
            + timedelta(days=15)
        )

        update_customer_device_access(
            device_id=self.device.pk,
            expires_at=device_expiry,
            apply_traffic="keep",
            traffic_limit_bytes=None,
            actor=self.operator,
        )

        later_account_expiry = (
            timezone.now()
            + timedelta(days=180)
        )

        update_customer_account_metadata(
            account_id=self.account.pk,
            display_name=(
                self.account.display_name
            ),
            email=self.account.email,
            expires_at=(
                later_account_expiry
            ),
            actor=self.operator,
        )

        self.device.refresh_from_db()
        self.vpn.refresh_from_db()

        self.assertEqual(
            self.device.expires_at,
            device_expiry,
        )

        self.assertEqual(
            self.vpn.expires_at,
            device_expiry,
        )

    def test_expired_device_is_not_ready(
        self,
    ):
        self.device.expires_at = (
            timezone.now()
            - timedelta(minutes=1)
        )

        self.device.save(
            update_fields=[
                "expires_at",
            ]
        )

        workspace = (
            build_customer_workspace(
                self.account
            )
        )

        row = workspace["devices"][0]

        self.assertTrue(
            row["device_expired"]
        )

        self.assertFalse(
            row["device_ready"]
        )

        self.assertFalse(
            row["can_add_connections"]
        )

        self.assertEqual(
            workspace[
                "active_device_total"
            ],
            0,
        )

        self.assertFalse(
            XHTTPDeviceService
            .is_device_available(
                self.device
            )
        )

    def test_expired_device_blocks_new_connection_selector(
        self,
    ):
        self.device.expires_at = (
            timezone.now()
            - timedelta(minutes=1)
        )

        self.device.save(
            update_fields=[
                "expires_at",
            ]
        )

        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            reverse(
                "customers-device-connection-create",
                args=[
                    self.device.pk,
                ],
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_expired_device_blocks_customer_vpn_download(
        self,
    ):
        self.device.expires_at = (
            timezone.now()
            - timedelta(minutes=1)
        )

        self.device.save(
            update_fields=[
                "expires_at",
            ]
        )

        self.client.force_login(
            self.customer_user
        )

        response = self.client.get(
            reverse(
                "customer-portal-vpn-download",
                args=[
                    self.vpn.pk,
                ],
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_operator_workspace_contains_device_editor(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            reverse(
                "customers-detail",
                args=[
                    self.account.pk,
                ],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Срок и VPN-лимиты",
        )

        self.assertContains(
            response,
            "VPN-лимит",
        )

        self.assertContains(
            response,
            reverse(
                "customers-device-access-update",
                args=[
                    self.device.pk,
                ],
            ),
        )

        self.assertContains(
            response,
            "Трафик:",
        )

    def test_operator_post_updates_device_policy(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        expiry = (
            timezone.now()
            + timedelta(days=40)
        )

        local_expiry = (
            timezone.localtime(
                expiry
            )
            .strftime(
                "%Y-%m-%dT%H:%M"
            )
        )

        prefix = (
            f"device-{self.device.pk}"
        )

        response = self.client.post(
            reverse(
                "customers-device-access-update",
                args=[
                    self.device.pk,
                ],
            ),
            {
                f"{prefix}-expires_at": (
                    local_expiry
                ),
                f"{prefix}-apply_traffic": (
                    "set"
                ),
                (
                    f"{prefix}-"
                    "traffic_limit_preset"
                ): "50gb",
                (
                    f"{prefix}-"
                    "traffic_custom_value"
                ): "",
                (
                    f"{prefix}-"
                    "traffic_custom_unit"
                ): "gb",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.device.refresh_from_db()
        self.vpn.refresh_from_db()

        self.assertEqual(
            self.device
            .vpn_traffic_limit_bytes,
            50 * 1024**3,
        )

        self.assertEqual(
            self.vpn.traffic_limit_bytes,
            50 * 1024**3,
        )

        self.assertEqual(
            self.device.expires_at.replace(
                second=0,
                microsecond=0,
            ),
            expiry.replace(
                second=0,
                microsecond=0,
            ),
        )

        self.assertEqual(
            self.vpn.expires_at,
            self.device.expires_at,
        )
