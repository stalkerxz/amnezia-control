from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from portal.models import ClientRenewalRequest
from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)
from vpn.models import (
    ClientConfigRevision,
    VPNClient,
)
from vpn.tasks import (
    _reconcile_all_vpn_devices,
    reconcile_vpn_account_task,
)

from .lifecycle_services import (
    CustomerConnectionLifecycleService,
)
from .models import (
    ClientDevice,
    CustomerAccount,
)
from .subscription_services import (
    extend_account_from_renewal,
)


User = get_user_model()


class AccountLifecycleTest(TestCase):
    def setUp(self):
        self.operator = User.objects.create_user(
            username="phase6c-operator",
            password="operator-password",
            is_owner=True,
            is_staff=True,
        )

        self.future = (
            timezone.now()
            + timedelta(days=30)
        )

        self.account = (
            CustomerAccount.objects.create(
                display_name="Phase 6C Customer",
                status=(
                    CustomerAccount.Status.ACTIVE
                ),
                expires_at=self.future,
                created_by=self.operator,
            )
        )

        self.device = ClientDevice.objects.create(
            account=self.account,
            name="Phase 6C Device",
            platform=ClientDevice.Platform.IOS,
            status=ClientDevice.Status.ACTIVE,
        )

        self.server = Server.objects.create(
            name="Phase 6C Server",
        )

        server_protocol = (
            ServerProtocol.objects.create(
                server=self.server,
                protocol_type=(
                    ServerProtocol.ProtocolType.AWG2
                ),
                enabled=True,
            )
        )

        self.profile = (
            ProtocolProfile.objects.create(
                server_protocol=server_protocol,
                name="FULL",
                protocol_type=(
                    ServerProtocol.ProtocolType.AWG2
                ),
                config_template="phase6c-template",
            )
        )

    def create_vpn(
        self,
        *,
        name,
        status=VPNClient.Status.ACTIVE,
        reason=VPNClient.DisableReason.NONE,
        expires_at=None,
        traffic_limit_bytes=None,
        traffic_used_bytes=0,
        device=None,
    ):
        return VPNClient.objects.create(
            server=self.server,
            name=name,
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            profile=self.profile,
            device=device or self.device,
            status=status,
            disable_reason=reason,
            expires_at=(
                self.future
                if expires_at is None
                else expires_at
            ),
            traffic_limit_bytes=(
                traffic_limit_bytes
            ),
            traffic_used_bytes=(
                traffic_used_bytes
            ),
            runtime_peer_public_key="",
            runtime_address="",
        )

    def test_expired_account_disables_active_vpn_as_expired(
        self,
    ):
        client = self.create_vpn(
            name="phase6c-expired-account",
            expires_at=self.future,
        )

        revision = (
            ClientConfigRevision.objects.create(
                client=client,
                revision_number=1,
                protocol_type=(
                    VPNClient.ProtocolType.AWG2
                ),
                config_blob_encrypted=(
                    "UNCHANGED-REVISION"
                ),
                config_hash="a" * 64,
            )
        )

        revision_before = (
            ClientConfigRevision.objects
            .values(
                "revision_number",
                "config_blob_encrypted",
                "config_hash",
            )
            .get(pk=revision.pk)
        )

        self.account.expires_at = (
            timezone.now()
            - timedelta(minutes=1)
        )

        self.account.save(
            update_fields=["expires_at"]
        )

        result = (
            CustomerConnectionLifecycleService
            .reconcile_vpn_device(
                device=self.device,
                actor=None,
            )
        )

        client.refresh_from_db()

        self.assertEqual(
            client.status,
            VPNClient.Status.DISABLED,
        )

        self.assertEqual(
            client.disable_reason,
            VPNClient.DisableReason.EXPIRED,
        )

        self.assertEqual(
            result["disabled"],
            1,
        )

        revision_after = (
            ClientConfigRevision.objects
            .values(
                *revision_before.keys()
            )
            .get(pk=revision.pk)
        )

        self.assertEqual(
            revision_before,
            revision_after,
        )

        self.assertEqual(
            client.revisions.count(),
            1,
        )

    def test_disabled_account_uses_owner_reason(
        self,
    ):
        client = self.create_vpn(
            name="phase6c-account-disabled",
        )

        self.account.status = (
            CustomerAccount.Status.DISABLED
        )

        self.account.save(
            update_fields=["status"]
        )

        CustomerConnectionLifecycleService.reconcile_vpn_device(
            device=self.device,
            actor=None,
        )

        client.refresh_from_db()

        self.assertEqual(
            client.status,
            VPNClient.Status.DISABLED,
        )

        self.assertEqual(
            client.disable_reason,
            VPNClient.DisableReason.OWNER,
        )

    def test_disabled_device_uses_owner_reason(
        self,
    ):
        client = self.create_vpn(
            name="phase6c-device-disabled",
        )

        self.device.status = (
            ClientDevice.Status.DISABLED
        )

        self.device.save(
            update_fields=["status"]
        )

        CustomerConnectionLifecycleService.reconcile_vpn_device(
            device=self.device,
            actor=None,
        )

        client.refresh_from_db()

        self.assertEqual(
            client.status,
            VPNClient.Status.DISABLED,
        )

        self.assertEqual(
            client.disable_reason,
            VPNClient.DisableReason.OWNER,
        )

    def test_owner_restore_does_not_restore_manual_disable(
        self,
    ):
        owner_client = self.create_vpn(
            name="phase6c-owner-restore",
            status=VPNClient.Status.DISABLED,
            reason=VPNClient.DisableReason.OWNER,
        )

        manual_client = self.create_vpn(
            name="phase6c-manual-preserve",
            status=VPNClient.Status.DISABLED,
            reason=VPNClient.DisableReason.MANUAL,
        )

        result = (
            CustomerConnectionLifecycleService
            .reconcile_vpn_device(
                device=self.device,
                actor=None,
            )
        )

        owner_client.refresh_from_db()
        manual_client.refresh_from_db()

        self.assertEqual(
            owner_client.status,
            VPNClient.Status.ACTIVE,
        )

        self.assertEqual(
            owner_client.disable_reason,
            VPNClient.DisableReason.NONE,
        )

        self.assertEqual(
            manual_client.status,
            VPNClient.Status.DISABLED,
        )

        self.assertEqual(
            manual_client.disable_reason,
            VPNClient.DisableReason.MANUAL,
        )

        self.assertEqual(
            result["enabled"],
            1,
        )

    def test_account_extension_restores_expired_client_without_reissue(
        self,
    ):
        past = (
            timezone.now()
            - timedelta(days=1)
        )

        self.account.expires_at = past

        self.account.save(
            update_fields=["expires_at"]
        )

        client = self.create_vpn(
            name="phase6c-renew-restore",
            status=VPNClient.Status.DISABLED,
            reason=VPNClient.DisableReason.EXPIRED,
            expires_at=past,
        )

        revision = (
            ClientConfigRevision.objects.create(
                client=client,
                revision_number=1,
                protocol_type=(
                    VPNClient.ProtocolType.AWG2
                ),
                config_blob_encrypted=(
                    "KEEP-ME"
                ),
                config_hash="b" * 64,
            )
        )

        request_obj = (
            ClientRenewalRequest.objects.create(
                account=self.account,
                client=None,
                status=(
                    ClientRenewalRequest.Status.NEW
                ),
            )
        )

        revision_before = (
            ClientConfigRevision.objects
            .values(
                "revision_number",
                "config_blob_encrypted",
                "config_hash",
            )
            .get(pk=revision.pk)
        )

        account, request_obj = (
            extend_account_from_renewal(
                account_id=self.account.pk,
                renewal_request_id=(
                    request_obj.pk
                ),
                extension_days=30,
                operator_note="paid",
                actor=self.operator,
            )
        )

        client.refresh_from_db()

        self.assertEqual(
            client.expires_at,
            account.expires_at,
        )

        CustomerConnectionLifecycleService.reconcile_vpn_device(
            device=self.device,
            actor=None,
        )

        client.refresh_from_db()

        self.assertEqual(
            client.status,
            VPNClient.Status.ACTIVE,
        )

        self.assertEqual(
            client.disable_reason,
            VPNClient.DisableReason.NONE,
        )

        revision_after = (
            ClientConfigRevision.objects
            .values(
                *revision_before.keys()
            )
            .get(pk=revision.pk)
        )

        self.assertEqual(
            revision_before,
            revision_after,
        )

        self.assertEqual(
            client.revisions.count(),
            1,
        )

    def test_traffic_disabled_client_is_never_auto_restored(
        self,
    ):
        client = self.create_vpn(
            name="phase6c-traffic-preserve",
            status=VPNClient.Status.DISABLED,
            reason=(
                VPNClient.DisableReason.TRAFFIC_EXCEEDED
            ),
            traffic_limit_bytes=100,
            traffic_used_bytes=100,
        )

        CustomerConnectionLifecycleService.reconcile_vpn_device(
            device=self.device,
            actor=None,
        )

        client.refresh_from_db()

        self.assertEqual(
            client.status,
            VPNClient.Status.DISABLED,
        )

        self.assertEqual(
            client.disable_reason,
            (
                VPNClient.DisableReason
                .TRAFFIC_EXCEEDED
            ),
        )

    def test_active_traffic_exceeded_is_disabled(
        self,
    ):
        client = self.create_vpn(
            name="phase6c-active-traffic",
            traffic_limit_bytes=100,
            traffic_used_bytes=100,
        )

        CustomerConnectionLifecycleService.reconcile_vpn_device(
            device=self.device,
            actor=None,
        )

        client.refresh_from_db()

        self.assertEqual(
            client.status,
            VPNClient.Status.DISABLED,
        )

        self.assertEqual(
            client.disable_reason,
            (
                VPNClient.DisableReason
                .TRAFFIC_EXCEEDED
            ),
        )

        self.assertEqual(
            client.limit_state,
            VPNClient.LimitState.TRAFFIC_EXCEEDED,
        )

    def test_deleted_client_is_ignored(
        self,
    ):
        client = self.create_vpn(
            name="phase6c-deleted",
            status=VPNClient.Status.DELETED,
            reason=VPNClient.DisableReason.MANUAL,
        )

        self.account.status = (
            CustomerAccount.Status.DISABLED
        )

        self.account.save(
            update_fields=["status"]
        )

        result = (
            CustomerConnectionLifecycleService
            .reconcile_vpn_device(
                device=self.device,
                actor=None,
            )
        )

        client.refresh_from_db()

        self.assertEqual(
            client.status,
            VPNClient.Status.DELETED,
        )

        self.assertEqual(
            result["processed"],
            0,
        )

    def test_expired_client_not_restored_while_account_unavailable(
        self,
    ):
        client = self.create_vpn(
            name="phase6c-expired-owner-down",
            status=VPNClient.Status.DISABLED,
            reason=VPNClient.DisableReason.EXPIRED,
            expires_at=self.future,
        )

        self.account.status = (
            CustomerAccount.Status.DISABLED
        )

        self.account.save(
            update_fields=["status"]
        )

        CustomerConnectionLifecycleService.reconcile_vpn_device(
            device=self.device,
            actor=None,
        )

        client.refresh_from_db()

        self.assertEqual(
            client.status,
            VPNClient.Status.DISABLED,
        )

    def test_account_task_reconciles_multiple_devices(
        self,
    ):
        first = self.create_vpn(
            name="phase6c-task-first",
            status=VPNClient.Status.DISABLED,
            reason=VPNClient.DisableReason.OWNER,
        )

        second_device = (
            ClientDevice.objects.create(
                account=self.account,
                name="Phase 6C Second",
                platform=ClientDevice.Platform.MACOS,
                status=ClientDevice.Status.ACTIVE,
            )
        )

        second = self.create_vpn(
            name="phase6c-task-second",
            status=VPNClient.Status.DISABLED,
            reason=VPNClient.DisableReason.OWNER,
            device=second_device,
        )

        result = reconcile_vpn_account_task(
            self.account.pk
        )

        first.refresh_from_db()
        second.refresh_from_db()

        self.assertEqual(
            first.status,
            VPNClient.Status.ACTIVE,
        )

        self.assertEqual(
            second.status,
            VPNClient.Status.ACTIVE,
        )

        self.assertEqual(
            result["enabled"],
            2,
        )

        self.assertEqual(
            result["devices"],
            2,
        )

    def test_periodic_reconcile_covers_device_owned_vpn(
        self,
    ):
        client = self.create_vpn(
            name="phase6c-periodic",
        )

        self.account.status = (
            CustomerAccount.Status.DISABLED
        )

        self.account.save(
            update_fields=["status"]
        )

        result = (
            _reconcile_all_vpn_devices()
        )

        client.refresh_from_db()

        self.assertEqual(
            client.status,
            VPNClient.Status.DISABLED,
        )

        self.assertEqual(
            client.disable_reason,
            VPNClient.DisableReason.OWNER,
        )

        self.assertGreaterEqual(
            result["disabled"],
            1,
        )
