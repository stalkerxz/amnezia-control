import uuid

from django.contrib.auth import (
    get_user_model,
)
from django.db.models.deletion import (
    ProtectedError,
)
from django.test import TestCase

from customers.models import (
    ClientDevice,
    CustomerAccount,
)
from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)
from vpn.models import (
    ClientConfigRevision,
    VPNClient,
    XHTTPDevice,
)


class ParentDeleteCleanupTest(TestCase):
    def setUp(self):
        self.user = (
            get_user_model()
            .objects.create_user(
                username="parent-delete-test",
                password="test-password",
            )
        )

        self.server = Server.objects.create(
            name="parent-delete-server",
            host="203.0.113.80",
        )

        self.server_protocol = (
            ServerProtocol.objects.create(
                server=self.server,
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
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
                config_template="",
            )
        )

    def make_parent(self):
        suffix = uuid.uuid4().hex[:8]

        account = (
            CustomerAccount.objects.create(
                display_name=(
                    f"Delete test {suffix}"
                ),
                created_by=self.user,
            )
        )

        device = ClientDevice.objects.create(
            account=account,
            name=f"Device {suffix}",
        )

        return account, device

    def make_xhttp(
        self,
        device,
        *,
        status,
    ):
        token = uuid.uuid4()

        return XHTTPDevice.objects.create(
            device=device,
            server=self.server,
            name=(
                f"XHTTP {token.hex[:8]}"
            ),
            client_uuid=token,
            xray_email=(
                f"xhttp-{token.hex}"
            ),
            status=status,
            disable_reason=(
                XHTTPDevice
                .DisableReason
                .MANUAL
                if status
                != XHTTPDevice.Status.ACTIVE
                else
                XHTTPDevice
                .DisableReason
                .NONE
            ),
            config_blob_encrypted="encrypted",
            config_hash="a" * 64,
        )

    def make_vpn(
        self,
        device,
        *,
        status,
    ):
        token = uuid.uuid4().hex[:8]

        return VPNClient.objects.create(
            server=self.server,
            name=f"VPN {token}",
            protocol_type=(
                VPNClient
                .ProtocolType
                .AWG2
            ),
            status=status,
            profile=self.profile,
            created_by=self.user,
            device=device,
        )

    def test_deleted_xhttp_does_not_block_account_delete(
        self,
    ):
        account, device = (
            self.make_parent()
        )

        xhttp = self.make_xhttp(
            device,
            status=(
                XHTTPDevice.Status.DELETED
            ),
        )

        account_id = account.pk
        device_id = device.pk
        xhttp_id = xhttp.pk

        account.delete()

        self.assertFalse(
            CustomerAccount.objects.filter(
                pk=account_id
            ).exists()
        )

        self.assertFalse(
            ClientDevice.objects.filter(
                pk=device_id
            ).exists()
        )

        self.assertFalse(
            XHTTPDevice.objects.filter(
                pk=xhttp_id
            ).exists()
        )

    def test_deleted_xhttp_does_not_block_device_delete(
        self,
    ):
        account, device = (
            self.make_parent()
        )

        xhttp = self.make_xhttp(
            device,
            status=(
                XHTTPDevice.Status.DELETED
            ),
        )

        device_id = device.pk
        xhttp_id = xhttp.pk

        device.delete()

        self.assertTrue(
            CustomerAccount.objects.filter(
                pk=account.pk
            ).exists()
        )

        self.assertFalse(
            ClientDevice.objects.filter(
                pk=device_id
            ).exists()
        )

        self.assertFalse(
            XHTTPDevice.objects.filter(
                pk=xhttp_id
            ).exists()
        )

    def test_active_xhttp_blocks_parent_delete(
        self,
    ):
        account, device = (
            self.make_parent()
        )

        xhttp = self.make_xhttp(
            device,
            status=(
                XHTTPDevice.Status.ACTIVE
            ),
        )

        with self.assertRaises(
            ProtectedError
        ):
            account.delete()

        self.assertTrue(
            CustomerAccount.objects.filter(
                pk=account.pk
            ).exists()
        )

        self.assertTrue(
            XHTTPDevice.objects.filter(
                pk=xhttp.pk
            ).exists()
        )

    def test_disabled_xhttp_blocks_parent_delete(
        self,
    ):
        account, device = (
            self.make_parent()
        )

        xhttp = self.make_xhttp(
            device,
            status=(
                XHTTPDevice.Status.DISABLED
            ),
        )

        with self.assertRaises(
            ProtectedError
        ):
            account.delete()

        self.assertTrue(
            XHTTPDevice.objects.filter(
                pk=xhttp.pk
            ).exists()
        )

    def test_deleted_vpn_and_revision_are_cascaded(
        self,
    ):
        account, device = (
            self.make_parent()
        )

        vpn = self.make_vpn(
            device,
            status=VPNClient.Status.DELETED,
        )

        revision = (
            ClientConfigRevision
            .objects.create(
                client=vpn,
                revision_number=1,
                protocol_type=(
                    VPNClient
                    .ProtocolType
                    .AWG2
                ),
                config_blob_encrypted="encrypted",
                config_hash="b" * 64,
            )
        )

        vpn_id = vpn.pk
        revision_id = revision.pk

        account.delete()

        self.assertFalse(
            VPNClient.objects.filter(
                pk=vpn_id
            ).exists()
        )

        self.assertFalse(
            ClientConfigRevision
            .objects.filter(
                pk=revision_id
            )
            .exists()
        )

    def test_active_vpn_blocks_parent_delete(
        self,
    ):
        account, device = (
            self.make_parent()
        )

        vpn = self.make_vpn(
            device,
            status=VPNClient.Status.ACTIVE,
        )

        with self.assertRaises(
            ProtectedError
        ):
            account.delete()

        self.assertTrue(
            VPNClient.objects.filter(
                pk=vpn.pk
            ).exists()
        )

    def test_disabled_vpn_blocks_parent_delete(
        self,
    ):
        account, device = (
            self.make_parent()
        )

        vpn = self.make_vpn(
            device,
            status=(
                VPNClient.Status.DISABLED
            ),
        )

        with self.assertRaises(
            ProtectedError
        ):
            account.delete()

        self.assertTrue(
            VPNClient.objects.filter(
                pk=vpn.pk
            ).exists()
        )

    def test_deleted_tombstone_does_not_hide_live_blocker(
        self,
    ):
        account, device = (
            self.make_parent()
        )

        deleted_xhttp = self.make_xhttp(
            device,
            status=(
                XHTTPDevice.Status.DELETED
            ),
        )

        active_vpn = self.make_vpn(
            device,
            status=VPNClient.Status.ACTIVE,
        )

        with self.assertRaises(
            ProtectedError
        ):
            account.delete()

        self.assertTrue(
            XHTTPDevice.objects.filter(
                pk=deleted_xhttp.pk
            ).exists()
        )

        self.assertTrue(
            VPNClient.objects.filter(
                pk=active_vpn.pk
            ).exists()
        )
