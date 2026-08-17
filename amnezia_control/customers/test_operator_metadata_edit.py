import hashlib

from cryptography.fernet import Fernet

from django.contrib.auth import get_user_model
from django.test import (
    TestCase,
    override_settings,
)
from django.urls import reverse

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)

from vpn.models import (
    ClientConfigRevision,
    VPNClient,
)

from vpn.services import ConfigCryptoService

from .models import (
    ClientDevice,
    CustomerAccount,
)


@override_settings(
    CONFIG_ENCRYPTION_KEY=(
        Fernet.generate_key().decode()
    )
)
class OperatorMetadataEditTest(
    TestCase
):
    def setUp(self):
        User = get_user_model()

        self.operator = (
            User.objects.create_user(
                username="metadata-operator",
                password="operator-password",
                is_owner=True,
            )
        )

        self.customer_user = (
            User.objects.create_user(
                username="metadata-customer",
                password="customer-password",
                is_owner=False,
            )
        )

        self.account = (
            CustomerAccount.objects.create(
                display_name="Old Customer",
                email="old@example.com",
                user=self.customer_user,
                created_by=self.operator,
            )
        )

        self.device = (
            ClientDevice.objects.create(
                account=self.account,
                name="Old Device",
                platform=(
                    ClientDevice.Platform.IOS
                ),
                notes="Old note",
            )
        )

        self.server = Server.objects.create(
            name="Metadata Server",
        )

        protocol = (
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

        profile = (
            ProtocolProfile.objects.create(
                server_protocol=protocol,
                name="FULL",
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                config_template="[Interface]",
            )
        )

        self.vpn = VPNClient.objects.create(
            server=self.server,
            name="stable-technical-name",
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            status=VPNClient.Status.ACTIVE,
            profile=profile,
            device=self.device,
            contact_email="old@example.com",
            runtime_peer_public_key=(
                "STABLE-PUBLIC-KEY"
            ),
            runtime_address="10.77.0.44",
        )

        plaintext = (
            "[Interface]\n"
            "PrivateKey = TEST-PRIVATE\n"
            "Address = 10.77.0.44/32\n"
        )

        self.revision = (
            ClientConfigRevision.objects.create(
                client=self.vpn,
                revision_number=1,
                protocol_type=(
                    VPNClient.ProtocolType.AWG2
                ),
                config_blob_encrypted=(
                    ConfigCryptoService.encrypt(
                        plaintext
                    )
                ),
                config_hash=hashlib.sha256(
                    plaintext.encode()
                ).hexdigest(),
            )
        )

    def _vpn_snapshot(self):
        self.vpn.refresh_from_db()

        return {
            "name": self.vpn.name,
            "status": self.vpn.status,
            "expires_at": self.vpn.expires_at,
            "public_key": (
                self.vpn.runtime_peer_public_key
            ),
            "address": (
                self.vpn.runtime_address
            ),
            "revision_count": (
                self.vpn.revisions.count()
            ),
            "revision_hash": (
                self.vpn.revisions.get(
                    pk=self.revision.pk
                ).config_hash
            ),
        }

    def test_operator_can_edit_account_metadata(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        before = self._vpn_snapshot()
        old_expiry = self.account.expires_at

        response = self.client.post(
            reverse(
                "customers-edit",
                args=[self.account.pk],
            ),
            {
                "display_name": (
                    "New Customer Name"
                ),
                "email": (
                    "new@example.com"
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.account.refresh_from_db()
        self.vpn.refresh_from_db()

        self.assertEqual(
            self.account.display_name,
            "New Customer Name",
        )

        self.assertEqual(
            self.account.email,
            "new@example.com",
        )

        self.assertEqual(
            self.account.expires_at,
            old_expiry,
        )

        self.assertEqual(
            self.vpn.contact_email,
            "new@example.com",
        )

        self.assertEqual(
            before,
            self._vpn_snapshot(),
        )

    def test_operator_can_edit_device_metadata_without_vpn_mutation(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        before = self._vpn_snapshot()
        old_account_id = self.device.account_id
        old_status = self.device.status

        response = self.client.post(
            reverse(
                "customers-device-edit",
                args=[self.device.pk],
            ),
            {
                "name": "MacBook Pro",
                "platform": (
                    ClientDevice.Platform.MACOS
                ),
                "notes": "Main laptop",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.device.refresh_from_db()

        self.assertEqual(
            self.device.name,
            "MacBook Pro",
        )

        self.assertEqual(
            self.device.platform,
            ClientDevice.Platform.MACOS,
        )

        self.assertEqual(
            self.device.notes,
            "Main laptop",
        )

        self.assertEqual(
            self.device.account_id,
            old_account_id,
        )

        self.assertEqual(
            self.device.status,
            old_status,
        )

        self.assertEqual(
            before,
            self._vpn_snapshot(),
        )

    def test_customer_cannot_edit_account(
        self,
    ):
        self.client.force_login(
            self.customer_user
        )

        response = self.client.get(
            reverse(
                "customers-edit",
                args=[self.account.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_customer_cannot_edit_device(
        self,
    ):
        self.client.force_login(
            self.customer_user
        )

        response = self.client.get(
            reverse(
                "customers-device-edit",
                args=[self.device.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_deleted_account_cannot_be_edited(
        self,
    ):
        self.account.status = (
            CustomerAccount.Status.DELETED
        )

        self.account.save(
            update_fields=["status"]
        )

        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            reverse(
                "customers-edit",
                args=[self.account.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_workspace_contains_edit_actions(
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
                "customers-edit",
                args=[self.account.pk],
            ),
        )

        self.assertContains(
            response,
            reverse(
                "customers-device-edit",
                args=[self.device.pk],
            ),
        )

        self.assertContains(
            response,
            "Редактировать аккаунт",
        )

        self.assertContains(
            response,
            "Изменить",
        )
