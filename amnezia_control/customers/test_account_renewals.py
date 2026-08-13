from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from portal.models import ClientRenewalRequest
from portal.services import RenewalRequestService
from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)
from vpn.models import (
    ClientConfigRevision,
    VPNClient,
)

from .models import (
    ClientDevice,
    CustomerAccount,
)
from .subscription_services import (
    extend_account_from_renewal,
    set_account_renewal_status,
)


User = get_user_model()


class AccountRenewalFlowTest(TestCase):
    def setUp(self):
        self.operator = User.objects.create_user(
            username="phase6b-operator",
            password="operator-password",
            is_owner=True,
            is_staff=True,
        )

        self.customer_user = User.objects.create_user(
            username="phase6b-customer",
            password="customer-password",
            is_owner=False,
            is_staff=False,
        )

        self.account = CustomerAccount.objects.create(
            display_name="Phase 6B Customer",
            email="phase6b@example.com",
            user=self.customer_user,
            created_by=self.operator,
            expires_at=(
                timezone.now()
                + timedelta(days=5)
            ),
        )

        self.device = ClientDevice.objects.create(
            account=self.account,
            name="Phase 6B iPhone",
            platform=ClientDevice.Platform.IOS,
        )

        self.server = Server.objects.create(
            name="Phase 6B Server",
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

        self.profile = ProtocolProfile.objects.create(
            server_protocol=server_protocol,
            name="FULL",
            protocol_type=(
                ServerProtocol.ProtocolType.AWG2
            ),
            config_template="phase6b-template",
        )

        self.vpn = VPNClient.objects.create(
            server=self.server,
            name="Phase6B-FULL",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=self.profile,
            device=self.device,
            expires_at=self.account.expires_at,
            runtime_peer_public_key="PHASE6B-PUBKEY-1",
            runtime_address="10.8.70.10",
        )

        self.revision = (
            ClientConfigRevision.objects.create(
                client=self.vpn,
                revision_number=1,
                protocol_type=VPNClient.ProtocolType.AWG2,
                config_blob_encrypted=(
                    "PHASE6B-ENCRYPTED-1"
                ),
                config_hash="a" * 64,
            )
        )

        self.second_device = (
            ClientDevice.objects.create(
                account=self.account,
                name="Phase 6B MacBook",
                platform=ClientDevice.Platform.MACOS,
            )
        )

        self.second_vpn = VPNClient.objects.create(
            server=self.server,
            name="Phase6B-SECOND",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=self.profile,
            device=self.second_device,
            expires_at=self.account.expires_at,
            runtime_peer_public_key="PHASE6B-PUBKEY-2",
            runtime_address="10.8.70.11",
        )

    def _new_request(self):
        request_obj, created = (
            RenewalRequestService
            .create_or_get_open_for_account(
                account=self.account,
            )
        )

        self.assertTrue(created)

        return request_obj

    def test_account_request_has_no_legacy_client(self):
        request_obj = self._new_request()

        self.assertEqual(
            request_obj.account_id,
            self.account.pk,
        )

        self.assertIsNone(
            request_obj.client_id
        )

    def test_database_allows_only_one_open_request_per_account(
        self,
    ):
        self._new_request()

        with self.assertRaises(
            IntegrityError
        ):
            with transaction.atomic():
                ClientRenewalRequest.objects.create(
                    account=self.account,
                    client=None,
                    status=(
                        ClientRenewalRequest.Status.NEW
                    ),
                )

    def test_customer_portal_creates_account_request(
        self,
    ):
        self.client.force_login(
            self.customer_user
        )

        response = self.client.post(
            reverse(
                "customer-portal-renewal-request"
            ),
            {},
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        request_obj = (
            ClientRenewalRequest.objects
            .get(account=self.account)
        )

        self.assertIsNone(
            request_obj.client_id
        )

        self.assertEqual(
            request_obj.status,
            ClientRenewalRequest.Status.NEW,
        )

    def test_repeated_customer_request_reuses_open_request(
        self,
    ):
        self.client.force_login(
            self.customer_user
        )

        url = reverse(
            "customer-portal-renewal-request"
        )

        self.client.post(
            url,
            {},
        )

        self.client.post(
            url,
            {},
        )

        self.assertEqual(
            ClientRenewalRequest.objects
            .filter(
                account=self.account,
                status__in=[
                    ClientRenewalRequest.Status.NEW,
                    ClientRenewalRequest.Status.IN_PROGRESS,
                ],
            )
            .count(),
            1,
        )

    def test_disabled_account_cannot_create_renewal(
        self,
    ):
        self.account.status = (
            CustomerAccount.Status.DISABLED
        )

        self.account.save(
            update_fields=["status"]
        )

        self.client.force_login(
            self.customer_user
        )

        response = self.client.post(
            reverse(
                "customer-portal-renewal-request"
            ),
            {},
        )

        self.assertEqual(
            response.status_code,
            403,
        )

        self.assertFalse(
            ClientRenewalRequest.objects
            .filter(
                account=self.account,
            )
            .exists()
        )

    def test_operator_can_mark_request_in_progress(
        self,
    ):
        request_obj = self._new_request()

        updated = set_account_renewal_status(
            account_id=self.account.pk,
            renewal_request_id=request_obj.pk,
            target_status=(
                ClientRenewalRequest.Status.IN_PROGRESS
            ),
            operator_note="Проверяю оплату",
            actor=self.operator,
        )

        self.assertEqual(
            updated.status,
            ClientRenewalRequest.Status.IN_PROGRESS,
        )

        self.assertEqual(
            updated.operator_note,
            "Проверяю оплату",
        )

    def test_extend_updates_account_and_all_vpn_expiry_without_reissue(
        self,
    ):
        request_obj = self._new_request()

        old_account_expiry = (
            self.account.expires_at
        )

        vpn_before = VPNClient.objects.values(
            "runtime_peer_public_key",
            "runtime_address",
        ).get(
            pk=self.vpn.pk
        )

        revision_before = (
            ClientConfigRevision.objects.values(
                "revision_number",
                "config_blob_encrypted",
                "config_hash",
            ).get(
                pk=self.revision.pk
            )
        )

        revision_count_before = (
            self.vpn.revisions.count()
        )

        account, request_obj = (
            extend_account_from_renewal(
                account_id=self.account.pk,
                renewal_request_id=request_obj.pk,
                extension_days=30,
                operator_note="Оплата подтверждена",
                actor=self.operator,
            )
        )

        self.vpn.refresh_from_db()
        self.second_vpn.refresh_from_db()

        self.assertGreater(
            account.expires_at,
            old_account_expiry,
        )

        self.assertEqual(
            self.vpn.expires_at,
            account.expires_at,
        )

        self.assertEqual(
            self.second_vpn.expires_at,
            account.expires_at,
        )

        self.assertEqual(
            request_obj.status,
            ClientRenewalRequest.Status.DONE,
        )

        vpn_after = VPNClient.objects.values(
            *vpn_before.keys()
        ).get(
            pk=self.vpn.pk
        )

        revision_after = (
            ClientConfigRevision.objects.values(
                *revision_before.keys()
            ).get(
                pk=self.revision.pk
            )
        )

        self.assertEqual(
            vpn_before,
            vpn_after,
        )

        self.assertEqual(
            revision_before,
            revision_after,
        )

        self.assertEqual(
            self.vpn.revisions.count(),
            revision_count_before,
        )

    def test_operator_can_dismiss_account_request(
        self,
    ):
        request_obj = self._new_request()

        updated = set_account_renewal_status(
            account_id=self.account.pk,
            renewal_request_id=request_obj.pk,
            target_status=(
                ClientRenewalRequest.Status.DISMISSED
            ),
            operator_note="Не подтверждено",
            actor=self.operator,
        )

        self.assertEqual(
            updated.status,
            ClientRenewalRequest.Status.DISMISSED,
        )

        self.assertIsNotNone(
            updated.processed_at
        )

    def test_legacy_portal_reuses_account_open_request(
        self,
    ):
        request_obj = self._new_request()

        legacy_request, created = (
            RenewalRequestService
            .create_or_get_open_from_portal(
                client=self.vpn,
            )
        )

        self.assertFalse(created)

        self.assertEqual(
            legacy_request.pk,
            request_obj.pk,
        )

        self.assertEqual(
            legacy_request.account_id,
            self.account.pk,
        )

    def test_legacy_operator_list_hides_account_only_requests(
        self,
    ):
        request_obj = self._new_request()

        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            reverse(
                "renewal-requests-list"
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        rows = list(
            response.context[
                "request_rows"
            ]
        )

        self.assertNotIn(
            request_obj,
            rows,
        )
