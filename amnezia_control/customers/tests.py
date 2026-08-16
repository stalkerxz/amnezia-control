from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import ClientDevice, CustomerAccount


class CustomerViewsTest(TestCase):
    def setUp(self):
        User = get_user_model()

        self.operator = User.objects.create_user(
            username="operator",
            password="test-password",
        )

        self.account = CustomerAccount.objects.create(
            display_name="Test Customer",
            email="customer@example.com",
        )

        self.device = ClientDevice.objects.create(
            account=self.account,
            name="Test iPhone",
            platform=ClientDevice.Platform.IOS,
        )

    def test_non_owner_cannot_access_customer_operator_pages(self):
        User = get_user_model()

        customer_user = User.objects.create_user(
            username="customer-user",
            password="test-password",
            is_owner=False,
        )

        self.client.force_login(customer_user)

        list_response = self.client.get(
            reverse("customers-list")
        )

        detail_response = self.client.get(
            reverse(
                "customers-detail",
                args=[self.account.pk],
            )
        )

        self.assertEqual(list_response.status_code, 403)
        self.assertEqual(detail_response.status_code, 403)

    def test_list_requires_login(self):
        response = self.client.get(reverse("customers-list"))

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_list_renders_account_and_counts(self):
        self.client.force_login(self.operator)

        response = self.client.get(reverse("customers-list"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response,
            "customers/customers_list.html",
        )
        self.assertContains(response, "Test Customer")

        account = response.context["accounts"].get(pk=self.account.pk)
        self.assertEqual(account.device_count, 1)
        self.assertEqual(account.vpn_config_count, 0)

    def test_detail_renders_device(self):
        self.client.force_login(self.operator)

        response = self.client.get(
            reverse(
                "customers-detail",
                args=[self.account.pk],
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response,
            "customers/customer_detail.html",
        )
        self.assertContains(response, "Test Customer")
        self.assertContains(response, "Test iPhone")
        self.assertContains(response, "iPhone / iPad")

    def test_unknown_account_returns_404(self):
        self.client.force_login(self.operator)

        response = self.client.get(
            reverse(
                "customers-detail",
                args=[999999],
            )
        )

        self.assertEqual(response.status_code, 404)

    def test_read_only_pages_reject_post(self):
        self.client.force_login(self.operator)

        list_response = self.client.post(reverse("customers-list"))
        detail_response = self.client.post(
            reverse(
                "customers-detail",
                args=[self.account.pk],
            )
        )

        self.assertEqual(list_response.status_code, 405)
        self.assertEqual(detail_response.status_code, 405)

    def test_read_only_pages_do_not_change_data(self):
        self.client.force_login(self.operator)

        before = (
            CustomerAccount.objects.count(),
            ClientDevice.objects.count(),
        )

        self.client.get(reverse("customers-list"))
        self.client.get(
            reverse(
                "customers-detail",
                args=[self.account.pk],
            )
        )

        after = (
            CustomerAccount.objects.count(),
            ClientDevice.objects.count(),
        )

        self.assertEqual(after, before)


class CustomerAccountServiceSafetyTest(TestCase):
    def setUp(self):
        from django.contrib.auth import get_user_model
        from servers.models import ProtocolProfile, Server, ServerProtocol
        from vpn.models import ClientConfigRevision, VPNClient

        User = get_user_model()

        self.operator = User.objects.create_user(
            username="service-operator",
            password="test-password",
        )

        self.source_account = CustomerAccount.objects.create(
            display_name="Source Customer",
        )
        self.target_account = CustomerAccount.objects.create(
            display_name="Target Customer",
        )

        self.device = ClientDevice.objects.create(
            account=self.source_account,
            name="Existing iPhone",
            platform=ClientDevice.Platform.IOS,
        )

        self.server = Server.objects.create(
            name="Safety Test Server",
        )

        self.server_protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
        )

        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.server_protocol,
            name="FULL",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="test-template",
        )

        self.vpn_client = VPNClient.objects.create(
            server=self.server,
            name="Existing-AWG2-FULL",
            contact_email="customer@example.com",
            protocol_type=VPNClient.ProtocolType.AWG2,
            status=VPNClient.Status.ACTIVE,
            profile=self.profile,
            created_by=self.operator,
            device=self.device,
            runtime_peer_public_key="PUBKEY-UNCHANGED",
            runtime_address="10.8.1.77",
            traffic_limit_bytes=123456789,
            traffic_used_bytes=456789,
        )

        self.revision = ClientConfigRevision.objects.create(
            client=self.vpn_client,
            revision_number=1,
            protocol_type=VPNClient.ProtocolType.AWG2,
            config_blob_encrypted="ENCRYPTED-CONFIG-UNCHANGED",
            config_hash="HASH-UNCHANGED",
        )

    def test_move_device_preserves_existing_vpn_configuration(self):
        from customers.services import move_device_to_account
        from vpn.models import ClientConfigRevision, VPNClient

        client_before = VPNClient.objects.values(
            "id",
            "server_id",
            "name",
            "contact_email",
            "protocol_type",
            "status",
            "profile_id",
            "created_by_id",
            "device_id",
            "runtime_peer_public_key",
            "runtime_address",
            "expires_at",
            "traffic_limit_bytes",
            "traffic_used_bytes",
            "limit_state",
            "disable_reason",
        ).get(pk=self.vpn_client.pk)

        revision_before = ClientConfigRevision.objects.values(
            "id",
            "client_id",
            "revision_number",
            "protocol_type",
            "config_blob_encrypted",
            "config_hash",
        ).get(pk=self.revision.pk)

        move_device_to_account(
            device_id=self.device.pk,
            target_account_id=self.target_account.pk,
        )

        self.device.refresh_from_db()
        self.vpn_client.refresh_from_db()
        self.revision.refresh_from_db()

        self.assertEqual(
            self.device.account_id,
            self.target_account.pk,
        )

        client_after = VPNClient.objects.values(
            *client_before.keys()
        ).get(pk=self.vpn_client.pk)

        revision_after = ClientConfigRevision.objects.values(
            *revision_before.keys()
        ).get(pk=self.revision.pk)

        self.assertEqual(client_after, client_before)
        self.assertEqual(revision_after, revision_before)

        self.assertEqual(
            self.vpn_client.runtime_peer_public_key,
            "PUBKEY-UNCHANGED",
        )
        self.assertEqual(
            self.vpn_client.runtime_address,
            "10.8.1.77",
        )
        self.assertEqual(
            self.revision.config_blob_encrypted,
            "ENCRYPTED-CONFIG-UNCHANGED",
        )


class CustomerAccountMergeSafetyTest(CustomerAccountServiceSafetyTest):
    def test_merge_preserves_both_vpn_configurations(self):
        from customers.services import merge_customer_accounts
        from vpn.models import ClientConfigRevision, VPNClient

        target_device = ClientDevice.objects.create(
            account=self.target_account,
            name="Existing MacBook",
            platform=ClientDevice.Platform.MACOS,
        )

        target_client = VPNClient.objects.create(
            server=self.server,
            name="Existing-AWG2-SELECTIVE",
            contact_email="customer@example.com",
            protocol_type=VPNClient.ProtocolType.AWG2,
            status=VPNClient.Status.ACTIVE,
            profile=self.profile,
            created_by=self.operator,
            device=target_device,
            runtime_peer_public_key="PUBKEY-TARGET-UNCHANGED",
            runtime_address="10.8.1.78",
            traffic_limit_bytes=987654321,
            traffic_used_bytes=654321,
        )

        target_revision = ClientConfigRevision.objects.create(
            client=target_client,
            revision_number=1,
            protocol_type=VPNClient.ProtocolType.AWG2,
            config_blob_encrypted="TARGET-CONFIG-UNCHANGED",
            config_hash="TARGET-HASH-UNCHANGED",
        )

        vpn_before = list(
            VPNClient.objects
            .filter(pk__in=[self.vpn_client.pk, target_client.pk])
            .order_by("pk")
            .values(
                "id",
                "server_id",
                "name",
                "contact_email",
                "protocol_type",
                "status",
                "profile_id",
                "created_by_id",
                "device_id",
                "runtime_peer_public_key",
                "runtime_address",
                "expires_at",
                "traffic_limit_bytes",
                "traffic_used_bytes",
                "limit_state",
                "disable_reason",
            )
        )

        revisions_before = list(
            ClientConfigRevision.objects
            .filter(pk__in=[self.revision.pk, target_revision.pk])
            .order_by("pk")
            .values(
                "id",
                "client_id",
                "revision_number",
                "protocol_type",
                "config_blob_encrypted",
                "config_hash",
            )
        )

        moved = merge_customer_accounts(
            source_account_id=self.source_account.pk,
            target_account_id=self.target_account.pk,
        )

        self.assertEqual(moved, 1)

        self.source_account.refresh_from_db()
        self.target_account.refresh_from_db()
        self.device.refresh_from_db()
        target_device.refresh_from_db()

        self.assertEqual(
            self.source_account.status,
            CustomerAccount.Status.DELETED,
        )
        self.assertEqual(
            self.target_account.status,
            CustomerAccount.Status.ACTIVE,
        )

        self.assertEqual(
            self.device.account_id,
            self.target_account.pk,
        )
        self.assertEqual(
            target_device.account_id,
            self.target_account.pk,
        )

        self.assertEqual(
            self.target_account.devices.count(),
            2,
        )
        self.assertEqual(
            self.source_account.devices.count(),
            0,
        )

        vpn_after = list(
            VPNClient.objects
            .filter(pk__in=[self.vpn_client.pk, target_client.pk])
            .order_by("pk")
            .values(*vpn_before[0].keys())
        )

        revisions_after = list(
            ClientConfigRevision.objects
            .filter(pk__in=[self.revision.pk, target_revision.pk])
            .order_by("pk")
            .values(*revisions_before[0].keys())
        )

        self.assertEqual(vpn_after, vpn_before)
        self.assertEqual(revisions_after, revisions_before)

        self.assertEqual(
            VPNClient.objects.get(pk=self.vpn_client.pk).runtime_peer_public_key,
            "PUBKEY-UNCHANGED",
        )
        self.assertEqual(
            VPNClient.objects.get(pk=target_client.pk).runtime_peer_public_key,
            "PUBKEY-TARGET-UNCHANGED",
        )


    def test_merge_reassigns_portal_and_renewal_account_ownership(
        self,
    ):
        from customers.services import (
            merge_customer_accounts,
        )
        from portal.models import (
            ClientPortalAccess,
            ClientRenewalRequest,
        )

        portal = ClientPortalAccess.objects.create(
            client=self.vpn_client,
            account=self.source_account,
            token_hash="1" * 64,
        )

        renewal = ClientRenewalRequest.objects.create(
            client=self.vpn_client,
            account=self.source_account,
            status=ClientRenewalRequest.Status.DONE,
            note="historical renewal",
        )

        moved = merge_customer_accounts(
            source_account_id=(
                self.source_account.pk
            ),
            target_account_id=(
                self.target_account.pk
            ),
        )

        self.assertEqual(
            moved,
            1,
        )

        portal.refresh_from_db()
        renewal.refresh_from_db()
        self.device.refresh_from_db()
        self.source_account.refresh_from_db()

        self.assertEqual(
            self.device.account_id,
            self.target_account.pk,
        )

        self.assertEqual(
            portal.account_id,
            self.target_account.pk,
        )

        self.assertEqual(
            renewal.account_id,
            self.target_account.pk,
        )

        self.assertEqual(
            self.source_account.status,
            CustomerAccount.Status.DELETED,
        )

    def test_merge_rejects_two_open_account_renewals_atomically(
        self,
    ):
        from customers.services import (
            CustomerAccountOperationError,
            merge_customer_accounts,
        )
        from portal.models import (
            ClientRenewalRequest,
        )

        source_request = (
            ClientRenewalRequest.objects.create(
                client=self.vpn_client,
                account=self.source_account,
                status=(
                    ClientRenewalRequest.Status.NEW
                ),
            )
        )

        target_request = (
            ClientRenewalRequest.objects.create(
                client=None,
                account=self.target_account,
                status=(
                    ClientRenewalRequest.Status.IN_PROGRESS
                ),
            )
        )

        with self.assertRaises(
            CustomerAccountOperationError
        ):
            merge_customer_accounts(
                source_account_id=(
                    self.source_account.pk
                ),
                target_account_id=(
                    self.target_account.pk
                ),
            )

        self.device.refresh_from_db()
        self.source_account.refresh_from_db()
        source_request.refresh_from_db()
        target_request.refresh_from_db()

        self.assertEqual(
            self.device.account_id,
            self.source_account.pk,
        )

        self.assertEqual(
            self.source_account.status,
            CustomerAccount.Status.ACTIVE,
        )

        self.assertEqual(
            source_request.account_id,
            self.source_account.pk,
        )

        self.assertEqual(
            target_request.account_id,
            self.target_account.pk,
        )


class CustomerAccountServiceGuardTest(TestCase):
    def setUp(self):
        User = get_user_model()

        self.operator = User.objects.create_user(
            username="guard-operator",
            password="test-password",
        )

        self.source = CustomerAccount.objects.create(
            display_name="Source",
        )

        self.target = CustomerAccount.objects.create(
            display_name="Target",
        )

        self.device = ClientDevice.objects.create(
            account=self.source,
            name="Source Device",
        )

    def test_cannot_merge_account_into_itself(self):
        from customers.services import (
            CustomerAccountOperationError,
            merge_customer_accounts,
        )

        with self.assertRaises(CustomerAccountOperationError):
            merge_customer_accounts(
                source_account_id=self.source.pk,
                target_account_id=self.source.pk,
            )

        self.device.refresh_from_db()
        self.source.refresh_from_db()

        self.assertEqual(self.device.account_id, self.source.pk)
        self.assertEqual(
            self.source.status,
            CustomerAccount.Status.ACTIVE,
        )

    def test_cannot_merge_into_deleted_account(self):
        from customers.services import (
            CustomerAccountOperationError,
            merge_customer_accounts,
        )

        self.target.status = CustomerAccount.Status.DELETED
        self.target.save(update_fields=["status"])

        with self.assertRaises(CustomerAccountOperationError):
            merge_customer_accounts(
                source_account_id=self.source.pk,
                target_account_id=self.target.pk,
            )

        self.device.refresh_from_db()
        self.source.refresh_from_db()

        self.assertEqual(self.device.account_id, self.source.pk)
        self.assertEqual(
            self.source.status,
            CustomerAccount.Status.ACTIVE,
        )

    def test_cannot_merge_source_with_attached_user(self):
        from customers.services import (
            CustomerAccountOperationError,
            merge_customer_accounts,
        )

        self.source.user = self.operator
        self.source.save(update_fields=["user"])

        with self.assertRaises(CustomerAccountOperationError):
            merge_customer_accounts(
                source_account_id=self.source.pk,
                target_account_id=self.target.pk,
            )

        self.device.refresh_from_db()
        self.source.refresh_from_db()

        self.assertEqual(self.device.account_id, self.source.pk)
        self.assertEqual(self.source.user_id, self.operator.pk)
        self.assertEqual(
            self.source.status,
            CustomerAccount.Status.ACTIVE,
        )

    def test_cannot_merge_deleted_source_account(
        self,
    ):
        from customers.services import (
            CustomerAccountOperationError,
            merge_customer_accounts,
        )

        self.source.status = (
            CustomerAccount.Status.DELETED
        )

        self.source.save(
            update_fields=["status"]
        )

        with self.assertRaises(
            CustomerAccountOperationError
        ):
            merge_customer_accounts(
                source_account_id=self.source.pk,
                target_account_id=self.target.pk,
            )

        self.device.refresh_from_db()
        self.source.refresh_from_db()

        self.assertEqual(
            self.device.account_id,
            self.source.pk,
        )

        self.assertEqual(
            self.source.status,
            CustomerAccount.Status.DELETED,
        )

    def test_cannot_move_device_into_deleted_account(self):
        from customers.services import (
            CustomerAccountOperationError,
            move_device_to_account,
        )

        self.target.status = CustomerAccount.Status.DELETED
        self.target.save(update_fields=["status"])

        with self.assertRaises(CustomerAccountOperationError):
            move_device_to_account(
                device_id=self.device.pk,
                target_account_id=self.target.pk,
            )

        self.device.refresh_from_db()

        self.assertEqual(
            self.device.account_id,
            self.source.pk,
        )


    def test_move_device_to_same_account_is_noop(self):
        from customers.services import move_device_to_account

        before_updated_at = self.device.updated_at

        result = move_device_to_account(
            device_id=self.device.pk,
            target_account_id=self.source.pk,
        )

        self.device.refresh_from_db()

        self.assertEqual(result.pk, self.device.pk)
        self.assertEqual(
            self.device.account_id,
            self.source.pk,
        )
        self.assertEqual(
            self.device.updated_at,
            before_updated_at,
        )


class CustomerAccountOperationHTTPTest(TestCase):
    def setUp(self):
        User = get_user_model()

        self.operator = User.objects.create_user(
            username="http-operator",
            password="test-password",
        )

        self.source = CustomerAccount.objects.create(
            display_name="HTTP Source",
        )

        self.target = CustomerAccount.objects.create(
            display_name="HTTP Target",
        )

        self.device = ClientDevice.objects.create(
            account=self.source,
            name="HTTP Device",
        )

    def _csrf_client(self):
        from django.conf import settings
        from django.middleware.csrf import get_token
        from django.test import Client, RequestFactory

        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)

        request = RequestFactory().get("/")
        token = get_token(request)

        client.cookies[settings.CSRF_COOKIE_NAME] = (
            request.META["CSRF_COOKIE"]
        )

        return client, token

    def test_non_owner_cannot_run_customer_operations(self):
        User = get_user_model()

        customer_user = User.objects.create_user(
            username="http-customer-user",
            password="test-password",
            is_owner=False,
        )

        self.client.force_login(customer_user)

        move_response = self.client.post(
            reverse(
                "customers-device-move",
                args=[self.device.pk],
            ),
            {
                "target_account_id": self.target.pk,
            },
        )

        merge_response = self.client.post(
            reverse(
                "customers-merge",
                args=[self.source.pk],
            ),
            {
                "target_account_id": self.target.pk,
            },
        )

        self.assertEqual(move_response.status_code, 403)
        self.assertEqual(merge_response.status_code, 403)

        self.device.refresh_from_db()
        self.source.refresh_from_db()

        self.assertEqual(
            self.device.account_id,
            self.source.pk,
        )

        self.assertEqual(
            self.source.status,
            CustomerAccount.Status.ACTIVE,
        )

    def test_anonymous_post_requires_login(self):
        move_response = self.client.post(
            reverse(
                "customers-device-move",
                args=[self.device.pk],
            ),
            {
                "target_account_id": self.target.pk,
            },
        )

        merge_response = self.client.post(
            reverse(
                "customers-merge",
                args=[self.source.pk],
            ),
            {
                "target_account_id": self.target.pk,
            },
        )

        self.assertEqual(move_response.status_code, 302)
        self.assertIn("/login/", move_response.url)

        self.assertEqual(merge_response.status_code, 302)
        self.assertIn("/login/", merge_response.url)

    def test_authenticated_get_is_not_allowed(self):
        self.client.force_login(self.operator)

        move_response = self.client.get(
            reverse(
                "customers-device-move",
                args=[self.device.pk],
            )
        )

        merge_response = self.client.get(
            reverse(
                "customers-merge",
                args=[self.source.pk],
            )
        )

        self.assertEqual(move_response.status_code, 405)
        self.assertEqual(merge_response.status_code, 405)

    def test_move_requires_csrf_token(self):
        from django.test import Client

        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)

        response = client.post(
            reverse(
                "customers-device-move",
                args=[self.device.pk],
            ),
            {
                "target_account_id": self.target.pk,
            },
        )

        self.assertEqual(response.status_code, 403)

        self.device.refresh_from_db()
        self.assertEqual(
            self.device.account_id,
            self.source.pk,
        )

    def test_merge_requires_csrf_token(self):
        from django.test import Client

        client = Client(enforce_csrf_checks=True)
        client.force_login(self.operator)

        response = client.post(
            reverse(
                "customers-merge",
                args=[self.source.pk],
            ),
            {
                "target_account_id": self.target.pk,
            },
        )

        self.assertEqual(response.status_code, 403)

        self.device.refresh_from_db()
        self.source.refresh_from_db()

        self.assertEqual(
            self.device.account_id,
            self.source.pk,
        )
        self.assertEqual(
            self.source.status,
            CustomerAccount.Status.ACTIVE,
        )

    def test_invalid_target_id_returns_400(self):
        self.client.force_login(self.operator)

        move_response = self.client.post(
            reverse(
                "customers-device-move",
                args=[self.device.pk],
            ),
            {
                "target_account_id": "not-an-id",
            },
        )

        merge_response = self.client.post(
            reverse(
                "customers-merge",
                args=[self.source.pk],
            ),
            {
                "target_account_id": "",
            },
        )

        self.assertEqual(move_response.status_code, 400)
        self.assertEqual(merge_response.status_code, 400)

    def test_missing_target_returns_404(self):
        self.client.force_login(self.operator)

        move_response = self.client.post(
            reverse(
                "customers-device-move",
                args=[self.device.pk],
            ),
            {
                "target_account_id": 999999,
            },
        )

        merge_response = self.client.post(
            reverse(
                "customers-merge",
                args=[self.source.pk],
            ),
            {
                "target_account_id": 999999,
            },
        )

        self.assertEqual(move_response.status_code, 404)
        self.assertEqual(merge_response.status_code, 404)

    def test_move_with_valid_csrf_succeeds(self):
        client, token = self._csrf_client()

        response = client.post(
            reverse(
                "customers-device-move",
                args=[self.device.pk],
            ),
            {
                "target_account_id": self.target.pk,
            },
            HTTP_X_CSRFTOKEN=token,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            reverse(
                "customers-detail",
                args=[self.target.pk],
            ),
        )

        self.device.refresh_from_db()

        self.assertEqual(
            self.device.account_id,
            self.target.pk,
        )

    def test_merge_with_valid_csrf_succeeds(self):
        client, token = self._csrf_client()

        response = client.post(
            reverse(
                "customers-merge",
                args=[self.source.pk],
            ),
            {
                "target_account_id": self.target.pk,
            },
            HTTP_X_CSRFTOKEN=token,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.url,
            reverse(
                "customers-detail",
                args=[self.target.pk],
            ),
        )

        self.device.refresh_from_db()
        self.source.refresh_from_db()

        self.assertEqual(
            self.device.account_id,
            self.target.pk,
        )
        self.assertEqual(
            self.source.status,
            CustomerAccount.Status.DELETED,
        )


class CustomerAccountOperatorUITest(TestCase):
    def setUp(self):
        User = get_user_model()

        self.operator = User.objects.create_user(
            username="ui-operator",
            password="test-password",
        )

        self.source = CustomerAccount.objects.create(
            display_name="UI Source",
            email="source@example.com",
        )

        self.target = CustomerAccount.objects.create(
            display_name="UI Target",
            email="target@example.com",
        )

        self.deleted_target = CustomerAccount.objects.create(
            display_name="UI Deleted Target",
            status=CustomerAccount.Status.DELETED,
        )

        self.device = ClientDevice.objects.create(
            account=self.source,
            name="UI iPhone",
            platform=ClientDevice.Platform.IOS,
        )

    def test_detail_renders_move_and_merge_controls(self):
        self.client.force_login(self.operator)

        response = self.client.get(
            reverse(
                "customers-detail",
                args=[self.source.pk],
            )
        )

        self.assertEqual(response.status_code, 200)

        self.assertContains(
            response,
            reverse(
                "customers-device-move",
                args=[self.device.pk],
            ),
        )

        self.assertContains(
            response,
            reverse(
                "customers-merge",
                args=[self.source.pk],
            ),
        )

        self.assertContains(
            response,
            "UI Target",
        )

        self.assertContains(
            response,
            "Перенести",
        )

        self.assertContains(
            response,
            "Объединить аккаунты",
        )

    def test_deleted_accounts_are_not_operation_targets(self):
        self.client.force_login(self.operator)

        response = self.client.get(
            reverse(
                "customers-detail",
                args=[self.source.pk],
            )
        )

        candidate_ids = list(
            response.context["candidate_accounts"]
            .values_list("pk", flat=True)
        )

        self.assertIn(
            self.target.pk,
            candidate_ids,
        )

        self.assertNotIn(
            self.source.pk,
            candidate_ids,
        )

        self.assertNotIn(
            self.deleted_target.pk,
            candidate_ids,
        )

    def test_deleted_source_has_no_operation_forms(self):
        self.source.status = CustomerAccount.Status.DELETED
        self.source.save(update_fields=["status"])

        self.client.force_login(self.operator)

        response = self.client.get(
            reverse(
                "customers-detail",
                args=[self.source.pk],
            )
        )

        self.assertEqual(response.status_code, 200)

        self.assertNotContains(
            response,
            reverse(
                "customers-device-move",
                args=[self.device.pk],
            ),
        )

        self.assertNotContains(
            response,
            reverse(
                "customers-merge",
                args=[self.source.pk],
            ),
        )

        self.assertContains(
            response,
            "Операции управления для него отключены",
        )

    def test_account_with_login_does_not_offer_merge(self):
        User = get_user_model()

        customer_user = User.objects.create_user(
            username="ui-customer-login",
            password="test-password",
            is_owner=False,
        )

        self.source.user = customer_user
        self.source.save(update_fields=["user"])

        self.client.force_login(self.operator)

        response = self.client.get(
            reverse(
                "customers-detail",
                args=[self.source.pk],
            )
        )

        self.assertEqual(response.status_code, 200)

        self.assertContains(
            response,
            "Автоматическое объединение запрещено",
        )

        self.assertNotContains(
            response,
            'action="'
            + reverse(
                "customers-merge",
                args=[self.source.pk],
            )
            + '"',
        )


class CustomerAccountCreationUITest(TestCase):
    def setUp(self):
        User = get_user_model()

        self.operator = User.objects.create_user(
            username="phase3-account-operator",
            password="test-password",
        )

    def test_account_create_page_requires_operator(self):
        User = get_user_model()

        customer_user = User.objects.create_user(
            username="phase3-non-owner",
            password="test-password",
            is_owner=False,
        )

        self.client.force_login(customer_user)

        response = self.client.get(
            reverse("customers-create")
        )

        self.assertEqual(response.status_code, 403)

    def test_operator_can_create_customer_account(self):
        self.client.force_login(self.operator)

        before = CustomerAccount.objects.count()

        response = self.client.post(
            reverse("customers-create"),
            {
                "display_name": "New Customer",
                "email": "new@example.com",
                "expires_at": "",
            },
        )

        self.assertEqual(response.status_code, 302)

        self.assertEqual(
            CustomerAccount.objects.count(),
            before + 1,
        )

        account = CustomerAccount.objects.get(
            display_name="New Customer"
        )

        self.assertEqual(
            account.email,
            "new@example.com",
        )

        self.assertEqual(
            account.status,
            CustomerAccount.Status.ACTIVE,
        )

        self.assertEqual(
            account.created_by_id,
            self.operator.pk,
        )

        self.assertEqual(
            response.url,
            reverse(
                "customers-detail",
                args=[account.pk],
            ),
        )

        self.assertEqual(
            account.devices.count(),
            0,
        )


class CustomerDeviceCreationUITest(TestCase):
    def setUp(self):
        User = get_user_model()

        self.operator = User.objects.create_user(
            username="phase3-device-operator",
            password="test-password",
        )

        self.account = CustomerAccount.objects.create(
            display_name="Device Customer",
            created_by=self.operator,
        )

    def test_device_create_page_is_rendered(self):
        self.client.force_login(self.operator)

        response = self.client.get(
            reverse(
                "customers-device-create",
                args=[self.account.pk],
            )
        )

        self.assertEqual(response.status_code, 200)

        self.assertTemplateUsed(
            response,
            "customers/device_form.html",
        )

        self.assertContains(
            response,
            "Device Customer",
        )

        self.assertContains(
            response,
            "Добавить устройство",
        )

    def test_operator_can_add_device(self):
        self.client.force_login(self.operator)

        response = self.client.post(
            reverse(
                "customers-device-create",
                args=[self.account.pk],
            ),
            {
                "name": "iPhone 15 Pro",
                "platform": ClientDevice.Platform.IOS,
                "notes": "Основной телефон",
            },
        )

        self.assertEqual(response.status_code, 302)

        device = ClientDevice.objects.get(
            account=self.account,
            name="iPhone 15 Pro",
        )

        self.assertEqual(
            device.platform,
            ClientDevice.Platform.IOS,
        )

        self.assertEqual(
            device.status,
            ClientDevice.Status.ACTIVE,
        )

        self.assertEqual(
            device.notes,
            "Основной телефон",
        )

        self.assertEqual(
            response.url,
            reverse(
                "customers-detail",
                args=[self.account.pk],
            ),
        )

    def test_cannot_add_device_to_deleted_account(self):
        self.account.status = CustomerAccount.Status.DELETED
        self.account.save(
            update_fields=["status"]
        )

        self.client.force_login(self.operator)

        before = ClientDevice.objects.count()

        response = self.client.post(
            reverse(
                "customers-device-create",
                args=[self.account.pk],
            ),
            {
                "name": "Forbidden Device",
                "platform": ClientDevice.Platform.IOS,
                "notes": "",
            },
        )

        self.assertEqual(response.status_code, 403)

        self.assertEqual(
            ClientDevice.objects.count(),
            before,
        )

    def test_account_and_device_creation_do_not_create_vpn_clients(self):
        from vpn.models import VPNClient

        self.client.force_login(self.operator)

        vpn_before = VPNClient.objects.count()

        response = self.client.post(
            reverse(
                "customers-device-create",
                args=[self.account.pk],
            ),
            {
                "name": "MacBook Pro",
                "platform": ClientDevice.Platform.MACOS,
                "notes": "",
            },
        )

        self.assertEqual(response.status_code, 302)

        self.assertEqual(
            VPNClient.objects.count(),
            vpn_before,
        )


class CustomerDeviceVPNCreationTest(TestCase):
    def setUp(self):
        from datetime import timedelta

        from servers.models import (
            ProtocolProfile,
            Server,
            ServerProtocol,
        )

        User = get_user_model()

        self.operator = User.objects.create_user(
            username="phase3-vpn-operator",
            password="test-password",
        )

        from django.utils import timezone

        self.account = CustomerAccount.objects.create(
            display_name="VPN Customer",
            email="vpn@example.com",
            expires_at=timezone.now() + timedelta(days=30),
            created_by=self.operator,
        )

        self.device = ClientDevice.objects.create(
            account=self.account,
            name="iPhone 15 Pro",
            platform=ClientDevice.Platform.IOS,
        )

        self.server = Server.objects.create(
            name="Phase 3 VPN Server",
            is_enabled=True,
        )

        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
        )

        self.full_profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="FULL",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template=(
                "# routing-mode: full\n"
                "0.0.0.0/0"
            ),
        )

        self.selective_profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="SELECTIVE",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template=(
                "# routing-mode: selective\n"
                "8.8.8.8/32"
            ),
        )

    def test_connection_page_defaults_to_full_product(self):
        self.client.force_login(self.operator)

        response = self.client.get(
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            )
        )

        self.assertEqual(response.status_code, 200)

        self.assertTemplateUsed(
            response,
            "customers/vpn_connection_form.html",
        )

        self.assertContains(
            response,
            "Весь интернет через VPN",
        )

        self.assertContains(
            response,
            'name="routing_mode"',
        )

        self.assertContains(
            response,
            'value="full"',
        )

        self.assertNotContains(
            response,
            "Только выбранные сервисы",
        )

        self.assertContains(
            response,
            "VPN Customer",
        )

        self.assertContains(
            response,
            "iPhone 15 Pro",
        )

        self.assertContains(
            response,
            reverse(
                "customers-device-connection-create",
                args=[self.device.pk],
            ),
        )

    def test_non_owner_cannot_create_device_vpn(self):
        User = get_user_model()

        customer_user = User.objects.create_user(
            username="phase3-vpn-customer",
            password="test-password",
            is_owner=False,
        )

        self.client.force_login(customer_user)

        response = self.client.get(
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            )
        )

        self.assertEqual(response.status_code, 403)

    def test_inactive_device_cannot_get_new_vpn(self):
        self.device.status = ClientDevice.Status.DISABLED
        self.device.save(update_fields=["status"])

        self.client.force_login(self.operator)

        response = self.client.post(
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            ),
            {
                "routing_mode": "full",
            },
        )

        self.assertEqual(response.status_code, 403)

    def test_expired_account_cannot_get_new_vpn(self):
        from datetime import timedelta
        from django.utils import timezone

        self.account.expires_at = (
            timezone.now() - timedelta(minutes=1)
        )
        self.account.save(update_fields=["expires_at"])

        self.client.force_login(self.operator)

        response = self.client.post(
            reverse(
                "customers-device-vpn-create",
                args=[self.device.pk],
            ),
            {
                "routing_mode": "full",
            },
        )

        self.assertEqual(response.status_code, 403)

    def test_vpn_service_associates_client_with_device(self):
        from unittest.mock import patch

        from vpn.models import VPNClient
        from vpn.services import VPNClientService

        with patch.object(
            VPNClientService,
            "reissue_config",
        ) as reissue:
            client = VPNClientService.create_client(
                server=self.server,
                name="Service-Device-FULL",
                protocol_type=VPNClient.ProtocolType.AWG2,
                routing_mode="full",
                actor=self.operator,
                expires_at=self.account.expires_at,
                contact_email=self.account.email,
                device=self.device,
            )

        self.assertEqual(
            client.device_id,
            self.device.pk,
        )

        self.assertEqual(
            client.profile_id,
            self.full_profile.pk,
        )

        self.assertEqual(
            client.contact_email,
            self.account.email,
        )

        reissue.assert_called_once()

    def test_vpn_service_rejects_inactive_device(self):
        from unittest.mock import patch

        from vpn.models import VPNClient
        from vpn.services import VPNClientService

        self.device.status = ClientDevice.Status.DISABLED
        self.device.save(update_fields=["status"])

        with patch.object(
            VPNClientService,
            "reissue_config",
        ):
            with self.assertRaises(ValueError):
                VPNClientService.create_client(
                    server=self.server,
                    name="Should-Not-Exist",
                    protocol_type=VPNClient.ProtocolType.AWG2,
                    routing_mode="full",
                    actor=self.operator,
                    device=self.device,
                )

        self.assertFalse(
            VPNClient.objects.filter(
                name="Should-Not-Exist",
            ).exists()
        )

    def test_full_creation_passes_device_to_existing_service(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        self.client.force_login(self.operator)

        with patch(
            "customers.views.VPNClientService.create_client"
        ) as create_client:
            create_client.return_value = SimpleNamespace(
                pk=4321,
            )

            response = self.client.post(
                reverse(
                    "customers-device-vpn-create",
                    args=[self.device.pk],
                ),
                {
                    "routing_mode": "full",
                },
            )

        self.assertEqual(response.status_code, 302)

        self.assertEqual(
            response.url,
            reverse(
                "clients-detail",
                args=[4321],
            ),
        )

        kwargs = create_client.call_args.kwargs

        self.assertEqual(
            kwargs["device"].pk,
            self.device.pk,
        )

        self.assertEqual(
            kwargs["routing_mode"],
            "full",
        )

        self.assertEqual(
            kwargs["protocol_type"],
            "awg2",
        )

        self.assertEqual(
            kwargs["expires_at"],
            self.account.expires_at,
        )

        self.assertEqual(
            kwargs["contact_email"],
            self.account.email,
        )

        self.assertTrue(
            kwargs["name"].endswith(
                f"-D{self.device.pk}-FULL"
            )
        )

    def test_selective_creation_uses_selective_mode(self):
        from types import SimpleNamespace
        from unittest.mock import patch

        self.client.force_login(self.operator)

        with patch(
            "customers.views.VPNClientService.create_client"
        ) as create_client:
            create_client.return_value = SimpleNamespace(
                pk=5432,
            )

            response = self.client.post(
                reverse(
                    "customers-device-vpn-create",
                    args=[self.device.pk],
                ),
                {
                    "routing_mode": "selective",
                },
            )

        self.assertEqual(response.status_code, 302)

        kwargs = create_client.call_args.kwargs

        self.assertEqual(
            kwargs["routing_mode"],
            "selective",
        )

        self.assertTrue(
            kwargs["name"].endswith(
                f"-D{self.device.pk}-SELECT"
            )
        )

    def test_duplicate_active_routing_mode_is_blocked(self):
        from unittest.mock import patch

        from vpn.models import VPNClient

        VPNClient.objects.create(
            server=self.server,
            name="Existing-FULL",
            contact_email=self.account.email,
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=self.full_profile,
            created_by=self.operator,
            device=self.device,
        )

        self.client.force_login(self.operator)

        with patch(
            "customers.views.VPNClientService.create_client"
        ) as create_client:
            response = self.client.post(
                reverse(
                    "customers-device-vpn-create",
                    args=[self.device.pk],
                ),
                {
                    "routing_mode": "full",
                },
            )

        self.assertEqual(response.status_code, 200)

        self.assertContains(
            response,
            "уже есть активное AWG2-подключение",
        )

        create_client.assert_not_called()


from django.contrib.auth import (
    get_user_model as _phase4_get_user_model,
)
from django.test import (
    TestCase as _Phase4TestCase,
)
from django.urls import (
    reverse as _phase4_reverse,
)


class CustomerXHTTPIntegrationTest(_Phase4TestCase):
    def setUp(self):
        from customers.models import (
            ClientDevice,
            CustomerAccount,
        )
        from servers.models import Server
        from vpn.models import XHTTPDevice

        User = _phase4_get_user_model()

        self.operator = User.objects.create_user(
            username="phase4-customer-operator",
            password="test-password",
        )

        self.source = CustomerAccount.objects.create(
            display_name="Phase 4 Customer",
            email="phase4@example.com",
            created_by=self.operator,
        )

        self.device = ClientDevice.objects.create(
            account=self.source,
            name="Phase 4 iPhone",
            platform=ClientDevice.Platform.IOS,
        )

        self.server = Server.objects.create(
            name="Phase 4 XHTTP Server",
            host="203.0.113.50",
            ssh_username="amnezia",
            is_enabled=True,
        )

        self.xhttp = XHTTPDevice.objects.create(
            device=self.device,
            server=self.server,
            name="Device CDN",
            xray_email=(
                "xhttp-"
                "11111111111111111111111111111111"
            ),
            config_blob_encrypted="encrypted-test-config",
            config_hash="0" * 64,
        )

    def test_customer_detail_renders_device_xhttp(self):
        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            _phase4_reverse(
                "customers-detail",
                args=[self.source.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Альтернативное подключение",
        )

        self.assertContains(
            response,
            "Device CDN",
        )

        self.assertContains(
            response,
            _phase4_reverse(
                "xhttp-device-download",
                args=[self.xhttp.pk],
            ),
        )

        self.assertContains(
            response,
            _phase4_reverse(
                "customers-device-connection-create",
                args=[self.device.pk],
            ),
        )

        self.assertContains(
            response,
            "+ Подключение",
        )

        self.assertNotContains(
            response,
            _phase4_reverse(
                "customers-device-xhttp-create",
                args=[self.device.pk],
            ),
        )

        self.assertNotContains(
            response,
            (
                _phase4_reverse(
                    "xhttp-devices"
                )
                + f"?device={self.device.pk}"
            ),
        )

    def test_deleted_xhttp_is_hidden_from_customer_detail(self):
        from vpn.models import XHTTPDevice

        self.xhttp.status = (
            XHTTPDevice.Status.DELETED
        )

        self.xhttp.save(
            update_fields=["status"]
        )

        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            _phase4_reverse(
                "customers-detail",
                args=[self.source.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertNotContains(
            response,
            "Device CDN",
        )

    def test_move_device_preserves_xhttp_connection(self):
        from customers.models import CustomerAccount
        from customers.services import (
            move_device_to_account,
        )

        target = CustomerAccount.objects.create(
            display_name="Phase 4 Move Target",
        )

        original_xhttp_id = self.xhttp.pk
        original_device_id = self.xhttp.device_id
        original_server_id = self.xhttp.server_id
        original_uuid = self.xhttp.client_uuid

        move_device_to_account(
            device_id=self.device.pk,
            target_account_id=target.pk,
        )

        self.device.refresh_from_db()
        self.xhttp.refresh_from_db()

        self.assertEqual(
            self.device.account_id,
            target.pk,
        )

        self.assertEqual(
            self.xhttp.pk,
            original_xhttp_id,
        )

        self.assertEqual(
            self.xhttp.device_id,
            original_device_id,
        )

        self.assertEqual(
            self.xhttp.server_id,
            original_server_id,
        )

        self.assertEqual(
            self.xhttp.client_uuid,
            original_uuid,
        )

        self.assertEqual(
            self.xhttp.device.account_id,
            target.pk,
        )

    def test_merge_accounts_preserves_xhttp_connection(self):
        from customers.models import CustomerAccount
        from customers.services import (
            merge_customer_accounts,
        )

        target = CustomerAccount.objects.create(
            display_name="Phase 4 Merge Target",
        )

        original_device_id = self.xhttp.device_id
        original_server_id = self.xhttp.server_id
        original_uuid = self.xhttp.client_uuid

        moved = merge_customer_accounts(
            source_account_id=self.source.pk,
            target_account_id=target.pk,
        )

        self.assertEqual(
            moved,
            1,
        )

        self.device.refresh_from_db()
        self.xhttp.refresh_from_db()
        self.source.refresh_from_db()

        self.assertEqual(
            self.device.account_id,
            target.pk,
        )

        self.assertEqual(
            self.xhttp.device_id,
            original_device_id,
        )

        self.assertEqual(
            self.xhttp.server_id,
            original_server_id,
        )

        self.assertEqual(
            self.xhttp.client_uuid,
            original_uuid,
        )

        self.assertEqual(
            self.xhttp.device.account_id,
            target.pk,
        )

        self.assertEqual(
            self.source.status,
            CustomerAccount.Status.DELETED,
        )
