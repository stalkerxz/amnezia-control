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
