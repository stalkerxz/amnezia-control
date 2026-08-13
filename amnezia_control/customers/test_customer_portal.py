from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .access_services import (
    CustomerAccessError,
    create_customer_login,
)
from .models import ClientDevice, CustomerAccount


User = get_user_model()


class CustomerAccessCreationTest(TestCase):
    def setUp(self):
        self.operator = User.objects.create_user(
            username="phase5-operator",
            password="operator-password",
            is_owner=True,
            is_staff=True,
        )

        self.account = CustomerAccount.objects.create(
            display_name="Phase 5 Customer",
            email="phase5@example.com",
            created_by=self.operator,
        )

    def test_service_creates_non_operator_user(self):
        user = create_customer_login(
            account_id=self.account.pk,
            username="phase5-customer",
            password="Strong-Test-Pass-481!",
            actor=self.operator,
        )

        self.account.refresh_from_db()

        self.assertEqual(
            self.account.user_id,
            user.pk,
        )

        self.assertFalse(user.is_owner)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)
        self.assertTrue(user.is_active)

        self.assertTrue(
            user.check_password(
                "Strong-Test-Pass-481!"
            )
        )

    def test_operator_can_create_login_through_ui(self):
        self.client.force_login(
            self.operator
        )

        response = self.client.post(
            reverse(
                "customers-access-create",
                args=[self.account.pk],
            ),
            {
                "username": "customer-ui",
                "password1": "Strong-Ui-Pass-481!",
                "password2": "Strong-Ui-Pass-481!",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.account.refresh_from_db()

        self.assertIsNotNone(
            self.account.user_id
        )

        self.assertFalse(
            self.account.user.is_owner
        )

    def test_deleted_account_cannot_receive_login(self):
        self.account.status = (
            CustomerAccount.Status.DELETED
        )

        self.account.save(
            update_fields=["status"]
        )

        with self.assertRaises(
            CustomerAccessError
        ):
            create_customer_login(
                account_id=self.account.pk,
                username="deleted-customer",
                password="Strong-Deleted-481!",
                actor=self.operator,
            )

    def test_second_login_is_rejected(self):
        create_customer_login(
            account_id=self.account.pk,
            username="first-customer",
            password="Strong-First-481!",
            actor=self.operator,
        )

        with self.assertRaises(
            CustomerAccessError
        ):
            create_customer_login(
                account_id=self.account.pk,
                username="second-customer",
                password="Strong-Second-481!",
                actor=self.operator,
            )


class CustomerPortalAccessTest(TestCase):
    def setUp(self):
        self.operator = User.objects.create_user(
            username="phase5-staff",
            password="operator-password",
            is_owner=True,
            is_staff=True,
        )

        self.customer_user = User.objects.create_user(
            username="phase5-client",
            password="client-password",
            is_owner=False,
            is_staff=False,
            is_superuser=False,
        )

        self.account = CustomerAccount.objects.create(
            display_name="My VPN Account",
            email="client@example.com",
            user=self.customer_user,
        )

        self.device = ClientDevice.objects.create(
            account=self.account,
            name="My iPhone",
            platform=ClientDevice.Platform.IOS,
        )

        other_user = User.objects.create_user(
            username="other-client",
            password="other-password",
            is_owner=False,
        )

        other_account = CustomerAccount.objects.create(
            display_name="Other Secret Account",
            user=other_user,
        )

        ClientDevice.objects.create(
            account=other_account,
            name="Other Secret Device",
        )

    def test_anonymous_dashboard_redirects_to_customer_login(self):
        response = self.client.get(
            reverse(
                "customer-portal-home"
            )
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.assertTrue(
            response.url.startswith(
                "/cabinet/login/"
            )
        )

    def test_operator_cannot_use_customer_dashboard(self):
        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            reverse(
                "customer-portal-home"
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_operator_credentials_rejected_by_customer_login(self):
        response = self.client.post(
            reverse(
                "customer-portal-login"
            ),
            {
                "username": self.operator.username,
                "password": "operator-password",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertFalse(
            response.wsgi_request.user.is_authenticated
        )

        self.assertContains(
            response,
            "не имеет доступа",
        )

    def test_customer_can_login_and_only_see_own_account(self):
        response = self.client.post(
            reverse(
                "customer-portal-login"
            ),
            {
                "username": self.customer_user.username,
                "password": "client-password",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.assertEqual(
            response.url,
            reverse(
                "customer-portal-home"
            ),
        )

        response = self.client.get(
            reverse(
                "customer-portal-home"
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "My VPN Account",
        )

        self.assertContains(
            response,
            "My iPhone",
        )

        self.assertNotContains(
            response,
            "Other Secret Account",
        )

        self.assertNotContains(
            response,
            "Other Secret Device",
        )


class CustomerPortalDownloadTest(TestCase):
    def setUp(self):
        import hashlib

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
        from vpn.services import (
            ConfigCryptoService,
        )

        self.customer_user = User.objects.create_user(
            username="phase5b-customer",
            password="phase5b-password",
            is_owner=False,
            is_staff=False,
            is_superuser=False,
        )

        self.account = CustomerAccount.objects.create(
            display_name="Phase 5B Customer",
            email="phase5b@example.com",
            user=self.customer_user,
        )

        self.device = ClientDevice.objects.create(
            account=self.account,
            name="Phase 5B iPhone",
            platform=ClientDevice.Platform.IOS,
        )

        self.server = Server.objects.create(
            name="Phase 5B Server",
        )

        self.server_protocol = (
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
                server_protocol=self.server_protocol,
                name="FULL",
                protocol_type=(
                    ServerProtocol.ProtocolType.AWG2
                ),
                config_template="test-template",
            )
        )

        self.vpn = VPNClient.objects.create(
            server=self.server,
            name="Phase5B-AWG2-FULL",
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            status=VPNClient.Status.ACTIVE,
            profile=self.profile,
            device=self.device,
            runtime_peer_public_key=(
                "PHASE5B-PUBLIC-KEY"
            ),
            runtime_address="10.8.55.10",
        )

        self.vpn_plaintext = """[Interface]
PrivateKey = PHASE5B-PRIVATE-KEY
Address = 10.8.55.10/32
DNS = 1.1.1.1

[Peer]
PublicKey = PHASE5B-SERVER-PUBLIC-KEY
Endpoint = 198.51.100.50:51830
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
"""

        self.revision = (
            ClientConfigRevision.objects.create(
                client=self.vpn,
                revision_number=1,
                protocol_type=(
                    VPNClient.ProtocolType.AWG2
                ),
                config_blob_encrypted=(
                    ConfigCryptoService.encrypt(
                        self.vpn_plaintext
                    )
                ),
                config_hash=hashlib.sha256(
                    self.vpn_plaintext.encode()
                ).hexdigest(),
            )
        )

        self.xhttp_plaintext = (
            '{"remarks":"phase5b-existing-xhttp"}\n'
        )

        self.xhttp = XHTTPDevice.objects.create(
            client=None,
            device=self.device,
            server=self.server,
            name="Phase 5B CDN",
            xray_email=(
                "xhttp-"
                "55555555555555555555555555555555"
            ),
            status=XHTTPDevice.Status.ACTIVE,
            config_blob_encrypted=(
                ConfigCryptoService.encrypt(
                    self.xhttp_plaintext
                )
            ),
            config_hash=hashlib.sha256(
                self.xhttp_plaintext.encode()
            ).hexdigest(),
        )

        self.operator = User.objects.create_user(
            username="phase5b-operator",
            password="operator-password",
            is_owner=True,
            is_staff=True,
        )

        self.other_user = User.objects.create_user(
            username="phase5b-other",
            password="other-password",
            is_owner=False,
            is_staff=False,
        )

        self.other_account = (
            CustomerAccount.objects.create(
                display_name="Other Customer",
                user=self.other_user,
            )
        )

        self.other_device = (
            ClientDevice.objects.create(
                account=self.other_account,
                name="Other Device",
            )
        )

        self.other_vpn = VPNClient.objects.create(
            server=self.server,
            name="Other-AWG2-FULL",
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            status=VPNClient.Status.ACTIVE,
            profile=self.profile,
            device=self.other_device,
            runtime_peer_public_key=(
                "OTHER-PUBLIC-KEY"
            ),
            runtime_address="10.8.55.11",
        )

        ClientConfigRevision.objects.create(
            client=self.other_vpn,
            revision_number=1,
            protocol_type=(
                VPNClient.ProtocolType.AWG2
            ),
            config_blob_encrypted=(
                ConfigCryptoService.encrypt(
                    self.vpn_plaintext
                )
            ),
            config_hash="f" * 64,
        )

        self.other_xhttp = (
            XHTTPDevice.objects.create(
                client=None,
                device=self.other_device,
                server=self.server,
                name="Other CDN",
                xray_email=(
                    "xhttp-"
                    "66666666666666666666666666666666"
                ),
                status=XHTTPDevice.Status.ACTIVE,
                config_blob_encrypted=(
                    ConfigCryptoService.encrypt(
                        self.xhttp_plaintext
                    )
                ),
                config_hash="e" * 64,
            )
        )

    def _login_customer(self):
        self.client.force_login(
            self.customer_user
        )

    def test_home_renders_download_buttons_for_active_connections(
        self,
    ):
        self._login_customer()

        response = self.client.get(
            reverse(
                "customer-portal-home"
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            reverse(
                "customer-portal-vpn-download",
                args=[self.vpn.pk],
            ),
        )

        self.assertContains(
            response,
            reverse(
                "customer-portal-vpn-qr",
                args=[self.vpn.pk],
            ),
        )

        self.assertContains(
            response,
            reverse(
                "customer-portal-xhttp-download",
                args=[self.xhttp.pk],
            ),
        )

    def test_home_hides_download_buttons_when_account_blocked(
        self,
    ):
        self.account.status = (
            CustomerAccount.Status.DISABLED
        )
        self.account.save(
            update_fields=["status"]
        )

        self._login_customer()

        response = self.client.get(
            reverse(
                "customer-portal-home"
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertNotContains(
            response,
            reverse(
                "customer-portal-vpn-download",
                args=[self.vpn.pk],
            ),
        )

        self.assertNotContains(
            response,
            reverse(
                "customer-portal-xhttp-download",
                args=[self.xhttp.pk],
            ),
        )

    def test_vpn_download_uses_existing_revision_without_reissue(
        self,
    ):
        from vpn.models import (
            ClientConfigRevision,
            VPNClient,
        )

        self._login_customer()

        before_client = (
            VPNClient.objects.values(
                "runtime_peer_public_key",
                "runtime_address",
                "last_runtime_sync_at",
            ).get(
                pk=self.vpn.pk
            )
        )

        before_revision = (
            ClientConfigRevision.objects.values(
                "revision_number",
                "config_blob_encrypted",
                "config_hash",
            ).get(
                pk=self.revision.pk
            )
        )

        before_revision_count = (
            self.vpn.revisions.count()
        )

        response = self.client.get(
            reverse(
                "customer-portal-vpn-download",
                args=[self.vpn.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertIn(
            "attachment;",
            response["Content-Disposition"],
        )

        self.assertEqual(
            response["Cache-Control"],
            "no-store, max-age=0",
        )

        body = response.content.decode()

        self.assertIn(
            "PHASE5B-PRIVATE-KEY",
            body,
        )

        self.assertIn(
            "10.8.55.10/32",
            body,
        )

        after_client = (
            VPNClient.objects.values(
                *before_client.keys()
            ).get(
                pk=self.vpn.pk
            )
        )

        after_revision = (
            ClientConfigRevision.objects.values(
                *before_revision.keys()
            ).get(
                pk=self.revision.pk
            )
        )

        self.assertEqual(
            before_client,
            after_client,
        )

        self.assertEqual(
            before_revision,
            after_revision,
        )

        self.assertEqual(
            before_revision_count,
            self.vpn.revisions.count(),
        )

    def test_vpn_qr_uses_existing_revision_without_reissue(
        self,
    ):
        self._login_customer()

        before_key = (
            self.vpn.runtime_peer_public_key
        )

        before_revision_count = (
            self.vpn.revisions.count()
        )

        response = self.client.get(
            reverse(
                "customer-portal-vpn-qr",
                args=[self.vpn.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response["Content-Type"],
            "image/png",
        )

        self.assertTrue(
            response.content.startswith(
                b"\x89PNG"
            )
        )

        self.vpn.refresh_from_db()

        self.assertEqual(
            self.vpn.runtime_peer_public_key,
            before_key,
        )

        self.assertEqual(
            self.vpn.revisions.count(),
            before_revision_count,
        )

    def test_xhttp_download_uses_existing_json_without_rotation(
        self,
    ):
        self._login_customer()

        before_uuid = self.xhttp.client_uuid
        before_hash = self.xhttp.config_hash
        before_blob = (
            self.xhttp.config_blob_encrypted
        )

        response = self.client.get(
            reverse(
                "customer-portal-xhttp-download",
                args=[self.xhttp.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response["Content-Type"],
            (
                "application/json; "
                "charset=utf-8"
            ),
        )

        self.assertIn(
            "phase5b-existing-xhttp",
            response.content.decode(),
        )

        self.xhttp.refresh_from_db()

        self.assertEqual(
            self.xhttp.client_uuid,
            before_uuid,
        )

        self.assertEqual(
            self.xhttp.config_hash,
            before_hash,
        )

        self.assertEqual(
            self.xhttp.config_blob_encrypted,
            before_blob,
        )

    def test_foreign_vpn_is_not_visible(
        self,
    ):
        self._login_customer()

        response = self.client.get(
            reverse(
                "customer-portal-vpn-download",
                args=[self.other_vpn.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            404,
        )

    def test_foreign_xhttp_is_not_visible(
        self,
    ):
        self._login_customer()

        response = self.client.get(
            reverse(
                "customer-portal-xhttp-download",
                args=[self.other_xhttp.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            404,
        )

    def test_operator_cannot_download_customer_secrets(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        for url in (
            reverse(
                "customer-portal-vpn-download",
                args=[self.vpn.pk],
            ),
            reverse(
                "customer-portal-vpn-qr",
                args=[self.vpn.pk],
            ),
            reverse(
                "customer-portal-xhttp-download",
                args=[self.xhttp.pk],
            ),
        ):
            with self.subTest(url=url):
                response = self.client.get(
                    url
                )

                self.assertEqual(
                    response.status_code,
                    403,
                )

    def test_blocked_account_cannot_download_secrets(
        self,
    ):
        self.account.status = (
            CustomerAccount.Status.DISABLED
        )

        self.account.save(
            update_fields=["status"]
        )

        self._login_customer()

        for url in (
            reverse(
                "customer-portal-vpn-download",
                args=[self.vpn.pk],
            ),
            reverse(
                "customer-portal-vpn-qr",
                args=[self.vpn.pk],
            ),
            reverse(
                "customer-portal-xhttp-download",
                args=[self.xhttp.pk],
            ),
        ):
            with self.subTest(url=url):
                response = self.client.get(
                    url
                )

                self.assertEqual(
                    response.status_code,
                    403,
                )

    def test_disabled_connections_cannot_download_secrets(
        self,
    ):
        from vpn.models import (
            VPNClient,
            XHTTPDevice,
        )

        self.vpn.status = (
            VPNClient.Status.DISABLED
        )

        self.vpn.save(
            update_fields=["status"]
        )

        self.xhttp.status = (
            XHTTPDevice.Status.DISABLED
        )

        self.xhttp.save(
            update_fields=["status"]
        )

        self._login_customer()

        vpn_response = self.client.get(
            reverse(
                "customer-portal-vpn-download",
                args=[self.vpn.pk],
            )
        )

        xhttp_response = self.client.get(
            reverse(
                "customer-portal-xhttp-download",
                args=[self.xhttp.pk],
            )
        )

        self.assertEqual(
            vpn_response.status_code,
            403,
        )

        self.assertEqual(
            xhttp_response.status_code,
            403,
        )
