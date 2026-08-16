import hashlib

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

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

from .access_services import (
    change_customer_password,
    detach_customer_login,
    set_customer_login_enabled,
)
from .models import (
    ClientDevice,
    CustomerAccount,
)


User = get_user_model()


class CustomerAccessManagementTest(TestCase):
    def setUp(self):
        self.operator = User.objects.create_user(
            username="phase5c-operator",
            password="operator-password",
            is_owner=True,
            is_staff=True,
        )

        self.customer_user = User.objects.create_user(
            username="phase5c-customer",
            password="old-customer-password",
            is_owner=False,
            is_staff=False,
            is_superuser=False,
        )

        self.account = CustomerAccount.objects.create(
            display_name="Phase 5C Customer",
            email="phase5c@example.com",
            user=self.customer_user,
            created_by=self.operator,
        )

        self.device = ClientDevice.objects.create(
            account=self.account,
            name="Phase 5C iPhone",
            platform=ClientDevice.Platform.IOS,
        )

        self.server = Server.objects.create(
            name="Phase 5C Server",
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
            config_template="phase5c-template",
        )

        self.vpn = VPNClient.objects.create(
            server=self.server,
            name="Phase5C-FULL",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=self.profile,
            device=self.device,
            runtime_peer_public_key="PHASE5C-PUBKEY",
            runtime_address="10.8.60.10",
        )

        self.revision = (
            ClientConfigRevision.objects.create(
                client=self.vpn,
                revision_number=1,
                protocol_type=VPNClient.ProtocolType.AWG2,
                config_blob_encrypted=(
                    "PHASE5C-ENCRYPTED-AWG2"
                ),
                config_hash=(
                    hashlib.sha256(
                        b"phase5c-awg2"
                    ).hexdigest()
                ),
            )
        )

        self.xhttp = XHTTPDevice.objects.create(
            device=self.device,
            server=self.server,
            name="Phase5C-XHTTP",
            xray_email=(
                "xhttp-"
                "77777777777777777777777777777777"
            ),
            config_blob_encrypted=(
                "PHASE5C-ENCRYPTED-XHTTP"
            ),
            config_hash=(
                hashlib.sha256(
                    b"phase5c-xhttp"
                ).hexdigest()
            ),
        )

    def test_operator_can_open_access_management(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        response = self.client.get(
            reverse(
                "customers-access-manage",
                args=[self.account.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            self.customer_user.username,
        )

        self.assertContains(
            response,
            "Управление доступом",
        )

        for technical_marker in (
            "AWG2",
            "VLESS/XHTTP",
            "UUID",
            "CustomerAccount",
        ):
            self.assertNotContains(
                response,
                technical_marker,
            )

    def test_non_owner_cannot_manage_access(
        self,
    ):
        self.client.force_login(
            self.customer_user
        )

        response = self.client.get(
            reverse(
                "customers-access-manage",
                args=[self.account.pk],
            )
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_password_change_preserves_customer_role(
        self,
    ):
        user = change_customer_password(
            account_id=self.account.pk,
            password="Phase5C-New-Pass-481!",
            actor=self.operator,
        )

        user.refresh_from_db()

        self.assertTrue(
            user.check_password(
                "Phase5C-New-Pass-481!"
            )
        )

        self.assertFalse(
            user.check_password(
                "old-customer-password"
            )
        )

        self.assertFalse(user.is_owner)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_ui_password_change(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        response = self.client.post(
            reverse(
                "customers-access-manage",
                args=[self.account.pk],
            ),
            {
                "action": "password",
                "password1": (
                    "Phase5C-Ui-New-Pass-481!"
                ),
                "password2": (
                    "Phase5C-Ui-New-Pass-481!"
                ),
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.customer_user.refresh_from_db()

        self.assertTrue(
            self.customer_user.check_password(
                "Phase5C-Ui-New-Pass-481!"
            )
        )

    def test_disable_revokes_customer_login(
        self,
    ):
        self.client.force_login(
            self.customer_user
        )

        before = self.client.get(
            reverse(
                "customer-portal-home"
            )
        )

        self.assertEqual(
            before.status_code,
            200,
        )

        set_customer_login_enabled(
            account_id=self.account.pk,
            enabled=False,
            actor=self.operator,
        )

        self.customer_user.refresh_from_db()

        self.assertFalse(
            self.customer_user.is_active
        )

        after = self.client.get(
            reverse(
                "customer-portal-home"
            )
        )

        self.assertNotEqual(
            after.status_code,
            200,
        )

    def test_enable_restores_customer_login(
        self,
    ):
        self.customer_user.is_active = False

        self.customer_user.save(
            update_fields=["is_active"]
        )

        set_customer_login_enabled(
            account_id=self.account.pk,
            enabled=True,
            actor=self.operator,
        )

        self.customer_user.refresh_from_db()

        self.assertTrue(
            self.customer_user.is_active
        )

        response = self.client.post(
            reverse(
                "customer-portal-login"
            ),
            {
                "username": (
                    self.customer_user.username
                ),
                "password": (
                    "old-customer-password"
                ),
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

    def test_ui_disable_and_enable(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        manage_url = reverse(
            "customers-access-manage",
            args=[self.account.pk],
        )

        response = self.client.post(
            manage_url,
            {
                "action": "disable",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.customer_user.refresh_from_db()

        self.assertFalse(
            self.customer_user.is_active
        )

        response = self.client.post(
            manage_url,
            {
                "action": "enable",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.customer_user.refresh_from_db()

        self.assertTrue(
            self.customer_user.is_active
        )

    def test_detach_revokes_login_and_preserves_protocol_secrets(
        self,
    ):
        vpn_before = VPNClient.objects.values(
            "id",
            "device_id",
            "server_id",
            "profile_id",
            "runtime_peer_public_key",
            "runtime_address",
        ).get(
            pk=self.vpn.pk
        )

        revision_before = (
            ClientConfigRevision.objects.values(
                "id",
                "client_id",
                "revision_number",
                "config_blob_encrypted",
                "config_hash",
            ).get(
                pk=self.revision.pk
            )
        )

        xhttp_before = XHTTPDevice.objects.values(
            "id",
            "device_id",
            "server_id",
            "client_uuid",
            "xray_email",
            "config_blob_encrypted",
            "config_hash",
        ).get(
            pk=self.xhttp.pk
        )

        old_user_id = self.customer_user.pk

        detached = detach_customer_login(
            account_id=self.account.pk,
            actor=self.operator,
        )

        self.account.refresh_from_db()
        detached.refresh_from_db()

        self.assertIsNone(
            self.account.user_id
        )

        self.assertEqual(
            detached.pk,
            old_user_id,
        )

        self.assertFalse(
            detached.is_active
        )

        self.assertFalse(
            detached.has_usable_password()
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

        xhttp_after = XHTTPDevice.objects.values(
            *xhttp_before.keys()
        ).get(
            pk=self.xhttp.pk
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
            xhttp_before,
            xhttp_after,
        )

    def test_ui_detach_allows_new_cabinet_later(
        self,
    ):
        self.client.force_login(
            self.operator
        )

        response = self.client.post(
            reverse(
                "customers-access-manage",
                args=[self.account.pk],
            ),
            {
                "action": "detach",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        self.account.refresh_from_db()
        self.customer_user.refresh_from_db()

        self.assertIsNone(
            self.account.user_id
        )

        self.assertFalse(
            self.customer_user.is_active
        )

        self.assertFalse(
            self.customer_user.has_usable_password()
        )

        create_response = self.client.get(
            reverse(
                "customers-access-create",
                args=[self.account.pk],
            )
        )

        self.assertEqual(
            create_response.status_code,
            200,
        )
