from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from audit.models import AuditLog
from servers.models import ProtocolProfile, Server, ServerProtocol
from vpn.models import ClientConfigRevision, VPNClient, XHTTPDevice
from vpn.services import ConfigCryptoService

from .models import ClientDevice, CustomerAccount


User = get_user_model()


class CustomerPortalReissueTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="selfservice-customer",
            password="selfservice-password",
            is_owner=False,
            is_staff=False,
            is_superuser=False,
        )
        self.account = CustomerAccount.objects.create(
            display_name="Self Service Customer",
            user=self.user,
        )
        self.device = ClientDevice.objects.create(
            account=self.account,
            name="Self Service iPhone",
            platform=ClientDevice.Platform.IOS,
        )

        self.server = Server.objects.create(
            name="Self Service Server",
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
        self.vpn = VPNClient.objects.create(
            server=self.server,
            name="Self-Service-AWG2-FULL",
            protocol_type=VPNClient.ProtocolType.AWG2,
            status=VPNClient.Status.ACTIVE,
            profile=self.profile,
            device=self.device,
            runtime_peer_public_key="SELF-SERVICE-PUBKEY",
            runtime_address="10.8.77.10",
        )

        config = (
            "[Interface]\n"
            "PrivateKey = TEST-PRIVATE-KEY\n"
            "Address = 10.8.77.10/32\n\n"
            "[Peer]\n"
            "PublicKey = TEST-SERVER-PUBKEY\n"
            "Endpoint = 198.51.100.77:51830\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
        )
        self.revision = ClientConfigRevision.objects.create(
            client=self.vpn,
            revision_number=1,
            protocol_type=VPNClient.ProtocolType.AWG2,
            config_blob_encrypted=ConfigCryptoService.encrypt(config),
            config_hash="a" * 64,
        )

        self.xhttp = XHTTPDevice.objects.create(
            device=self.device,
            server=self.server,
            name="Self Service ALT",
            xray_email=(
                "xhttp-"
                "77777777777777777777777777777777"
            ),
            status=XHTTPDevice.Status.ACTIVE,
            config_blob_encrypted="existing-config",
            config_hash="b" * 64,
        )

        self.other_user = User.objects.create_user(
            username="other-selfservice-customer",
            password="other-password",
            is_owner=False,
        )
        self.other_account = CustomerAccount.objects.create(
            display_name="Other Customer",
            user=self.other_user,
        )
        self.other_device = ClientDevice.objects.create(
            account=self.other_account,
            name="Other Device",
        )
        self.other_vpn = VPNClient.objects.create(
            server=self.server,
            name="Other-Self-Service-AWG2-FULL",
            protocol_type=VPNClient.ProtocolType.AWG2,
            status=VPNClient.Status.ACTIVE,
            profile=self.profile,
            device=self.other_device,
        )

        self.client.force_login(self.user)

    def test_home_shows_reissue_for_existing_vpn(self):
        response = self.client.get(
            reverse("customer-portal-home")
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            reverse(
                "customer-portal-vpn-reissue",
                args=[self.vpn.pk],
            ),
        )
        self.assertContains(response, "Перевыпустить")

    def test_home_shows_issue_when_vpn_has_no_revision(self):
        self.revision.delete()

        response = self.client.get(
            reverse("customer-portal-home")
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            reverse(
                "customer-portal-vpn-reissue",
                args=[self.vpn.pk],
            ),
        )
        self.assertContains(response, "Выпустить")

    @patch(
        "customers.portal_selfservice."
        "VPNClientService.reissue_config"
    )
    def test_customer_can_reissue_own_vpn(self, reissue_config):
        response = self.client.post(
            reverse(
                "customer-portal-vpn-reissue",
                args=[self.vpn.pk],
            ),
            {"confirm_reissue": "1"},
        )

        self.assertRedirects(
            response,
            reverse("customer-portal-home"),
            fetch_redirect_response=False,
        )
        reissue_config.assert_called_once()
        self.assertEqual(
            reissue_config.call_args.kwargs["client"].pk,
            self.vpn.pk,
        )
        self.assertEqual(
            reissue_config.call_args.kwargs["actor"].pk,
            self.user.pk,
        )

    @patch(
        "customers.portal_selfservice."
        "VPNClientService.reissue_config"
    )
    def test_customer_cannot_reissue_another_account(self, reissue_config):
        response = self.client.post(
            reverse(
                "customer-portal-vpn-reissue",
                args=[self.other_vpn.pk],
            ),
            {"confirm_reissue": "1"},
        )

        self.assertEqual(response.status_code, 404)
        reissue_config.assert_not_called()

    @patch(
        "customers.portal_selfservice."
        "VPNClientService.reissue_config"
    )
    def test_vpn_reissue_respects_customer_cooldown(self, reissue_config):
        AuditLog.objects.create(
            actor=self.user,
            action="client.reissue",
            entity_type="VPNClient",
            entity_id=str(self.vpn.pk),
        )

        response = self.client.post(
            reverse(
                "customer-portal-vpn-reissue",
                args=[self.vpn.pk],
            ),
            {"confirm_reissue": "1"},
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            "Повторный выпуск будет доступен",
        )
        reissue_config.assert_not_called()

    @patch(
        "customers.portal_selfservice."
        "XHTTPDeviceService.rotate"
    )
    def test_customer_can_reissue_own_xhttp(self, rotate):
        response = self.client.post(
            reverse(
                "customer-portal-xhttp-reissue",
                args=[self.xhttp.pk],
            ),
            {"confirm_reissue": "1"},
        )

        self.assertRedirects(
            response,
            reverse("customer-portal-home"),
            fetch_redirect_response=False,
        )
        rotate.assert_called_once()
        self.assertEqual(
            rotate.call_args.kwargs["device"].pk,
            self.xhttp.pk,
        )
        self.assertEqual(
            rotate.call_args.kwargs["actor"].pk,
            self.user.pk,
        )

    @patch(
        "customers.portal_selfservice."
        "VPNClientService.reissue_config"
    )
    def test_reissue_requires_explicit_confirmation(self, reissue_config):
        response = self.client.post(
            reverse(
                "customer-portal-vpn-reissue",
                args=[self.vpn.pk],
            ),
        )

        self.assertRedirects(
            response,
            reverse("customer-portal-home"),
            fetch_redirect_response=False,
        )
        reissue_config.assert_not_called()

    def test_reissue_endpoint_is_post_only(self):
        response = self.client.get(
            reverse(
                "customer-portal-vpn-reissue",
                args=[self.vpn.pk],
            )
        )

        self.assertEqual(response.status_code, 405)
