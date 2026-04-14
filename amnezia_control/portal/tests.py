from datetime import timedelta

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditLog
from servers.models import ProtocolProfile, Server, ServerProtocol
from vpn.models import VPNClient
from vpn.services import VPNClientService

from .models import ClientPortalAccess
from .services import PortalAccessService


@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class PortalFlowTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin", password="123", is_staff=True)
        self.server = Server.objects.create(name="local", host="vpn-host.example")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            container_name="amnezia-awg",
            enabled=True,
            runtime_metadata={"udp_port": 51820},
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="default-awg",
            protocol_type=ServerProtocol.ProtocolType.AWG,
            config_template="[Interface]",
        )
        self.client_obj = VPNClient.objects.create(
            server=self.server,
            name="portal-client",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
        )

    def _issue_token(self):
        _, token = PortalAccessService.issue_for_client(self.client_obj)
        return token

    def test_valid_portal_token_opens_home(self):
        token = self._issue_token()
        response = self.client.get(reverse("portal-home", kwargs={"token": token}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.client_obj.name)

    def test_revoked_token_is_denied(self):
        token = self._issue_token()
        PortalAccessService.revoke_for_client(self.client_obj)

        response = self.client.get(reverse("portal-home", kwargs={"token": token}))

        self.assertEqual(response.status_code, 404)
        self.assertContains(response, "Ссылка отозвана")

    def test_expired_token_is_denied(self):
        token = self._issue_token()
        access = ClientPortalAccess.objects.get(client=self.client_obj)
        access.expires_at = timezone.now() - timedelta(minutes=1)
        access.save(update_fields=["expires_at"])

        response = self.client.get(reverse("portal-home", kwargs={"token": token}))

        self.assertEqual(response.status_code, 404)
        self.assertContains(response, "Срок действия ссылки истёк")

    def test_config_download_works_when_revision_exists(self):
        from unittest.mock import patch

        token = self._issue_token()
        config_text = "[Interface]\nPrivateKey = test"
        VPNClientService._store_revision(self.client_obj, config_text)

        with patch("portal.views.VPNClientService.portal_export_config", return_value="native-export-config") as export_mock:
            response = self.client.get(reverse("portal-config", kwargs={"token": token}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "native-export-config")
        export_mock.assert_called_once_with(self.client_obj)

    def test_portal_qr_uses_portal_export_payload(self):
        from unittest.mock import patch

        token = self._issue_token()
        VPNClientService._store_revision(self.client_obj, "[Interface]\nPrivateKey = test")
        with patch("portal.views.VPNClientService.portal_qr_png_base64", return_value="base64-qr") as qr_mock:
            response = self.client.get(reverse("portal-qr", kwargs={"token": token}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "base64-qr")
        qr_mock.assert_called_once_with(self.client_obj)

    def test_renewal_request_creates_audit_entry(self):
        token = self._issue_token()

        response = self.client.post(reverse("portal-request-renewal", kwargs={"token": token}), follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            AuditLog.objects.filter(action="portal.renewal.request", entity_type="VPNClient", entity_id=str(self.client_obj.id)).count(),
            1,
        )

    def test_repeated_renewal_request_inside_cooldown_does_not_duplicate(self):
        token = self._issue_token()

        self.client.post(reverse("portal-request-renewal", kwargs={"token": token}), follow=True)
        response = self.client.post(reverse("portal-request-renewal", kwargs={"token": token}), follow=True)

        self.assertEqual(
            AuditLog.objects.filter(action="portal.renewal.request", entity_type="VPNClient", entity_id=str(self.client_obj.id)).count(),
            1,
        )
        self.assertContains(response, "Заявка уже была отправлена недавно")
