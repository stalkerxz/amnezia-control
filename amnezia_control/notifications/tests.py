from datetime import timedelta
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from portal.services import PortalAccessService
from servers.models import ProtocolProfile, Server, ServerProtocol
from vpn.models import VPNClient

from .services import NotificationEventType, NotificationService


@override_settings(
    CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode(),
    NOTIFICATIONS_ENABLED=True,
    NOTIFICATIONS_CHANNELS=["email"],
    NOTIFICATIONS_EMAIL_FROM="noreply@example.com",
)
class NotificationFlowTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_user("admin", password="123", is_staff=True, email="admin@example.com")
        self.server = Server.objects.create(name="srv", host="vpn-host.example")
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
            name="client-one",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.admin,
            contact_email="client@example.com",
        )

    def _issue_token(self):
        _, token = PortalAccessService.issue_for_client(self.client_obj)
        return token

    def test_admin_notification_on_new_renewal_request(self):
        with patch("notifications.services.send_mail") as send_mail_mock:
            NotificationService.deliver(
                event_type=NotificationEventType.RENEWAL_REQUEST_CREATED,
                payload={"client_id": self.client_obj.id, "client_name": self.client_obj.name, "renewal_request_id": 11, "has_attachment": False},
            )

        self.assertEqual(send_mail_mock.call_count, 1)
        self.assertIn("Новая заявка на продление", send_mail_mock.call_args.kwargs["subject"])
        self.assertIn("Новая заявка на продление от клиента", send_mail_mock.call_args.kwargs["message"])

    def test_admin_notification_mentions_attachment(self):
        with patch("notifications.services.send_mail") as send_mail_mock:
            NotificationService.deliver(
                event_type=NotificationEventType.RENEWAL_REQUEST_CREATED,
                payload={"client_id": self.client_obj.id, "client_name": self.client_obj.name, "renewal_request_id": 12, "has_attachment": True},
            )

        self.assertEqual(send_mail_mock.call_count, 1)
        self.assertIn("с вложением", send_mail_mock.call_args.kwargs["message"])

    def test_client_notification_on_renewal_status_change(self):
        with patch("notifications.services.send_mail") as send_mail_mock:
            NotificationService.deliver(
                event_type=NotificationEventType.RENEWAL_REQUEST_STATUS_CHANGED,
                payload={
                    "client_id": self.client_obj.id,
                    "client_name": self.client_obj.name,
                    "renewal_request_id": 99,
                    "status": "in_progress",
                },
            )

        self.assertEqual(send_mail_mock.call_count, 2)
        messages = [call.kwargs["message"] for call in send_mail_mock.call_args_list]
        self.assertTrue(any("Оператор взял вашу заявку в работу." in msg for msg in messages))

    def test_main_flow_succeeds_when_notification_enqueue_fails(self):
        token = self._issue_token()
        pdf = SimpleUploadedFile("renewal.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n", content_type="application/pdf")
        with patch("notifications.tasks.deliver_notification_event.delay", side_effect=RuntimeError("queue down")):
            response = self.client.post(reverse("portal-request-renewal", kwargs={"token": token}), {"attachment": pdf}, follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Заявка на продление отправлена")

    def test_expiring_and_expired_dedup(self):
        self.client_obj.expires_at = timezone.now() + timedelta(days=2)
        self.client_obj.save(update_fields=["expires_at"])
        with patch.object(NotificationService, "emit_event") as emit_mock:
            first = NotificationService.emit_client_access_limits_notifications()
            second = NotificationService.emit_client_access_limits_notifications()

        self.assertEqual(first["expiring"], 1)
        self.assertEqual(second["expiring"], 0)
        self.assertEqual(emit_mock.call_count, 1)
