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


    def test_client_notification_on_dismissed_status_change(self):
        with patch("notifications.services.send_mail") as send_mail_mock:
            NotificationService.deliver(
                event_type=NotificationEventType.RENEWAL_REQUEST_STATUS_CHANGED,
                payload={
                    "client_id": self.client_obj.id,
                    "client_name": self.client_obj.name,
                    "renewal_request_id": 100,
                    "status": "dismissed",
                },
            )

        messages = [call.kwargs["message"] for call in send_mail_mock.call_args_list]
        self.assertTrue(any("Заявка отклонена." in msg for msg in messages))

    def test_main_flow_succeeds_when_notification_enqueue_fails(self):
        token = self._issue_token()
        pdf = SimpleUploadedFile("renewal.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n", content_type="application/pdf")
        with patch("notifications.tasks.deliver_notification_event.delay", side_effect=RuntimeError("queue down")):
            response = self.client.post(reverse("portal-request-renewal", kwargs={"token": token}), {"attachment": pdf}, follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Заявка на продление отправлена")

    def test_expiring_and_expired_dedup(self):
        self.client_obj.expires_at = timezone.now() + timedelta(days=2, hours=1)
        self.client_obj.save(update_fields=["expires_at"])
        with patch.object(NotificationService, "emit_event") as emit_mock:
            first = NotificationService.emit_client_access_limits_notifications()
            second = NotificationService.emit_client_access_limits_notifications()

        self.assertEqual(first["expiring"], 1)
        self.assertEqual(second["expiring"], 0)
        self.assertEqual(emit_mock.call_count, 1)
        event_payload = emit_mock.call_args.kwargs["payload"]
        self.assertEqual(event_payload["days_left"], 3)

    @override_settings(
        NOTIFICATIONS_CHANNELS=["telegram"],
        NOTIFICATIONS_TELEGRAM_BOT_TOKEN="bot-token",
        NOTIFICATIONS_TELEGRAM_ADMIN_CHAT_IDS=["1001", "1002"],
        NOTIFICATIONS_BASE_URL="https://panel.example.com",
    )
    def test_telegram_delivery_attempted_when_enabled(self):
        with patch("notifications.telegram.send_telegram_message") as telegram_mock:
            NotificationService.deliver(
                event_type=NotificationEventType.RENEWAL_REQUEST_CREATED,
                payload={
                    "client_id": self.client_obj.id,
                    "client_name": self.client_obj.name,
                    "renewal_request_id": 11,
                    "has_attachment": True,
                },
            )

        self.assertEqual(telegram_mock.call_count, 2)
        first_text = telegram_mock.call_args_list[0].kwargs["text"]
        self.assertIn("с вложением", first_text)
        self.assertIn("https://panel.example.com/clients/renewal-requests/", first_text)

    @override_settings(
        NOTIFICATIONS_CHANNELS=["telegram"],
        NOTIFICATIONS_TELEGRAM_BOT_TOKEN="",
        NOTIFICATIONS_TELEGRAM_ADMIN_CHAT_IDS=[],
    )
    def test_telegram_skipped_when_config_missing(self):
        with patch("notifications.telegram.send_telegram_message") as telegram_mock:
            NotificationService.deliver(
                event_type=NotificationEventType.CLIENT_ACCESS_EXPIRING,
                payload={"client_id": self.client_obj.id, "client_name": self.client_obj.name, "days_left": 3},
            )
        telegram_mock.assert_not_called()

    @override_settings(
        NOTIFICATIONS_CHANNELS=["email", "telegram"],
        NOTIFICATIONS_TELEGRAM_BOT_TOKEN="bot-token",
        NOTIFICATIONS_TELEGRAM_ADMIN_CHAT_IDS=["1001"],
    )
    def test_email_and_telegram_coexist(self):
        with patch("notifications.services.send_mail") as send_mail_mock, patch("notifications.telegram.send_telegram_message") as telegram_mock:
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
        telegram_mock.assert_called_once()

    @override_settings(
        NOTIFICATIONS_CHANNELS=["email", "telegram"],
        NOTIFICATIONS_TELEGRAM_BOT_TOKEN="bot-token",
        NOTIFICATIONS_TELEGRAM_ADMIN_CHAT_IDS=["1001"],
    )
    def test_telegram_failure_does_not_break_email_delivery(self):
        with patch("notifications.services.send_mail") as send_mail_mock, patch(
            "notifications.telegram.send_telegram_message", side_effect=RuntimeError("telegram down")
        ):
            NotificationService.deliver(
                event_type=NotificationEventType.BACKGROUND_JOB_FAILED,
                payload={"action": "sync", "job_id": 123},
            )
        send_mail_mock.assert_called_once()

    @override_settings(
        NOTIFICATIONS_CHANNELS=["telegram"],
        NOTIFICATIONS_TELEGRAM_BOT_TOKEN="bot-token",
        NOTIFICATIONS_TELEGRAM_ADMIN_CHAT_IDS=["1001"],
        NOTIFICATIONS_BASE_URL="https://panel.example.com",
    )
    def test_telegram_message_content_for_required_events(self):
        with patch("notifications.telegram.send_telegram_message") as telegram_mock:
            NotificationService.deliver(
                event_type=NotificationEventType.CLIENT_ACCESS_EXPIRING,
                payload={"client_id": self.client_obj.id, "client_name": self.client_obj.name, "days_left": 3},
            )
            NotificationService.deliver(
                event_type=NotificationEventType.BACKGROUND_JOB_FAILED,
                payload={"action": "backup", "job_id": 123},
            )

        messages = [call.kwargs["text"] for call in telegram_mock.call_args_list]
        self.assertTrue(any("истекает через 3 дня" in msg for msg in messages))
        self.assertTrue(any("https://panel.example.com/clients/" in msg for msg in messages))
        self.assertTrue(any("Сбой фоновой задачи: backup. Job #123." in msg for msg in messages))
