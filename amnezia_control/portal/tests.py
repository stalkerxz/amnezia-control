from datetime import timedelta

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from audit.models import AuditLog
from core.models import SystemSettings
from servers.models import ProtocolProfile, Server, ServerProtocol
from vpn.models import VPNClient
from vpn.services import VPNClientService

from .models import ClientPortalAccess, ClientRenewalRequest
from .services import PortalAccessService, PortalReissuePolicyService


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

    def test_renewal_request_creates_workflow_request_and_audit_entry(self):
        token = self._issue_token()

        response = self.client.post(reverse("portal-request-renewal", kwargs={"token": token}), follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            AuditLog.objects.filter(action="portal.renewal.request", entity_type="VPNClient", entity_id=str(self.client_obj.id)).count(),
            1,
        )
        self.assertEqual(ClientRenewalRequest.objects.filter(client=self.client_obj, status="new").count(), 1)

    def test_repeated_renewal_request_does_not_create_duplicate_open_requests(self):
        token = self._issue_token()

        self.client.post(reverse("portal-request-renewal", kwargs={"token": token}), follow=True)
        response = self.client.post(reverse("portal-request-renewal", kwargs={"token": token}), follow=True)

        self.assertEqual(
            AuditLog.objects.filter(action="portal.renewal.request", entity_type="VPNClient", entity_id=str(self.client_obj.id)).count(),
            1,
        )
        self.assertEqual(ClientRenewalRequest.objects.filter(client=self.client_obj, status="new").count(), 1)
        self.assertContains(response, "Заявка уже отправлена")


    def test_new_request_can_be_created_after_done(self):
        token = self._issue_token()
        self.client.post(reverse("portal-request-renewal", kwargs={"token": token}), follow=True)
        request_obj = ClientRenewalRequest.objects.get(client=self.client_obj)
        request_obj.status = ClientRenewalRequest.Status.DONE
        request_obj.processed_at = timezone.now()
        request_obj.save(update_fields=["status", "processed_at", "updated_at"])

        self.client.post(reverse("portal-request-renewal", kwargs={"token": token}), follow=True)

        self.assertEqual(
            ClientRenewalRequest.objects.filter(client=self.client_obj).count(),
            2,
        )
        self.assertEqual(
            ClientRenewalRequest.objects.filter(
                client=self.client_obj,
                status__in=[ClientRenewalRequest.Status.NEW, ClientRenewalRequest.Status.IN_PROGRESS],
            ).count(),
            1,
        )

    def test_new_request_can_be_created_after_dismissed(self):
        token = self._issue_token()
        self.client.post(reverse("portal-request-renewal", kwargs={"token": token}), follow=True)
        request_obj = ClientRenewalRequest.objects.get(client=self.client_obj)
        request_obj.status = ClientRenewalRequest.Status.DISMISSED
        request_obj.processed_at = timezone.now()
        request_obj.save(update_fields=["status", "processed_at", "updated_at"])

        self.client.post(reverse("portal-request-renewal", kwargs={"token": token}), follow=True)

        self.assertEqual(ClientRenewalRequest.objects.filter(client=self.client_obj).count(), 2)
        self.assertEqual(
            ClientRenewalRequest.objects.filter(client=self.client_obj, status=ClientRenewalRequest.Status.NEW).count(),
            1,
        )

    def test_portal_shows_status_text_for_latest_closed_request(self):
        token = self._issue_token()
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_obj,
            status=ClientRenewalRequest.Status.DONE,
            processed_at=timezone.now(),
            operator_note="Продление уже применено.",
            created_from_portal=True,
        )

        response = self.client.get(reverse("portal-home", kwargs={"token": token}))

        self.assertContains(response, "Последняя заявка выполнена")
        self.assertContains(response, request_obj.operator_note)

    def test_portal_history_shows_recent_client_friendly_events(self):
        token = self._issue_token()
        access = ClientPortalAccess.objects.get(client=self.client_obj)
        access.last_selfservice_reissue_at = timezone.now()
        access.save(update_fields=["last_selfservice_reissue_at"])
        done_request = ClientRenewalRequest.objects.create(
            client=self.client_obj,
            status=ClientRenewalRequest.Status.DONE,
            processed_at=timezone.now(),
            operator_note="Продление подтверждено.",
            created_from_portal=True,
        )
        AuditLog.objects.create(
            actor=self.user,
            action="portal.renewal.done",
            entity_type="VPNClient",
            entity_id=str(self.client_obj.id),
            details={"renewal_request_id": done_request.id, "operator_note": "Продление подтверждено."},
        )
        AuditLog.objects.create(
            actor=self.user,
            action="portal.renewal.request",
            entity_type="VPNClient",
            entity_id=str(self.client_obj.id),
            details={"renewal_request_id": done_request.id},
        )

        response = self.client.get(reverse("portal-home", kwargs={"token": token}))

        self.assertContains(response, "История действий")
        self.assertContains(response, "Доступ к кабинету выдан")
        self.assertContains(response, "Заявка выполнена")
        self.assertContains(response, "Комментарий оператора: Продление подтверждено.")
        self.assertContains(response, "Конфигурация переиздана")

    def test_portal_shows_in_progress_state_for_open_request(self):
        token = self._issue_token()
        ClientRenewalRequest.objects.create(
            client=self.client_obj,
            status=ClientRenewalRequest.Status.IN_PROGRESS,
            created_from_portal=True,
        )

        response = self.client.get(reverse("portal-home", kwargs={"token": token}))

        self.assertContains(response, "Заявка в работе")
        self.assertContains(response, "Текущий статус")
        self.assertContains(response, "В работе")

    def test_portal_shows_done_result_block_with_operator_comment(self):
        token = self._issue_token()
        ClientRenewalRequest.objects.create(
            client=self.client_obj,
            status=ClientRenewalRequest.Status.DONE,
            processed_at=timezone.now(),
            operator_note="Продлили до конца месяца.",
            created_from_portal=True,
        )

        response = self.client.get(reverse("portal-home", kwargs={"token": token}))

        self.assertContains(response, "Текущий статус")
        self.assertContains(response, "Последняя заявка выполнена")
        self.assertContains(response, "Комментарий оператора")
        self.assertContains(response, "Продлили до конца месяца.")

    def test_portal_shows_dismissed_result_block(self):
        token = self._issue_token()
        ClientRenewalRequest.objects.create(
            client=self.client_obj,
            status=ClientRenewalRequest.Status.DISMISSED,
            processed_at=timezone.now(),
            operator_note="Срок уже активен, продление пока не требуется.",
            created_from_portal=True,
        )

        response = self.client.get(reverse("portal-home", kwargs={"token": token}))

        self.assertContains(response, "Текущий статус")
        self.assertContains(response, "Последняя заявка отклонена")
        self.assertContains(response, "Срок уже активен, продление пока не требуется.")

    def test_portal_history_does_not_show_raw_technical_audit_internals(self):
        token = self._issue_token()
        AuditLog.objects.create(
            actor=self.user,
            action="portal.renewal.request",
            entity_type="VPNClient",
            entity_id=str(self.client_obj.id),
            details={"ip": "10.10.10.10", "user_agent": "test-agent", "renewal_request_id": 42},
        )

        response = self.client.get(reverse("portal-home", kwargs={"token": token}))

        self.assertContains(response, "Заявка на продление отправлена")
        self.assertNotContains(response, "10.10.10.10")
        self.assertNotContains(response, "test-agent")
        self.assertNotContains(response, "renewal_request_id")

    def test_portal_link_lifetime_uses_system_settings(self):
        SystemSettings.get_solo().portal_link_lifetime_days = 10
        SystemSettings.get_solo().save(update_fields=["portal_link_lifetime_days"])

        self._issue_token()
        access = ClientPortalAccess.objects.get(client=self.client_obj)
        self.assertGreaterEqual(access.expires_at, timezone.now() + timedelta(days=9, hours=23))

    def test_portal_hides_technical_traffic_error_details(self):
        token = self._issue_token()
        self.client_obj.traffic_sync_error = "Peer отсутствует в runtime"
        self.client_obj.save(update_fields=["traffic_sync_error"])

        response = self.client.get(reverse("portal-home", kwargs={"token": token}))

        self.assertContains(response, "Статистика трафика временно недоступна")
        self.assertNotContains(response, "Peer отсутствует в runtime")

    def test_portal_selfservice_reissue_works_and_writes_audit_log(self):
        from unittest.mock import patch

        token = self._issue_token()
        VPNClientService._store_revision(
            self.client_obj,
            "[Interface]\nPrivateKey = old\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = server\nEndpoint = host:51820\n",
        )

        def _mock_reissue(*, client, actor):
            VPNClientService._store_revision(
                client,
                "[Interface]\nPrivateKey = new\nAddress = 10.66.0.3/32\n\n[Peer]\nPublicKey = server\nEndpoint = host:51820\n",
            )

        with patch("portal.views.VPNClientService.reissue_config", side_effect=_mock_reissue):
            response = self.client.post(
                reverse("portal-reissue-config", kwargs={"token": token}),
                {"confirm_reissue": "1"},
                follow=True,
            )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "новая конфигурация выпущена")
        self.assertTrue(
            AuditLog.objects.filter(action="portal.config.reissue", entity_type="VPNClient", entity_id=str(self.client_obj.id)).exists()
        )
        access = ClientPortalAccess.objects.get(client=self.client_obj)
        self.assertIsNotNone(access.last_selfservice_reissue_at)

    def test_portal_reissue_cooldown_prevents_second_immediate_reissue(self):
        from unittest.mock import patch

        token = self._issue_token()
        VPNClientService._store_revision(
            self.client_obj,
            "[Interface]\nPrivateKey = old\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = server\nEndpoint = host:51820\n",
        )
        with patch("portal.views.VPNClientService.reissue_config", return_value=None):
            first = self.client.post(
                reverse("portal-reissue-config", kwargs={"token": token}),
                {"confirm_reissue": "1"},
                follow=True,
            )
            second = self.client.post(
                reverse("portal-reissue-config", kwargs={"token": token}),
                {"confirm_reissue": "1"},
                follow=True,
            )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertContains(second, "Переиздать конфигурацию можно позже")

    def test_portal_download_and_qr_use_new_current_config_after_reissue(self):
        from unittest.mock import patch

        token = self._issue_token()
        VPNClientService._store_revision(
            self.client_obj,
            "[Interface]\nPrivateKey = old\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = server\nEndpoint = old-host:51820\n",
        )

        def _mock_reissue(*, client, actor):
            VPNClientService._store_revision(
                client,
                "[Interface]\nPrivateKey = new\nAddress = 10.66.0.3/32\n\n[Peer]\nPublicKey = server\nEndpoint = new-host:51820\n",
            )

        qr_before = self.client.get(reverse("portal-qr", kwargs={"token": token}))
        self.assertContains(qr_before, "data:image/png;base64")

        with patch("portal.views.VPNClientService.reissue_config", side_effect=_mock_reissue):
            self.client.post(reverse("portal-reissue-config", kwargs={"token": token}), {"confirm_reissue": "1"}, follow=True)

        config_response = self.client.get(reverse("portal-config", kwargs={"token": token}))
        qr_response = self.client.get(reverse("portal-qr", kwargs={"token": token}))

        self.assertEqual(config_response.status_code, 200)
        self.assertContains(config_response, "new-host:51820")
        self.assertContains(qr_response, "data:image/png;base64")
        self.assertNotEqual(qr_before.context["qr_base64"], qr_response.context["qr_base64"])

    def test_portal_reissue_blocked_client_shows_russian_message(self):
        token = self._issue_token()
        self.client_obj.status = VPNClient.Status.DELETED
        self.client_obj.save(update_fields=["status"])
        VPNClientService._store_revision(
            self.client_obj,
            "[Interface]\nPrivateKey = old\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = server\nEndpoint = host:51820\n",
        )

        response = self.client.post(
            reverse("portal-reissue-config", kwargs={"token": token}),
            {"confirm_reissue": "1"},
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Переиздание недоступно: обратитесь к оператору.")

    def test_blocked_reissue_does_not_update_last_selfservice_reissue_at(self):
        token = self._issue_token()
        access = ClientPortalAccess.objects.get(client=self.client_obj)
        VPNClientService._store_revision(
            self.client_obj,
            "[Interface]\nPrivateKey = old\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = server\nEndpoint = host:51820\n",
        )
        self.client_obj.status = VPNClient.Status.DELETED
        self.client_obj.save(update_fields=["status"])

        self.client.post(
            reverse("portal-reissue-config", kwargs={"token": token}),
            {"confirm_reissue": "1"},
            follow=True,
        )

        access.refresh_from_db()
        self.assertIsNone(access.last_selfservice_reissue_at)

    def test_reissue_timestamp_is_not_updated_when_reissue_fails(self):
        from unittest.mock import patch

        token = self._issue_token()
        access = ClientPortalAccess.objects.get(client=self.client_obj)
        VPNClientService._store_revision(
            self.client_obj,
            "[Interface]\nPrivateKey = old\nAddress = 10.66.0.2/32\n\n[Peer]\nPublicKey = server\nEndpoint = host:51820\n",
        )

        with patch("portal.views.VPNClientService.reissue_config", side_effect=RuntimeError("boom")):
            response = self.client.post(
                reverse("portal-reissue-config", kwargs={"token": token}),
                {"confirm_reissue": "1"},
                follow=True,
            )

        access.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Не удалось переиздать конфигурацию")
        self.assertIsNone(access.last_selfservice_reissue_at)

    def test_portal_reissue_policy_cooldown_helper_returns_timedelta(self):
        self.assertEqual(PortalReissuePolicyService.cooldown_timedelta(), timedelta(hours=12))
