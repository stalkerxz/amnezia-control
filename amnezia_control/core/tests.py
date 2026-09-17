from django.contrib.auth import get_user_model
from django.conf import settings
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from core.models import SystemSettings
from customers.models import CustomerAccount
from jobs.models import Job, JobEvent
from portal.models import ClientRenewalRequest
from servers.models import ProtocolProfile, Server, ServerProtocol
from vpn.models import VPNClient


class DashboardViewTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin-dashboard", password="123", is_staff=True)
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="dashboard-server")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            runtime_metadata={"peer_source": "config file fallback (degraded telemetry)"},
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="dashboard-profile",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="[Interface]",
        )

    def _make_client(self, **kwargs):
        defaults = {
            "server": self.server,
            "name": kwargs.pop("name", "client"),
            "protocol_type": VPNClient.ProtocolType.AWG2,
            "profile": self.profile,
            "created_by": self.user,
        }
        defaults.update(kwargs)
        return VPNClient.objects.create(**defaults)

    def test_dashboard_shows_operational_overview_cards(self):
        CustomerAccount.objects.create(
            display_name="Active Customer",
            status=CustomerAccount.Status.ACTIVE,
            created_by=self.user,
        )
        CustomerAccount.objects.create(
            display_name="Disabled Customer",
            status=CustomerAccount.Status.DISABLED,
            created_by=self.user,
        )

        self._make_client(
            name="active",
            status=VPNClient.Status.ACTIVE,
            limit_state=VPNClient.LimitState.ACTIVE,
        )
        self._make_client(
            name="disabled",
            status=VPNClient.Status.DISABLED,
            limit_state=VPNClient.LimitState.ACTIVE,
        )
        self._make_client(
            name="expired",
            status=VPNClient.Status.ACTIVE,
            limit_state=VPNClient.LimitState.EXPIRED,
        )
        self._make_client(
            name="traffic",
            status=VPNClient.Status.ACTIVE,
            limit_state=VPNClient.LimitState.TRAFFIC_EXCEEDED,
        )
        self._make_client(
            name="deleted",
            status=VPNClient.Status.DELETED,
            limit_state=VPNClient.LimitState.ACTIVE,
        )

        response = self.client.get(
            reverse("dashboard")
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Клиенты",
        )
        self.assertContains(
            response,
            "активны сейчас",
        )
        self.assertContains(
            response,
            "Клиенты: срок действия истёк",
        )
        self.assertContains(
            response,
            "Клиенты: превышен лимит трафика",
        )
        self.assertContains(
            response,
            "AWG2 работает в резервном режиме",
        )
        self.assertContains(
            response,
            "Требует внимания",
        )
        self.assertContains(
            response,
            "/servers/?health=degraded",
        )
        self.assertContains(
            response,
            "/clients/?quick=expired",
        )
        self.assertContains(
            response,
            "Текущие ограничения",
        )

        self.assertEqual(
            response.context["clients_total_count"],
            2,
        )
        self.assertEqual(
            response.context["active_clients_count"],
            1,
        )
        self.assertEqual(
            response.context["customer_attention_count"],
            1,
        )
        self.assertEqual(
            response.context["disabled_clients_count"],
            1,
        )
        self.assertEqual(
            response.context["expired_clients_count"],
            1,
        )
        self.assertEqual(
            response.context[
                "traffic_exceeded_clients_count"
            ],
            1,
        )
        self.assertEqual(
            response.context["degraded_clients_count"],
            4,
        )

    def test_dashboard_marks_success_with_warning(self):
        job = Job.objects.create(server=self.server, actor=self.user, action="server.sync_runtime", status=Job.Status.SUCCESS)
        JobEvent.objects.create(
            job=job,
            level="warning",
            message="Нужно проверить результат",
        )

        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            "Предупреждение",
        )
        self.assertContains(
            response,
            "Синхронизация состояния сервера",
        )
        self.assertEqual(
            response.context[
                "jobs_recent_rows"
            ][0]["job_signal"],
            "warning",
        )

    def test_dashboard_job_counters_split_failed_warning_and_degraded(self):
        failed_job = Job.objects.create(server=self.server, actor=self.user, action="server.sync_runtime", status=Job.Status.FAILED)
        warning_job = Job.objects.create(server=self.server, actor=self.user, action="server.sync_runtime", status=Job.Status.SUCCESS)
        degraded_job = Job.objects.create(server=self.server, actor=self.user, action="server.sync_runtime", status=Job.Status.SUCCESS)
        stale_failed_job = Job.objects.create(server=self.server, actor=self.user, action="server.sync_runtime", status=Job.Status.FAILED)

        JobEvent.objects.create(job=warning_job, level="warning", message="Нужно проверить результат")
        JobEvent.objects.create(
            job=degraded_job,
            level="warning",
            message="AWG2 runtime telemetry unavailable: using config fallback (degraded mode).",
        )

        Job.objects.filter(id=stale_failed_job.id).update(created_at=timezone.now() - timezone.timedelta(hours=30))

        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            "Ошибки задач за последние 24 часа",
        )
        self.assertContains(
            response,
            "/jobs/?status=failed&amp;created_from=",
            html=False,
        )

        self.assertEqual(
            response.context[
                "failed_jobs_recent_count"
            ],
            1,
        )
        self.assertEqual(
            response.context[
                "warning_jobs_recent_count"
            ],
            1,
        )
        self.assertEqual(
            response.context[
                "degraded_jobs_recent_count"
            ],
            1,
        )

        signals = {
            row["job_signal"]
            for row in response.context[
                "jobs_recent_rows"
            ]
        }

        self.assertIn(
            "failed",
            signals,
        )
        self.assertIn(
            "warning",
            signals,
        )
        self.assertIn(
            "degraded_success",
            signals,
        )

    def test_dashboard_shows_portal_renewal_request_counters(self):
        client = self._make_client(
            name="renewal-client"
        )

        ClientRenewalRequest.objects.create(
            client=client,
            status=(
                ClientRenewalRequest.Status.NEW
            ),
        )

        old_request = (
            ClientRenewalRequest.objects.create(
                client=client,
                status=(
                    ClientRenewalRequest.Status.DONE
                ),
            )
        )

        ClientRenewalRequest.objects.filter(
            id=old_request.id
        ).update(
            created_at=(
                timezone.now()
                - timezone.timedelta(days=8)
            )
        )

        response = self.client.get(
            reverse("dashboard")
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Продления",
        )
        self.assertContains(
            response,
            "новых за 24 часа",
        )
        self.assertContains(
            response,
            "Продления за 7 дней",
        )
        self.assertContains(
            response,
            "/customers/?renewal=open",
        )

        self.assertEqual(
            response.context[
                "renewal_requests_last_24h"
            ],
            1,
        )
        self.assertEqual(
            response.context[
                "renewal_requests_last_7d"
            ],
            1,
        )
        self.assertEqual(
            response.context[
                "renewal_open_count"
            ],
            1,
        )



class LoginTemplateViewTest(TestCase):
    def test_login_page_renders_polished_layout_elements(self):
        response = self.client.get(reverse("login"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "amnezia-control")
        self.assertContains(
            response,
            "Операционный центр управления сервисами",
        )
        self.assertContains(
            response,
            "Безопасный вход",
        )
        self.assertContains(response, "id=\"togglePasswordBtn\"", html=False)


class SettingsViewTest(TestCase):
    def setUp(self):
        self.staff_user = get_user_model().objects.create_user("staff", password="123", is_staff=True)
        self.regular_user = get_user_model().objects.create_user("regular", password="123", is_staff=False)

    def test_settings_page_requires_staff(self):
        self.client.force_login(self.regular_user)
        response = self.client.get(reverse("settings"))
        self.assertEqual(response.status_code, 302)

    def test_staff_can_update_system_settings(self):
        self.client.force_login(self.staff_user)
        response = self.client.post(
            reverse("settings"),
            {
                "default_account_lifetime_days": 60,
                "default_renewal_extension_days": 45,
                "expiration_reminders_enabled": "on",
                "expiration_reminder_days": "14, 7, 3, 3, 1",
                "notify_new_renewal_requests": "on",
                "portal_link_lifetime_days": 45,
                "portal_renewal_cooldown_hours": 12,
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        settings_obj = SystemSettings.get_solo()
        self.assertEqual(
            settings_obj.default_account_lifetime_days,
            60,
        )
        self.assertEqual(
            settings_obj.default_renewal_extension_days,
            45,
        )
        self.assertTrue(
            settings_obj.expiration_reminders_enabled
        )
        self.assertEqual(
            settings_obj.expiration_reminder_days,
            "14,7,3,1",
        )
        self.assertTrue(
            settings_obj.notify_new_renewal_requests
        )
        self.assertEqual(
            settings_obj.portal_link_lifetime_days,
            45,
        )
        self.assertEqual(
            settings_obj.portal_renewal_cooldown_hours,
            12,
        )
        self.assertContains(response, "Настройки сохранены")

    def test_settings_rejects_invalid_reminder_thresholds(
        self,
    ):
        self.client.force_login(
            self.staff_user
        )

        response = self.client.post(
            reverse("settings"),
            {
                "default_account_lifetime_days": 30,
                "default_renewal_extension_days": 30,
                "expiration_reminders_enabled": "on",
                "expiration_reminder_days": "7,0,366",
                "notify_new_renewal_requests": "on",
                "portal_link_lifetime_days": 30,
                "portal_renewal_cooldown_hours": 24,
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertFormError(
            response.context["form"],
            "expiration_reminder_days",
            (
                "Каждый порог должен быть "
                "от 1 до 365 дней."
            ),
        )

    def test_settings_page_language_switch_sets_language_cookie(self):
        self.client.force_login(
            self.staff_user
        )

        response = self.client.post(
            reverse("set_language"),
            {
                "language": "en",
                "next": reverse("settings"),
            },
            follow=False,
        )

        self.assertEqual(
            response.status_code,
            302,
        )
        self.assertEqual(
            response.url,
            reverse("settings"),
        )

        cookie_name = (
            settings.LANGUAGE_COOKIE_NAME
        )

        self.assertIn(
            cookie_name,
            response.cookies,
        )
        self.assertEqual(
            response.cookies[
                cookie_name
            ].value,
            "en",
        )
        self.assertEqual(
            self.client.cookies[
                cookie_name
            ].value,
            "en",
        )

    def test_settings_page_handles_duplicate_system_settings_rows(self):
        self.client.force_login(self.staff_user)
        SystemSettings.objects.create(id=2)
        SystemSettings.objects.create(id=3)

        response = self.client.get(reverse("settings"))
        self.assertEqual(response.status_code, 200)
