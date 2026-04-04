from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from jobs.models import Job, JobEvent
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
        self._make_client(name="active", status=VPNClient.Status.ACTIVE, limit_state=VPNClient.LimitState.ACTIVE)
        self._make_client(name="disabled", status=VPNClient.Status.DISABLED, limit_state=VPNClient.LimitState.ACTIVE)
        self._make_client(name="expired", status=VPNClient.Status.ACTIVE, limit_state=VPNClient.LimitState.EXPIRED)
        self._make_client(name="traffic", status=VPNClient.Status.ACTIVE, limit_state=VPNClient.LimitState.TRAFFIC_EXCEEDED)
        self._make_client(name="deleted", status=VPNClient.Status.DELETED, limit_state=VPNClient.LimitState.ACTIVE)

        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Клиентов всего")
        self.assertContains(response, "Отключённые")
        self.assertContains(response, "Истёк срок")
        self.assertContains(response, "Трафик превышен")
        self.assertContains(response, "Fallback-телеметрия")
        self.assertContains(response, "Требует внимания")
        self.assertContains(response, "/servers/?health=degraded")
        self.assertContains(response, "/clients/?quick=expired")
        self.assertContains(response, "Текущие ограничения")
        self.assertContains(response, ">5<", html=False)
        self.assertContains(response, ">1<", html=False)

    def test_dashboard_marks_success_with_warning(self):
        job = Job.objects.create(server=self.server, actor=self.user, action="server.sync_runtime", status=Job.Status.SUCCESS)
        JobEvent.objects.create(job=job, level="warning", message="AWG2 fallback")

        response = self.client.get(reverse("dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Успех с предупреждением")
        self.assertContains(response, "Синхронизация состояния сервера")

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
        self.assertContains(response, "Ошибки задач (24ч)")
        self.assertContains(response, "Предупреждения задач (24ч)")
        self.assertContains(response, "Успех с деградацией (24ч)")
        self.assertContains(response, "/jobs/?signal=failed")
        self.assertContains(response, "/jobs/?signal=warning")
        self.assertContains(response, "/jobs/?signal=degraded_success")

        self.assertEqual(response.context["failed_jobs_recent_count"], 1)
        self.assertEqual(response.context["warning_jobs_recent_count"], 1)
        self.assertEqual(response.context["degraded_jobs_recent_count"], 1)


class LoginTemplateViewTest(TestCase):
    def test_login_page_renders_polished_layout_elements(self):
        response = self.client.get(reverse("login"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "amnezia-control")
        self.assertContains(response, "Безопасное управление клиентами")
        self.assertContains(response, "id=\"togglePasswordBtn\"", html=False)
