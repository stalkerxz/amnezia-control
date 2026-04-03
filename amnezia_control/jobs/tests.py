from unittest import TestCase
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase as DjangoTestCase
from django.urls import reverse

from servers.models import Server

from .models import Job, JobEvent
from .executors import SafeSSHExecutor


class SSHExecutorTest(TestCase):
    @patch("jobs.executors.paramiko.SSHClient")
    def test_run_allowlisted_command(self, ssh_client_cls):
        mock_client = MagicMock()
        ssh_client_cls.return_value = mock_client
        stdout = MagicMock()
        stderr = MagicMock()
        stdout.read.return_value = b"amnezia-awg\n"
        stderr.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 0
        mock_client.exec_command.return_value = (None, stdout, stderr)

        executor = SafeSSHExecutor(host="127.0.0.1", username="u")
        result = executor.run("docker ps --format '{{.Names}}'")
        self.assertEqual(result.exit_code, 0)

    def test_reject_non_allowlisted_command(self):
        executor = SafeSSHExecutor(host="127.0.0.1", username="u")
        with self.assertRaises(ValueError):
            executor._validate("rm -rf /")

    def test_allow_pubkey_pipeline_with_quoted_key(self):
        executor = SafeSSHExecutor(host="127.0.0.1", username="u")
        executor._validate("printf %s 'Abc+/=123' | docker exec -i amnezia-awg2 wg pubkey")

    def test_allow_pubkey_pipeline_with_unquoted_key(self):
        executor = SafeSSHExecutor(host="127.0.0.1", username="u")
        executor._validate("printf %s Abc+/=123 | docker exec -i amnezia-awg2 wg pubkey")

    def test_reject_pubkey_pipeline_with_unsafe_key(self):
        executor = SafeSSHExecutor(host="127.0.0.1", username="u")
        with self.assertRaises(ValueError):
            executor._validate("printf %s bad$key | docker exec -i amnezia-awg2 wg pubkey")

    def test_allow_wg_genpsk(self):
        executor = SafeSSHExecutor(host="127.0.0.1", username="u")
        executor._validate("docker exec amnezia-awg2 wg genpsk")

    def test_allow_psk_set_pipeline(self):
        executor = SafeSSHExecutor(host="127.0.0.1", username="u")
        executor._validate(
            "printf %s 'Abc+/=123' | docker exec -i amnezia-awg2 wg set wg0 peer QWERTY+/= preshared-key /dev/stdin allowed-ips 10.8.0.2/32"
        )

    def test_reject_psk_set_pipeline_with_unsafe_psk(self):
        executor = SafeSSHExecutor(host="127.0.0.1", username="u")
        with self.assertRaises(ValueError):
            executor._validate(
                "printf %s bad$key | docker exec -i amnezia-awg2 wg set wg0 peer QWERTY+/= preshared-key /dev/stdin allowed-ips 10.8.0.2/32"
            )


class JobsListViewTest(DjangoTestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin", password="123", is_staff=True)
        self.other = get_user_model().objects.create_user("other-admin", password="123", is_staff=True)
        self.server = Server.objects.create(name="srv-1")
        Job.objects.create(server=self.server, actor=self.user, action="server.sync_runtime", status=Job.Status.RUNNING)

    def test_jobs_list_renders_filters_and_quick_view(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("jobs-list"))
        self.assertContains(response, "Операционные задания")
        self.assertContains(response, "Создано с даты")
        self.assertContains(response, "Быстрый просмотр")

    def test_jobs_list_filters_by_status(self):
        Job.objects.create(server=self.server, actor=self.user, action="vpn.client.create", status=Job.Status.SUCCESS)
        self.client.force_login(self.user)
        response = self.client.get(reverse("jobs-list"), {"status": Job.Status.RUNNING})
        self.assertContains(response, "server.sync_runtime")
        self.assertNotContains(response, "vpn.client.create")

    def test_jobs_list_filters_by_failed_signal(self):
        warning_job = Job.objects.create(server=self.server, actor=self.user, action="vpn.client.create", status=Job.Status.SUCCESS)
        JobEvent.objects.create(job=warning_job, level="warning", message="warning")
        failed_job = Job.objects.create(server=self.server, actor=self.user, action="vpn.client.delete", status=Job.Status.FAILED)

        self.client.force_login(self.user)
        response = self.client.get(reverse("jobs-list"), {"signal": "failed"})
        self.assertContains(response, f"/jobs/{failed_job.id}/")
        self.assertNotContains(response, f"/jobs/{warning_job.id}/")

    def test_jobs_list_filters_by_degraded_success_signal(self):
        degraded_job = Job.objects.create(server=self.server, actor=self.user, action="vpn.client.reissue", status=Job.Status.SUCCESS)
        JobEvent.objects.create(
            job=degraded_job,
            level="warning",
            message="AWG2 runtime telemetry unavailable: using config fallback (degraded mode).",
        )
        regular_warning_job = Job.objects.create(server=self.server, actor=self.user, action="vpn.client.create", status=Job.Status.SUCCESS)
        JobEvent.objects.create(job=regular_warning_job, level="warning", message="Проверьте вручную")

        self.client.force_login(self.user)
        response = self.client.get(reverse("jobs-list"), {"signal": "degraded_success"})
        self.assertContains(response, f"/jobs/{degraded_job.id}/")
        self.assertNotContains(response, f"/jobs/{regular_warning_job.id}/")

    def test_jobs_list_filters_by_my_jobs(self):
        Job.objects.create(server=self.server, actor=self.other, action="vpn.client.delete", status=Job.Status.SUCCESS)
        self.client.force_login(self.user)
        response = self.client.get(reverse("jobs-list"), {"operator_scope": "mine"})
        self.assertContains(response, "server.sync_runtime")
        self.assertNotContains(response, "vpn.client.delete")

    def test_jobs_list_shows_operator_context_labels(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("jobs-list"))
        self.assertContains(response, "Инициатор")
        self.assertContains(response, "Мой")
