from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase

from jobs.models import Job, JobEvent
from servers.models import Server


class SensitiveRuntimeLogScrubberTest(TestCase):
    def setUp(self):
        self.actor = get_user_model().objects.create_user(
            "runtime-scrub-admin",
            password="123",
            is_staff=True,
        )
        self.server = Server.objects.create(name="runtime-scrub-server")

    def _event(self, action, stdout="secret", stderr="sensitive-error"):
        job = Job.objects.create(
            server=self.server,
            actor=self.actor,
            action=action,
            payload={"command": "diagnostic-command"},
            status=Job.Status.SUCCESS,
        )
        return JobEvent.objects.create(
            job=job,
            message="Executed",
            stdout=stdout,
            stderr=stderr,
            exit_code=0,
        )

    def test_scrubs_only_known_sensitive_runtime_actions(self):
        inspect_event = self._event(
            "runtime.inspect.awg2",
            stdout='{"Env":["HEADER_PROTECTION_KEY=secret"]}',
        )
        conf_event = self._event(
            "runtime.conf.awg2",
            stdout="[Interface]\nPrivateKey = server-private\n",
        )
        dump_event = self._event(
            "awg2.list_all",
            stdout="awg0\tprivate\tpublic\t51830\npeer\tpsk\tep\n",
        )
        safe_event = self._event(
            "runtime.iface.awg2",
            stdout="awg0",
            stderr="",
        )

        output = StringIO()
        call_command("scrub_sensitive_runtime_logs", stdout=output)

        for event in (inspect_event, conf_event, dump_event):
            event.refresh_from_db()
            self.assertEqual(event.stdout, "")
            self.assertEqual(event.stderr, "")

        safe_event.refresh_from_db()
        self.assertEqual(safe_event.stdout, "awg0")
        self.assertEqual(safe_event.stderr, "")
        self.assertIn("Redacted 3 sensitive runtime JobEvent(s).", output.getvalue())

    def test_dry_run_does_not_modify_events(self):
        event = self._event(
            "runtime.peers.awg2.all",
            stdout="private-runtime-dump",
        )

        output = StringIO()
        call_command(
            "scrub_sensitive_runtime_logs",
            "--dry-run",
            stdout=output,
        )

        event.refresh_from_db()
        self.assertEqual(event.stdout, "private-runtime-dump")
        self.assertEqual(event.stderr, "sensitive-error")
        self.assertIn(
            "Would redact 1 sensitive runtime JobEvent(s).",
            output.getvalue(),
        )
