from io import StringIO

from cryptography.fernet import Fernet
from django.core.management import call_command
from django.test import TestCase, override_settings

from jobs.models import Job, JobEvent
from jobs.services import (
    JobService,
    SENSITIVE_OUTPUT_PLACEHOLDER,
)
from servers.models import Server, ServerProtocol
from vpn.services import ConfigCryptoService


@override_settings(
    CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode()
)
class RuntimeSecretScrubTest(TestCase):
    def setUp(self):
        self.server = Server.objects.create(
            name="secret-hardening-server",
        )
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            runtime_metadata={
                "awg2_metadata": {
                    "Jc": "6",
                    "HeaderProtectionKey": "plain-secret",
                },
                "awg2_active_keys": [
                    "Jc",
                    "HeaderProtectionKey",
                ],
            },
        )
        self.job = Job.objects.create(
            server=self.server,
            action="runtime.conf.awg2",
        )

    def test_job_service_redacts_sensitive_stdout(self):
        event = JobService.event(
            self.job,
            "runtime output",
            stdout=(
                "[Interface]\n"
                "PrivateKey = private-value\n"
                "HeaderProtectionKey = header-value\n"
            ),
        )

        self.assertEqual(
            event.stdout,
            SENSITIVE_OUTPUT_PLACEHOLDER,
        )
        self.assertNotIn(
            "private-value",
            event.stdout,
        )
        self.assertNotIn(
            "header-value",
            event.stdout,
        )

    def test_job_service_redacts_compact_env_secret_alias(self):
        event = JobService.event(
            self.job,
            "runtime env",
            stdout=(
                "AWG2_HEADERPROTECTIONKEY="
                "compact-header-secret"
            ),
        )

        self.assertEqual(
            event.stdout,
            SENSITIVE_OUTPUT_PLACEHOLDER,
        )
        self.assertNotIn(
            "compact-header-secret",
            event.stdout,
        )

    def test_scrubber_is_dry_run_by_default(self):
        JobEvent.objects.create(
            job=self.job,
            message="legacy",
            stdout="PresharedKey = old-psk",
        )

        out = StringIO()
        call_command(
            "scrub_runtime_secrets",
            stdout=out,
        )

        self.protocol.refresh_from_db()
        event = JobEvent.objects.get(
            message="legacy"
        )

        self.assertIn(
            "HeaderProtectionKey",
            self.protocol.runtime_metadata[
                "awg2_metadata"
            ],
        )
        self.assertIn(
            "old-psk",
            event.stdout,
        )
        self.assertIn(
            "DRY RUN",
            out.getvalue(),
        )

    def test_scrubber_encrypts_runtime_secret_and_redacts_history(self):
        JobEvent.objects.create(
            job=self.job,
            message="legacy",
            stdout=(
                "[Interface]\n"
                "PrivateKey = old-private\n"
                "HeaderProtectionKey = old-header\n"
            ),
        )

        call_command(
            "scrub_runtime_secrets",
            "--apply",
        )

        self.protocol.refresh_from_db()
        metadata = (
            self.protocol.runtime_metadata
        )
        public_metadata = (
            metadata["awg2_metadata"]
        )
        secret_metadata = (
            metadata[
                "awg2_secret_metadata"
            ]
        )

        self.assertNotIn(
            "HeaderProtectionKey",
            public_metadata,
        )
        encrypted = secret_metadata[
            "HeaderProtectionKey"
        ]
        self.assertNotEqual(
            encrypted,
            "plain-secret",
        )
        self.assertEqual(
            ConfigCryptoService.decrypt(
                encrypted
            ),
            "plain-secret",
        )
        self.assertIn(
            "HeaderProtectionKey",
            metadata[
                "awg2_active_keys"
            ],
        )

        event = JobEvent.objects.get(
            message="legacy"
        )
        self.assertEqual(
            event.stdout,
            SENSITIVE_OUTPUT_PLACEHOLDER,
        )
        self.assertNotIn(
            "old-private",
            event.stdout,
        )
