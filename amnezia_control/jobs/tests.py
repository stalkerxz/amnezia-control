from unittest.mock import MagicMock, patch

from django.test import TestCase

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
