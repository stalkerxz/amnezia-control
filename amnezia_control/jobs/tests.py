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
        stdout.read.return_value = b"active"
        stderr.read.return_value = b""
        stdout.channel.recv_exit_status.return_value = 0
        mock_client.exec_command.return_value = (None, stdout, stderr)

        executor = SafeSSHExecutor(host="127.0.0.1", username="u")
        result = executor.run("systemctl is-active amnezia-awg")
        self.assertEqual(result.exit_code, 0)
