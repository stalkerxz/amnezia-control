from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase

from servers.agent_backend import (
    RemoteAWG2AgentAdapter,
)
from vpn.services import (
    AWG2Adapter,
    PeerState,
    RuntimeCommandService,
)


class RuntimeTelemetryLoggingTest(
    SimpleTestCase
):
    @patch(
        "vpn.services."
        "RuntimeCommandService.executor_for_server"
    )
    @patch(
        "vpn.services."
        "JobService.create_job"
    )
    def test_untracked_success_creates_no_job(
        self,
        create_job,
        executor_for_server,
    ):
        executor_for_server.return_value.run.return_value = (
            SimpleNamespace(
                exit_code=0,
                stdout="ok",
                stderr="",
            )
        )

        result = (
            RuntimeCommandService
            .run_untracked(
                SimpleNamespace(),
                "awg2.list_all",
                "docker exec awg wg show all dump",
            )
        )

        self.assertEqual(
            result.stdout,
            "ok",
        )

        create_job.assert_not_called()

    @patch(
        "vpn.services."
        "RuntimeCommandService.executor_for_server"
    )
    @patch(
        "vpn.services."
        "JobService.create_job"
    )
    def test_untracked_expected_failure_creates_no_job(
        self,
        create_job,
        executor_for_server,
    ):
        executor_for_server.return_value.run.return_value = (
            SimpleNamespace(
                exit_code=1,
                stdout="",
                stderr="protocol not supported",
            )
        )

        result = (
            RuntimeCommandService
            .run_with_expected_failure_untracked(
                SimpleNamespace(),
                "awg2.list_all",
                "docker exec awg wg show all dump",
                expected_error_patterns=(
                    "protocol not supported",
                ),
            )
        )

        self.assertIsNone(result)

        create_job.assert_not_called()

    def test_awg2_transfer_poll_is_untracked(
        self,
    ):
        adapter = object.__new__(
            AWG2Adapter
        )

        peer = PeerState(
            public_key="peer-key",
            allowed_ips="10.8.1.10/32",
            transfer_rx=100,
            transfer_tx=200,
        )

        with patch.object(
            adapter,
            "_awg2_runtime_peers",
            return_value=[peer],
        ) as runtime_peers:
            result = (
                adapter
                .peer_transfer_map(None)
            )

        self.assertEqual(
            result,
            {"peer-key": 300},
        )

        runtime_peers.assert_called_once_with(
            None,
            record_job=False,
        )

    @patch(
        "servers.agent_backend._agent_call"
    )
    def test_agent_transfer_poll_is_untracked(
        self,
        agent_call,
    ):
        adapter = object.__new__(
            RemoteAWG2AgentAdapter
        )

        adapter.server = SimpleNamespace()

        agent_call.return_value = {
            "peers": {
                "peer-key": {
                    "rx_bytes": 100,
                    "tx_bytes": 200,
                }
            }
        }

        result = (
            adapter
            .peer_transfer_map(None)
        )

        self.assertEqual(
            result,
            {"peer-key": 300},
        )

        self.assertFalse(
            agent_call
            .call_args
            .kwargs["record_job"]
        )
