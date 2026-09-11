from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, TestCase
from django.utils import timezone

from servers.agent_backend import (
    RemoteAWG2AgentAdapter,
)
from vpn.services import (
    AWG2Adapter,
    PeerState,
    RuntimeCommandService,
    VPNClientLimitsService,
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


class BackgroundAuditNoiseTest(TestCase):
    @patch(
        "vpn.services.AuditService.log"
    )
    def test_clean_system_cycles_are_not_audited(
        self,
        audit_log,
    ):
        traffic = (
            VPNClientLimitsService
            .sync_traffic_usage(
                actor=None,
            )
        )

        limits = (
            VPNClientLimitsService
            .enforce_limits(
                actor=None,
            )
        )

        self.assertEqual(
            traffic,
            {
                "synced": 0,
                "unavailable": 0,
            },
        )

        self.assertEqual(
            limits,
            {
                "processed": 0,
                "expired": 0,
                "traffic_exceeded": 0,
            },
        )

        audit_log.assert_not_called()

    @patch(
        "vpn.services.AuditService.log"
    )
    def test_manual_clean_cycles_remain_audited(
        self,
        audit_log,
    ):
        actor = object()

        (
            VPNClientLimitsService
            .sync_traffic_usage(
                actor=actor,
            )
        )

        (
            VPNClientLimitsService
            .enforce_limits(
                actor=actor,
            )
        )

        actions = [
            call.args[1]
            for call
            in audit_log.call_args_list
        ]

        self.assertEqual(
            actions,
            [
                "client.limit.traffic_sync",
                "client.limit.enforce",
            ],
        )

    @patch(
        "vpn.services.AuditService.log"
    )
    @patch(
        "vpn.services."
        "AdapterFactory.get_for_server",
        side_effect=RuntimeError(
            "runtime unavailable"
        ),
    )
    @patch(
        "vpn.services.VPNClient.objects.filter"
    )
    def test_system_telemetry_failure_is_audited(
        self,
        filter_clients,
        _adapter_factory,
        audit_log,
    ):
        client = SimpleNamespace(
            server_id=1,
            protocol_type="awg2",
            server=SimpleNamespace(),
            save=Mock(),
        )

        queryset = Mock()

        (
            filter_clients
            .return_value
            .exclude
            .return_value
            .select_related
            .return_value
        ) = [client]

        result = (
            VPNClientLimitsService
            .sync_traffic_usage(
                actor=None,
            )
        )

        self.assertEqual(
            result,
            {
                "synced": 0,
                "unavailable": 1,
            },
        )

        audit_log.assert_called_once()

        self.assertEqual(
            audit_log.call_args.args[1],
            "client.limit.traffic_sync",
        )

    @patch(
        "vpn.services.AuditService.log"
    )
    @patch(
        "vpn.services."
        "VPNClientService.set_status"
    )
    @patch(
        "vpn.services."
        "VPNClient.objects.select_related"
    )
    def test_system_enforcement_change_is_audited(
        self,
        select_related,
        set_status,
        audit_log,
    ):
        client = SimpleNamespace(
            expires_at=(
                timezone.now()
                - timedelta(seconds=1)
            ),
            traffic_limit_bytes=None,
            traffic_used_bytes=0,
        )

        (
            select_related
            .return_value
            .filter
            .return_value
        ) = [client]

        result = (
            VPNClientLimitsService
            .enforce_limits(
                actor=None,
            )
        )

        self.assertEqual(
            result["expired"],
            1,
        )

        self.assertEqual(
            result["traffic_exceeded"],
            0,
        )

        set_status.assert_called_once()
        audit_log.assert_called_once()

        self.assertEqual(
            audit_log.call_args.args[1],
            "client.limit.enforce",
        )
