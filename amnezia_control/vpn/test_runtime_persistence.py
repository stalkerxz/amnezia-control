from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from jobs.executors import SafeSSHExecutor
from servers.models import Server, ServerProtocol
from vpn.models import VPNClient
from vpn.services import AWG2Adapter, RuntimeCommandService


class AWG2RuntimePersistenceTest(TestCase):
    def setUp(self):
        self.actor = get_user_model().objects.create_user(
            username="persistence-admin",
            password="test",
            is_staff=True,
        )
        self.server = Server.objects.create(
            name="runtime-persistence",
            host="127.0.0.1",
        )
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=VPNClient.ProtocolType.AWG2,
            container_name="amnezia-awg2",
            enabled=True,
            runtime_metadata={
                "interface": "awg0",
                "subnet": "10.8.1.0/24",
                "config_path": "/opt/amnezia/awg/awg0.conf",
            },
        )
        self.adapter = AWG2Adapter(self.server)

    def test_allowlist_accepts_awg2_save(self):
        executor = SafeSSHExecutor(
            host="127.0.0.1",
            username="root",
        )

        executor._validate(
            "docker exec amnezia-awg2 "
            "awg-quick save /opt/amnezia/awg/awg0.conf"
        )

    def test_allowlist_rejects_unsafe_save_path(self):
        executor = SafeSSHExecutor(
            host="127.0.0.1",
            username="root",
        )

        with self.assertRaises(ValueError):
            executor._validate(
                "docker exec amnezia-awg2 "
                "awg-quick save /tmp/../../etc/shadow"
            )

    def test_persist_runtime_uses_discovered_config_path(self):
        calls = []

        def fake_run(server, actor, action, command, **kwargs):
            calls.append(
                {
                    "action": action,
                    "command": command,
                    "sensitive_output": kwargs.get(
                        "sensitive_output",
                        False,
                    ),
                }
            )

            class Result:
                stdout = ""
                stderr = ""
                exit_code = 0

            return Result()

        with patch.object(
            RuntimeCommandService,
            "run",
            side_effect=fake_run,
        ):
            self.adapter._persist_runtime(self.actor)

        self.assertEqual(len(calls), 1)
        self.assertEqual(
            calls[0]["action"],
            "awg2.save_runtime",
        )
        self.assertEqual(
            calls[0]["command"],
            "flock -x -w 10 "
            "/run/lock/amnezia-control-awg2-save.lock "
            "docker exec amnezia-awg2 "
            "awg-quick save /opt/amnezia/awg/awg0.conf",
        )
        self.assertTrue(calls[0]["sensitive_output"])

    def test_create_peer_rolls_back_live_peer_when_persist_fails(self):
        calls = []

        def fake_run(actor, action, command, sensitive_output=False):
            calls.append(action)

            class Result:
                stdout = ""

            return Result()

        with patch.object(
            self.adapter,
            "interface_name",
            return_value="awg0",
        ), patch.object(
            self.adapter,
            "generate_keypair",
            return_value=("private", "new-public"),
        ), patch.object(
            self.adapter,
            "generate_preshared_key",
            return_value="psk",
        ), patch.object(
            self.adapter,
            "_next_address",
            return_value="10.8.1.20",
        ), patch.object(
            self.adapter,
            "_run",
            side_effect=fake_run,
        ), patch.object(
            self.adapter,
            "_persist_runtime",
            side_effect=[
                RuntimeError("save failed"),
                None,
            ],
        ) as persist_mock, patch.object(
            self.adapter,
            "server_public_key",
        ) as server_key_mock:
            with self.assertRaisesRegex(
                RuntimeError,
                "save failed",
            ):
                self.adapter.create_peer(
                    self.actor
                )

        self.assertEqual(
            calls,
            [
                "awg2.add_peer",
                "awg2.rollback_peer",
            ],
        )
        self.assertEqual(
            persist_mock.call_count,
            2,
        )
        server_key_mock.assert_not_called()

    def test_create_peer_reports_incomplete_compensation(self):
        calls = []

        def fake_run(actor, action, command, sensitive_output=False):
            calls.append(action)

            class Result:
                stdout = ""

            if action == "awg2.rollback_peer":
                raise RuntimeError(
                    "rollback failed"
                )

            return Result()

        with patch.object(
            self.adapter,
            "interface_name",
            return_value="awg0",
        ), patch.object(
            self.adapter,
            "generate_keypair",
            return_value=("private", "new-public"),
        ), patch.object(
            self.adapter,
            "generate_preshared_key",
            return_value="psk",
        ), patch.object(
            self.adapter,
            "_next_address",
            return_value="10.8.1.20",
        ), patch.object(
            self.adapter,
            "_run",
            side_effect=fake_run,
        ), patch.object(
            self.adapter,
            "_persist_runtime",
            side_effect=RuntimeError(
                "save failed"
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "runtime cleanup was incomplete",
            ):
                self.adapter.create_peer(
                    self.actor
                )

        self.assertEqual(
            calls,
            [
                "awg2.add_peer",
                "awg2.rollback_peer",
            ],
        )

    def test_missing_config_path_is_backward_compatible(self):
        self.protocol.runtime_metadata = {
            "interface": "awg0",
            "subnet": "10.8.1.0/24",
        }
        self.protocol.save(update_fields=["runtime_metadata"])

        adapter = AWG2Adapter(self.server)

        with patch.object(
            RuntimeCommandService,
            "run",
        ) as runtime_run:
            adapter._persist_runtime(self.actor)

        runtime_run.assert_not_called()
