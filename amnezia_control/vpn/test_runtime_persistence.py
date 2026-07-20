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
            "docker exec amnezia-awg2 "
            "awg-quick save /opt/amnezia/awg/awg0.conf",
        )
        self.assertTrue(calls[0]["sensitive_output"])

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
