import os
from tempfile import TemporaryDirectory
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from jobs.executors import ExecutionResult
from servers.models import ProtocolProfile, Server, ServerProtocol

from .models import VPNClient
from .preflight import ClientCreationPreflightService


class ClientCreationPreflightTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("preflight-admin", password="123", is_staff=True)
        self.client.force_login(self.user)
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.key_path = os.path.join(self.tmp.name, "id_ed25519")
        self.known_hosts_path = os.path.join(self.tmp.name, "known_hosts")
        with open(self.key_path, "w", encoding="utf-8") as fh:
            fh.write("test-private-key")
        os.chmod(self.key_path, 0o600)
        with open(self.known_hosts_path, "w", encoding="utf-8") as fh:
            fh.write("203.0.113.10 ssh-ed25519 AAAATESTKEY\n")
        os.chmod(self.known_hosts_path, 0o600)

        self.server = Server.objects.create(
            name="preflight-server",
            host="203.0.113.10",
            port=22,
            ssh_username="root",
            ssh_private_key_path=self.key_path,
            public_endpoint_host="vpn.example.com",
            public_endpoint_port=51830,
            last_runtime_sync_at=timezone.now(),
            is_enabled=True,
        )
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
            runtime_metadata={
                "interface": "awg0",
                "config_path": "/opt/amnezia/awg/awg0.conf",
                "subnet": "10.8.1.0/24",
                "peer_count": 33,
                "endpoint_host_ready": True,
                "endpoint_port_ready": True,
                "subnet_ready": True,
                "awg2_metadata": {
                    "Jc": "7",
                    "Jmin": "8",
                    "Jmax": "9",
                    "S1": "1",
                    "S2": "2",
                    "S3": "3",
                    "S4": "4",
                    "H1": "1",
                    "H2": "2",
                    "H3": "3",
                    "H4": "4",
                },
            },
        )
        ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="default-awg2",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            status=ProtocolProfile.ProfileStatus.ACTIVE,
            config_template="[Interface]",
        )

    def _env(self):
        return patch.dict(os.environ, {"SSH_KNOWN_HOSTS_PATH": self.known_hosts_path})

    def test_ready_when_all_blocking_checks_pass(self):
        ssh_result = ExecutionResult(
            command="docker ps --format '{{.Names}}'",
            exit_code=0,
            stdout="amnezia-awg2\namnezia-control-worker-1\n",
            stderr="",
        )
        with self._env(), patch("vpn.preflight.SafeSSHExecutor.run", return_value=ssh_result), patch.object(
            ClientCreationPreflightService,
            "_worker_state",
            return_value=(True, "Активных worker: 1."),
        ):
            result = ClientCreationPreflightService.check(
                server=self.server,
                protocol_type=VPNClient.ProtocolType.AWG2,
                include_live=True,
            )

        self.assertTrue(result["ready"])
        self.assertTrue(all(item["ok"] or not item["blocking"] for item in result["checks"]))

    def test_live_ssh_failure_blocks_creation(self):
        with self._env(), patch("vpn.preflight.SafeSSHExecutor.run", side_effect=RuntimeError("Authentication failed")), patch.object(
            ClientCreationPreflightService,
            "_worker_state",
            return_value=(True, "Активных worker: 1."),
        ):
            result = ClientCreationPreflightService.check(
                server=self.server,
                protocol_type=VPNClient.ProtocolType.AWG2,
                include_live=True,
            )

        self.assertFalse(result["ready"])
        ssh_check = next(item for item in result["checks"] if item["key"] == "ssh_live")
        self.assertFalse(ssh_check["ok"])
        self.assertIn("Authentication failed", ssh_check["detail"])

    def test_post_is_blocked_when_preflight_fails(self):
        failed_result = {
            "ready": False,
            "checks": [
                {
                    "key": "ssh_live",
                    "label": "Живое SSH-подключение",
                    "ok": False,
                    "detail": "Authentication failed",
                    "blocking": True,
                }
            ],
        }
        with patch("vpn.middleware.ClientCreationPreflightService.check", return_value=failed_result):
            response = self.client.post(
                "/clients/new/",
                data={"name": "blocked-client", "protocol_type": VPNClient.ProtocolType.AWG2},
                follow=True,
            )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(VPNClient.objects.filter(name="blocked-client").exists())
        self.assertContains(response, "Создание клиента заблокировано")

    def test_preflight_endpoint_returns_structured_result(self):
        ready_result = {
            "ready": True,
            "server": self.server.name,
            "protocol_type": VPNClient.ProtocolType.AWG2,
            "checks": [],
            "checked_at": "01.01.2030 10:00:00",
        }
        with patch("vpn.preflight_views.ClientCreationPreflightService.check", return_value=ready_result):
            response = self.client.get("/clients/preflight/", {"protocol": VPNClient.ProtocolType.AWG2})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["ready"])

    def test_runtime_peer_import_routes_are_disabled_by_default(self):
        self.assertFalse(settings.ENABLE_RUNTIME_PEER_IMPORT)
        self.assertEqual(self.client.post("/clients/import/").status_code, 404)
        self.assertEqual(self.client.post(f"/servers/{self.server.id}/import-peers/").status_code, 404)
