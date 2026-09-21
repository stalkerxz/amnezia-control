from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from jobs.executors import SafeSSHExecutor
from servers.models import ProtocolProfile, Server, ServerProtocol
from servers.services import ServerService
from vpn.models import VPNClient
from vpn.services import AdapterFactory, VPNClientService


@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class AWG3CompatibilityTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            "awg3-admin",
            password="123",
            is_staff=True,
        )
        self.server = Server.objects.create(
            name="awg3-server",
            public_endpoint_host="vpn.example.com",
            public_endpoint_port=51830,
        )
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            container_name="amnezia-awg2",
            container_status="running",
            enabled=True,
            runtime_metadata={
                "command_bin": "wg",
                "quick_bin": "awg-quick",
                "subnet": "10.77.0.0/24",
                "subnet_ready": True,
                "endpoint_host_ready": True,
                "endpoint_port_ready": True,
                "runtime_interface_ready": True,
                "runtime_command_ready": True,
                "runtime_listener_ready": True,
                "awg_config_supported": True,
                "awg_unsupported_keys": [],
                "awg2_metadata": self._metadata(),
                "awg2_metadata_ready": True,
                "peer_source": "runtime wg dump",
            },
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="awg3-full",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="[Interface]",
        )

    @staticmethod
    def _metadata():
        return {
            "Jc": "7",
            "Jmin": "8",
            "Jmax": "9",
            "S1": "1",
            "S2": "2",
            "S3": "3",
            "S4": "4",
            "H1": "101",
            "H2": "102",
            "H3": "103",
            "H4": "104",
            "I1": "11",
            "HeaderProtectionKey": "base64-key",
            "ContentPaddingAddition": "0-64",
            "RekeyAfterTime": "120-180",
            "RekeyTimeout": "5-10",
            "RejectAfterTime": "180-240",
            "KeepaliveTimeout": "5-15",
            "MaxHandshakeAttempts": "15-20",
            "RandomTrailers": "on",
            "DisableCookies": "on",
        }

    def test_parser_preserves_awg3_keys_and_detects_generation(self):
        conf = "\n".join(
            [
                "[Interface]",
                "Address = 10.77.0.1/24",
                "Jc = 7",
                "Jmin = 8",
                "Jmax = 9",
                "S1 = 1",
                "S2 = 2",
                "S3 = 3",
                "S4 = 4",
                "H1 = 101",
                "H2 = 102",
                "H3 = 103",
                "H4 = 104",
                "HeaderProtectionKey = base64-key",
                "ContentPaddingAddition = 0-64",
                "RandomTrailers = on",
                "DisableCookies = on",
            ]
        )

        parsed, required_missing, _ = ServerService._parse_awg2_metadata([], conf)

        self.assertEqual(required_missing, [])
        self.assertEqual(parsed["HeaderProtectionKey"], "base64-key")
        self.assertEqual(parsed["ContentPaddingAddition"], "0-64")
        self.assertEqual(ServerService._awg_generation(parsed), "3.1")
        capabilities = ServerService._awg_capabilities(parsed)
        self.assertIn("header_protection", capabilities)
        self.assertIn("content_padding", capabilities)
        self.assertIn("random_trailers", capabilities)
        self.assertIn("disable_cookies", capabilities)

    def test_sensitive_awg_metadata_is_encrypted_at_rest(self):
        public_metadata, encrypted_metadata = ServerService._protect_awg_metadata(
            self._metadata()
        )

        self.assertNotIn("HeaderProtectionKey", public_metadata)
        self.assertIn("HeaderProtectionKey", encrypted_metadata)
        self.assertNotEqual(
            encrypted_metadata["HeaderProtectionKey"],
            "base64-key",
        )

        runtime_metadata = dict(self.protocol.runtime_metadata)
        runtime_metadata["awg2_metadata"] = public_metadata
        runtime_metadata["awg_sensitive_metadata_encrypted"] = encrypted_metadata
        self.protocol.runtime_metadata = runtime_metadata
        self.protocol.save(update_fields=["runtime_metadata"])

        resolved = VPNClientService.resolved_awg_runtime_metadata(self.protocol)
        self.assertEqual(resolved["HeaderProtectionKey"], "base64-key")

    def test_runtime_dump_falls_back_from_wg_to_awg(self):
        class Result:
            def __init__(self, stdout):
                self.stdout = stdout

        def run_side_effect(server, actor, action, command, **kwargs):
            if command == "docker exec amnezia-awg2 awg show interfaces":
                return Result("awg0\n")
            raise AssertionError(f"Unexpected runtime command: {command}")

        def expected_side_effect(server, actor, action, command, **kwargs):
            if " wg show " in command:
                return None
            if command == "docker exec amnezia-awg2 awg show all dump":
                return Result(
                    "awg0\tprivate\tpublic\t51830\n"
                    "peer\tpsk\tep\t10.77.0.10/32\t0\t1\t2\t25-35\n"
                )
            raise AssertionError(f"Unexpected expected-failure command: {command}")

        with patch(
            "servers.services.RuntimeCommandService.run",
            side_effect=run_side_effect,
        ), patch(
            "servers.services.RuntimeCommandService.run_with_expected_failure",
            side_effect=expected_side_effect,
        ):
            command_bin, iface, dump = ServerService._discover_awg_runtime_dump(
                server=self.server,
                actor=self.user,
                container_name="amnezia-awg2",
                preferred_command_bin="wg",
                preferred_iface="wg0",
            )

        self.assertEqual(command_bin, "awg")
        self.assertEqual(iface, "awg0")
        self.assertIn("10.77.0.10/32", dump.stdout)

    def test_unknown_interface_parameter_is_fail_closed_marker(self):
        conf = (
            "[Interface]\n"
            "Address = 10.77.0.1/24\n"
            "Jc = 7\n"
            "FutureHandshakeMode = on\n"
            "[Peer]\n"
            "PublicKey = peer\n"
        )

        self.assertEqual(
            ServerService._unsupported_awg_interface_keys(conf),
            ["FutureHandshakeMode"],
        )

    def test_awg3_params_are_exported_in_interface_section(self):
        config = VPNClientService.build_awg2_client_config(
            private_key="private",
            address="10.77.0.10",
            endpoint="vpn.example.com:51830",
            server_public_key="server-public",
            awg2_metadata=self._metadata(),
        )

        interface_block, peer_block = config.split("[Peer]", 1)
        self.assertIn("HeaderProtectionKey = base64-key", interface_block)
        self.assertIn("ContentPaddingAddition = 0-64", interface_block)
        self.assertIn("RandomTrailers = on", interface_block)
        self.assertNotIn("HeaderProtectionKey", peer_block)
        self.assertIn("PersistentKeepalive = 25-35", peer_block)

    def test_reissue_blocks_before_old_peer_is_removed_for_unknown_runtime_params(self):
        metadata = dict(self.protocol.runtime_metadata)
        metadata["awg_config_supported"] = False
        metadata["awg_unsupported_keys"] = ["FutureHandshakeMode"]
        self.protocol.runtime_metadata = metadata
        self.protocol.save(update_fields=["runtime_metadata"])

        client = VPNClient.objects.create(
            server=self.server,
            name="unsafe-reissue",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=self.profile,
            created_by=self.user,
            status=VPNClient.Status.ACTIVE,
            runtime_peer_public_key="old-peer-key",
            runtime_address="10.77.0.10",
        )
        adapter = AdapterFactory.get_for_client(client)

        with patch(
            "vpn.services.AdapterFactory.get_for_client",
            return_value=adapter,
        ), patch.object(adapter, "remove_peer") as remove_peer:
            with self.assertRaisesRegex(
                RuntimeError,
                "FutureHandshakeMode",
            ):
                VPNClientService.reissue_config(
                    client=client,
                    actor=self.user,
                )

        remove_peer.assert_not_called()

    def test_adapter_uses_discovered_runtime_command_binary(self):
        metadata = dict(self.protocol.runtime_metadata)
        metadata["command_bin"] = "awg"
        self.protocol.runtime_metadata = metadata
        self.protocol.save(update_fields=["runtime_metadata"])

        adapter = AdapterFactory.get_for_server(
            self.server,
            VPNClient.ProtocolType.AWG2,
        )

        self.assertEqual(adapter.command_bin, "wg")
        self.assertEqual(adapter.effective_command_bin, "awg")
        self.assertIn(" awg show interfaces", adapter._wg_cmd("show interfaces"))

    def test_health_is_degraded_for_mtu_mismatch_and_unsupported_config(self):
        self.server.last_runtime_sync_at = timezone.now()
        self.server.save(update_fields=["last_runtime_sync_at"])
        metadata = dict(self.protocol.runtime_metadata)
        metadata.update(
            {
                "config_mtu": 1420,
                "runtime_mtu": 1376,
                "mtu_mismatch": True,
                "awg_config_supported": False,
                "awg_unsupported_keys": ["FutureHandshakeMode"],
            }
        )
        self.protocol.runtime_metadata = metadata
        self.protocol.save(update_fields=["runtime_metadata"])

        result = ServerService.evaluate_health(self.server)

        self.assertEqual(result["status"], ServerService.HEALTH_DEGRADED)
        self.assertTrue(any("MTU mismatch" in reason for reason in result["reasons"]))
        self.assertTrue(any("FutureHandshakeMode" in reason for reason in result["reasons"]))

    def test_health_is_unhealthy_when_runtime_listener_is_missing(self):
        self.server.last_runtime_sync_at = timezone.now()
        self.server.save(update_fields=["last_runtime_sync_at"])
        metadata = dict(self.protocol.runtime_metadata)
        metadata["runtime_listener_ready"] = False
        self.protocol.runtime_metadata = metadata
        self.protocol.save(update_fields=["runtime_metadata"])

        result = ServerService.evaluate_health(self.server)

        self.assertEqual(result["status"], ServerService.HEALTH_UNHEALTHY)
        self.assertTrue(any("listen-port" in reason for reason in result["reasons"]))

    def test_safe_executor_accepts_only_expected_readiness_probes(self):
        executor = SafeSSHExecutor(host="127.0.0.1", username="u")

        executor._validate("docker exec amnezia-awg2 wg show awg0 listen-port")
        executor._validate("docker exec amnezia-awg2 awg show awg0 listen-port")
        executor._validate("docker exec amnezia-awg2 ip -o link show awg0")

        with self.assertRaises(ValueError):
            executor._validate("docker exec amnezia-awg2 sh -lc 'ip link; id'")
