from cryptography.fernet import Fernet
from audit.models import AuditLog
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from jobs.models import Job
from servers.models import ProtocolProfile, Server, ServerProtocol
from servers.services import ServerService
from portal.services import PortalAccessService

from .forms import VPNClientCreateForm, VPNClientLimitsUpdateForm
from .models import VPNClient
from .services import AWG2Adapter, AdapterFactory, PeerState, RuntimeCommandService, VPNClientLimitsService, VPNClientService


@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class VPNClientFlowTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin", password="123", is_staff=True)
        self.server = Server.objects.create(name="local", public_endpoint_host="vpn.example.com")
        self.awg_protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            container_name="amnezia-awg",
            enabled=True,
            runtime_metadata={"udp_port": 51820, "subnet": "10.66.0.0/24"},
        )
        self.awg2_protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            container_name="amnezia-awg2",
            enabled=True,
            runtime_metadata={
                "udp_port": 51830,
                "subnet": "10.77.0.0/24",
                "awg2_metadata": {"I1": "11", "I2": "12", "I3": "13", "I4": "14", "I5": "15", "S1": "1", "S2": "2", "S3": "3", "S4": "4", "Jc": "7", "Jmin": "8", "Jmax": "9", "H1": "3", "H2": "4", "H3": "5", "H4": "6"},
            },
        )
        ProtocolProfile.objects.create(server_protocol=self.awg_protocol, name="default-awg", protocol_type=ServerProtocol.ProtocolType.AWG, config_template="[Interface]")
        ProtocolProfile.objects.create(server_protocol=self.awg2_protocol, name="default-awg2", protocol_type=ServerProtocol.ProtocolType.AWG2, config_template="[Interface]")

    def _mock_run(self, *args, **kwargs):
        class R:
            def __init__(self, stdout):
                self.stdout = stdout

        action = args[2]
        mapping = {
            "awg.iface": R("awg0\n"),
            "awg.genkey": R("client-private-key==\n"),
            "awg.pubkey": R("client-public-key==\n"),
            "awg.genpsk": R("client-psk==\n"),
            "awg.add_peer": R(""),
            "awg.add_existing_peer": R(""),
            "awg.remove_peer": R(""),
            "awg.server_pub": R("server-public-key==\n"),
            "awg.list": R("peerkey\tpsk\tendpoint\t10.66.0.10/32\t0\t0\t0\t25\n"),
            "awg2.iface": R("wg0\n"),
            "awg2.genkey": R("client2-private-key==\n"),
            "awg2.pubkey": R("client2-public-key==\n"),
            "awg2.genpsk": R("client2-psk==\n"),
            "awg2.add_peer": R(""),
            "awg2.add_existing_peer": R(""),
            "awg2.remove_peer": R(""),
            "awg2.server_pub": R("server2-public-key==\n"),
            "awg2.list": R("peer2\tpsk\tendpoint\t10.77.0.10/32\t0\t0\t0\t25\n"),
        }
        return mapping[action]

    def test_endpoint_discovery_uses_server_override(self):
        endpoint = VPNClientService.resolve_endpoint(self.server, self.awg_protocol)
        self.assertEqual(endpoint, "vpn.example.com:51820")

    def test_prevent_localhost_endpoint_export(self):
        self.server.public_endpoint_host = "127.0.0.1"
        self.server.save(update_fields=["public_endpoint_host"])
        self.awg_protocol.runtime_metadata["public_host"] = ""
        self.awg_protocol.save(update_fields=["runtime_metadata"])
        with self.assertRaises(RuntimeError):
            VPNClientService.resolve_endpoint(self.server, self.awg_protocol)

    def test_config_export_for_awg_legacy(self):
        from unittest.mock import patch

        with patch("vpn.services.RuntimeCommandService.run", side_effect=self._mock_run):
            client = VPNClientService.create_client(server=self.server, name="awg-client", protocol_type=VPNClient.ProtocolType.AWG, actor=self.user)
        conf = VPNClientService.latest_config(client)
        self.assertIn("Endpoint = vpn.example.com:51820", conf)
        self.assertIn("PresharedKey = client-psk==", conf)
        self.assertNotIn("YOUR_VPS_IP", conf)

    def test_config_export_for_awg2_uses_discovered_metadata(self):
        from unittest.mock import patch

        with patch("vpn.services.RuntimeCommandService.run", side_effect=self._mock_run):
            client = VPNClientService.create_client(server=self.server, name="awg2-client", protocol_type=VPNClient.ProtocolType.AWG2, actor=self.user)
        conf = VPNClientService.latest_config(client)
        self.assertIn("I1 = 11", conf)
        self.assertIn("S4 = 4", conf)
        self.assertIn("Jc = 7", conf)
        self.assertIn("H4 = 6", conf)
        self.assertIn("[Peer]\nPublicKey = server2-public-key==", conf)
        self.assertIn("PresharedKey = client2-psk==", conf)


    def test_awg2_export_succeeds_without_optional_i_keys(self):
        from unittest.mock import patch

        self.awg2_protocol.runtime_metadata["awg2_metadata"] = {
            "S1": "1", "S2": "2", "S3": "3", "S4": "4",
            "Jc": "7", "Jmin": "8", "Jmax": "9",
            "H1": "3", "H2": "4", "H3": "5", "H4": "6",
        }
        self.awg2_protocol.save(update_fields=["runtime_metadata"])
        with patch("vpn.services.RuntimeCommandService.run", side_effect=self._mock_run):
            client = VPNClientService.create_client(server=self.server, name="awg2-no-i", protocol_type=VPNClient.ProtocolType.AWG2, actor=self.user)
        conf = VPNClientService.latest_config(client)
        self.assertIn("Jc = 7", conf)
        self.assertNotIn("I1 =", conf)

    def test_native_awg2_export_moves_amnezia_fields_to_interface(self):
        from unittest.mock import patch

        with patch("vpn.services.RuntimeCommandService.run", side_effect=self._mock_run):
            client = VPNClientService.create_client(server=self.server, name="awg2-native", protocol_type=VPNClient.ProtocolType.AWG2, actor=self.user)

        native_conf = VPNClientService.build_native_client_config(client)
        interface_block = native_conf.split("[Peer]")[0]
        peer_block = native_conf.split("[Peer]")[1]
        self.assertIn("Jc = 7", interface_block)
        self.assertIn("S4 = 4", interface_block)
        self.assertIn("H4 = 6", interface_block)
        self.assertIn("I1 = 11", interface_block)
        self.assertNotIn("Jc = 7", peer_block)
        self.assertNotIn("S4 = 4", peer_block)
        self.assertNotIn("H4 = 6", peer_block)
        self.assertIn("Endpoint = vpn.example.com:51830", peer_block)

    def test_native_export_uses_runtime_client_address(self):
        conf = (
            "[Interface]\n"
            "PrivateKey = private\n"
            "Address = 10.66.0.1/24\n"
            "DNS = 1.1.1.1\n\n"
            "[Peer]\n"
            "PublicKey = server\n"
            "Endpoint = vpn.example.com:51820\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
        )
        client = VPNClient.objects.create(
            server=self.server,
            name="native-runtime-address",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=ProtocolProfile.objects.filter(protocol_type=ServerProtocol.ProtocolType.AWG).first(),
            created_by=self.user,
            runtime_address="10.66.0.22",
        )
        VPNClientService._store_revision(client, conf)

        native_conf = VPNClientService.build_native_client_config(client)
        self.assertIn("Address = 10.66.0.22/32", native_conf)
        self.assertNotIn("Address = 10.66.0.1/24", native_conf)

    def test_native_export_peer_block_contains_peer_specific_fields_only(self):
        conf = (
            "[Interface]\n"
            "PrivateKey = private\n"
            "Address = 10.66.0.10/32\n"
            "DNS = 1.1.1.1\n\n"
            "[Peer]\n"
            "PublicKey = server\n"
            "PresharedKey = psk\n"
            "Endpoint = vpn.example.com:51820\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
            "Jc = 7\n"
            "S1 = 1\n"
        )
        client = VPNClient.objects.create(
            server=self.server,
            name="native-peer-fields",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=ProtocolProfile.objects.filter(protocol_type=ServerProtocol.ProtocolType.AWG).first(),
            created_by=self.user,
        )
        VPNClientService._store_revision(client, conf)

        native_conf = VPNClientService.build_native_client_config(client)
        peer_block = native_conf.split("[Peer]")[1]
        self.assertIn("PublicKey = server", peer_block)
        self.assertIn("PresharedKey = psk", peer_block)
        self.assertIn("Endpoint = vpn.example.com:51820", peer_block)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", peer_block)
        self.assertIn("PersistentKeepalive = 25", peer_block)
        self.assertNotIn("Jc =", peer_block)
        self.assertNotIn("S1 =", peer_block)

    def test_native_export_keeps_full_amnezia_interface_keys(self):
        conf = (
            "[Interface]\n"
            "PrivateKey = private\n"
            "Address = 10.77.0.12/32\n\n"
            "[Peer]\n"
            "PublicKey = server\n"
            "Endpoint = vpn.example.com:51830\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
        )
        client = VPNClient.objects.create(
            server=self.server,
            name="native-awg2-interface-keys",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=ProtocolProfile.objects.filter(protocol_type=ServerProtocol.ProtocolType.AWG2).first(),
            created_by=self.user,
            runtime_address="10.77.0.12",
        )
        VPNClientService._store_revision(client, conf)

        native_conf = VPNClientService.build_native_client_config(client)
        interface_block = native_conf.split("[Peer]")[0]
        for key, value in {
            "Jc": "7",
            "Jmin": "8",
            "Jmax": "9",
            "S1": "1",
            "S2": "2",
            "S3": "3",
            "S4": "4",
            "H1": "3",
            "H2": "4",
            "H3": "5",
            "H4": "6",
            "I1": "11",
            "I2": "12",
            "I3": "13",
            "I4": "14",
            "I5": "15",
        }.items():
            self.assertIn(f"{key} = {value}", interface_block)

    def test_awg2_missing_metadata_fails_export(self):
        from unittest.mock import patch

        self.awg2_protocol.runtime_metadata = {"udp_port": 51830, "subnet": "10.77.0.0/24", "awg2_metadata": {"S1": "1"}}
        self.awg2_protocol.save(update_fields=["runtime_metadata"])
        with patch("vpn.services.RuntimeCommandService.run", side_effect=self._mock_run):
            with self.assertRaises(RuntimeError):
                VPNClientService.create_client(server=self.server, name="awg2-broken", protocol_type=VPNClient.ProtocolType.AWG2, actor=self.user)



    def test_awg2_export_fails_when_subnet_missing(self):
        from unittest.mock import patch

        self.awg2_protocol.runtime_metadata.pop("subnet", None)
        self.awg2_protocol.save(update_fields=["runtime_metadata"])
        with patch("vpn.services.RuntimeCommandService.run", side_effect=self._mock_run):
            with self.assertRaises(RuntimeError):
                VPNClientService.create_client(server=self.server, name="awg2-no-subnet", protocol_type=VPNClient.ProtocolType.AWG2, actor=self.user)

    def test_export_succeeds_with_runtime_public_host(self):
        from unittest.mock import patch

        self.server.public_endpoint_host = ""
        self.server.host = "127.0.0.1"
        self.server.save(update_fields=["public_endpoint_host", "host"])
        self.awg_protocol.runtime_metadata["public_host"] = "vpn2.example.com"
        self.awg_protocol.save(update_fields=["runtime_metadata"])

        with patch("vpn.services.RuntimeCommandService.run", side_effect=self._mock_run):
            client = VPNClientService.create_client(server=self.server, name="awg-client-runtime-host", protocol_type=VPNClient.ProtocolType.AWG, actor=self.user)
        conf = VPNClientService.latest_config(client)
        self.assertIn("Endpoint = vpn2.example.com:51820", conf)


    def test_export_succeeds_with_parser_normalized_metadata(self):
        from unittest.mock import patch

        env = [
            "AWG2_I1=11", "AWG2_I2=12", "AWG2_I3=13", "AWG2_I4=14", "AWG2_I5=15",
            "AWG2_S1=1", "AWG2_S2=2", "AWG2_S3=3", "AWG2_S4=4",
            "AWG2_JC=7", "AWG2_JMIN=8", "AWG2_JMAX=9",
            "AWG2_H1=3", "AWG2_H2=4", "AWG2_H3=5", "AWG2_H4=6",
        ]
        parsed, required_missing, optional_missing = ServerService._parse_awg2_metadata(env, "")
        self.assertEqual(required_missing, [])
        self.assertEqual(optional_missing, [])
        self.awg2_protocol.runtime_metadata["awg2_metadata"] = parsed
        self.awg2_protocol.save(update_fields=["runtime_metadata"])

        with patch("vpn.services.RuntimeCommandService.run", side_effect=self._mock_run):
            client = VPNClientService.create_client(server=self.server, name="awg2-parser-ok", protocol_type=VPNClient.ProtocolType.AWG2, actor=self.user)
        conf = VPNClientService.latest_config(client)
        self.assertIn("Jc = 7", conf)
        self.assertIn("Jmin = 8", conf)
        self.assertIn("Jmax = 9", conf)

    def test_adapter_factory_separates_protocols(self):
        awg_adapter = AdapterFactory.get_for_server(self.server, VPNClient.ProtocolType.AWG)
        awg2_adapter = AdapterFactory.get_for_server(self.server, VPNClient.ProtocolType.AWG2)
        self.assertEqual(awg_adapter.command_bin, "wg")
        self.assertEqual(awg2_adapter.command_bin, "wg")

    def test_parse_peers_from_config_text(self):
        raw_conf = (
            "[Interface]\nAddress = 10.77.0.1/24\n"
            "[Peer]\nPublicKey = pk1\nAllowedIPs = 10.77.0.10/32\n"
            "[Peer]\nPublicKey = pk2\nAllowedIPs = 10.77.0.11/32, 10.77.0.12/32\n"
        )
        peers = AWG2Adapter._parse_peers_from_config_text(raw_conf)
        self.assertEqual(len(peers), 2)
        self.assertEqual(peers[0].public_key, "pk1")
        self.assertIn("10.77.0.11/32", peers[1].allowed_ips)

    def test_next_address_uses_all_allowed_ips_tokens(self):
        from unittest.mock import patch

        self.awg2_protocol.runtime_metadata["subnet"] = "10.77.0.0/29"
        self.awg2_protocol.save(update_fields=["runtime_metadata"])

        class R:
            def __init__(self, stdout):
                self.stdout = stdout

        def run_side_effect(*args, **kwargs):
            action = args[2]
            mapping = {
                "awg2.list": R(
                    "peerA\tpsk\tep\t10.77.0.2/32,10.77.0.3/32\t0\t0\t0\t25\n"
                    "peerB\tpsk\tep\t10.77.0.4/32\t0\t0\t0\t25\n"
                )
            }
            return mapping[action]

        with patch("vpn.services.RuntimeCommandService.run", side_effect=run_side_effect):
            adapter = AdapterFactory.get_for_server(self.server, VPNClient.ProtocolType.AWG2)
            self.assertEqual(adapter._next_address(self.user), "10.77.0.1")

    def test_awg2_client_creation_falls_back_to_config_peers_when_dump_fails(self):
        from unittest.mock import patch

        self.awg2_protocol.runtime_metadata["config_path"] = "/opt/amnezia/awg/awg0.conf"
        self.awg2_protocol.runtime_metadata["subnet"] = "10.77.0.0/24"
        self.awg2_protocol.save(update_fields=["runtime_metadata"])

        class R:
            def __init__(self, stdout):
                self.stdout = stdout

        def run_side_effect(*args, **kwargs):
            action = args[2]
            if action == "awg2.list":
                raise RuntimeError("Unable to access interface: Protocol not supported")
            mapping = {
                "awg2.iface": R("wg0\n"),
                "awg2.genkey": R("client2-private-key==\n"),
                "awg2.pubkey": R("client2-public-key==\n"),
                "awg2.list_fallback_conf": R(
                    "[Interface]\nAddress = 10.77.0.1/24\n"
                    "[Peer]\nPublicKey = oldpeer\nAllowedIPs = 10.77.0.10/32\n"
                ),
                "awg2.add_peer": R(""),
                "awg2.server_pub": R("server2-public-key==\n"),
            }
            return mapping[action]

        with patch("vpn.services.RuntimeCommandService.run", side_effect=run_side_effect):
            client = VPNClientService.create_client(server=self.server, name="awg2-fallback", protocol_type=VPNClient.ProtocolType.AWG2, actor=self.user)
        self.assertTrue(client.runtime_address)

    def test_awg2_expected_runtime_dump_failure_is_recorded_as_warning_success_job(self):
        from unittest.mock import patch

        class Result:
            def __init__(self, stdout="", stderr="", exit_code=0):
                self.stdout = stdout
                self.stderr = stderr
                self.exit_code = exit_code

        class FakeExecutor:
            @staticmethod
            def run(command):
                return Result(stderr="Unable to access interface: Protocol not supported", exit_code=1)

        with patch.object(RuntimeCommandService, "executor_for_server", return_value=FakeExecutor()):
            result = RuntimeCommandService.run_with_expected_failure(
                self.server,
                self.user,
                "awg2.list",
                "docker exec amnezia-awg2 wg show dump",
                expected_error_patterns=RuntimeCommandService.AWG2_EXPECTED_RUNTIME_DUMP_ERRORS,
                fallback_message="AWG2 runtime telemetry unavailable: using config fallback (degraded mode).",
            )

        self.assertIsNone(result)
        job = Job.objects.filter(action="awg2.list").latest("id")
        self.assertEqual(job.status, Job.Status.SUCCESS)
        self.assertEqual(job.events.latest("id").level, "warning")

    def test_awg2_list_peers_prefers_show_all_dump_runtime_telemetry(self):
        from unittest.mock import patch

        class Result:
            def __init__(self, stdout="", stderr="", exit_code=0):
                self.stdout = stdout
                self.stderr = stderr
                self.exit_code = exit_code

        class FakeExecutor:
            commands = []

            @classmethod
            def run(cls, command):
                cls.commands.append(command)
                if "show all dump" in command:
                    return Result("wg0\tprivate\tpub\t51830\npk1\tpsk\tep\t10.77.0.10/32\t0\t1\t2\t25\n")
                raise AssertionError("show dump should not be called when show all dump succeeds")

        adapter = AdapterFactory.get_for_server(self.server, VPNClient.ProtocolType.AWG2)
        with patch.object(RuntimeCommandService, "executor_for_server", return_value=FakeExecutor()):
            peers = adapter.list_peers(self.user)

        self.assertEqual(len(peers), 1)
        self.assertTrue(peers[0].telemetry_available)
        self.assertEqual(peers[0].transfer_rx, 1)
        self.assertEqual(peers[0].transfer_tx, 2)
        self.assertEqual(sum("show all dump" in command for command in FakeExecutor.commands), 1)
        self.assertEqual(sum("show dump" in command and "show all dump" not in command for command in FakeExecutor.commands), 0)

    def test_awg2_list_peers_falls_back_to_show_dump_when_show_all_fails(self):
        from unittest.mock import patch

        class Result:
            def __init__(self, stdout="", stderr="", exit_code=0):
                self.stdout = stdout
                self.stderr = stderr
                self.exit_code = exit_code

        class FakeExecutor:
            @staticmethod
            def run(command):
                if "show all dump" in command:
                    return Result(stderr="Unable to access interface: Protocol not supported", exit_code=1)
                if "show dump" in command:
                    return Result("wg0\tprivate\tpub\t51830\npk1\tpsk\tep\t10.77.0.10/32\t0\t3\t4\t25\n")
                raise AssertionError(f"unexpected command: {command}")

        adapter = AdapterFactory.get_for_server(self.server, VPNClient.ProtocolType.AWG2)
        with patch.object(RuntimeCommandService, "executor_for_server", return_value=FakeExecutor()):
            peers = adapter.list_peers(self.user)

        self.assertEqual(len(peers), 1)
        self.assertTrue(peers[0].telemetry_available)
        self.assertEqual(peers[0].transfer_rx, 3)
        self.assertEqual(peers[0].transfer_tx, 4)

    def test_awg2_list_peers_uses_config_fallback_when_runtime_dumps_fail(self):
        from unittest.mock import patch

        class Result:
            def __init__(self, stdout="", stderr="", exit_code=0):
                self.stdout = stdout
                self.stderr = stderr
                self.exit_code = exit_code

        class FakeExecutor:
            @staticmethod
            def run(command):
                if "show all dump" in command or command.endswith(" show dump"):
                    return Result(stderr="Unable to access interface: Protocol not supported", exit_code=1)
                raise AssertionError(f"unexpected command: {command}")

        adapter = AdapterFactory.get_for_server(self.server, VPNClient.ProtocolType.AWG2)
        with patch.object(RuntimeCommandService, "executor_for_server", return_value=FakeExecutor()):
            with patch.object(
                adapter,
                "_list_peers_from_config",
                return_value=[PeerState(public_key="pk1", allowed_ips="10.77.0.10/32", telemetry_available=False)],
            ):
                peers = adapter.list_peers(self.user)

        self.assertEqual(len(peers), 1)
        self.assertFalse(peers[0].telemetry_available)

    def test_new_client_uses_peer_address_not_server_interface_address(self):
        from unittest.mock import patch

        self.awg_protocol.runtime_metadata["subnet"] = "10.66.0.0/29"
        self.awg_protocol.runtime_metadata["interface_addresses"] = ["10.66.0.1/24"]
        self.awg_protocol.save(update_fields=["runtime_metadata"])

        class R:
            def __init__(self, stdout):
                self.stdout = stdout

        def run_side_effect(*args, **kwargs):
            action = args[2]
            mapping = {
                "awg.iface": R("awg0\n"),
                "awg.genkey": R("client-private-key==\n"),
                "awg.pubkey": R("client-public-key==\n"),
                "awg.genpsk": R("client-psk==\n"),
                "awg.add_peer": R(""),
                "awg.server_pub": R("server-public-key==\n"),
                "awg.list": R(""),
            }
            return mapping[action]

        with patch("vpn.services.RuntimeCommandService.run", side_effect=run_side_effect):
            client = VPNClientService.create_client(server=self.server, name="new-client-peer-address", protocol_type=VPNClient.ProtocolType.AWG, actor=self.user)

        client.refresh_from_db()
        self.assertEqual(client.runtime_address, "10.66.0.2")
        self.assertNotEqual(client.runtime_address, "10.66.0.1")
        self.assertIn("Address = 10.66.0.2/32", VPNClientService.latest_config(client))
        self.assertIn("Address = 10.66.0.2/32", VPNClientService.build_native_client_config(client))

    def test_imported_peers_keep_allowed_ips_value(self):
        from unittest.mock import patch

        class R:
            def __init__(self, stdout):
                self.stdout = stdout

        def run_side_effect(*args, **kwargs):
            action = args[2]
            mapping = {
                "awg.list": R("imported-peer\tpsk\tendpoint\t10.66.0.33/32\t0\t0\t0\t25\n"),
                "awg2.list": R(""),
            }
            return mapping[action]

        with patch("vpn.services.RuntimeCommandService.run", side_effect=run_side_effect):
            imported_count = VPNClientService.import_runtime_peers(server=self.server, actor=self.user)

        self.assertEqual(imported_count, 1)
        imported_client = VPNClient.objects.get(server=self.server, runtime_peer_public_key="imported-peer")
        self.assertEqual(imported_client.runtime_address, "10.66.0.33/32")

    def test_new_client_skips_addresses_reserved_in_db_when_runtime_empty(self):
        from unittest.mock import patch

        self.awg_protocol.runtime_metadata["subnet"] = "10.66.0.0/29"
        self.awg_protocol.runtime_metadata["interface_addresses"] = ["10.66.0.1/24"]
        self.awg_protocol.save(update_fields=["runtime_metadata"])

        profile = ProtocolProfile.objects.get(
            server_protocol=self.awg_protocol,
            protocol_type=ServerProtocol.ProtocolType.AWG,
        )
        VPNClient.objects.create(
            server=self.server,
            name="existing-active",
            protocol_type=VPNClient.ProtocolType.AWG,
            status=VPNClient.Status.ACTIVE,
            profile=profile,
            created_by=self.user,
            runtime_address="10.66.0.2",
        )
        VPNClient.objects.create(
            server=self.server,
            name="existing-disabled",
            protocol_type=VPNClient.ProtocolType.AWG,
            status=VPNClient.Status.DISABLED,
            profile=profile,
            created_by=self.user,
            runtime_address="10.66.0.3/32",
        )
        VPNClient.objects.create(
            server=self.server,
            name="existing-deleted",
            protocol_type=VPNClient.ProtocolType.AWG,
            status=VPNClient.Status.DELETED,
            profile=profile,
            created_by=self.user,
            runtime_address="10.66.0.4",
        )

        class R:
            def __init__(self, stdout):
                self.stdout = stdout

        def run_side_effect(*args, **kwargs):
            action = args[2]
            mapping = {
                "awg.iface": R("awg0\n"),
                "awg.genkey": R("new-private-key==\n"),
                "awg.pubkey": R("new-public-key==\n"),
                "awg.genpsk": R("new-psk==\n"),
                "awg.add_peer": R(""),
                "awg.server_pub": R("server-public-key==\n"),
                "awg.list": R(""),
            }
            return mapping[action]

        with patch("vpn.services.RuntimeCommandService.run", side_effect=run_side_effect):
            client = VPNClientService.create_client(
                server=self.server,
                name="new-db-aware-client",
                protocol_type=VPNClient.ProtocolType.AWG,
                actor=self.user,
            )

        client.refresh_from_db()
        self.assertEqual(client.runtime_address, "10.66.0.4")

    def test_deleted_db_clients_do_not_block_address_reuse(self):
        from unittest.mock import patch

        self.awg_protocol.runtime_metadata["subnet"] = "10.66.0.0/29"
        self.awg_protocol.runtime_metadata["interface_addresses"] = ["10.66.0.1/24"]
        self.awg_protocol.save(update_fields=["runtime_metadata"])

        profile = ProtocolProfile.objects.get(
            server_protocol=self.awg_protocol,
            protocol_type=ServerProtocol.ProtocolType.AWG,
        )
        VPNClient.objects.create(
            server=self.server,
            name="deleted-only",
            protocol_type=VPNClient.ProtocolType.AWG,
            status=VPNClient.Status.DELETED,
            profile=profile,
            created_by=self.user,
            runtime_address="10.66.0.2",
        )

        class R:
            def __init__(self, stdout):
                self.stdout = stdout

        def run_side_effect(*args, **kwargs):
            action = args[2]
            mapping = {
                "awg.iface": R("awg0\n"),
                "awg.genkey": R("new-private-key==\n"),
                "awg.pubkey": R("new-public-key==\n"),
                "awg.genpsk": R("new-psk==\n"),
                "awg.add_peer": R(""),
                "awg.server_pub": R("server-public-key==\n"),
                "awg.list": R(""),
            }
            return mapping[action]

        with patch("vpn.services.RuntimeCommandService.run", side_effect=run_side_effect):
            client = VPNClientService.create_client(
                server=self.server,
                name="reuse-deleted-ip-client",
                protocol_type=VPNClient.ProtocolType.AWG,
                actor=self.user,
            )

        client.refresh_from_db()
        self.assertEqual(client.runtime_address, "10.66.0.2")


@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class VPNClientLimitsTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin2", password="123", is_staff=True)
        self.server = Server.objects.create(name="limits-server", public_endpoint_host="vpn.example.com")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            container_name="amnezia-awg",
            enabled=True,
            runtime_metadata={"udp_port": 51820, "subnet": "10.66.0.0/24"},
        )
        self.awg2_protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            container_name="amnezia-awg2",
            enabled=True,
            runtime_metadata={"udp_port": 51830, "subnet": "10.77.0.0/24"},
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="limits-profile",
            protocol_type=ServerProtocol.ProtocolType.AWG,
            config_template="[Interface]",
        )
        self.awg2_profile = ProtocolProfile.objects.create(
            server_protocol=self.awg2_protocol,
            name="limits-profile-awg2",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="[Interface]",
        )

    def _make_client(self, **kwargs):
        defaults = {
            "server": self.server,
            "name": kwargs.pop("name", "limits-client"),
            "protocol_type": kwargs.pop("protocol_type", VPNClient.ProtocolType.AWG),
            "profile": kwargs.pop("profile", self.profile),
            "created_by": self.user,
            "runtime_peer_public_key": kwargs.pop("runtime_peer_public_key", "peer-key-1"),
            "runtime_address": "10.66.0.10",
            "status": VPNClient.Status.DISABLED,
        }
        defaults.update(kwargs)
        return VPNClient.objects.create(**defaults)

    def test_peer_transfer_map_returns_zero_values(self):
        from unittest.mock import patch

        adapter = AdapterFactory.get_for_server(self.server, VPNClient.ProtocolType.AWG)
        peers = [PeerState(public_key="p1", allowed_ips="10.66.0.10/32", transfer_rx=0, transfer_tx=0)]

        with patch.object(adapter, "list_peers", return_value=peers):
            transfer_map = adapter.peer_transfer_map(actor=self.user)

        self.assertEqual(transfer_map, {"p1": 0})

    def test_sync_traffic_usage_keeps_zero_traffic_as_available(self):
        from unittest.mock import patch

        client = self._make_client(status=VPNClient.Status.ACTIVE, runtime_peer_public_key="peer-zero")
        adapter = AdapterFactory.get_for_server(self.server, VPNClient.ProtocolType.AWG)

        with patch("vpn.services.AdapterFactory.get_for_server", return_value=adapter), patch.object(
            adapter, "peer_transfer_map", return_value={"peer-zero": 0}
        ):
            result = VPNClientLimitsService.sync_traffic_usage(actor=self.user)

        client.refresh_from_db()
        self.assertEqual(result["unavailable"], 0)
        self.assertEqual(client.traffic_used_bytes, 0)
        self.assertEqual(client.traffic_sync_error, "")
        self.assertIsNotNone(client.traffic_last_sync_at)

    def test_expired_client_cannot_be_reactivated(self):
        client = self._make_client(
            expires_at=timezone.now() - timezone.timedelta(minutes=1),
            disable_reason=VPNClient.DisableReason.EXPIRED,
            limit_state=VPNClient.LimitState.EXPIRED,
        )

        VPNClientService.set_status(client=client, status=VPNClient.Status.ACTIVE, actor=self.user)
        client.refresh_from_db()

        self.assertEqual(client.status, VPNClient.Status.DISABLED)
        self.assertEqual(client.disable_reason, VPNClient.DisableReason.EXPIRED)
        self.assertEqual(client.limit_state, VPNClient.LimitState.EXPIRED)

    def test_quota_exceeded_client_cannot_be_reactivated(self):
        client = self._make_client(
            traffic_limit_bytes=100,
            traffic_used_bytes=100,
            disable_reason=VPNClient.DisableReason.TRAFFIC_EXCEEDED,
            limit_state=VPNClient.LimitState.TRAFFIC_EXCEEDED,
        )

        VPNClientService.set_status(client=client, status=VPNClient.Status.ACTIVE, actor=self.user)
        client.refresh_from_db()

        self.assertEqual(client.status, VPNClient.Status.DISABLED)
        self.assertEqual(client.disable_reason, VPNClient.DisableReason.TRAFFIC_EXCEEDED)
        self.assertEqual(client.limit_state, VPNClient.LimitState.TRAFFIC_EXCEEDED)

    def test_client_without_limit_violation_can_be_activated(self):
        client = self._make_client(
            traffic_limit_bytes=1000,
            traffic_used_bytes=10,
            expires_at=timezone.now() + timezone.timedelta(days=1),
            disable_reason=VPNClient.DisableReason.MANUAL,
            limit_state=VPNClient.LimitState.ACTIVE,
        )

        VPNClientService.set_status(client=client, status=VPNClient.Status.ACTIVE, actor=self.user)
        client.refresh_from_db()

        self.assertEqual(client.status, VPNClient.Status.ACTIVE)
        self.assertEqual(client.disable_reason, VPNClient.DisableReason.NONE)
        self.assertEqual(client.limit_state, VPNClient.LimitState.ACTIVE)

    def test_disable_then_enable_restores_same_runtime_identity_without_reissue(self):
        from unittest.mock import patch

        config = (
            "[Interface]\n"
            "PrivateKey = private\n"
            "Address = 10.66.0.10/32\n\n"
            "[Peer]\n"
            "PublicKey = server\n"
            "PresharedKey = psk-keep\n"
            "Endpoint = vpn.example.com:51820\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
        )
        client = self._make_client(
            name="disable-enable-restore",
            status=VPNClient.Status.ACTIVE,
            runtime_peer_public_key="peer-keep",
            runtime_address="10.66.0.10",
            disable_reason=VPNClient.DisableReason.NONE,
        )
        VPNClientService._store_revision(client, config)
        initial_revision_count = client.revisions.count()
        initial_key = client.runtime_peer_public_key
        initial_address = client.runtime_address
        initial_config = VPNClientService.latest_config(client)

        class R:
            def __init__(self, stdout):
                self.stdout = stdout

        def run_side_effect(*args, **kwargs):
            action = args[2]
            mapping = {
                "awg.iface": R("awg0\n"),
                "awg.remove_peer": R(""),
                "awg.add_existing_peer": R(""),
            }
            return mapping[action]

        with patch("vpn.services.RuntimeCommandService.run", side_effect=run_side_effect), patch(
            "vpn.services.VPNClientService.reissue_config"
        ) as reissue_mock:
            VPNClientService.set_status(client=client, status=VPNClient.Status.DISABLED, actor=self.user)
            client.refresh_from_db()
            self.assertEqual(client.status, VPNClient.Status.DISABLED)

            VPNClientService.set_status(client=client, status=VPNClient.Status.ACTIVE, actor=self.user)
            reissue_mock.assert_not_called()

        client.refresh_from_db()
        self.assertEqual(client.status, VPNClient.Status.ACTIVE)
        self.assertEqual(client.runtime_peer_public_key, initial_key)
        self.assertEqual(client.runtime_address, initial_address)
        self.assertEqual(client.revisions.count(), initial_revision_count)
        self.assertEqual(VPNClientService.latest_config(client), initial_config)

    def test_enable_without_revision_does_not_reissue_or_restore(self):
        from unittest.mock import patch

        client = self._make_client(
            name="enable-no-revision",
            status=VPNClient.Status.DISABLED,
            runtime_peer_public_key="peer-no-revision",
            runtime_address="10.66.0.20",
            disable_reason=VPNClient.DisableReason.MANUAL,
            limit_state=VPNClient.LimitState.ACTIVE,
        )

        with patch("vpn.services.RuntimeCommandService.run") as runtime_run, patch(
            "vpn.services.VPNClientService.reissue_config"
        ) as reissue_mock:
            VPNClientService.set_status(client=client, status=VPNClient.Status.ACTIVE, actor=self.user)

        client.refresh_from_db()
        self.assertEqual(client.status, VPNClient.Status.ACTIVE)
        reissue_mock.assert_not_called()
        runtime_run.assert_not_called()

    def test_reactivate_with_violated_limit_logs_disabled_action(self):
        client = self._make_client(
            expires_at=timezone.now() - timezone.timedelta(minutes=1),
            disable_reason=VPNClient.DisableReason.EXPIRED,
            limit_state=VPNClient.LimitState.EXPIRED,
        )

        VPNClientService.set_status(client=client, status=VPNClient.Status.ACTIVE, actor=self.user)
        client.refresh_from_db()
        latest_log = AuditLog.objects.first()

        self.assertEqual(client.status, VPNClient.Status.DISABLED)
        self.assertIsNotNone(latest_log)
        self.assertEqual(latest_log.action, "client.disabled")
        self.assertEqual(latest_log.details.get("disable_reason"), VPNClient.DisableReason.EXPIRED)

    def test_awg2_telemetry_unavailable_does_not_write_fake_zero_usage(self):
        from unittest.mock import patch

        client = self._make_client(
            name="awg2-telemetry",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=self.awg2_profile,
            status=VPNClient.Status.ACTIVE,
            runtime_peer_public_key="awg2-peer",
            traffic_used_bytes=777,
        )
        adapter = AdapterFactory.get_for_server(self.server, VPNClient.ProtocolType.AWG2)
        fallback_peers = [
            PeerState(
                public_key="awg2-peer",
                allowed_ips="10.77.0.10/32",
                transfer_rx=0,
                transfer_tx=0,
                telemetry_available=False,
            )
        ]

        with patch("vpn.services.AdapterFactory.get_for_server", return_value=adapter), patch.object(
            adapter, "list_peers", return_value=fallback_peers
        ):
            result = VPNClientLimitsService.sync_traffic_usage(actor=self.user)

        client.refresh_from_db()
        self.assertEqual(result["synced"], 0)
        self.assertEqual(result["unavailable"], 1)
        self.assertEqual(client.traffic_used_bytes, 777)
        self.assertEqual(client.traffic_sync_error, "Счетчики трафика недоступны")

    def test_expired_client_cannot_be_reissued(self):
        client = self._make_client(
            name="expired-reissue",
            status=VPNClient.Status.DISABLED,
            expires_at=timezone.now() - timezone.timedelta(minutes=1),
            disable_reason=VPNClient.DisableReason.EXPIRED,
            limit_state=VPNClient.LimitState.EXPIRED,
        )

        with self.assertRaises(RuntimeError):
            VPNClientService.reissue_config(client=client, actor=self.user)

    def test_traffic_exceeded_client_cannot_be_reissued(self):
        client = self._make_client(
            name="quota-reissue",
            status=VPNClient.Status.DISABLED,
            traffic_limit_bytes=100,
            traffic_used_bytes=100,
            disable_reason=VPNClient.DisableReason.TRAFFIC_EXCEEDED,
            limit_state=VPNClient.LimitState.TRAFFIC_EXCEEDED,
        )

        with self.assertRaises(RuntimeError):
            VPNClientService.reissue_config(client=client, actor=self.user)

    def test_client_without_limit_violation_can_be_reissued(self):
        from unittest.mock import patch

        client = self._make_client(
            name="reissue-ok",
            status=VPNClient.Status.ACTIVE,
            traffic_limit_bytes=1000,
            traffic_used_bytes=10,
            expires_at=timezone.now() + timezone.timedelta(days=1),
            runtime_peer_public_key="",
        )

        class R:
            def __init__(self, stdout):
                self.stdout = stdout

        def run_side_effect(*args, **kwargs):
            action = args[2]
            mapping = {
                "awg.iface": R("awg0\n"),
                "awg.genkey": R("client-private-key==\n"),
                "awg.pubkey": R("client-public-key==\n"),
                "awg.add_peer": R(""),
                "awg.server_pub": R("server-public-key==\n"),
                "awg.list": R("peerkey\tpsk\tendpoint\t10.66.0.10/32\t0\t0\t0\t25\n"),
            }
            return mapping[action]

        with patch("vpn.services.RuntimeCommandService.run", side_effect=run_side_effect):
            VPNClientService.reissue_config(client=client, actor=self.user)

        client.refresh_from_db()
        self.assertTrue(client.runtime_peer_public_key)
        self.assertEqual(client.revisions.count(), 1)


class VPNClientCreateFormTest(SimpleTestCase):
    def test_expiration_preset_builds_expires_at(self):
        form = VPNClientCreateForm(
            data={
                "name": "preset-exp",
                "protocol_type": VPNClient.ProtocolType.AWG,
                "expires_preset": "1w",
                "traffic_limit_preset": VPNClientCreateForm.TRAFFIC_PRESET_UNLIMITED,
            }
        )

        self.assertTrue(form.is_valid(), form.errors)
        expires_at = form.cleaned_data["expires_at"]
        self.assertIsNotNone(expires_at)
        self.assertGreater(expires_at, timezone.now())

    def test_custom_expiration_requires_datetime(self):
        form = VPNClientCreateForm(
            data={
                "name": "custom-exp",
                "protocol_type": VPNClient.ProtocolType.AWG,
                "expires_preset": VPNClientCreateForm.EXPIRATION_PRESET_CUSTOM,
                "traffic_limit_preset": VPNClientCreateForm.TRAFFIC_PRESET_UNLIMITED,
            }
        )

        self.assertFalse(form.is_valid())
        self.assertIn("expires_at", form.errors)

    def test_traffic_custom_mb_converted_to_bytes(self):
        form = VPNClientCreateForm(
            data={
                "name": "traffic-custom",
                "protocol_type": VPNClient.ProtocolType.AWG,
                "expires_preset": VPNClientCreateForm.EXPIRATION_PRESET_UNLIMITED,
                "traffic_limit_preset": VPNClientCreateForm.TRAFFIC_PRESET_CUSTOM,
                "traffic_custom_value": "512",
                "traffic_custom_unit": VPNClientCreateForm.TRAFFIC_UNIT_MB,
            }
        )

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["traffic_limit_bytes"], 512 * 1024**2)

    def test_traffic_preset_converted_to_bytes(self):
        form = VPNClientCreateForm(
            data={
                "name": "traffic-preset",
                "protocol_type": VPNClient.ProtocolType.AWG,
                "expires_preset": VPNClientCreateForm.EXPIRATION_PRESET_UNLIMITED,
                "traffic_limit_preset": "25gb",
            }
        )

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["traffic_limit_bytes"], 25 * 1024**3)


@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class VPNClientLimitsUpdateFlowTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin-limits", password="123", is_staff=True)
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="limits-edit-server", public_endpoint_host="vpn.example.com")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            container_name="amnezia-awg",
            enabled=True,
            runtime_metadata={"udp_port": 51820, "subnet": "10.66.0.0/24"},
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="limits-edit-profile",
            protocol_type=ServerProtocol.ProtocolType.AWG,
            config_template="[Interface]",
        )
        self.vpn_client = VPNClient.objects.create(
            server=self.server,
            name="edited-client",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
            runtime_peer_public_key="peer-keep",
            runtime_address="10.66.0.10",
            expires_at=None,
            traffic_limit_bytes=None,
            status=VPNClient.Status.DISABLED,
            disable_reason=VPNClient.DisableReason.EXPIRED,
            limit_state=VPNClient.LimitState.EXPIRED,
        )

    def test_updating_limits_does_not_reissue_config(self):
        from unittest.mock import patch

        with patch("vpn.services.RuntimeCommandService.run") as runtime_run:
            response = self.client.post(
                f"/clients/{self.vpn_client.id}/limits/update/",
                data={
                    "expires_preset": "1w",
                    "traffic_limit_preset": "10gb",
                },
            )
        self.assertEqual(response.status_code, 302)
        self.vpn_client.refresh_from_db()
        self.assertEqual(self.vpn_client.runtime_peer_public_key, "peer-keep")
        self.assertEqual(self.vpn_client.revisions.count(), 0)
        runtime_run.assert_not_called()

    def test_updating_unlimited_to_preset(self):
        self.client.post(
            f"/clients/{self.vpn_client.id}/limits/update/",
            data={
                "expires_preset": "1d",
                "traffic_limit_preset": "5gb",
            },
        )
        self.vpn_client.refresh_from_db()
        self.assertIsNotNone(self.vpn_client.expires_at)
        self.assertEqual(self.vpn_client.traffic_limit_bytes, 5 * 1024**3)

    def test_updating_preset_to_unlimited(self):
        self.vpn_client.expires_at = timezone.now() + timezone.timedelta(days=5)
        self.vpn_client.traffic_limit_bytes = 25 * 1024**3
        self.vpn_client.save(update_fields=["expires_at", "traffic_limit_bytes"])

        self.client.post(
            f"/clients/{self.vpn_client.id}/limits/update/",
            data={
                "expires_preset": "unlimited",
                "traffic_limit_preset": "unlimited",
            },
        )
        self.vpn_client.refresh_from_db()
        self.assertIsNone(self.vpn_client.expires_at)
        self.assertIsNone(self.vpn_client.traffic_limit_bytes)

    def test_custom_traffic_conversion_on_update(self):
        self.client.post(
            f"/clients/{self.vpn_client.id}/limits/update/",
            data={
                "expires_preset": "unlimited",
                "traffic_limit_preset": "custom",
                "traffic_custom_value": "512",
                "traffic_custom_unit": "mb",
            },
        )
        self.vpn_client.refresh_from_db()
        self.assertEqual(self.vpn_client.traffic_limit_bytes, 512 * 1024**2)

    def test_blocked_client_limits_update_does_not_auto_reissue(self):
        self.vpn_client.expires_at = timezone.now() - timezone.timedelta(minutes=10)
        self.vpn_client.traffic_limit_bytes = 1024
        self.vpn_client.traffic_used_bytes = 0
        self.vpn_client.limit_state = VPNClient.LimitState.EXPIRED
        self.vpn_client.save(update_fields=["expires_at", "traffic_limit_bytes", "traffic_used_bytes", "limit_state"])

        self.client.post(
            f"/clients/{self.vpn_client.id}/limits/update/",
            data={
                "expires_preset": "unlimited",
                "traffic_limit_preset": "unlimited",
            },
        )
        self.vpn_client.refresh_from_db()
        self.assertEqual(self.vpn_client.status, VPNClient.Status.DISABLED)
        self.assertEqual(self.vpn_client.revisions.count(), 0)
        self.assertEqual(self.vpn_client.limit_state, VPNClient.LimitState.ACTIVE)

    def test_limits_update_writes_audit_log(self):
        self.client.post(
            f"/clients/{self.vpn_client.id}/limits/update/",
            data={
                "expires_preset": "unlimited",
                "traffic_limit_preset": "1gb",
            },
        )
        audit = AuditLog.objects.filter(action="client.limits.update", entity_id=str(self.vpn_client.id)).first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.details.get("old_expires_at"), None)
        self.assertEqual(audit.details.get("new_traffic_limit_bytes"), 1024**3)

    def test_update_form_initializes_custom_traffic_for_non_preset_value(self):
        self.vpn_client.traffic_limit_bytes = 7 * 1024**3
        self.vpn_client.expires_at = timezone.now() + timezone.timedelta(days=10)
        self.vpn_client.save(update_fields=["traffic_limit_bytes", "expires_at"])

        form = VPNClientLimitsUpdateForm(client=self.vpn_client)
        self.assertEqual(form.initial["expires_preset"], VPNClientLimitsUpdateForm.EXPIRATION_PRESET_CUSTOM)
        self.assertEqual(form.initial["traffic_limit_preset"], VPNClientLimitsUpdateForm.TRAFFIC_PRESET_CUSTOM)


@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class VPNClientSoftDeleteVisibilityTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin-delete-ux", password="123", is_staff=True)
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="delete-ux-server", public_endpoint_host="vpn.example.com")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            container_name="amnezia-awg",
            enabled=True,
            runtime_metadata={"udp_port": 51820, "subnet": "10.66.0.0/24"},
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="delete-ux-profile",
            protocol_type=ServerProtocol.ProtocolType.AWG,
            config_template="[Interface]",
        )
        self.active_client = VPNClient.objects.create(
            server=self.server,
            name="visible-client",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
            status=VPNClient.Status.ACTIVE,
        )
        self.deleted_client = VPNClient.objects.create(
            server=self.server,
            name="hidden-client",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
            status=VPNClient.Status.DELETED,
        )

    def test_default_clients_list_hides_deleted_clients(self):
        response = self.client.get("/clients/")

        self.assertContains(response, self.active_client.name)
        self.assertNotContains(response, self.deleted_client.name)

    def test_deleted_clients_visible_only_when_explicitly_filtered(self):
        response = self.client.get("/clients/", data={"status": VPNClient.Status.DELETED})
        self.assertContains(response, self.deleted_client.name)
        self.assertNotContains(response, self.active_client.name)

    def test_delete_action_marks_client_deleted_and_keeps_row(self):
        response = self.client.post(
            f"/clients/{self.active_client.id}/action/delete/",
            data={"next": "/clients/"},
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.active_client.refresh_from_db()
        self.assertEqual(self.active_client.status, VPNClient.Status.DELETED)
        self.assertTrue(VPNClient.objects.filter(pk=self.active_client.pk).exists())
        self.assertContains(response, "Клиент помечен как удаленный и скрыт из основного списка")
        self.assertNotContains(response, self.active_client.name)

    def test_single_restore_from_deleted_changes_status_to_disabled(self):
        response = self.client.post(
            f"/clients/{self.deleted_client.id}/action/restore/",
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.deleted_client.refresh_from_db()
        self.assertEqual(self.deleted_client.status, VPNClient.Status.DISABLED)
        self.assertContains(response, "Клиент восстановлен в состояние «Отключён»")


@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class VPNClientBulkActionsAndQuickFiltersTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin-bulk", password="123", is_staff=True)
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="bulk-server", public_endpoint_host="vpn.example.com")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            container_name="amnezia-awg",
            enabled=True,
            runtime_metadata={"udp_port": 51820, "subnet": "10.66.0.0/24"},
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="bulk-profile",
            protocol_type=ServerProtocol.ProtocolType.AWG,
            config_template="[Interface]",
        )
        self.active_client = VPNClient.objects.create(
            server=self.server,
            name="bulk-active",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
            status=VPNClient.Status.ACTIVE,
        )
        self.disabled_client = VPNClient.objects.create(
            server=self.server,
            name="bulk-disabled",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
            status=VPNClient.Status.DISABLED,
        )
        self.expired_client = VPNClient.objects.create(
            server=self.server,
            name="bulk-expired",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
            status=VPNClient.Status.ACTIVE,
            limit_state=VPNClient.LimitState.EXPIRED,
        )
        self.traffic_client = VPNClient.objects.create(
            server=self.server,
            name="bulk-traffic",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
            status=VPNClient.Status.ACTIVE,
            limit_state=VPNClient.LimitState.TRAFFIC_EXCEEDED,
        )
        self.deleted_client = VPNClient.objects.create(
            server=self.server,
            name="bulk-deleted",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
            status=VPNClient.Status.DELETED,
        )

    def test_bulk_selection_form_submission_flow(self):
        response = self.client.post(
            "/clients/bulk-action/",
            data={
                "action": "disable",
                "client_ids": [self.active_client.id, self.expired_client.id],
                "next": "/clients/?q=bulk",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Массовое действие выполнено")

    def test_clients_list_contains_bulk_toolbar_controls(self):
        response = self.client.get("/clients/")

        self.assertContains(response, 'id="bulkActionForm"')
        self.assertContains(response, 'id="bulkToolbar"')
        self.assertContains(response, 'id="bulkLimitsBtn"')
        self.assertContains(response, 'id="bulkLimitsModal"')
        self.assertContains(response, 'id="selectAllVisible"')
        self.assertContains(response, 'class="form-check-input js-client-checkbox"')
        self.assertContains(response, 'id="bulkSelectionContainer"')
        self.assertContains(response, 'data-action="restore"')

    def test_bulk_disable(self):
        self.client.post(
            "/clients/bulk-action/",
            data={"action": "disable", "client_ids": [self.active_client.id, self.expired_client.id]},
        )
        self.active_client.refresh_from_db()
        self.expired_client.refresh_from_db()
        self.assertEqual(self.active_client.status, VPNClient.Status.DISABLED)
        self.assertEqual(self.expired_client.status, VPNClient.Status.DISABLED)

    def test_bulk_enable(self):
        self.client.post(
            "/clients/bulk-action/",
            data={"action": "enable", "client_ids": [self.disabled_client.id]},
        )
        self.disabled_client.refresh_from_db()
        self.assertEqual(self.disabled_client.status, VPNClient.Status.ACTIVE)

    def test_bulk_delete_soft_delete(self):
        self.client.post(
            "/clients/bulk-action/",
            data={"action": "delete", "client_ids": [self.active_client.id, self.disabled_client.id]},
        )
        self.active_client.refresh_from_db()
        self.disabled_client.refresh_from_db()
        self.assertEqual(self.active_client.status, VPNClient.Status.DELETED)
        self.assertEqual(self.disabled_client.status, VPNClient.Status.DELETED)
        self.assertTrue(VPNClient.objects.filter(pk=self.active_client.pk).exists())
        self.assertTrue(VPNClient.objects.filter(pk=self.disabled_client.pk).exists())

    def test_bulk_restore_only_deleted_clients(self):
        response = self.client.post(
            "/clients/bulk-action/",
            data={"action": "restore", "client_ids": [self.deleted_client.id, self.active_client.id]},
            follow=True,
        )
        self.deleted_client.refresh_from_db()
        self.active_client.refresh_from_db()
        self.assertEqual(self.deleted_client.status, VPNClient.Status.DISABLED)
        self.assertEqual(self.active_client.status, VPNClient.Status.ACTIVE)
        self.assertContains(response, "восстановлено — 1 шт.")
        self.assertContains(response, "Пропущены не удалённые: 1.")

    def test_restored_client_returns_to_normal_list(self):
        self.client.post(
            "/clients/bulk-action/",
            data={"action": "restore", "client_ids": [self.deleted_client.id]},
        )
        default_response = self.client.get("/clients/")
        deleted_response = self.client.get("/clients/", data={"quick": "deleted"})
        self.assertContains(default_response, self.deleted_client.name)
        self.assertNotContains(deleted_response, self.deleted_client.name)

    def test_default_list_still_hides_deleted_clients(self):
        response = self.client.get("/clients/")
        self.assertNotContains(response, self.deleted_client.name)
        self.assertContains(response, self.active_client.name)

    def test_bulk_update_expiration_limit(self):
        before_request_time = timezone.now()
        self.client.post(
            "/clients/bulk-action/",
            data={
                "action": "limits",
                "client_ids": [self.active_client.id, self.disabled_client.id],
                "apply_expires": "set",
                "expires_preset": "1w",
                "apply_traffic": "keep",
            },
        )
        self.active_client.refresh_from_db()
        self.disabled_client.refresh_from_db()
        self.assertIsNotNone(self.active_client.expires_at)
        self.assertIsNotNone(self.disabled_client.expires_at)
        self.assertGreaterEqual(self.active_client.expires_at, before_request_time + timezone.timedelta(days=6))

    def test_bulk_update_traffic_limit(self):
        self.client.post(
            "/clients/bulk-action/",
            data={
                "action": "limits",
                "client_ids": [self.active_client.id, self.expired_client.id],
                "apply_expires": "keep",
                "apply_traffic": "set",
                "traffic_limit_preset": "10gb",
            },
        )
        self.active_client.refresh_from_db()
        self.expired_client.refresh_from_db()
        self.assertEqual(self.active_client.traffic_limit_bytes, 10 * 1024**3)
        self.assertEqual(self.expired_client.traffic_limit_bytes, 10 * 1024**3)

    def test_bulk_remove_limits(self):
        limit_time = timezone.now() + timezone.timedelta(days=3)
        self.active_client.expires_at = limit_time
        self.active_client.traffic_limit_bytes = 5 * 1024**3
        self.active_client.save(update_fields=["expires_at", "traffic_limit_bytes"])
        self.client.post(
            "/clients/bulk-action/",
            data={
                "action": "limits",
                "client_ids": [self.active_client.id],
                "apply_expires": "clear",
                "apply_traffic": "clear",
            },
        )
        self.active_client.refresh_from_db()
        self.assertIsNone(self.active_client.expires_at)
        self.assertIsNone(self.active_client.traffic_limit_bytes)

    def test_bulk_limits_skip_deleted_clients_by_default(self):
        self.deleted_client.expires_at = timezone.now() + timezone.timedelta(days=1)
        self.deleted_client.traffic_limit_bytes = 1024**3
        self.deleted_client.save(update_fields=["expires_at", "traffic_limit_bytes"])
        self.client.post(
            "/clients/bulk-action/",
            data={
                "action": "limits",
                "client_ids": [self.deleted_client.id, self.active_client.id],
                "apply_expires": "set",
                "expires_preset": "1m",
                "apply_traffic": "set",
                "traffic_limit_preset": "25gb",
            },
        )
        self.deleted_client.refresh_from_db()
        self.active_client.refresh_from_db()
        self.assertEqual(self.deleted_client.traffic_limit_bytes, 1024**3)
        self.assertEqual(self.active_client.traffic_limit_bytes, 25 * 1024**3)

    def test_bulk_limits_submission_flow(self):
        response = self.client.post(
            "/clients/bulk-action/",
            data={
                "action": "limits",
                "client_ids": [self.active_client.id, self.disabled_client.id],
                "apply_expires": "set",
                "expires_preset": "custom",
                "expires_at": "2030-01-01T10:00",
                "apply_traffic": "set",
                "traffic_limit_preset": "custom",
                "traffic_custom_value": "512",
                "traffic_custom_unit": "mb",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Лимиты обновлены для 2 клиент(ов)")

    def test_quick_filters_produce_correct_subsets(self):
        active_response = self.client.get("/clients/", data={"quick": "active"})
        self.assertContains(active_response, self.active_client.name)
        self.assertNotContains(active_response, self.disabled_client.name)

        disabled_response = self.client.get("/clients/", data={"quick": "disabled"})
        self.assertContains(disabled_response, self.disabled_client.name)
        self.assertNotContains(disabled_response, self.active_client.name)

        expired_response = self.client.get("/clients/", data={"quick": "expired"})
        self.assertContains(expired_response, self.expired_client.name)
        self.assertNotContains(expired_response, self.traffic_client.name)

        traffic_response = self.client.get("/clients/", data={"quick": "traffic_exceeded"})
        self.assertContains(traffic_response, self.traffic_client.name)
        self.assertNotContains(traffic_response, self.expired_client.name)

        deleted_response = self.client.get("/clients/", data={"quick": "deleted"})
        self.assertContains(deleted_response, self.deleted_client.name)
        self.assertNotContains(deleted_response, self.active_client.name)


@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class VPNClientDetailDiagnosticsViewTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin-detail", password="123", is_staff=True)
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="detail-server", public_endpoint_host="vpn.example.com")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            container_name="amnezia-awg",
            enabled=True,
            runtime_metadata={"udp_port": 51820, "subnet": "10.66.0.0/24"},
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="detail-profile",
            protocol_type=ServerProtocol.ProtocolType.AWG,
            config_template="[Interface]",
        )

    def test_detail_page_renders_diagnostics_warning_and_activity_sections(self):
        vpn_client = VPNClient.objects.create(
            server=self.server,
            name="diag-client",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
            status=VPNClient.Status.DELETED,
            limit_state=VPNClient.LimitState.EXPIRED,
            imported_from_runtime=True,
            runtime_address="10.66.0.10",
            runtime_peer_public_key="",
            traffic_sync_error="Счетчики трафика недоступны",
        )
        AuditLog.objects.create(
            actor=self.user,
            action="client.disabled",
            entity_type="VPNClient",
            entity_id=str(vpn_client.id),
            details={"reason": "expired"},
        )
        Job.objects.create(
            server=self.server,
            actor=self.user,
            action="vpn.client.sync",
            payload={"command": "sync diag-client"},
            status=Job.Status.SUCCESS,
        )

        response = self.client.get(f"/clients/{vpn_client.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Диагностика клиента")
        self.assertContains(response, "Требуется внимание оператора")
        self.assertContains(response, "Недавняя активность")
        self.assertContains(response, "Последние действия в аудите по клиенту")
        self.assertContains(response, "Последние jobs по серверу/клиенту")
        self.assertContains(response, "Опасные действия")

    def test_detail_page_shows_no_revision_warning(self):
        vpn_client = VPNClient.objects.create(
            server=self.server,
            name="no-revision-client",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
            status=VPNClient.Status.ACTIVE,
            limit_state=VPNClient.LimitState.ACTIVE,
            imported_from_runtime=False,
            runtime_peer_public_key="peer-key-1",
        )

        response = self.client.get(f"/clients/{vpn_client.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Для клиента отсутствует выпущенная ревизия конфига.")


@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class VPNClientDegradedTelemetryWordingTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin-degraded", password="123", is_staff=True)
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="degraded-server", public_endpoint_host="vpn.example.com")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            runtime_metadata={"peer_source": "config file fallback (degraded telemetry)"},
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="degraded-profile",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="[Interface]",
        )

    def test_awg2_fallback_wording_is_calm_in_client_views(self):
        vpn_client = VPNClient.objects.create(
            server=self.server,
            name="degraded-client",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=self.profile,
            created_by=self.user,
            runtime_peer_public_key="peer-key",
            traffic_sync_error="Счетчики трафика недоступны",
        )

        detail_response = self.client.get(f"/clients/{vpn_client.id}/")
        self.assertContains(detail_response, "Runtime-опрос недоступен")
        self.assertContains(detail_response, "Используется fallback. Peers читаются из конфигурации")
        self.assertNotContains(detail_response, "проверьте синхронизацию runtime")

        list_response = self.client.get("/clients/")
        self.assertContains(list_response, "Fallback-режим")
        self.assertContains(list_response, "live-счётчики трафика сейчас недоступны")


@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class VPNClientOperatorVisibilityTest(TestCase):
    def setUp(self):
        self.me = get_user_model().objects.create_user("me-admin", password="123", is_staff=True)
        self.other = get_user_model().objects.create_user("other-admin", password="123", is_staff=True)
        self.client.force_login(self.me)
        self.server = Server.objects.create(name="operator-server")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            runtime_metadata={"udp_port": 51820, "subnet": "10.66.0.0/24"},
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="operator-profile",
            protocol_type=ServerProtocol.ProtocolType.AWG,
            config_template="[Interface]",
        )
        self.my_client = VPNClient.objects.create(
            server=self.server,
            name="mine-client",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.me,
        )
        self.other_client = VPNClient.objects.create(
            server=self.server,
            name="other-client",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.other,
        )
        AuditLog.objects.create(
            actor=self.other,
            action="vpn.client.disable",
            entity_type="VPNClient",
            entity_id=str(self.my_client.id),
            details={"reason": "manual"},
        )

    def test_clients_list_filters_mine_only(self):
        response = self.client.get("/clients/", {"operator_scope": "mine"})
        self.assertContains(response, "mine-client")
        self.assertNotContains(response, "other-client")

    def test_clients_list_shows_creator_and_last_operator_action(self):
        response = self.client.get("/clients/")
        self.assertContains(response, "Создал:")
        self.assertContains(response, "Последнее действие:")
        self.assertContains(response, "vpn.client.disable")

    def test_client_detail_shows_operator_summary(self):
        response = self.client.get(f"/clients/{self.my_client.id}/")
        self.assertContains(response, "Оператор")
        self.assertContains(response, "Создал")
        self.assertContains(response, "Последнее действие")


@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class VPNClientPortalAdminAndRenewalVisibilityTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin-portal-renewal", password="123", is_staff=True)
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="portal-renewal-server")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            runtime_metadata={"udp_port": 51820, "subnet": "10.66.0.0/24"},
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="portal-renewal-profile",
            protocol_type=ServerProtocol.ProtocolType.AWG,
            config_template="[Interface]",
        )
        self.client_with_renewal = VPNClient.objects.create(
            server=self.server,
            name="client-with-renewal",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
        )
        self.client_without_renewal = VPNClient.objects.create(
            server=self.server,
            name="client-without-renewal",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.user,
        )

    def test_admin_can_retrieve_current_portal_link_after_issue(self):
        _, token = PortalAccessService.issue_for_client(self.client_with_renewal)
        response = self.client.get(f"/clients/{self.client_with_renewal.id}/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Текущая ссылка кабинета")
        self.assertContains(response, f"/portal/{token}/")

    def test_clients_list_marks_and_filters_recent_renewal_requests(self):
        AuditLog.objects.create(
            action="portal.renewal.request",
            entity_type="VPNClient",
            entity_id=str(self.client_with_renewal.id),
            details={},
        )

        response = self.client.get("/clients/")
        self.assertContains(response, "client-with-renewal")
        self.assertContains(response, "Запрос продления")
        self.assertContains(response, "Последний запрос продления")

        filtered = self.client.get("/clients/", {"renewal_state": "with"})
        self.assertContains(filtered, "client-with-renewal")
        self.assertNotContains(filtered, "client-without-renewal")
