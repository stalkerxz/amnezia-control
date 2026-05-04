import json
from io import BytesIO, StringIO
from unittest.mock import patch
import urllib.error


from cryptography.fernet import Fernet
from audit.models import AuditLog
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.management import call_command
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from jobs.models import Job
from servers.models import ProtocolProfile, Server, ServerProtocol
from servers.services import ServerService
from portal.models import ClientRenewalRequest
from portal.services import PortalAccessService

from .expiration_reminders import ClientExpirationReminderService
from .forms import VPNClientCreateForm, VPNClientLimitsUpdateForm
from .models import ClientExpirationReminderLog, VPNClient
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

    def test_contact_email_is_optional_and_preserved(self):
        form = VPNClientCreateForm(
            data={
                "name": "contact-email",
                "contact_email": "client@example.com",
                "protocol_type": VPNClient.ProtocolType.AWG,
                "expires_preset": VPNClientCreateForm.EXPIRATION_PRESET_UNLIMITED,
                "traffic_limit_preset": "1gb",
            }
        )

        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["contact_email"], "client@example.com")

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

    def test_update_form_initializes_contact_email(self):
        self.vpn_client.contact_email = "client@old.example"
        self.vpn_client.save(update_fields=["contact_email"])

        form = VPNClientLimitsUpdateForm(client=self.vpn_client)
        self.assertEqual(form.initial["contact_email"], "client@old.example")

    def test_limits_update_can_change_contact_email(self):
        response = self.client.post(
            f"/clients/{self.vpn_client.id}/limits/update/",
            data={
                "expires_preset": "unlimited",
                "traffic_limit_preset": "unlimited",
                "contact_email": "client@new.example",
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.vpn_client.refresh_from_db()
        self.assertEqual(self.vpn_client.contact_email, "client@new.example")
        self.assertContains(response, "контактный email")

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
class VPNClientAdminExportParityTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin-export", password="123", is_staff=True)
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="export-server", public_endpoint_host="vpn.example.com")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            container_name="amnezia-awg2",
            enabled=True,
            runtime_metadata={
                "udp_port": 51820,
                "subnet": "10.66.0.0/24",
                "awg2_metadata": {
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
                },
            },
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="export-profile",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="[Interface]",
        )
        self.vpn_client = VPNClient.objects.create(
            server=self.server,
            name="export-client",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=self.profile,
            created_by=self.user,
        )
        VPNClientService._store_revision(self.vpn_client, "[Interface]\nPrivateKey = test")

    def test_admin_client_detail_uses_target_specific_qrs(self):
        from unittest.mock import call, patch

        with patch(
            "vpn.views.VPNClientService.portal_qr_png_base64_for_target",
            side_effect=lambda client, target: f"{target}-qr",
        ) as target_qr_mock:
            with patch("vpn.views.VPNClientService.portal_qr_png_base64") as legacy_portal_qr_mock:
                with patch("vpn.views.VPNClientService.qr_png_base64") as legacy_qr_mock:
                    response = self.client.get(f"/clients/{self.vpn_client.id}/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "amneziavpn-qr")
        self.assertContains(response, "amneziawg-qr")
        self.assertContains(response, "QR для AmneziaVPN")
        self.assertContains(response, "рекомендуется")
        self.assertEqual(response.context["qr_base64_amneziavpn"], "amneziavpn-qr")
        self.assertEqual(response.context["qr_base64_amneziawg"], "amneziawg-qr")
        target_qr_mock.assert_has_calls(
            [
                call(self.vpn_client, "amneziavpn"),
                call(self.vpn_client, "amneziawg"),
            ]
        )
        self.assertEqual(target_qr_mock.call_count, 2)
        legacy_portal_qr_mock.assert_not_called()
        legacy_qr_mock.assert_not_called()

    def test_admin_qr_modal_uses_target_specific_qrs(self):
        from unittest.mock import call, patch

        with patch(
            "vpn.views.VPNClientService.portal_qr_png_base64_for_target",
            side_effect=lambda client, target: f"{target}-qr",
        ) as target_qr_mock:
            with patch("vpn.views.VPNClientService.portal_qr_png_base64") as legacy_portal_qr_mock:
                with patch("vpn.views.VPNClientService.qr_png_base64") as legacy_qr_mock:
                    response = self.client.get(f"/clients/{self.vpn_client.id}/qr-modal/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "amneziavpn-qr")
        self.assertContains(response, "amneziawg-qr")
        self.assertContains(response, "QR для AmneziaVPN")
        self.assertContains(response, "рекомендуется")
        self.assertEqual(response.context["qr_base64_amneziavpn"], "amneziavpn-qr")
        self.assertEqual(response.context["qr_base64_amneziawg"], "amneziawg-qr")
        target_qr_mock.assert_has_calls(
            [
                call(self.vpn_client, "amneziavpn"),
                call(self.vpn_client, "amneziawg"),
            ]
        )
        self.assertEqual(target_qr_mock.call_count, 2)
        legacy_portal_qr_mock.assert_not_called()
        legacy_qr_mock.assert_not_called()

    def test_admin_download_uses_portal_export_config(self):
        from unittest.mock import patch

        with patch("vpn.views.VPNClientService.portal_export_config", return_value="portal-export") as portal_export_mock:
            with patch("vpn.views.VPNClientService.latest_config") as latest_config_mock:
                response = self.client.get(f"/clients/{self.vpn_client.id}/download/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "portal-export")
        portal_export_mock.assert_called_once_with(self.vpn_client)
        latest_config_mock.assert_not_called()

    def test_admin_and_portal_export_payloads_match(self):
        from unittest.mock import patch

        portal_access, token = PortalAccessService.issue_for_client(self.vpn_client)

        with patch("vpn.views.VPNClientService.portal_export_config", return_value="shared-export"):
            admin_response = self.client.get(f"/clients/{self.vpn_client.id}/download/")

        with patch("portal.views.VPNClientService.portal_export_config_for_target", return_value="shared-export"):
            portal_response = self.client.get(f"/portal/{token}/config/")

        self.assertEqual(admin_response.status_code, 200)
        self.assertEqual(portal_response.status_code, 200)
        self.assertEqual(admin_response.content, portal_response.content)
        self.assertEqual(portal_access.client_id, self.vpn_client.id)

    def test_target_specific_export_uses_different_generators(self):
        from unittest.mock import patch

        with patch("vpn.services.VPNClientService.portal_export_config", return_value="wg-config") as wg_mock:
            with patch("vpn.services.VPNClientService.latest_config", return_value="vpn-config") as vpn_mock:
                self.assertEqual(
                    VPNClientService.portal_export_config_for_target(self.vpn_client, "amneziawg"),
                    "wg-config",
                )
                self.assertEqual(
                    VPNClientService.portal_export_config_for_target(self.vpn_client, "amneziavpn"),
                    "vpn-config",
                )

        wg_mock.assert_called_once_with(self.vpn_client)
        vpn_mock.assert_called_once_with(self.vpn_client)


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
        self.other_user = get_user_model().objects.create_user("admin-portal-renewal-2", password="123", is_staff=True)
        self.client.force_login(self.user)
        self.server = Server.objects.create(name="portal-renewal-server")
        self.server_2 = Server.objects.create(name="portal-renewal-server-2")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            runtime_metadata={"udp_port": 51820, "subnet": "10.66.0.0/24"},
        )
        self.protocol_2 = ServerProtocol.objects.create(
            server=self.server_2,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            runtime_metadata={"udp_port": 51821, "subnet": "10.67.0.0/24"},
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
        self.client_on_second_server = VPNClient.objects.create(
            server=self.server_2,
            name="client-second-server",
            protocol_type=VPNClient.ProtocolType.AWG,
            profile=self.profile,
            created_by=self.other_user,
        )

    def test_admin_can_retrieve_current_portal_link_after_issue(self):
        _, token = PortalAccessService.issue_for_client(self.client_with_renewal)
        response = self.client.get(f"/clients/{self.client_with_renewal.id}/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Сейчас ссылка скрыта.")
        self.assertNotContains(response, f"/portal/{token}/")

    def test_portal_block_renders_open_action_and_link_state(self):
        response = self.client.get(f"/clients/{self.client_with_renewal.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Открыть кабинет")
        self.assertContains(response, "Ссылка кабинета ещё не выпущена.")
        self.assertNotContains(response, "••••••••")
        self.assertContains(response, "disabled>Открыть кабинет")

    def test_portal_show_redirects_back_to_client_detail_and_reveals_link_inline(self):
        _, token = PortalAccessService.issue_for_client(self.client_with_renewal)
        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/portal_show/",
            {"next": f"/clients/{self.client_with_renewal.id}/"},
            follow=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f"/clients/{self.client_with_renewal.id}/?show_portal_link=1")

        detail_response = self.client.get(response.url)
        self.assertContains(detail_response, "Сейчас ссылка показана.")
        self.assertContains(detail_response, f"/portal/{token}/")

    def test_portal_open_reuses_existing_link(self):
        _, token = PortalAccessService.issue_for_client(self.client_with_renewal)
        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/portal_open/",
            follow=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f"/portal/{token}/")

    def test_portal_open_is_blocked_when_link_is_missing(self):
        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/portal_open/",
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Сначала выполните «Регенерировать».")
        self.assertEqual(
            AuditLog.objects.filter(action="portal.access.issue", entity_id=str(self.client_with_renewal.id)).count(),
            0,
        )

    def test_portal_open_is_blocked_after_revoke_until_regeneration(self):
        PortalAccessService.issue_for_client(self.client_with_renewal)
        PortalAccessService.revoke_for_client(self.client_with_renewal)
        blocked_response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/portal_open/",
            follow=True,
        )
        self.assertContains(blocked_response, "Сначала выполните «Регенерировать».")
        self.assertNotContains(blocked_response, "status-success\">активен")

        issue_response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/portal_issue/",
            {"next": f"/clients/{self.client_with_renewal.id}/"},
            follow=False,
        )
        self.assertEqual(issue_response.status_code, 302)
        self.assertIn("show_portal_link=1", issue_response.url)

        reopen_response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/portal_open/",
            follow=False,
        )
        self.assertEqual(reopen_response.status_code, 302)
        self.assertIn("/portal/", reopen_response.url)

    def test_portal_block_has_single_copy_link_action(self):
        PortalAccessService.issue_for_client(self.client_with_renewal)
        response = self.client.get(f"/clients/{self.client_with_renewal.id}/?show_portal_link=1")
        self.assertContains(response, "Скопировать ссылку", count=1)

    def test_portal_actions_use_safe_next_fallback_when_next_is_external(self):
        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/portal_issue/",
            {"next": "https://evil.example/phish"},
            follow=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, f"/clients/{self.client_with_renewal.id}/?show_portal_link=1")

    def test_portal_revoke_redirects_back_to_renewal_queue_when_triggered_from_queue(self):
        PortalAccessService.issue_for_client(self.client_with_renewal)
        next_url = "/clients/renewal-requests/?status=open"
        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/portal_revoke/",
            {"next": next_url},
            follow=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, next_url)

    def test_clients_list_marks_and_filters_open_renewal_requests(self):
        ClientRenewalRequest.objects.create(client=self.client_with_renewal, status=ClientRenewalRequest.Status.NEW)

        response = self.client.get("/clients/")
        self.assertContains(response, "client-with-renewal")
        self.assertContains(response, "Продление")
        self.assertContains(response, "Последняя заявка на продление")

        filtered = self.client.get("/clients/", {"renewal_state": "with"})
        self.assertContains(filtered, "client-with-renewal")
        self.assertNotContains(filtered, "client-without-renewal")

    def test_operator_can_change_renewal_status_and_save_note(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.NEW,
            note="Нужно продление",
        )

        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_obj.id,
                "target_status": ClientRenewalRequest.Status.IN_PROGRESS,
                "operator_note": "Связались с клиентом.",
            },
            follow=True,
        )
        request_obj.refresh_from_db()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(request_obj.status, ClientRenewalRequest.Status.IN_PROGRESS)
        self.assertEqual(request_obj.operator_note, "Связались с клиентом.")
        self.assertTrue(
            AuditLog.objects.filter(
                action="portal.renewal.in_progress",
                entity_type="VPNClient",
                entity_id=str(self.client_with_renewal.id),
            ).exists()
        )

    def test_operator_can_extend_and_close_renewal_request(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.NEW,
            note="Нужно продление",
        )
        old_expires_at = timezone.now() - timedelta(days=1)
        self.client_with_renewal.expires_at = old_expires_at
        self.client_with_renewal.save(update_fields=["expires_at"])

        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_obj.id,
                "target_status": "extend_and_close",
                "extension_days": "14",
                "operator_note": "Продлили на 14 дней.",
            },
            follow=True,
        )
        request_obj.refresh_from_db()
        self.client_with_renewal.refresh_from_db()

        self.assertEqual(response.status_code, 200)
        self.assertEqual(request_obj.status, ClientRenewalRequest.Status.DONE)
        self.assertEqual(request_obj.operator_note, "Продлили на 14 дней.")
        self.assertIsNotNone(request_obj.processed_at)
        self.assertEqual(request_obj.processed_by_id, self.user.id)
        self.assertGreaterEqual(self.client_with_renewal.expires_at, timezone.now() + timedelta(days=13, hours=23))
        self.assertTrue(
            AuditLog.objects.filter(
                action="portal.renewal.extend_and_close",
                entity_type="VPNClient",
                entity_id=str(self.client_with_renewal.id),
            ).exists()
        )

    def test_extend_and_close_uses_default_30_days_when_days_not_passed(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.NEW,
        )
        self.client_with_renewal.expires_at = timezone.now() + timedelta(days=5)
        self.client_with_renewal.save(update_fields=["expires_at"])
        previous_expires = self.client_with_renewal.expires_at

        self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_obj.id,
                "target_status": "extend_and_close",
                "operator_note": "Продлили по стандартному сроку.",
            },
            follow=True,
        )
        self.client_with_renewal.refresh_from_db()

        self.assertGreaterEqual(self.client_with_renewal.expires_at, previous_expires + timedelta(days=29, hours=23))

    def test_extend_and_close_rejects_non_numeric_days(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.NEW,
        )

        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_obj.id,
                "target_status": "extend_and_close",
                "extension_days": "abc",
            },
            follow=True,
        )
        request_obj.refresh_from_db()

        self.assertContains(response, "Укажите число дней продления цифрами.")
        self.assertEqual(request_obj.status, ClientRenewalRequest.Status.NEW)

    def test_extend_and_close_rejects_out_of_range_days(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.NEW,
        )

        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_obj.id,
                "target_status": "extend_and_close",
                "extension_days": "366",
            },
            follow=True,
        )
        request_obj.refresh_from_db()

        self.assertContains(response, "Число дней продления должно быть в диапазоне от 1 до 365.")
        self.assertEqual(request_obj.status, ClientRenewalRequest.Status.NEW)

    def test_extend_and_close_rejects_closed_request(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.DONE,
            processed_at=timezone.now(),
        )

        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_obj.id,
                "target_status": "extend_and_close",
                "extension_days": "30",
            },
            follow=True,
        )
        request_obj.refresh_from_db()

        self.assertContains(response, "Продление доступно только для открытой заявки.")
        self.assertEqual(request_obj.status, ClientRenewalRequest.Status.DONE)


    def test_renewal_status_change_redirects_to_next_url(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.NEW,
        )
        next_url = "/clients/renewal-requests/?status=open"

        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_obj.id,
                "target_status": ClientRenewalRequest.Status.IN_PROGRESS,
                "operator_note": "Берём в работу",
                "next": next_url,
            },
            follow=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, next_url)


    def test_invalid_status_value_redirects_safely_to_next_url(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.NEW,
        )
        next_url = "/clients/renewal-requests/"

        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_obj.id,
                "target_status": "bad_status",
                "operator_note": "",
                "next": next_url,
            },
            follow=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, next_url)

    def test_invalid_transition_redirects_safely_to_next_url(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.DONE,
            processed_at=timezone.now(),
        )
        next_url = "/clients/renewal-requests/?status=done"

        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_obj.id,
                "target_status": ClientRenewalRequest.Status.IN_PROGRESS,
                "operator_note": "Попытка открыть заново",
                "next": next_url,
            },
            follow=False,
        )
        request_obj.refresh_from_db()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, next_url)
        self.assertEqual(request_obj.status, ClientRenewalRequest.Status.DONE)

    def test_comment_only_save_redirects_and_persists_note(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.DISMISSED,
            processed_at=timezone.now(),
        )
        next_url = "/clients/renewal-requests/?status=dismissed"

        response = self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_obj.id,
                "target_status": ClientRenewalRequest.Status.DISMISSED,
                "operator_note": "Комментарий сохранён без смены статуса",
                "next": next_url,
            },
            follow=False,
        )
        request_obj.refresh_from_db()

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, next_url)
        self.assertEqual(request_obj.status, ClientRenewalRequest.Status.DISMISSED)
        self.assertEqual(request_obj.operator_note, "Комментарий сохранён без смены статуса")
        self.assertTrue(
            AuditLog.objects.filter(
                action="portal.renewal.note_updated",
                entity_type="VPNClient",
                entity_id=str(self.client_with_renewal.id),
            ).exists()
        )

    def test_closed_renewal_request_rejects_reopen_transition(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.DONE,
            processed_at=timezone.now(),
        )

        self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_obj.id,
                "target_status": ClientRenewalRequest.Status.IN_PROGRESS,
                "operator_note": "Попытка вернуть в работу",
            },
            follow=True,
        )
        request_obj.refresh_from_db()

        self.assertEqual(request_obj.status, ClientRenewalRequest.Status.DONE)

    def test_client_detail_shows_expired_portal_access_as_not_active(self):
        access, _ = PortalAccessService.issue_for_client(self.client_with_renewal)
        access.expires_at = timezone.now() - timedelta(minutes=5)
        access.save(update_fields=["expires_at"])

        response = self.client.get(f"/clients/{self.client_with_renewal.id}/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Статус доступа:")
        self.assertContains(response, "истёк")
        self.assertNotContains(response, "status-success\">активен")

    def test_client_detail_shows_revoked_portal_access_as_not_active(self):
        PortalAccessService.issue_for_client(self.client_with_renewal)
        PortalAccessService.revoke_for_client(self.client_with_renewal)

        response = self.client.get(f"/clients/{self.client_with_renewal.id}/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Статус доступа:")
        self.assertContains(response, "отозван")
        self.assertNotContains(response, "status-success\">активен")

    def test_client_detail_shows_non_expired_portal_access_as_active(self):
        PortalAccessService.issue_for_client(self.client_with_renewal)

        response = self.client.get(f"/clients/{self.client_with_renewal.id}/")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Статус доступа:")
        self.assertContains(response, "status-success\">активен")

    def test_renewal_requests_list_can_be_filtered_by_server(self):
        first_request = ClientRenewalRequest.objects.create(client=self.client_with_renewal, status=ClientRenewalRequest.Status.NEW)
        second_request = ClientRenewalRequest.objects.create(client=self.client_on_second_server, status=ClientRenewalRequest.Status.NEW)

        response = self.client.get("/clients/renewal-requests/", {"status": "open", "server": str(self.server.id)})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f"#{first_request.id}")
        self.assertNotContains(response, f"#{second_request.id}")

    def test_renewal_requests_list_operator_and_my_actions_filters_work(self):
        request_first = ClientRenewalRequest.objects.create(client=self.client_with_renewal, status=ClientRenewalRequest.Status.NEW)
        request_second = ClientRenewalRequest.objects.create(client=self.client_on_second_server, status=ClientRenewalRequest.Status.NEW)

        self.client.post(
            f"/clients/{self.client_with_renewal.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_first.id,
                "target_status": ClientRenewalRequest.Status.IN_PROGRESS,
                "operator_note": "Взял в работу",
            },
            follow=False,
        )
        self.client.force_login(self.other_user)
        self.client.post(
            f"/clients/{self.client_on_second_server.id}/action/renewal_set_status/",
            {
                "renewal_request_id": request_second.id,
                "target_status": ClientRenewalRequest.Status.IN_PROGRESS,
                "operator_note": "Берём в работу",
            },
            follow=False,
        )
        self.client.force_login(self.user)

        by_operator = self.client.get("/clients/renewal-requests/", {"status": "open", "operator": str(self.user.id)})
        self.assertContains(by_operator, f"#{request_first.id}")
        self.assertNotContains(by_operator, f"#{request_second.id}")

        only_mine = self.client.get("/clients/renewal-requests/", {"status": "open", "only_my_actions": "1"})
        self.assertContains(only_mine, f"#{request_first.id}")
        self.assertNotContains(only_mine, f"#{request_second.id}")

    def test_operator_ui_shows_attachment_presence_and_can_open_it(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.NEW,
            attachment=SimpleUploadedFile("evidence.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n", content_type="application/pdf"),
            attachment_original_name="evidence.pdf",
        )
        list_response = self.client.get("/clients/renewal-requests/")
        detail_response = self.client.get(f"/clients/{self.client_with_renewal.id}/")

        self.assertContains(list_response, "Есть файл")
        self.assertContains(list_response, "evidence.pdf")
        self.assertContains(list_response, "Открыть файл")
        self.assertContains(detail_response, "evidence.pdf")
        self.assertContains(detail_response, "Вложение:")

        download_response = self.client.get(f"/clients/renewal-requests/{request_obj.id}/attachment/")
        self.assertEqual(download_response.status_code, 200)

    def test_attachment_download_is_protected_for_anonymous(self):
        request_obj = ClientRenewalRequest.objects.create(
            client=self.client_with_renewal,
            status=ClientRenewalRequest.Status.NEW,
            attachment=SimpleUploadedFile("evidence.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n", content_type="application/pdf"),
        )
        self.client.logout()
        response = self.client.get(f"/clients/renewal-requests/{request_obj.id}/attachment/")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class VPNClientCreateFormProtocolAvailabilityTests(TestCase):
    def setUp(self):
        self.server = Server.objects.create(name="form-protocol-server")
        self.awg_protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            enabled=False,
            container_status="exited",
        )
        self.awg2_protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_status="running",
        )
        ProtocolProfile.objects.create(
            server_protocol=self.awg_protocol,
            name="default-awg",
            protocol_type=ServerProtocol.ProtocolType.AWG,
            config_template="[Interface]",
            status=ProtocolProfile.ProfileStatus.ACTIVE,
        )
        ProtocolProfile.objects.create(
            server_protocol=self.awg2_protocol,
            name="default-awg2",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="[Interface]",
            status=ProtocolProfile.ProfileStatus.ACTIVE,
        )

    def test_form_lists_only_available_protocols_and_defaults_to_awg2(self):
        form = VPNClientCreateForm(server=self.server)
        self.assertEqual(list(form.fields["protocol_type"].choices), [(VPNClient.ProtocolType.AWG2, "AWG2")])
        self.assertEqual(form.fields["protocol_type"].initial, VPNClient.ProtocolType.AWG2)

    def test_form_rejects_protocol_without_enabled_server_protocol(self):
        form = VPNClientCreateForm(
            data={
                "name": "client-1",
                "protocol_type": VPNClient.ProtocolType.AWG,
                "expires_preset": VPNClientCreateForm.EXPIRATION_PRESET_UNLIMITED,
                "traffic_limit_preset": VPNClientCreateForm.TRAFFIC_PRESET_UNLIMITED,
            },
            server=self.server,
        )
        self.assertFalse(form.is_valid())
        self.assertIn("protocol_type", form.errors)


@override_settings(
    CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode(),
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="no-reply@example.com",
    ADMIN_EXPIRATION_REMINDER_EMAILS=["admin@example.com"],
    ADMINS=(),
    EXPIRATION_REMINDER_ENABLED=True,
    EXPIRATION_REMINDER_DAYS=[7, 3, 1],
    SITE_URL="https://control.example.com",
    PUBLIC_BASE_URL="",
)
class ClientExpirationReminderTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("reminder-admin", password="123", is_staff=True)
        self.server = Server.objects.create(name="reminder-server")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            container_name="amnezia-awg",
            enabled=True,
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="reminder-profile",
            protocol_type=ServerProtocol.ProtocolType.AWG,
            config_template="[Interface]",
        )
        mail.outbox = []

    def _make_client(self, *, name, expires_at, status=VPNClient.Status.ACTIVE):
        return VPNClient.objects.create(
            server=self.server,
            name=name,
            protocol_type=VPNClient.ProtocolType.AWG,
            status=status,
            profile=self.profile,
            created_by=self.user,
            expires_at=expires_at,
        )

    def test_clients_expiring_in_configured_days_are_included_once_at_closest_threshold(self):
        now = timezone.now()
        self._make_client(name="expires-seven", expires_at=now + timezone.timedelta(days=7))
        self._make_client(name="expires-three", expires_at=now + timezone.timedelta(days=3))
        self._make_client(name="expires-one", expires_at=now + timezone.timedelta(days=1))

        result = ClientExpirationReminderService.send_reminders()

        self.assertEqual(result["emails_sent"], 1)
        self.assertEqual(result["clients"], 3)
        self.assertEqual(result["items"], 3)
        self.assertEqual(len(mail.outbox), 1)
        body = mail.outbox[0].body
        self.assertIn("expires-seven", body)
        self.assertIn("expires-three", body)
        self.assertIn("expires-one", body)
        self.assertEqual(body.count("expires-seven"), 1)
        self.assertEqual(body.count("expires-three"), 1)
        self.assertEqual(body.count("expires-one"), 1)
        self.assertIn("protocol_type: awg", body)
        self.assertIn("status: active", body)
        self.assertIn("https://control.example.com/clients/", body)
        thresholds_by_name = dict(
            ClientExpirationReminderLog.objects.values_list("client__name", "threshold_days")
        )
        self.assertEqual(thresholds_by_name["expires-seven"], 7)
        self.assertEqual(thresholds_by_name["expires-three"], 3)
        self.assertEqual(thresholds_by_name["expires-one"], 1)

    def test_expired_clients_are_not_included_as_upcoming(self):
        now = timezone.now()
        self._make_client(name="already-expired", expires_at=now - timezone.timedelta(minutes=1))
        self._make_client(name="upcoming", expires_at=now + timezone.timedelta(days=1))

        ClientExpirationReminderService.send_reminders()

        self.assertEqual(len(mail.outbox), 1)
        self.assertNotIn("already-expired", mail.outbox[0].body)
        self.assertIn("upcoming", mail.outbox[0].body)

    def test_clients_without_expires_at_are_ignored(self):
        self._make_client(name="no-expiration", expires_at=None)
        self._make_client(name="with-expiration", expires_at=timezone.now() + timezone.timedelta(days=1))

        ClientExpirationReminderService.send_reminders()

        self.assertEqual(len(mail.outbox), 1)
        self.assertNotIn("no-expiration", mail.outbox[0].body)
        self.assertIn("with-expiration", mail.outbox[0].body)

    def test_duplicate_reminders_are_not_sent_for_same_client_threshold_and_expiration(self):
        self._make_client(name="dedup-client", expires_at=timezone.now() + timezone.timedelta(days=3))

        first_result = ClientExpirationReminderService.send_reminders()
        second_result = ClientExpirationReminderService.send_reminders()

        self.assertEqual(first_result["emails_sent"], 1)
        self.assertEqual(second_result["emails_sent"], 0)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(ClientExpirationReminderLog.objects.count(), first_result["logs_created"])

    def test_after_expires_at_changes_reminder_can_be_sent_again(self):
        client = self._make_client(name="extended-client", expires_at=timezone.now() + timezone.timedelta(days=3))
        ClientExpirationReminderService.send_reminders()
        client.expires_at = timezone.now() + timezone.timedelta(days=5)
        client.save(update_fields=["expires_at"])

        result = ClientExpirationReminderService.send_reminders()

        self.assertEqual(result["emails_sent"], 1)
        self.assertEqual(len(mail.outbox), 2)
        self.assertIn("extended-client", mail.outbox[1].body)

    @override_settings(ADMIN_EXPIRATION_REMINDER_EMAILS=[], ADMINS=())
    def test_no_recipients_configured_does_not_crash(self):
        self._make_client(name="no-recipient-client", expires_at=timezone.now() + timezone.timedelta(days=1))

        result = ClientExpirationReminderService.send_reminders()

        self.assertEqual(result["emails_sent"], 0)
        self.assertEqual(len(mail.outbox), 0)

    def test_management_command_returns_success(self):
        self._make_client(name="command-client", expires_at=timezone.now() + timezone.timedelta(days=1))
        out = StringIO()

        call_command("send_expiration_reminders", stdout=out)

        self.assertIn("Expiration reminders completed", out.getvalue())
        self.assertIn("email_sent=True", out.getvalue())
        self.assertEqual(len(mail.outbox), 1)

    class _TelegramResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def getcode(self):
            return self.status

        def read(self):
            return b'{"ok": true}'

    @override_settings(
        EXPIRATION_REMINDER_CHANNELS=["telegram"],
        TELEGRAM_BOT_TOKEN="123456:test-token",
        TELEGRAM_ADMIN_CHAT_IDS=["123456789"],
    )
    @patch("vpn.expiration_reminders.urllib.request.urlopen")
    def test_telegram_channel_sends_https_request_with_correct_url_and_payload(self, mock_urlopen):
        mock_urlopen.return_value = self._TelegramResponse()
        client = self._make_client(name="telegram-client", expires_at=timezone.now() + timezone.timedelta(days=1))

        result = ClientExpirationReminderService.send_reminders()

        self.assertTrue(result["channels"]["telegram"]["sent"])
        self.assertEqual(result["logs_created"], 1)
        request = mock_urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.telegram.org/bot123456:test-token/sendMessage")
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["chat_id"], "123456789")
        self.assertIn("Истекают VPN-клиенты", payload["text"])
        self.assertIn(str(client.id), payload["text"])
        self.assertIn("telegram-client", payload["text"])
        self.assertIn("protocol_type: awg", payload["text"])
        self.assertIn("status: active", payload["text"])
        self.assertIn("https://control.example.com/clients/", payload["text"])

    @override_settings(
        EXPIRATION_REMINDER_CHANNELS=["telegram"],
        TELEGRAM_BOT_TOKEN="",
        TELEGRAM_ADMIN_CHAT_IDS=["123456789"],
    )
    def test_missing_telegram_bot_token_creates_no_logs_when_telegram_only(self):
        self._make_client(name="missing-token", expires_at=timezone.now() + timezone.timedelta(days=1))

        result = ClientExpirationReminderService.send_reminders()

        self.assertFalse(result["channels"]["telegram"]["sent"])
        self.assertIn("TELEGRAM_BOT_TOKEN", result["channels"]["telegram"]["error"])
        self.assertEqual(ClientExpirationReminderLog.objects.count(), 0)

    @override_settings(
        EXPIRATION_REMINDER_CHANNELS=["telegram"],
        TELEGRAM_BOT_TOKEN="123456:test-token",
        TELEGRAM_ADMIN_CHAT_IDS=[],
    )
    def test_missing_telegram_chat_ids_creates_no_logs_when_telegram_only(self):
        self._make_client(name="missing-chat", expires_at=timezone.now() + timezone.timedelta(days=1))

        result = ClientExpirationReminderService.send_reminders()

        self.assertFalse(result["channels"]["telegram"]["sent"])
        self.assertIn("TELEGRAM_ADMIN_CHAT_IDS", result["channels"]["telegram"]["error"])
        self.assertEqual(ClientExpirationReminderLog.objects.count(), 0)

    @override_settings(
        EXPIRATION_REMINDER_CHANNELS=["telegram"],
        TELEGRAM_BOT_TOKEN="123456:test-token",
        TELEGRAM_ADMIN_CHAT_IDS=["123456789"],
    )
    @patch("vpn.expiration_reminders.urllib.request.urlopen")
    def test_telegram_api_error_creates_no_logs_when_telegram_only(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.HTTPError(
            url="https://api.telegram.org/bot123456:test-token/sendMessage",
            code=400,
            msg="Bad Request",
            hdrs=None,
            fp=BytesIO(b'{"ok":false,"description":"bad chat"}'),
        )
        self._make_client(name="telegram-error", expires_at=timezone.now() + timezone.timedelta(days=1))

        result = ClientExpirationReminderService.send_reminders()

        self.assertFalse(result["channels"]["telegram"]["sent"])
        self.assertIn("HTTP 400", result["channels"]["telegram"]["error"])
        self.assertNotIn("123456:test-token", result["channels"]["telegram"]["error"])
        self.assertEqual(ClientExpirationReminderLog.objects.count(), 0)

    @override_settings(
        EXPIRATION_REMINDER_CHANNELS=["telegram"],
        TELEGRAM_BOT_TOKEN="123456:test-token",
        TELEGRAM_ADMIN_CHAT_IDS=["123456789"],
    )
    @patch("vpn.expiration_reminders.urllib.request.urlopen")
    def test_successful_telegram_send_creates_logs(self, mock_urlopen):
        mock_urlopen.return_value = self._TelegramResponse()
        self._make_client(name="telegram-success", expires_at=timezone.now() + timezone.timedelta(days=1))

        result = ClientExpirationReminderService.send_reminders()

        self.assertTrue(result["channels"]["telegram"]["sent"])
        self.assertEqual(result["logs_created"], 1)
        self.assertEqual(ClientExpirationReminderLog.objects.count(), 1)
        self.assertEqual(len(mail.outbox), 0)

    @override_settings(
        EXPIRATION_REMINDER_CHANNELS=["email", "telegram"],
        TELEGRAM_BOT_TOKEN="123456:test-token",
        TELEGRAM_ADMIN_CHAT_IDS=["123456789"],
    )
    @patch("vpn.expiration_reminders.urllib.request.urlopen")
    def test_email_success_and_telegram_failure_still_creates_logs(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError("network blocked")
        self._make_client(name="email-fallback", expires_at=timezone.now() + timezone.timedelta(days=1))

        result = ClientExpirationReminderService.send_reminders()

        self.assertTrue(result["channels"]["email"]["sent"])
        self.assertFalse(result["channels"]["telegram"]["sent"])
        self.assertEqual(result["logs_created"], 1)
        self.assertEqual(ClientExpirationReminderLog.objects.count(), 1)
        self.assertEqual(len(mail.outbox), 1)

    @override_settings(
        EXPIRATION_REMINDER_CHANNELS=["telegram"],
        TELEGRAM_BOT_TOKEN="123456:test-token",
        TELEGRAM_ADMIN_CHAT_IDS=["111", "222"],
    )
    @patch("vpn.expiration_reminders.urllib.request.urlopen")
    def test_telegram_partial_chat_failure_is_not_sent_and_creates_no_logs_when_telegram_only(self, mock_urlopen):
        mock_urlopen.side_effect = [self._TelegramResponse(), urllib.error.URLError("chat 222 blocked")]
        self._make_client(name="partial-telegram", expires_at=timezone.now() + timezone.timedelta(days=1))

        result = ClientExpirationReminderService.send_reminders()

        self.assertFalse(result["channels"]["telegram"]["sent"])
        self.assertIn("chat_id=222", result["channels"]["telegram"]["error"])
        self.assertNotIn("123456:test-token", result["channels"]["telegram"]["error"])
        self.assertEqual(result["logs_created"], 0)
        self.assertEqual(ClientExpirationReminderLog.objects.count(), 0)
        self.assertEqual(mock_urlopen.call_count, 2)

    @override_settings(
        EXPIRATION_REMINDER_CHANNELS=["telegram"],
        TELEGRAM_BOT_TOKEN="123456:test-token",
        TELEGRAM_ADMIN_CHAT_IDS=["111", "222"],
    )
    @patch("vpn.expiration_reminders.urllib.request.urlopen")
    def test_telegram_multiple_chat_success_creates_logs(self, mock_urlopen):
        mock_urlopen.side_effect = [self._TelegramResponse(), self._TelegramResponse()]
        self._make_client(name="multi-chat-success", expires_at=timezone.now() + timezone.timedelta(days=1))

        result = ClientExpirationReminderService.send_reminders()

        self.assertTrue(result["channels"]["telegram"]["sent"])
        self.assertEqual(result["channels"]["telegram"]["error"], "")
        self.assertEqual(result["logs_created"], 1)
        self.assertEqual(ClientExpirationReminderLog.objects.count(), 1)
        self.assertEqual(mock_urlopen.call_count, 2)

    @override_settings(
        EXPIRATION_REMINDER_CHANNELS=["email", "telegram"],
        TELEGRAM_BOT_TOKEN="123456:test-token",
        TELEGRAM_ADMIN_CHAT_IDS=["111", "222"],
    )
    @patch("vpn.expiration_reminders.urllib.request.urlopen")
    def test_email_success_with_telegram_partial_chat_failure_still_creates_logs(self, mock_urlopen):
        mock_urlopen.side_effect = [self._TelegramResponse(), urllib.error.URLError("chat 222 blocked")]
        self._make_client(name="email-with-partial-telegram", expires_at=timezone.now() + timezone.timedelta(days=1))

        result = ClientExpirationReminderService.send_reminders()

        self.assertTrue(result["channels"]["email"]["sent"])
        self.assertFalse(result["channels"]["telegram"]["sent"])
        self.assertIn("chat_id=222", result["channels"]["telegram"]["error"])
        self.assertEqual(result["logs_created"], 1)
        self.assertEqual(ClientExpirationReminderLog.objects.count(), 1)
        self.assertEqual(len(mail.outbox), 1)

    @override_settings(
        EXPIRATION_REMINDER_CHANNELS=["telegram"],
        TELEGRAM_BOT_TOKEN="123456:test-token",
        TELEGRAM_ADMIN_CHAT_IDS=["123456789"],
    )
    @patch("vpn.expiration_reminders.urllib.request.urlopen")
    def test_long_telegram_message_is_split_into_multiple_send_message_calls(self, mock_urlopen):
        mock_urlopen.return_value = self._TelegramResponse()
        for number in range(70):
            self._make_client(
                name=f"long-telegram-client-{number}-" + ("x" * 80),
                expires_at=timezone.now() + timezone.timedelta(days=1, minutes=number),
            )

        result = ClientExpirationReminderService.send_reminders()

        self.assertTrue(result["channels"]["telegram"]["sent"])
        self.assertGreater(mock_urlopen.call_count, 1)
        for call in mock_urlopen.call_args_list:
            payload = json.loads(call.args[0].data.decode("utf-8"))
            self.assertLessEqual(len(payload["text"]), 4096)

    @override_settings(
        EXPIRATION_REMINDER_CHANNELS=["telegram"],
        TELEGRAM_BOT_TOKEN="super-secret-bot-token",
        TELEGRAM_ADMIN_CHAT_IDS=["123456789", "-1001234567890"],
    )
    def test_settings_page_renders_without_exposing_telegram_bot_token(self):
        self.client.force_login(self.user)

        response = self.client.get("/settings/")

        self.assertEqual(response.status_code, 200)
        content = response.content.decode("utf-8")
        self.assertIn("Telegram chat ids", content)
        self.assertIn("2", content)
        self.assertNotIn("super-secret-bot-token", content)
        self.assertNotIn("123456789", content)
        self.assertNotIn("-1001234567890", content)
