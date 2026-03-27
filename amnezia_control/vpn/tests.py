from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from servers.models import ProtocolProfile, Server, ServerProtocol

from .models import VPNClient
from .services import AdapterFactory, VPNClientService


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
            "awg.add_peer": R(""),
            "awg.remove_peer": R(""),
            "awg.server_pub": R("server-public-key==\n"),
            "awg.list": R("peerkey\tpsk\tendpoint\t10.66.0.10/32\t0\t0\t0\t25\n"),
            "awg2.iface": R("wg0\n"),
            "awg2.genkey": R("client2-private-key==\n"),
            "awg2.pubkey": R("client2-public-key==\n"),
            "awg2.add_peer": R(""),
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

    def test_awg2_missing_metadata_fails_export(self):
        from unittest.mock import patch

        self.awg2_protocol.runtime_metadata = {"udp_port": 51830, "subnet": "10.77.0.0/24", "awg2_metadata": {"S1": "1"}}
        self.awg2_protocol.save(update_fields=["runtime_metadata"])
        with patch("vpn.services.RuntimeCommandService.run", side_effect=self._mock_run):
            with self.assertRaises(RuntimeError):
                VPNClientService.create_client(server=self.server, name="awg2-broken", protocol_type=VPNClient.ProtocolType.AWG2, actor=self.user)


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

    def test_adapter_factory_separates_protocols(self):
        awg_adapter = AdapterFactory.get_for_server(self.server, VPNClient.ProtocolType.AWG)
        awg2_adapter = AdapterFactory.get_for_server(self.server, VPNClient.ProtocolType.AWG2)
        self.assertEqual(awg_adapter.command_bin, "awg")
        self.assertEqual(awg2_adapter.command_bin, "wg")
