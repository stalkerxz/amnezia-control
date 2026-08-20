from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from servers.agent_backend import RemoteAWG2AgentAdapter
from servers.agent_vpn_hooks import _agent_routes, _validate_agent_config
from servers.models import ProtocolProfile, Server, ServerProtocol
from servers.services import ServerService
from vpn.models import VPNClient
from vpn.services import AWG2Adapter, AdapterFactory


AWG2_META = {
    "Jc": "4",
    "Jmin": "40",
    "Jmax": "70",
    "S1": "12",
    "S2": "12",
    "S3": "12",
    "S4": "12",
    "H1": "1077348047",
    "H2": "1103300055",
    "H3": "1875543015",
    "H4": "1939083639",
}


class AgentBackendTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            "agent-admin",
            password="123",
            is_staff=True,
        )

    def test_server_defaults_to_docker_backend(self):
        server = Server.objects.create(name="docker-default")
        self.assertEqual(server.runtime_backend, Server.RuntimeBackend.DOCKER)

    def test_docker_adapter_dispatch_is_unchanged(self):
        server = Server.objects.create(name="docker")
        ServerProtocol.objects.create(
            server=server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
        )
        adapter = AdapterFactory.get_for_server(
            server,
            ServerProtocol.ProtocolType.AWG2,
        )
        self.assertIsInstance(adapter, AWG2Adapter)

    @patch("servers.agent_backend._agent_call")
    def test_agent_sync_maps_awg4_to_awg2(self, agent_call):
        server = Server.objects.create(
            name="agent",
            host="198.51.100.20",
            public_endpoint_host="vpn.example.com",
            runtime_backend=Server.RuntimeBackend.AWG_AGENT,
        )

        def result(_server, _actor, agent, operation, **_kwargs):
            self.assertEqual(operation, "runtime_info")
            if agent == "awg3":
                return {
                    "backend": "awg_agent",
                    "agent": "awg3",
                    "interface": "awg3",
                    "interface_up": True,
                    "config_path": "/etc/amnezia/amneziawg/awg3.conf",
                    "udp_port": 51830,
                    "subnet": "10.77.0.0/24",
                    "interface_addresses": ["10.77.0.1/24"],
                    "peer_count": 10,
                    "reservation_count": 0,
                }
            return {
                "backend": "awg_agent",
                "agent": "awg4",
                "interface": "awg4",
                "interface_up": True,
                "config_path": "/etc/amnezia/amneziawg/awg4.conf",
                "udp_port": 51831,
                "subnet": "10.78.0.0/24",
                "interface_addresses": ["10.78.0.1/24"],
                "peer_count": 15,
                "reservation_count": 0,
                "awg2_metadata": AWG2_META,
            }

        agent_call.side_effect = result
        ServerService.sync_runtime_state(server=server, actor=self.user)

        server.refresh_from_db()
        awg = server.protocols.get(protocol_type=ServerProtocol.ProtocolType.AWG)
        awg2 = server.protocols.get(protocol_type=ServerProtocol.ProtocolType.AWG2)

        self.assertFalse(awg.enabled)
        self.assertEqual(awg.container_name, "awg-agent:awg3")
        self.assertTrue(awg2.enabled)
        self.assertEqual(awg2.container_name, "awg-agent:awg4")
        self.assertEqual(awg2.container_status, "running")
        self.assertEqual(awg2.runtime_metadata["backend"], "awg_agent")
        self.assertEqual(awg2.runtime_metadata["udp_port"], 51831)
        self.assertEqual(awg2.runtime_metadata["subnet"], "10.78.0.0/24")
        self.assertTrue(awg2.runtime_metadata["awg2_metadata_ready"])
        self.assertEqual(server.health_status, "healthy")

        adapter = AdapterFactory.get_for_server(
            server,
            ServerProtocol.ProtocolType.AWG2,
        )
        self.assertIsInstance(adapter, RemoteAWG2AgentAdapter)

    def test_agent_config_validation_keeps_agent_native_layout(self):
        config = "\n".join(
            [
                "[Interface]",
                "PrivateKey = client-private",
                "Address = 10.78.0.20/32",
                "Jc = 4",
                "Jmin = 40",
                "Jmax = 70",
                "S1 = 12",
                "S2 = 12",
                "S3 = 12",
                "S4 = 12",
                "H1 = 1",
                "H2 = 2",
                "H3 = 3",
                "H4 = 4",
                "",
                "[Peer]",
                "PublicKey = server-public",
                "Endpoint = 198.51.100.20:51831",
                "AllowedIPs = 0.0.0.0/0",
                "PersistentKeepalive = 25",
                "",
            ]
        )
        returned, public_key, address = _validate_agent_config(
            {
                "conf": config,
                "public_key": "client-public",
                "address": "10.78.0.20/32",
            }
        )
        self.assertEqual(returned, config)
        self.assertEqual(public_key, "client-public")
        self.assertEqual(address, "10.78.0.20")
        self.assertIn("Jc = 4\nJmin = 40", returned)
        self.assertLess(returned.index("Jc = 4"), returned.index("[Peer]"))

    def test_agent_routes_use_selective_profile(self):
        server = Server.objects.create(
            name="agent-routes",
            runtime_backend=Server.RuntimeBackend.AWG_AGENT,
        )
        protocol = ServerProtocol.objects.create(
            server=server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="awg-agent:awg4",
            container_status="running",
            runtime_metadata={"backend": "awg_agent", "agent": "awg4"},
        )
        profile = ProtocolProfile.objects.create(
            server_protocol=protocol,
            name="selective",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template=(
                "# routing-mode: selective\n"
                "8.8.8.0/24\n"
                "1.1.1.0/24\n"
            ),
        )
        client = VPNClient.objects.create(
            server=server,
            name="selective-client",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=profile,
            created_by=self.user,
        )
        mode, routes = _agent_routes(client)
        self.assertEqual(mode, "selective")
        self.assertEqual(routes, ["1.1.1.0/24", "8.8.8.0/24"])
