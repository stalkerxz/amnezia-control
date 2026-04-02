from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import Server, ServerProtocol
from .services import ServerService


class ServerModelTest(TestCase):
    def test_create_server(self):
        server = Server.objects.create(name="s1")
        self.assertEqual(server.port, 22)


class RuntimeDetectionTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin", password="123", is_staff=True)
        self.server = Server.objects.create(name="local", public_endpoint_host="vpn.example.com")

    def test_awg2_parser_env_parse_canonical_keys(self):
        env = [
            "AWG2_I1=1", "AWG2_I2=2", "AWG2_I3=3", "AWG2_I4=4", "AWG2_I5=5",
            "AWG2_S1=6", "AWG2_S2=7", "AWG2_S3=8", "AWG2_S4=9",
            "AWG2_JC=10", "AWG2_JMIN=11", "AWG2_JMAX=12",
            "AWG2_H1=13", "AWG2_H2=14", "AWG2_H3=15", "AWG2_H4=16",
        ]
        parsed, required_missing, optional_missing = ServerService._parse_awg2_metadata(env, "")
        self.assertEqual(parsed["Jc"], "10")
        self.assertEqual(parsed["Jmin"], "11")
        self.assertEqual(parsed["Jmax"], "12")
        self.assertEqual(required_missing, [])
        self.assertEqual(optional_missing, [])

    def test_awg2_parser_config_parse_canonical_keys(self):
        conf = "\n".join([
            "S1 = 6", "S2 = 7", "S3 = 8", "S4 = 9",
            "Jc = 10", "Jmin = 11", "Jmax = 12",
            "H1 = 13", "H2 = 14", "H3 = 15", "H4 = 16",
            "# I1 = 1",
        ])
        parsed, required_missing, optional_missing = ServerService._parse_awg2_metadata([], conf)
        self.assertEqual(parsed["Jc"], "10")
        self.assertEqual(required_missing, [])
        self.assertIn("I1", optional_missing)

    def test_awg2_parser_reports_exact_missing_keys(self):
        env = ["AWG2_S1=2", "AWG2_JC=3"]
        parsed, required_missing, _ = ServerService._parse_awg2_metadata(env, "")
        self.assertEqual(parsed["Jc"], "3")
        self.assertIn("S2", required_missing)
        self.assertIn("Jmin", required_missing)

    def test_parse_peers_from_config_text(self):
        conf = (
            "[Interface]\nAddress = 10.8.1.0/24\n"
            "[Peer]\nPublicKey = pk1\nAllowedIPs = 10.8.1.10/32\n"
            "[Peer]\nPublicKey = pk2\nAllowedIPs = 10.8.1.11/32\n"
        )
        peers = ServerService._parse_peers_from_config_text(conf)
        self.assertEqual(len(peers), 2)
        self.assertEqual(peers[0]["public_key"], "pk1")

    @patch("servers.services.RuntimeCommandService.run")
    def test_sync_runtime_state_metadata_storage_canonical_awg2(self, run_mock):
        class Result:
            def __init__(self, stdout):
                self.stdout = stdout

        run_mock.side_effect = [
            Result("amnezia-awg\namnezia-awg2\n"),
            Result("amnezia-awg\namnezia-awg2\n"),
            Result('[{"State":{"Status":"running"},"NetworkSettings":{"Ports":{"51820/udp":[{"HostIp":"203.0.113.10","HostPort":"51820"}]}},"Config":{"Image":"awg","Env":["A=1"]},"Mounts":[]}]'),
            Result("awg0\n"),
            Result("awg0\tprivate\tpub\t51820\npeer1\tpsk\tep\t10.66.0.10/32\t0\t0\t0\t25\n"),
            Result("[Interface]\nAddress = 10.66.0.1/24\nListenPort = 51820\n"),
            Result('[{"State":{"Status":"running"},"NetworkSettings":{"Ports":{"51830/udp":[{"HostIp":"198.51.100.20","HostPort":"51830"}]}},"Config":{"Image":"awg2","Env":["AWG2_S1=6","AWG2_S2=7","AWG2_S3=8","AWG2_S4=9","AWG2_JC=10","AWG2_JMIN=11","AWG2_JMAX=12","AWG2_H1=13","AWG2_H2=14","AWG2_H3=15","AWG2_H4=16"]},"Mounts":[]}]'),
            Result("wg0\n"),
            Result("wg0\tprivate\tpub\t51830\npeer2\tpsk\tep\t10.8.1.10/32\t0\t0\t0\t25\n"),
            Result("[Interface]\nAddress = 10.8.1.0/24\nListenPort = 49561\nJc = 10\n"),
        ]

        ServerService.sync_runtime_state(server=self.server, actor=self.user)
        awg2 = self.server.protocols.get(protocol_type="awg2")
        self.assertEqual(awg2.runtime_metadata["awg2_metadata"]["Jc"], "10")
        self.assertTrue(awg2.runtime_metadata["endpoint_host_ready"])
        self.assertTrue(awg2.runtime_metadata["subnet_ready"])
        self.assertEqual(awg2.runtime_metadata["peer_source"], "runtime wg dump")

    @patch("servers.services.RuntimeCommandService.run")
    def test_sync_runtime_state_awg2_uses_config_peer_fallback_when_dump_fails(self, run_mock):
        class Result:
            def __init__(self, stdout):
                self.stdout = stdout

        def side_effect(*args, **kwargs):
            action = args[2]
            mapping = {
                "runtime.ps_all": Result("amnezia-awg2\n"),
                "runtime.ps_running": Result("amnezia-awg2\n"),
                "runtime.inspect.awg2": Result('[{"State":{"Status":"running"},"NetworkSettings":{"Ports":{"51830/udp":[{"HostIp":"198.51.100.20","HostPort":"51830"}]}},"Config":{"Image":"awg2","Env":["AWG2_S1=6","AWG2_S2=7","AWG2_S3=8","AWG2_S4=9","AWG2_JC=10","AWG2_JMIN=11","AWG2_JMAX=12","AWG2_H1=13","AWG2_H2=14","AWG2_H3=15","AWG2_H4=16"]},"Mounts":[]}]'),
                "runtime.iface.awg2": Result("wg0\n"),
                "runtime.conf.awg2": Result("[Interface]\nAddress = 10.8.1.0/24\nListenPort = 49561\n[Peer]\nPublicKey = pk1\nAllowedIPs = 10.8.1.10/32\n"),
            }
            if action == "runtime.peers.awg2":
                raise RuntimeError("Unable to access interface: Protocol not supported")
            return mapping[action]

        run_mock.side_effect = side_effect
        ServerService.sync_runtime_state(server=self.server, actor=self.user)
        awg2 = self.server.protocols.get(protocol_type="awg2")
        self.assertEqual(awg2.runtime_metadata["peer_source"], "config file fallback (degraded telemetry)")
        self.assertEqual(awg2.runtime_metadata["peer_count"], 1)


class ServerDetailViewTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin", password="123", is_staff=True)
        self.server = Server.objects.create(
            name="dc-1",
            public_endpoint_host="vpn.example.com",
            public_endpoint_port=51820,
            health_status="unknown",
        )
        ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            runtime_metadata={"endpoint_host_ready": True, "endpoint_port_ready": True, "subnet_ready": True},
        )

    def test_server_detail_renders_operator_summary(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("servers-detail", kwargs={"pk": self.server.id}))
        self.assertContains(response, "Контур сервера")
        self.assertContains(response, "Публичный endpoint")
        self.assertContains(response, "Ключевые действия оператора")
        self.assertContains(response, "Диагностика протоколов и readiness")
