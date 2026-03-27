from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase

from .models import Server
from .services import ServerService


class ServerModelTest(TestCase):
    def test_create_server(self):
        server = Server.objects.create(name="s1")
        self.assertEqual(server.port, 22)


class RuntimeDetectionTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin", password="123", is_staff=True)
        self.server = Server.objects.create(name="local")

    @patch("servers.services.RuntimeCommandService.run")
    def test_sync_runtime_state_detects_subnet_and_awg2_metadata(self, run_mock):
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
            Result('[{"State":{"Status":"running"},"NetworkSettings":{"Ports":{"51830/udp":[{"HostIp":"198.51.100.20","HostPort":"51830"}]}},"Config":{"Image":"awg2","Env":["AWG2_S1=1","AWG2_S2=2","AWG2_H1=3","AWG2_H2=4","AWG2_H3=5","AWG2_H4=6"]},"Mounts":[]}]'),
            Result("wg0\n"),
            Result("wg0\tprivate\tpub\t51830\npeer2\tpsk\tep\t10.77.0.10/32\t0\t0\t0\t25\n"),
            Result("[Interface]\nAddress = 10.77.0.1/24\nListenPort = 51830\n"),
        ]

        ServerService.sync_runtime_state(server=self.server, actor=self.user)
        awg = self.server.protocols.get(protocol_type="awg")
        awg2 = self.server.protocols.get(protocol_type="awg2")

        self.assertEqual(awg.runtime_metadata["subnet"], "10.66.0.0/24")
        self.assertEqual(awg2.runtime_metadata["subnet"], "10.77.0.0/24")
        self.assertTrue(awg2.runtime_metadata["awg2_metadata_ready"])
