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
    def test_sync_runtime_state_detects_containers(self, run_mock):
        class Result:
            def __init__(self, stdout):
                self.stdout = stdout

        run_mock.side_effect = [
            Result("amnezia-awg\namnezia-awg2\n"),
            Result('[{"State":{"Status":"running"},"NetworkSettings":{"Ports":{"51820/udp":[{"HostPort":"51820"}]}},"Config":{"Image":"awg"},"Mounts":[]}]'),
            Result('[{"State":{"Status":"running"},"NetworkSettings":{"Ports":{"51830/udp":[{"HostPort":"51830"}]}},"Config":{"Image":"awg2"},"Mounts":[]}]'),
        ]

        ServerService.sync_runtime_state(server=self.server, actor=self.user)
        self.assertEqual(self.server.protocols.count(), 2)
        self.assertTrue(self.server.protocols.filter(protocol_type="awg", enabled=True).exists())
