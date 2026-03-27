from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from servers.models import ProtocolProfile, Server, ServerProtocol

from .models import VPNClient
from .services import VPNClientService


@override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
class VPNClientFlowTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin", password="123", is_staff=True)
        self.server = Server.objects.create(name="local")
        self.sp = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            container_name="amnezia-awg",
            enabled=True,
            runtime_metadata={"udp_port": 51820},
        )
        ProtocolProfile.objects.create(
            server_protocol=self.sp,
            name="default",
            protocol_type=ServerProtocol.ProtocolType.AWG,
            config_template="[Interface]",
        )

    def _mock_run(self, *args, **kwargs):
        class R:
            def __init__(self, stdout):
                self.stdout = stdout

        action = args[2]
        mapping = {
            "awg.iface": R("wg0\n"),
            "awg.genkey": R("client-private-key==\n"),
            "awg.pubkey": R("client-public-key==\n"),
            "awg.add_peer": R(""),
            "awg.server_pub": R("server-public-key==\n"),
            "awg.list": R("wg0\tprivate\tpub\t51820\n"),
        }
        return mapping[action]

    @override_settings(CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_create_client_creates_revision(self):
        from unittest.mock import patch

        with patch("vpn.services.RuntimeCommandService.run", side_effect=self._mock_run):
            client = VPNClientService.create_client(
                server=self.server,
                name="client1",
                protocol_type=VPNClient.ProtocolType.AWG,
                actor=self.user,
            )
        self.assertEqual(client.revisions.count(), 1)
        self.assertEqual(client.runtime_peer_public_key, "client-public-key==")

    def test_import_runtime_peers(self):
        from unittest.mock import patch

        class R:
            def __init__(self, stdout):
                self.stdout = stdout

        with patch("vpn.services.RuntimeCommandService.run", return_value=R("peerkey\tpsk\tendpoint\t10.8.0.10/32\t0\t0\t0\t25\n")):
            imported = VPNClientService.import_runtime_peers(server=self.server, actor=self.user)
        self.assertEqual(imported, 1)
        self.assertTrue(VPNClient.objects.filter(imported_from_runtime=True).exists())
