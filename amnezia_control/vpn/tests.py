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
        sp = ServerProtocol.objects.create(server=self.server, protocol_type=ServerProtocol.ProtocolType.AWG)
        ProtocolProfile.objects.create(
            server_protocol=sp,
            name="default",
            protocol_type=ServerProtocol.ProtocolType.AWG,
            config_template="[Interface]\\n# {client_name} {protocol}",
        )

    def test_create_client_creates_revision(self):
        client = VPNClientService.create_client(server=self.server, name="client1", protocol_type=VPNClient.ProtocolType.AWG, actor=self.user)
        self.assertEqual(client.revisions.count(), 1)
