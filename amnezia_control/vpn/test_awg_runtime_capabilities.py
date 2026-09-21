from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse

from jobs.executors import SafeSSHExecutor
from servers.models import ProtocolProfile, Server, ServerProtocol
from servers.services import ServerService
from vpn.models import VPNClient
from vpn.services import AdapterFactory, ConfigCryptoService, VPNClientService


def _legacy_metadata():
    return {
        "Jc": "6",
        "Jmin": "10",
        "Jmax": "50",
        "S1": "134",
        "S2": "86",
        "S3": "33",
        "S4": "12",
        "H1": "1",
        "H2": "2",
        "H3": "3",
        "H4": "4",
    }


class AWGRuntimeCapabilitiesTest(SimpleTestCase):
    def test_runtime_env_sanitizer_redacts_sensitive_values(self):
        sanitized = ServerService._sanitize_runtime_env(
            [
                "AWG2_S1=123",
                "HEADER_PROTECTION_KEY=value-a",
                "AWG2_HEADERPROTECTIONKEY=value-c",
                "WIREGUARD_SERVER_PRIVATE_KEY=value-b",
                "PUBLIC_ENDPOINT=vpn.example.com",
            ]
        )
        self.assertIn("AWG2_S1=123", sanitized)
        self.assertIn(
            "HEADER_PROTECTION_KEY=[REDACTED]",
            sanitized,
        )
        self.assertIn(
            "AWG2_HEADERPROTECTIONKEY=[REDACTED]",
            sanitized,
        )
        self.assertIn(
            "WIREGUARD_SERVER_PRIVATE_KEY=[REDACTED]",
            sanitized,
        )
        self.assertIn(
            "PUBLIC_ENDPOINT=vpn.example.com",
            sanitized,
        )
        joined = "\n".join(sanitized)
        self.assertNotIn("value-a", joined)
        self.assertNotIn("value-b", joined)
        self.assertNotIn("value-c", joined)

    def test_parser_reads_awg31_and_ignores_commented_special_junk(self):
        conf = """[Interface]
PrivateKey = server-private
Address = 10.77.0.1/24
ListenPort = 51830
Jc = 6
Jmin = 10
Jmax = 50
S1 = 134
S2 = 86
S3 = 33
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = header-key
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on
# I1 = <r 2><b 0x01>
"""
        parsed, missing, optional_missing = ServerService._parse_awg2_metadata(
            [],
            conf,
        )

        self.assertEqual(missing, [])
        self.assertEqual(parsed["HeaderProtectionKey"], "header-key")
        self.assertEqual(parsed["ContentPaddingAddition"], "10-100")
        self.assertEqual(parsed["RandomTrailers"], "on")
        self.assertEqual(parsed["DisableCookies"], "on")
        self.assertNotIn("I1", parsed)
        self.assertIn("I1", optional_missing)

        runtime = ServerService._classify_awg_runtime(conf, parsed)
        self.assertEqual(runtime["generation"], "3.1")
        self.assertTrue(runtime["export_compatible"])
        self.assertIn("header_protection", runtime["capabilities"])
        self.assertIn("random_trailers", runtime["capabilities"])

    def test_parser_reads_active_i1(self):
        metadata = _legacy_metadata()
        conf = """[Interface]
Jc = 6
Jmin = 10
Jmax = 50
S1 = 134
S2 = 86
S3 = 33
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <r 2><b 0x01>
"""
        parsed, missing, optional_missing = ServerService._parse_awg2_metadata(
            [],
            conf,
        )
        self.assertEqual(missing, [])
        self.assertEqual(parsed["I1"], "<r 2><b 0x01>")
        self.assertNotIn("I1", optional_missing)

    def test_unknown_interface_key_makes_export_fail_closed(self):
        metadata = _legacy_metadata()
        conf = """[Interface]
PrivateKey = server-private
Address = 10.77.0.1/24
ListenPort = 51830
Jc = 6
Jmin = 10
Jmax = 50
S1 = 134
S2 = 86
S3 = 33
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
FutureObfuscationMode = enabled
"""
        runtime = ServerService._classify_awg_runtime(conf, metadata)

        self.assertFalse(runtime["export_compatible"])
        self.assertEqual(
            runtime["unknown_interface_keys"],
            ["FutureObfuscationMode"],
        )

    def test_awg31_export_matches_upstream_section_layout(self):
        metadata = {
            **_legacy_metadata(),
            "HeaderProtectionKey": "header-key",
            "ContentPaddingAddition": "10-100",
            "RekeyAfterTime": "100-120",
            "RekeyTimeout": "3-7",
            "RejectAfterTime": "150-180",
            "KeepaliveTimeout": "5-15",
            "MaxHandshakeAttempts": "15-20",
            "RandomTrailers": "on",
            "DisableCookies": "on",
        }
        conf = VPNClientService.build_awg2_client_config(
            private_key="client-private",
            address="10.77.0.2",
            endpoint="vpn.example.com:51830",
            server_public_key="server-public",
            awg2_metadata=metadata,
            preshared_key="psk",
            mtu=1280,
        )

        interface_block, peer_block = conf.split("[Peer]", 1)
        self.assertIn("Jc = 6", interface_block)
        self.assertIn("HeaderProtectionKey = header-key", interface_block)
        self.assertIn("RandomTrailers = on", interface_block)
        self.assertIn("MTU = 1280", interface_block)
        self.assertNotIn("HeaderProtectionKey", peer_block)
        self.assertIn("PersistentKeepalive = 25-35", peer_block)

    def test_awg2_export_keeps_legacy_keepalive(self):
        conf = VPNClientService.build_awg2_client_config(
            private_key="client-private",
            address="10.77.0.2",
            endpoint="vpn.example.com:51830",
            server_public_key="server-public",
            awg2_metadata=_legacy_metadata(),
        )
        self.assertIn("PersistentKeepalive = 25", conf)
        self.assertNotIn("PersistentKeepalive = 25-35", conf)


    @override_settings(
        CONFIG_ENCRYPTION_KEY=Fernet.generate_key().decode()
    )
    def test_runtime_header_protection_key_is_decrypted_on_export(self):
        encrypted = ConfigCryptoService.encrypt("header-secret")
        protocol = SimpleNamespace(
            runtime_metadata={
                "awg2_metadata": _legacy_metadata(),
                "awg2_secret_metadata": {
                    "HeaderProtectionKey": encrypted,
                },
            }
        )
        metadata = VPNClientService._runtime_awg_metadata(protocol)
        self.assertEqual(
            metadata["HeaderProtectionKey"],
            "header-secret",
        )

    def test_safe_executor_accepts_awg_monitoring_command(self):
        executor = SafeSSHExecutor(
            host="127.0.0.1",
            username="u",
        )
        executor._validate(
            "docker exec amnezia-awg2 sh -lc "
            "'grep -c \"^\\[Peer\\]\" "
            "/opt/amnezia/awg/awg0.conf; "
            "awg show awg0 peers | wc -l'"
        )

    def test_safe_executor_accepts_runtime_mtu_read(self):
        executor = SafeSSHExecutor(
            host="127.0.0.1",
            username="u",
        )
        executor._validate(
            "docker exec amnezia-awg2 "
            "cat /sys/class/net/awg0/mtu"
        )


class AWGCompatibilityPolicyTest(TestCase):
    def test_adapter_uses_discovered_awg_command(self):
        server = Server.objects.create(
            name="awg-command-server",
            public_endpoint_host="vpn.example.com",
        )
        ServerProtocol.objects.create(
            server=server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
            runtime_metadata={"command_bin": "awg"},
        )
        adapter = AdapterFactory.get_for_server(
            server,
            VPNClient.ProtocolType.AWG2,
        )
        self.assertEqual(adapter.command_bin, "awg")

    def test_reissue_is_blocked_before_runtime_mutation(self):
        server = Server.objects.create(
            name="awg-compat-server",
            public_endpoint_host="vpn.example.com",
        )
        protocol = ServerProtocol.objects.create(
            server=server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
            runtime_metadata={
                "awg_export_compatible": False,
                "awg_unknown_interface_keys": [
                    "FutureObfuscationMode",
                ],
            },
        )
        profile = ProtocolProfile.objects.create(
            server_protocol=protocol,
            name="full",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="[Interface]",
        )
        client = VPNClient.objects.create(
            server=server,
            name="blocked-reissue",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=profile,
            status=VPNClient.Status.ACTIVE,
        )

        with patch(
            "vpn.services.AdapterFactory.get_for_client"
        ) as adapter_factory:
            with self.assertRaisesRegex(
                RuntimeError,
                "неподдерживаемую схему",
            ):
                VPNClientService.reissue_config(
                    client=client,
                    actor=None,
                )

        adapter_factory.assert_not_called()

    def test_reissue_requires_runtime_sync_before_mutation(self):
        server = Server.objects.create(
            name="awg-unsynced-server",
            public_endpoint_host="vpn.example.com",
        )
        protocol = ServerProtocol.objects.create(
            server=server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
            runtime_metadata={
                "awg2_metadata": _legacy_metadata(),
            },
        )
        profile = ProtocolProfile.objects.create(
            server_protocol=protocol,
            name="full-unsynced",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="[Interface]",
        )
        client = VPNClient.objects.create(
            server=server,
            name="unsynced-reissue",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=profile,
            status=VPNClient.Status.ACTIVE,
        )

        with patch(
            "vpn.services.AdapterFactory.get_for_client"
        ) as adapter_factory:
            with self.assertRaisesRegex(
                RuntimeError,
                "совместимость runtime AWG ещё не проверена",
            ):
                VPNClientService.reissue_config(
                    client=client,
                    actor=None,
                )

        adapter_factory.assert_not_called()

    def test_reissue_is_blocked_on_mtu_mismatch_before_mutation(self):
        server = Server.objects.create(
            name="awg-mtu-mismatch-server",
            public_endpoint_host="vpn.example.com",
        )
        protocol = ServerProtocol.objects.create(
            server=server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
            runtime_metadata={
                "awg_export_compatible": True,
                "awg_generation": "2.x",
                "awg_capabilities": ["legacy_obfuscation"],
                "awg2_metadata": _legacy_metadata(),
                "config_mtu": 1376,
                "runtime_mtu": 1420,
                "mtu_mismatch": True,
            },
        )
        profile = ProtocolProfile.objects.create(
            server_protocol=protocol,
            name="full-mtu-mismatch",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="[Interface]",
        )
        client = VPNClient.objects.create(
            server=server,
            name="mtu-mismatch-reissue",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=profile,
            status=VPNClient.Status.ACTIVE,
        )

        with patch(
            "vpn.services.AdapterFactory.get_for_client"
        ) as adapter_factory:
            with self.assertRaisesRegex(
                RuntimeError,
                "MTU конфигурации AWG",
            ):
                VPNClientService.reissue_config(
                    client=client,
                    actor=None,
                )

        adapter_factory.assert_not_called()


class AWGOperatorReadinessViewTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="awg-readiness-admin",
            password="test",
            is_staff=True,
        )
        self.server = Server.objects.create(
            name="awg-readiness-server",
            public_endpoint_host="vpn.example.com",
            public_endpoint_port=51830,
        )
        ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
            runtime_metadata={
                "interface": "awg0",
                "interface_ready": True,
                "subnet": "10.77.0.0/24",
                "subnet_ready": True,
                "endpoint_host_ready": True,
                "endpoint_port_ready": True,
                "awg_generation": "2.x",
                "awg_capabilities": ["legacy_obfuscation"],
                "command_bin": "awg",
                "awg_export_compatible": True,
                "awg2_metadata_ready": True,
                "config_mtu": 1376,
                "runtime_mtu": 1420,
                "mtu_mismatch": True,
            },
        )

    def test_server_detail_marks_mtu_mismatch_not_ready(self):
        self.client.force_login(self.user)

        response = self.client.get(
            reverse(
                "servers-detail",
                kwargs={"pk": self.server.id},
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Config MTU 1376")
        self.assertContains(response, "Runtime MTU 1420")
        self.assertContains(response, "MTU mismatch")
        self.assertContains(response, "CLI:")
        self.assertContains(response, "legacy_obfuscation")
        self.assertContains(response, "Требует внимания")
        self.assertContains(response, "0 / 1")

