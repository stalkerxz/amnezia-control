from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.urls import reverse

from jobs.executors import SafeSSHExecutor
from servers.models import ProtocolProfile, Server, ServerProtocol
from servers.services import ServerService
from vpn.models import VPNClient
from vpn.services import AdapterFactory, VPNClientService


def _legacy_metadata():
    return {
        "Jc": "6",
        "Jmin": "10",
        "Jmax": "50",
        "S1": "76",
        "S2": "56",
        "S3": "63",
        "S4": "12",
        "H1": "1",
        "H2": "2",
        "H3": "3",
        "H4": "4",
    }


def _awg31_metadata():
    return {
        **_legacy_metadata(),
        "HeaderProtectionKey": "header-secret",
        "ContentPaddingAddition": "10-100",
        "RekeyAfterTime": "100-120",
        "RekeyTimeout": "3-7",
        "RejectAfterTime": "150-180",
        "KeepaliveTimeout": "5-15",
        "MaxHandshakeAttempts": "15-20",
        "RandomTrailers": "on",
        "DisableCookies": "on",
    }


class ProdAWGRuntimeParserTest(SimpleTestCase):
    def test_env_sanitizer_redacts_compact_secret_aliases(self):
        sanitized = ServerService._sanitize_runtime_env(
            [
                "AWG2_S1=123",
                "AWG2_HEADERPROTECTIONKEY=header-value",
                "WIREGUARD_SERVER_PRIVATEKEY=private-value",
                "PUBLIC_ENDPOINT=vpn.example.com",
            ]
        )

        self.assertIn("AWG2_S1=123", sanitized)
        self.assertIn(
            "AWG2_HEADERPROTECTIONKEY=[REDACTED]",
            sanitized,
        )
        self.assertIn(
            "WIREGUARD_SERVER_PRIVATEKEY=[REDACTED]",
            sanitized,
        )
        self.assertIn(
            "PUBLIC_ENDPOINT=vpn.example.com",
            sanitized,
        )
        joined = "\n".join(sanitized)
        self.assertNotIn("header-value", joined)
        self.assertNotIn("private-value", joined)

    def test_awg31_classifier_reports_capabilities(self):
        conf = """[Interface]
PrivateKey = server-private
Address = 10.77.0.1/24
MTU = 1376
Jc = 6
Jmin = 10
Jmax = 50
S1 = 76
S2 = 56
S3 = 63
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = header-secret
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on
# FutureIgnored = commented
"""
        runtime = ServerService._classify_awg_runtime(
            conf,
            _awg31_metadata(),
        )

        self.assertEqual(runtime["generation"], "3.1")
        self.assertTrue(runtime["export_compatible"])
        self.assertEqual(runtime["unknown_interface_keys"], [])
        self.assertIn("header_protection", runtime["capabilities"])
        self.assertIn("content_padding", runtime["capabilities"])
        self.assertIn("custom_timings", runtime["capabilities"])
        self.assertIn("random_trailers", runtime["capabilities"])
        self.assertIn("disable_cookies", runtime["capabilities"])

    def test_unknown_interface_key_blocks_export(self):
        metadata = _awg31_metadata()
        conf = """[Interface]
PrivateKey = server-private
Address = 10.77.0.1/24
Jc = 6
Jmin = 10
Jmax = 50
S1 = 76
S2 = 56
S3 = 63
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = header-secret
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on
FutureObfuscationMode = enabled
"""
        runtime = ServerService._classify_awg_runtime(
            conf,
            metadata,
        )

        self.assertFalse(runtime["export_compatible"])
        self.assertEqual(
            runtime["unknown_interface_keys"],
            ["FutureObfuscationMode"],
        )

    def test_interface_parser_returns_ipv4_subnet_port_and_mtu(self):
        subnet, listen_port, mtu = (
            ServerService._parse_interface_metadata(
                """[Interface]
Address = fe80::1/64, 10.77.0.1/24
ListenPort = 51830
MTU = 1376
"""
            )
        )

        self.assertEqual(subnet, "10.77.0.0/24")
        self.assertEqual(listen_port, 51830)
        self.assertEqual(mtu, 1376)

    def test_awg31_builder_includes_discovered_mtu(self):
        config = VPNClientService.build_awg2_client_config(
            private_key="client-private",
            address="10.77.0.2",
            endpoint="vpn.example.com:51830",
            server_public_key="server-public",
            awg2_metadata=_awg31_metadata(),
            mtu=1376,
        )

        interface = (
            VPNClientService._parse_config_sections(config)
            .get("Interface", {})
        )
        self.assertEqual(interface["MTU"], "1376")
        self.assertEqual(
            interface["HeaderProtectionKey"],
            "header-secret",
        )

    def test_safe_executor_accepts_runtime_mtu_read(self):
        executor = SafeSSHExecutor(
            host="127.0.0.1",
            username="root",
        )

        executor._validate(
            "docker exec amnezia-awg2 "
            "cat /sys/class/net/awg0/mtu"
        )


class ProdAWGCompatibilityPolicyTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="prod-awg-hardening-admin",
            password="test",
            is_staff=True,
        )
        self.server = Server.objects.create(
            name="prod-awg-hardening",
            public_endpoint_host="vpn.example.com",
            public_endpoint_port=51830,
            runtime_backend=Server.RuntimeBackend.DOCKER,
        )
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            enabled=True,
            container_name="amnezia-awg2",
            container_status="running",
            runtime_metadata={},
        )
        self.profile = ProtocolProfile.objects.create(
            server_protocol=self.protocol,
            name="full",
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            config_template="# routing-mode: full\n",
        )
        self.client_obj = VPNClient.objects.create(
            server=self.server,
            name="guarded-client",
            protocol_type=VPNClient.ProtocolType.AWG2,
            profile=self.profile,
            created_by=self.user,
            status=VPNClient.Status.ACTIVE,
        )

    def test_reissue_requires_new_runtime_sync_before_mutation(self):
        self.protocol.runtime_metadata = {
            "awg2_metadata": _legacy_metadata(),
        }
        self.protocol.save(update_fields=["runtime_metadata"])

        with patch(
            "vpn.services.AdapterFactory.get_for_client"
        ) as adapter_factory:
            with self.assertRaisesRegex(
                RuntimeError,
                "совместимость runtime AWG ещё не проверена",
            ):
                VPNClientService.reissue_config(
                    client=self.client_obj,
                    actor=self.user,
                )

        adapter_factory.assert_not_called()

    def test_unknown_schema_blocks_reissue_before_mutation(self):
        self.protocol.runtime_metadata = {
            "awg_export_compatible": False,
            "awg_unknown_interface_keys": [
                "FutureObfuscationMode",
            ],
        }
        self.protocol.save(update_fields=["runtime_metadata"])

        with patch(
            "vpn.services.AdapterFactory.get_for_client"
        ) as adapter_factory:
            with self.assertRaisesRegex(
                RuntimeError,
                "неподдерживаемую схему",
            ):
                VPNClientService.reissue_config(
                    client=self.client_obj,
                    actor=self.user,
                )

        adapter_factory.assert_not_called()

    def test_incomplete_runtime_readiness_blocks_before_mutation(self):
        self.protocol.runtime_metadata = {
            "awg_export_compatible": True,
            "awg2_metadata": _legacy_metadata(),
            "interface": "awg0",
            "interface_ready": True,
        }
        self.protocol.save(update_fields=["runtime_metadata"])

        with patch(
            "vpn.services.AdapterFactory.get_for_client"
        ) as adapter_factory:
            with self.assertRaisesRegex(
                RuntimeError,
                "проверку готовности",
            ):
                VPNClientService.reissue_config(
                    client=self.client_obj,
                    actor=self.user,
                )

        adapter_factory.assert_not_called()

    def test_mtu_mismatch_blocks_reissue_before_mutation(self):
        self.protocol.runtime_metadata = {
            "config_path": "/opt/amnezia/awg/awg0.conf",
            "interface": "awg0",
            "interface_ready": True,
            "subnet": "10.77.0.0/24",
            "subnet_ready": True,
            "endpoint_host_ready": True,
            "endpoint_port_ready": True,
            "awg_export_compatible": True,
            "awg2_metadata": _legacy_metadata(),
            "config_mtu": 1420,
            "runtime_mtu": 1376,
            "mtu_mismatch": True,
        }
        self.protocol.save(update_fields=["runtime_metadata"])

        with patch(
            "vpn.services.AdapterFactory.get_for_client"
        ) as adapter_factory:
            with self.assertRaisesRegex(
                RuntimeError,
                "MTU конфигурации AWG",
            ):
                VPNClientService.reissue_config(
                    client=self.client_obj,
                    actor=self.user,
                )

        adapter_factory.assert_not_called()

    def test_invalid_awg31_metadata_fails_before_peer_mutation(self):
        metadata = _awg31_metadata()
        metadata["S4"] = "7"
        self.protocol.runtime_metadata = {
            "config_path": "/opt/amnezia/awg/awg0.conf",
            "interface": "awg0",
            "interface_ready": True,
            "subnet": "10.77.0.0/24",
            "subnet_ready": True,
            "endpoint_host_ready": True,
            "endpoint_port_ready": True,
            "awg_export_compatible": True,
            "awg2_metadata": metadata,
            "awg31_metadata_ready": True,
            "runtime_mtu": 1376,
            "mtu_mismatch": False,
        }
        self.protocol.save(update_fields=["runtime_metadata"])
        self.client_obj.runtime_peer_public_key = "old-peer"
        self.client_obj.runtime_address = "10.77.0.20"
        self.client_obj.save(
            update_fields=[
                "runtime_peer_public_key",
                "runtime_address",
            ]
        )

        adapter = SimpleNamespace(
            protocol=self.protocol,
            remove_peer=Mock(),
            create_peer=Mock(),
        )

        with patch(
            "vpn.services.AdapterFactory.get_for_client",
            return_value=adapter,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "S1-S4 >= 12",
            ):
                VPNClientService.reissue_config(
                    client=self.client_obj,
                    actor=self.user,
                )

        adapter.remove_peer.assert_not_called()
        adapter.create_peer.assert_not_called()

    def test_adapter_uses_discovered_awg_cli(self):
        self.protocol.runtime_metadata = {
            "command_bin": "awg",
        }
        self.protocol.save(update_fields=["runtime_metadata"])

        adapter = AdapterFactory.get_for_server(
            self.server,
            VPNClient.ProtocolType.AWG2,
        )

        self.assertEqual(adapter.command_bin, "awg")


class ProdAWGOperatorReadinessViewTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="prod-awg-view-admin",
            password="test",
            is_staff=True,
        )
        self.server = Server.objects.create(
            name="prod-awg-view",
            public_endpoint_host="vpn.example.com",
            public_endpoint_port=51830,
            health_status=ServerService.HEALTH_DEGRADED,
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
                "peer_source": "runtime wg dump",
                "awg2_metadata_ready": True,
                "awg31_metadata_ready": True,
                "awg_generation": "3.1",
                "awg_capabilities": [
                    "legacy_obfuscation",
                    "header_protection",
                ],
                "command_bin": "awg",
                "config_mtu": 1420,
                "runtime_mtu": 1376,
                "mtu_mismatch": True,
                "awg_export_compatible": True,
            },
        )

    def test_server_detail_surfaces_runtime_mtu_and_not_ready(self):
        self.client.force_login(self.user)

        response = self.client.get(
            reverse(
                "servers-detail",
                kwargs={"pk": self.server.id},
            )
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "AWG 3.1")
        self.assertContains(response, "CLI")
        self.assertContains(response, "header_protection")
        self.assertContains(response, "1420")
        self.assertContains(response, "1376")
        self.assertContains(response, "MTU mismatch")
        self.assertContains(response, "0 / 1")
        self.assertContains(response, "Внимание")
