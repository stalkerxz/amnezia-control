from cryptography.fernet import Fernet
from audit.models import AuditLog
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from servers.models import ProtocolProfile, Server, ServerProtocol
from servers.services import ServerService

from .forms import VPNClientCreateForm
from .models import VPNClient
from .services import AWG2Adapter, AdapterFactory, PeerState, VPNClientLimitsService, VPNClientService


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
