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
    def test_sync_runtime_state_awg2_uses_show_dump_when_show_all_fails(self, run_mock):
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
                "runtime.peers.awg2": Result("wg0\tprivate\tpub\t51830\npk1\tpsk\tep\t10.8.1.10/32\t0\t1\t2\t25\n"),
                "runtime.conf.awg2": Result("[Interface]\nAddress = 10.8.1.0/24\nListenPort = 49561\n[Peer]\nPublicKey = pk1\nAllowedIPs = 10.8.1.10/32\n"),
            }
            if action == "runtime.peers.awg2.all":
                raise RuntimeError("Unable to access interface: Protocol not supported")
            return mapping[action]

        run_mock.side_effect = side_effect
        ServerService.sync_runtime_state(server=self.server, actor=self.user)
        awg2 = self.server.protocols.get(protocol_type="awg2")
        self.assertEqual(awg2.runtime_metadata["peer_source"], "runtime wg dump")
        self.assertEqual(awg2.runtime_metadata["peer_count"], 1)

    @patch("servers.services.RuntimeCommandService.run")
    def test_sync_runtime_state_awg2_uses_config_peer_fallback_when_runtime_commands_fail(self, run_mock):
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
            if action in {"runtime.peers.awg2.all", "runtime.peers.awg2"}:
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
        self.assertContains(response, "Диагностика протоколов и готовности")
        self.assertContains(response, "Не проверялся")


class ServerHealthEvaluationTest(TestCase):
    def setUp(self):
        self.server = Server.objects.create(
            name="health-srv",
            public_endpoint_host="vpn.example.com",
            public_endpoint_port=51820,
        )

    def test_not_checked_state(self):
        result = ServerService.evaluate_health(self.server)
        self.assertEqual(result["status"], ServerService.HEALTH_NOT_CHECKED)

    def test_healthy_state(self):
        self.server.last_runtime_sync_at = self.server.created_at
        self.server.save(update_fields=["last_runtime_sync_at"])
        ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            container_name="amnezia-awg",
            container_status="running",
            runtime_metadata={"subnet_ready": True, "endpoint_host_ready": True, "endpoint_port_ready": True},
        )
        ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            container_name="amnezia-awg2",
            container_status="running",
            runtime_metadata={
                "subnet_ready": True,
                "endpoint_host_ready": True,
                "endpoint_port_ready": True,
                "awg2_metadata_ready": True,
                "peer_source": "runtime wg dump",
            },
        )
        result = ServerService.evaluate_health(self.server)
        self.assertEqual(result["status"], ServerService.HEALTH_HEALTHY)

    def test_degraded_state_awg2_fallback(self):
        self.server.last_runtime_sync_at = self.server.created_at
        self.server.save(update_fields=["last_runtime_sync_at"])
        ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            container_name="amnezia-awg",
            container_status="running",
            runtime_metadata={"subnet_ready": True, "endpoint_host_ready": True, "endpoint_port_ready": True},
        )
        ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            container_name="amnezia-awg2",
            container_status="running",
            runtime_metadata={
                "subnet_ready": True,
                "endpoint_host_ready": True,
                "endpoint_port_ready": True,
                "awg2_metadata_ready": True,
                "peer_source": "config file fallback (degraded telemetry)",
            },
        )
        result = ServerService.evaluate_health(self.server)
        self.assertEqual(result["status"], ServerService.HEALTH_DEGRADED)
        self.assertTrue(any("fallback" in reason for reason in result["reasons"]))

    def test_unhealthy_state(self):
        self.server.last_runtime_sync_at = self.server.created_at
        self.server.save(update_fields=["last_runtime_sync_at"])
        ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            container_name="amnezia-awg",
            container_status="missing",
            runtime_metadata={},
        )
        ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            container_name="amnezia-awg2",
            container_status="exited",
            runtime_metadata={"subnet_ready": False, "endpoint_host_ready": False, "endpoint_port_ready": False},
        )
        result = ServerService.evaluate_health(self.server)
        self.assertEqual(result["status"], ServerService.HEALTH_UNHEALTHY)


class ServerListHealthLabelRenderingTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin2", password="123", is_staff=True)

    def test_server_list_renders_health_labels(self):
        Server.objects.create(name="srv-ok", health_status=ServerService.HEALTH_HEALTHY)
        Server.objects.create(name="srv-degraded", health_status=ServerService.HEALTH_DEGRADED)
        Server.objects.create(name="srv-bad", health_status=ServerService.HEALTH_UNHEALTHY)
        Server.objects.create(name="srv-nc", health_status=ServerService.HEALTH_NOT_CHECKED)

        self.client.force_login(self.user)
        response = self.client.get(reverse("servers-list"))
        self.assertContains(response, "Здоров")
        self.assertContains(response, "Ограниченно работоспособен")
        self.assertContains(response, "Нездоров")
        self.assertContains(response, "Не проверялся")

    def test_server_list_applies_health_filter(self):
        Server.objects.create(name="srv-ok", health_status=ServerService.HEALTH_HEALTHY)
        Server.objects.create(name="srv-degraded", health_status=ServerService.HEALTH_DEGRADED)

        self.client.force_login(self.user)
        response = self.client.get(f"{reverse('servers-list')}?health=degraded")
        self.assertContains(response, "srv-degraded")
        self.assertNotContains(response, "srv-ok")


class ServerMonitoringParserTest(TestCase):
    def test_parse_load_average(self):
        parsed = ServerService._parse_load_average(" 11:20:55 up 1 day,  load average: 0.11, 0.22, 0.33")
        self.assertEqual(parsed["1"], 0.11)
        self.assertEqual(parsed["5"], 0.22)
        self.assertEqual(parsed["15"], 0.33)

    def test_parse_memory_and_disk(self):
        free_out = """              total        used        free      shared  buff/cache   available
Mem:      1000000000   250000000   750000000
Swap:             0          0          0
"""
        df_out = """Filesystem     1B-blocks      Used Available Use% Mounted on
/dev/sda1   10000000000 5000000000 5000000000  50% /
"""
        mem = ServerService._parse_free_bytes(free_out)
        disk = ServerService._parse_disk_root(df_out)
        self.assertEqual(mem["used_percent"], 25.0)
        self.assertEqual(disk["used_percent"], 50.0)


    def test_parse_docker_ps_returns_list(self):
        rows = ServerService._parse_docker_ps_statuses("web\tUp 1 hour\nwg\tUp 2 hours\n")
        self.assertEqual(rows[0]["name"], "web")
        self.assertEqual(rows[1]["status"], "Up 2 hours")
    def test_parse_main_interface_and_netdev(self):
        iface = ServerService._parse_main_interface("1.1.1.1 via 10.0.2.2 dev eth0 src 10.0.2.15")
        net = ServerService._parse_net_dev_counters(
            """Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n  eth0: 12345 0 0 0 0 0 0 0 67890 0 0 0 0 0 0 0\n""",
            iface,
        )
        self.assertEqual(iface, "eth0")
        self.assertEqual(net["rx_bytes"], 12345)
        self.assertEqual(net["tx_bytes"], 67890)

class ServerSyncDoesNotReenableDisabledProtocolTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin-sync", password="123", is_staff=True)
        self.server = Server.objects.create(name="sync-disabled")
        self.protocol = ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG2,
            container_name="test-container",
            enabled=False,
        )

    @patch("servers.services.RuntimeCommandService.run")
    def test_sync_preserves_manual_disabled_flag(self, run_mock):
        class Result:
            def __init__(self, stdout):
                self.stdout = stdout

        def side_effect(*args, **kwargs):
            action = args[2]
            mapping = {
                "runtime.ps_all": Result("amnezia-awg\namnezia-awg2\n"),
                "runtime.ps_running": Result("amnezia-awg\namnezia-awg2\n"),
                "runtime.inspect.awg": Result('[{"State":{"Status":"running"},"NetworkSettings":{"Ports":{"51820/udp":[{"HostIp":"0.0.0.0","HostPort":"51820"}]}},"Config":{"Image":"awg","Env":[]},"Mounts":[]}]'),
                "runtime.iface.awg": Result("awg0\n"),
                "runtime.peers.awg": Result("awg0\tprivate\tpub\t51820\n"),
                "runtime.conf.awg": Result("[Interface]\nAddress = 10.0.0.1/24\nListenPort = 51820\n"),
                "runtime.inspect.awg2": Result('[{"State":{"Status":"running"},"NetworkSettings":{"Ports":{"51830/udp":[{"HostIp":"0.0.0.0","HostPort":"51830"}]}},"Config":{"Image":"awg2","Env":[]},"Mounts":[]}]'),
                "runtime.iface.awg2": Result("awg0\n"),
                "runtime.peers.awg2.all": Result("awg0\tprivate\tpub\t51830\n"),
                "runtime.conf.awg2": Result("[Interface]\nAddress = 10.1.0.1/24\nListenPort = 51830\n"),
            }
            return mapping[action]

        run_mock.side_effect = side_effect
        ServerService.sync_runtime_state(server=self.server, actor=self.user)
        self.protocol.refresh_from_db()
        self.assertFalse(self.protocol.enabled)


class ServerMonitoringCollectMetricsTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user("admin-monitor", password="123", is_staff=True)
        self.server = Server.objects.create(name="monitor-server")
        ServerProtocol.objects.create(
            server=self.server,
            protocol_type=ServerProtocol.ProtocolType.AWG,
            enabled=True,
            container_name="proto-awg",
            runtime_metadata={"interface": "wg-test", "config_path": "/tmp/wg.conf"},
        )

    @patch("servers.services.RuntimeCommandService.run")
    def test_collect_load_metrics_marks_protocol_containers(self, run_mock):
        class Result:
            def __init__(self, stdout):
                self.stdout = stdout

        def side_effect(*args, **kwargs):
            action = args[2]
            mapping = {
                "monitoring.hostname": Result("host1\n"),
                "monitoring.uptime": Result(" 11:20:55 up 1 day,  load average: 0.11, 0.22, 0.33\n"),
                "monitoring.nproc": Result("4\n"),
                "monitoring.free": Result("Mem: 1000 250 750\n"),
                "monitoring.df": Result("Filesystem 1B-blocks Used Available Use% Mounted on\n/dev/sda1 1000 500 500 50% /\n"),
                "monitoring.route": Result("1.1.1.1 via 10.0.2.2 dev eth0 src 10.0.2.15\n"),
                "monitoring.netdev": Result("eth0: 12 0 0 0 0 0 0 0 34 0 0 0 0 0 0 0\n"),
                "monitoring.docker": Result("proto-awg\tUp 1 hour\nother\tUp 2 hours\n"),
                "monitoring.protocol.peers.awg": Result("1\n1\n"),
            }
            return mapping[action]

        run_mock.side_effect = side_effect
        metrics = ServerService.collect_load_metrics(self.server, self.user)
        self.assertIsInstance(metrics["docker"]["containers"], list)
        self.assertTrue(metrics["docker"]["containers"][0]["is_protocol_container"])
        self.assertFalse(metrics["docker"]["containers"][1]["is_protocol_container"])
