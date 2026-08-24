from django.test import TestCase

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)

from .server_selection import (
    ROUTING_MODE_FULL,
    ROUTING_MODE_SELECTIVE,
    resolve_vpn_server_choice,
    select_vpn_server,
    vpn_server_candidate_rows,
)


class VPNServerSelectionTests(TestCase):
    def make_server(
        self,
        *,
        name,
        peer_count=0,
        accepts=True,
        awg31_ready=True,
        full=True,
        selective=False,
        health="healthy",
        subnet="10.8.1.0/24",
    ):
        server = Server.objects.create(
            name=name,
            host="203.0.113.10",
            is_enabled=True,
            is_default_for_new_clients=False,
            accepts_new_vpn_clients=accepts,
            health_status=health,
            public_endpoint_host=(
                "203.0.113.10"
            ),
            public_endpoint_port=36784,
        )

        protocol = (
            ServerProtocol.objects.create(
                server=server,
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                enabled=True,
                container_name="awg",
                container_status="running",
                runtime_metadata={
                    "awg31_metadata_ready": (
                        awg31_ready
                    ),
                    "subnet_ready": True,
                    "endpoint_host_ready": True,
                    "endpoint_port_ready": True,
                    "subnet": subnet,
                    "peer_count": peer_count,
                },
            )
        )

        if full:
            ProtocolProfile.objects.create(
                server_protocol=protocol,
                name="FULL",
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                config_template=(
                    "# routing-mode: full\n"
                ),
                status=(
                    ProtocolProfile
                    .ProfileStatus
                    .ACTIVE
                ),
            )

        if selective:
            ProtocolProfile.objects.create(
                server_protocol=protocol,
                name="SELECT",
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                config_template=(
                    "# routing-mode: selective\n"
                ),
                status=(
                    ProtocolProfile
                    .ProfileStatus
                    .ACTIVE
                ),
            )

        return server

    def test_requires_pool_opt_in(self):
        self.make_server(
            name="Not accepted",
            accepts=False,
        )

        self.assertEqual(
            vpn_server_candidate_rows(
                routing_mode=(
                    ROUTING_MODE_FULL
                ),
            ),
            [],
        )

    def test_requires_awg31_readiness(self):
        self.make_server(
            name="Old AWG",
            awg31_ready=False,
        )

        self.assertIsNone(
            select_vpn_server(
                routing_mode=(
                    ROUTING_MODE_FULL
                ),
            )
        )

    def test_full_and_selective_are_separate(self):
        full = self.make_server(
            name="Full",
            full=True,
            selective=False,
        )

        selective = self.make_server(
            name="Selective",
            full=False,
            selective=True,
        )

        self.assertEqual(
            select_vpn_server(
                routing_mode=(
                    ROUTING_MODE_FULL
                ),
            ),
            full,
        )

        self.assertEqual(
            select_vpn_server(
                routing_mode=(
                    ROUTING_MODE_SELECTIVE
                ),
            ),
            selective,
        )

    def test_least_loaded_server_wins(self):
        busy = self.make_server(
            name="Busy",
            peer_count=100,
        )

        quiet = self.make_server(
            name="Quiet",
            peer_count=5,
        )

        selected = select_vpn_server(
            routing_mode=(
                ROUTING_MODE_FULL
            ),
        )

        self.assertEqual(
            selected,
            quiet,
        )

        self.assertNotEqual(
            selected,
            busy,
        )

    def test_manual_choice_must_be_candidate(self):
        allowed = self.make_server(
            name="Allowed",
        )

        blocked = self.make_server(
            name="Blocked",
            accepts=False,
        )

        self.assertEqual(
            resolve_vpn_server_choice(
                choice=str(allowed.id),
                routing_mode=(
                    ROUTING_MODE_FULL
                ),
            ),
            allowed,
        )

        with self.assertRaises(
            ValueError
        ):
            resolve_vpn_server_choice(
                choice=str(blocked.id),
                routing_mode=(
                    ROUTING_MODE_FULL
                ),
            )

    def test_auto_uses_same_candidate_order(self):
        first = self.make_server(
            name="First",
            peer_count=2,
        )

        self.make_server(
            name="Second",
            peer_count=20,
        )

        self.assertEqual(
            resolve_vpn_server_choice(
                choice="auto",
                routing_mode=(
                    ROUTING_MODE_FULL
                ),
            ),
            first,
        )


class VPNServerDashboardStatusTests(
    VPNServerSelectionTests
):
    def test_peer_count_visible_when_not_ready(
        self,
    ):
        server = self.make_server(
            name="Legacy runtime",
            peer_count=15,
            awg31_ready=False,
        )

        from .server_selection import (
            vpn_server_mode_status,
        )

        status = (
            vpn_server_mode_status(
                server=server,
                routing_mode=(
                    ROUTING_MODE_FULL
                ),
            )
        )

        self.assertFalse(
            status["eligible"]
        )

        self.assertEqual(
            status["peer_count"],
            15,
        )

        self.assertGreater(
            status["capacity"],
            1,
        )

        self.assertIn(
            "AWG 3.1",
            status["reason"],
        )
