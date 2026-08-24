from django.test import SimpleTestCase

from servers.services import ServerService


class AWGAddressPoolParserTest(SimpleTestCase):
    def test_ipv4_wins_over_link_local_ipv6(self):
        raw = """
[Interface]
Address = 10.8.1.0/24
Address = fe80::2a5:3bf6:6e6e:2cc5/64
Address = fe80::85c9:b552:7a09:e9ed/64
ListenPort = 49561

[Peer]
AllowedIPs = 10.8.1.2/32
"""

        subnet, port = (
            ServerService
            ._parse_interface_metadata(raw)
        )

        self.assertEqual(
            subnet,
            "10.8.1.0/24",
        )

        self.assertEqual(
            port,
            49561,
        )

    def test_link_local_ipv6_is_not_client_pool(self):
        raw = """
[Interface]
Address = fe80::1234/64
Address = fe80::5678/64
ListenPort = 49561
"""

        subnet, port = (
            ServerService
            ._parse_interface_metadata(raw)
        )

        self.assertEqual(
            subnet,
            "",
        )

        self.assertEqual(
            port,
            49561,
        )

    def test_comma_separated_addresses_find_ipv4(self):
        raw = """
[Interface]
Address = fe80::1234/64, 10.8.1.0/24
ListenPort = 49561
"""

        subnet, port = (
            ServerService
            ._parse_interface_metadata(raw)
        )

        self.assertEqual(
            subnet,
            "10.8.1.0/24",
        )

        self.assertEqual(
            port,
            49561,
        )
