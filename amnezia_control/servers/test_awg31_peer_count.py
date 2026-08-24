from django.test import SimpleTestCase

from servers.services import ServerService


class AWG31PeerCountTest(SimpleTestCase):
    def test_extended_interface_row_is_not_peer(self):
        dump = "\n".join(
            [
                # AWG 3.1 extended interface metadata row.
                # It deliberately has >= 9 columns, but
                # column 5 is not a valid AllowedIPs field.
                (
                    "awg0\tSERVER_PRIVATE\tSERVER_PUBLIC\t"
                    "49561\t6\t10\t50\t76\t56\t63\t12\t1\t2\t3\t4"
                ),
                (
                    "awg0\tPEER_PUBLIC_1\t(none)\t"
                    "198.51.100.10:50000\t10.8.1.2/32\t"
                    "123\t100\t200\t25"
                ),
                (
                    "awg0\tPEER_PUBLIC_2\t(none)\t"
                    "(none)\t10.8.1.3/32\t"
                    "0\t0\t0\t25"
                ),
            ]
        )

        self.assertEqual(
            ServerService._count_awg2_runtime_peers(
                dump,
                "awg0",
            ),
            2,
        )

    def test_plain_show_dump_is_counted(self):
        dump = "\n".join(
            [
                (
                    "PEER_PUBLIC_1\t(none)\t"
                    "198.51.100.10:50000\t10.8.1.2/32\t"
                    "123\t100\t200\t25"
                ),
                (
                    "PEER_PUBLIC_2\t(none)\t"
                    "(none)\t10.8.1.3/32\t"
                    "0\t0\t0\t25"
                ),
            ]
        )

        self.assertEqual(
            ServerService._count_awg2_runtime_peers(
                dump,
                "awg0",
            ),
            2,
        )

    def test_invalid_allowed_ips_is_not_peer(self):
        dump = (
            "awg0\tNOT_A_PEER\tfoo\tbar\t"
            "6\t10\t50\t76\t56\t63\t12"
        )

        self.assertEqual(
            ServerService._count_awg2_runtime_peers(
                dump,
                "awg0",
            ),
            0,
        )
