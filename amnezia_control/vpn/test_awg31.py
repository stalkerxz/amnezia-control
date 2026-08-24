from django.test import SimpleTestCase

from servers.services import ServerService
from vpn.services import VPNClientService


class AWG31MetadataTest(SimpleTestCase):
    def metadata(self):
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
            "HeaderProtectionKey": "TEST-HPK",
            "ContentPaddingAddition": "10-100",
            "RekeyAfterTime": "100-120",
            "RekeyTimeout": "3-7",
            "RejectAfterTime": "150-180",
            "KeepaliveTimeout": "5-15",
            "MaxHandshakeAttempts": "15-20",
            "RandomTrailers": "on",
            "DisableCookies": "on",
        }

    def test_runtime_parser_discovers_awg31(self):
        conf = """
[Interface]
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
HeaderProtectionKey = TEST-HPK
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 3-7
RejectAfterTime = 150-180
KeepaliveTimeout = 5-15
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = on
"""

        metadata, missing, _ = (
            ServerService._parse_awg2_metadata(
                [],
                conf,
            )
        )

        self.assertEqual(missing, [])
        self.assertEqual(
            metadata["HeaderProtectionKey"],
            "TEST-HPK",
        )
        self.assertEqual(
            metadata["RandomTrailers"],
            "on",
        )
        self.assertEqual(
            metadata["DisableCookies"],
            "on",
        )

    def test_awg31_config_uses_interface_fields(self):
        config = (
            VPNClientService.build_awg2_client_config(
                private_key="CLIENT-PRIVATE",
                address="10.8.1.99",
                endpoint="64.188.96.240:49561",
                server_public_key="SERVER-PUBLIC",
                preshared_key="PSK",
                awg2_metadata=self.metadata(),
            )
        )

        sections = (
            VPNClientService._parse_config_sections(
                config
            )
        )

        interface = sections["Interface"]
        peer = sections["Peer"]

        self.assertEqual(
            interface["HeaderProtectionKey"],
            "TEST-HPK",
        )
        self.assertEqual(
            interface["RandomTrailers"],
            "on",
        )
        self.assertEqual(
            interface["DisableCookies"],
            "on",
        )

        self.assertEqual(
            interface["S4"],
            "12",
        )

        self.assertNotIn(
            "I1",
            interface,
        )

        self.assertNotIn(
            "Jc",
            peer,
        )

        self.assertEqual(
            peer["PersistentKeepalive"],
            "25-35",
        )

    def test_awg31_preserves_explicit_i1(self):
        metadata = self.metadata()
        metadata["I1"] = "<r 10><c 1>"

        config = (
            VPNClientService.build_awg2_client_config(
                private_key="CLIENT",
                address="10.8.1.99",
                endpoint="64.188.96.240:49561",
                server_public_key="SERVER",
                awg2_metadata=metadata,
            )
        )

        sections = (
            VPNClientService._parse_config_sections(
                config
            )
        )

        self.assertEqual(
            sections["Interface"]["I1"],
            "<r 10><c 1>",
        )

    def test_awg31_rejects_small_s4(self):
        metadata = self.metadata()
        metadata["S4"] = "7"

        with self.assertRaisesRegex(
            RuntimeError,
            "S1-S4 >= 12",
        ):
            VPNClientService.build_awg2_client_config(
                private_key="CLIENT",
                address="10.8.1.99",
                endpoint="64.188.96.240:49561",
                server_public_key="SERVER",
                awg2_metadata=metadata,
            )

    def test_old_awg2_still_supported(self):
        metadata = {
            "Jc": "6",
            "Jmin": "10",
            "Jmax": "50",
            "S1": "76",
            "S2": "56",
            "S3": "63",
            "S4": "7",
            "H1": "10-20",
            "H2": "30-40",
            "H3": "50-60",
            "H4": "70-80",
        }

        config = (
            VPNClientService.build_awg2_client_config(
                private_key="CLIENT",
                address="10.8.1.99",
                endpoint="64.188.96.240:49561",
                server_public_key="SERVER",
                awg2_metadata=metadata,
            )
        )

        sections = (
            VPNClientService._parse_config_sections(
                config
            )
        )

        self.assertNotIn(
            "HeaderProtectionKey",
            sections["Interface"],
        )

        self.assertEqual(
            sections["Peer"]["Jc"],
            "6",
        )

        self.assertEqual(
            sections["Peer"]["PersistentKeepalive"],
            "25",
        )
