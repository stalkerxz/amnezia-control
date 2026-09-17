import base64
import json
import struct
import zlib
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from servers.agent_vpn_hooks import (
    _validate_agent_vpn_artifact,
)
from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)

from .models import VPNClient
from .services import VPNClientService


def decode_artifact(value):
    assert value.startswith("vpn://")

    encoded = value[6:]
    encoded += "=" * (
        (-len(encoded)) % 4
    )

    raw = (
        base64
        .urlsafe_b64decode(
            encoded
        )
    )

    declared = struct.unpack(
        ">I",
        raw[:4],
    )[0]

    payload = zlib.decompress(
        raw[4:]
    )

    assert declared == len(payload)

    return json.loads(
        payload.decode("utf-8")
    )


class FakeAdapter:
    def __init__(
        self,
        protocol,
        results,
    ):
        self.protocol = protocol
        self.results = iter(results)
        self.removed = []

    def create_peer(self, actor):
        return next(self.results)

    def remove_peer(
        self,
        actor,
        public_key,
    ):
        self.removed.append(
            public_key
        )


@override_settings(
    CONFIG_ENCRYPTION_KEY=(
        Fernet.generate_key().decode()
    )
)
class DockerAmneziaVPNArtifactTest(
    TestCase
):

    def setUp(self):
        self.user = (
            get_user_model()
            .objects
            .create_user(
                "docker-vpn-artifact",
                password="test",
                is_staff=True,
            )
        )

        self.server = (
            Server.objects.create(
                name="docker-awg31",
                host="64.188.96.240",
                public_endpoint_host=(
                    "185.249.154.150"
                ),
                public_endpoint_port=(
                    49561
                ),
                runtime_backend=(
                    Server.RuntimeBackend
                    .DOCKER
                ),
            )
        )

        self.protocol = (
            ServerProtocol.objects.create(
                server=self.server,
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                enabled=True,
                container_status=(
                    "running"
                ),
                runtime_metadata={
                    "awg31_metadata_ready":
                        True,
                    "subnet":
                        "10.8.1.0/24",
                    "awg2_metadata": {
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
                        "HeaderProtectionKey":
                            (
                                "AAAAAAAAAAAAAAAA"
                                "AAAAAAAAAAAAAAAA"
                                "AAAAAAAAAAA="
                            ),
                        "ContentPaddingAddition":
                            "10-100",
                        "RekeyAfterTime":
                            "120-180",
                        "RekeyTimeout":
                            "5-10",
                        "RejectAfterTime":
                            "150-180",
                        "KeepaliveTimeout":
                            "5-15",
                        "MaxHandshakeAttempts":
                            "15-20",
                        "RandomTrailers":
                            "on",
                        "DisableCookies":
                            "on",
                    },
                },
            )
        )

        self.profile = (
            ProtocolProfile.objects.create(
                server_protocol=(
                    self.protocol
                ),
                name="full",
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                config_template=(
                    "# routing-mode: full"
                ),
            )
        )

        self.client_obj = (
            VPNClient.objects.create(
                server=self.server,
                name="docker-test",
                protocol_type=(
                    VPNClient
                    .ProtocolType
                    .AWG2
                ),
                profile=self.profile,
                created_by=self.user,
            )
        )

    @staticmethod
    def result(
        number,
    ):
        key_char = (
            "B"
            if number == 1
            else "C"
        )

        return {
            "private_key":
                (
                    key_char * 43
                    + "="
                ),
            "public_key":
                (
                    str(number) * 43
                    + "="
                ),
            "address":
                (
                    "10.8.1.60"
                    if number == 1
                    else "10.8.1.61"
                ),
            "server_public_key":
                (
                    "D" * 43
                    + "="
                ),
            "preshared_key":
                (
                    "E" * 43
                    + "="
                ),
        }

    def test_reissue_stores_real_vpn_artifact(
        self,
    ):
        fake = FakeAdapter(
            self.protocol,
            [
                self.result(1),
                self.result(2),
            ],
        )

        with (
            patch(
                "vpn.services."
                "VPNClientPolicyService."
                "assert_reissue_allowed",
            ),
            patch(
                "vpn.services."
                "AdapterFactory."
                "get_for_client",
                return_value=fake,
            ),
        ):
            VPNClientService.reissue_config(
                client=self.client_obj,
                actor=self.user,
            )

            first = (
                VPNClientService
                .latest_amneziavpn_config(
                    self.client_obj
                )
            )

            self.assertTrue(
                first.startswith(
                    "vpn://"
                )
            )

            _validate_agent_vpn_artifact(
                first,
                expected_endpoint=(
                    "185.249.154.150:"
                    "49561"
                ),
                expected_allowed_ips=[
                    "0.0.0.0/0",
                    "::/0",
                ],
            )

            first_profile = (
                decode_artifact(
                    first
                )
            )

            self.assertEqual(
                first_profile[
                    "hostName"
                ],
                "185.249.154.150",
            )

            self.assertEqual(
                first_profile[
                    "defaultContainer"
                ],
                "amnezia-awg2",
            )

            first_awg = (
                first_profile[
                    "containers"
                ][0]["awg"]
            )

            self.assertEqual(
                first_awg[
                    "protocol_version"
                ],
                "3.1",
            )

            self.assertEqual(
                first_awg["I1"],
                "",
            )

            self.assertEqual(
                first_awg["I5"],
                "",
            )

            first_last = json.loads(
                first_awg[
                    "last_config"
                ]
            )

            self.assertEqual(
                first_last[
                    "clientId"
                ],
                self.result(1)[
                    "public_key"
                ],
            )

            self.assertEqual(
                first_last[
                    "client_pub_key"
                ],
                self.result(1)[
                    "public_key"
                ],
            )

            self.assertEqual(
                first_last[
                    "client_priv_key"
                ],
                self.result(1)[
                    "private_key"
                ],
            )

            self.assertEqual(
                first_last[
                    "client_ip"
                ],
                "10.8.1.60",
            )

            self.assertEqual(
                first_last["port"],
                49561,
            )

            self.assertEqual(
                first_last["mtu"],
                "1280",
            )

            self.assertEqual(
                first_last[
                    "allowed_ips"
                ],
                [
                    "0.0.0.0/0",
                    "::/0",
                ],
            )

            self.assertIn(
                "Endpoint = "
                "185.249.154.150:"
                "49561",
                first_last["config"],
            )

            VPNClientService.reissue_config(
                client=self.client_obj,
                actor=self.user,
            )

        second = (
            VPNClientService
            .latest_amneziavpn_config(
                self.client_obj
            )
        )

        second_profile = (
            decode_artifact(
                second
            )
        )

        second_last = json.loads(
            second_profile[
                "containers"
            ][0]["awg"][
                "last_config"
            ]
        )

        self.assertEqual(
            second_last[
                "client_pub_key"
            ],
            self.result(2)[
                "public_key"
            ],
        )

        self.assertEqual(
            second_last[
                "client_priv_key"
            ],
            self.result(2)[
                "private_key"
            ],
        )

        self.assertNotIn(
            self.result(1)[
                "private_key"
            ],
            json.dumps(
                second_profile
            ),
        )

        self.assertNotIn(
            self.result(1)[
                "public_key"
            ],
            json.dumps(
                second_profile
            ),
        )

        self.assertEqual(
            fake.removed,
            [
                self.result(1)[
                    "public_key"
                ],
            ],
        )

        self.assertEqual(
            self.client_obj
            .revisions
            .count(),
            2,
        )
