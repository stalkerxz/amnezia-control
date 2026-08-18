from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)
from vpn.models import VPNClient
from vpn.services import (
    AWG2Adapter,
    VPNClientPolicyService,
    VPNClientService,
)


class AWG2RuntimeDumpParserTest(
    SimpleTestCase
):
    @staticmethod
    def _adapter():
        adapter = object.__new__(
            AWG2Adapter
        )

        adapter.protocol = SimpleNamespace(
            runtime_metadata={
                "interface": "awg0",
            }
        )

        return adapter

    def test_extended_interface_row_is_ignored(
        self,
    ):
        adapter = self._adapter()

        interface_row = "\t".join(
            [
                "awg0",
                "server-private-key",
                "server-public-key",
                "49561",
                "6",
                "10",
                "50",
                "76",
                "56",
                "63",
                "7",
                "meta1",
                "meta2",
                "meta3",
                "meta4",
                "meta5",
                "meta6",
                "meta7",
                "meta8",
                "meta9",
                "end",
            ]
        )

        peer_row = "\t".join(
            [
                "awg0",
                "peer-public-key",
                "peer-psk",
                "198.51.100.1:12345",
                "10.8.1.10/32",
                "123",
                "456",
                "789",
                "25",
            ]
        )

        peers = (
            adapter
            ._parse_runtime_dump_peers(
                interface_row
                + "\n"
                + peer_row
                + "\n"
            )
        )

        self.assertEqual(
            len(peers),
            1,
        )

        self.assertEqual(
            peers[0].public_key,
            "peer-public-key",
        )

        self.assertEqual(
            peers[0].allowed_ips,
            "10.8.1.10/32",
        )

        self.assertEqual(
            peers[0].transfer_rx,
            456,
        )

        self.assertEqual(
            peers[0].transfer_tx,
            789,
        )

    def test_plain_show_dump_peer_still_parses(
        self,
    ):
        adapter = self._adapter()

        row = "\t".join(
            [
                "peer-public-key",
                "peer-psk",
                "198.51.100.1:12345",
                "10.8.1.11/32",
                "123",
                "456",
                "789",
                "25",
            ]
        )

        peers = (
            adapter
            ._parse_runtime_dump_peers(
                row + "\n"
            )
        )

        self.assertEqual(
            len(peers),
            1,
        )

        self.assertEqual(
            peers[0].allowed_ips,
            "10.8.1.11/32",
        )

    def test_invalid_allowed_ips_row_is_ignored(
        self,
    ):
        adapter = self._adapter()

        row = "\t".join(
            [
                "awg0",
                "not-a-peer",
                "value",
                "49561",
                "6",
                "10",
                "50",
                "76",
                "56",
            ]
        )

        peers = (
            adapter
            ._parse_runtime_dump_peers(
                row + "\n"
            )
        )

        self.assertEqual(
            peers,
            [],
        )


class VPNReissueStatusSafetyTest(
    TestCase
):
    def setUp(self):
        self.user = (
            get_user_model()
            .objects
            .create_user(
                username="reissue-safety",
            )
        )

        self.server = Server.objects.create(
            name="reissue-safety-server",
            public_endpoint_host=(
                "vpn.example.com"
            ),
        )

        self.protocol = (
            ServerProtocol.objects.create(
                server=self.server,
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                container_name=(
                    "amnezia-awg2"
                ),
                enabled=True,
                runtime_metadata={
                    "udp_port": 51830,
                    "subnet": (
                        "10.77.0.0/24"
                    ),
                },
            )
        )

        self.profile = (
            ProtocolProfile.objects.create(
                server_protocol=(
                    self.protocol
                ),
                name="default-awg2",
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                config_template=(
                    "[Interface]"
                ),
            )
        )

    def _client(
        self,
        *,
        status,
        name,
    ):
        return VPNClient.objects.create(
            server=self.server,
            name=name,
            protocol_type=(
                VPNClient
                .ProtocolType
                .AWG2
            ),
            profile=self.profile,
            created_by=self.user,
            status=status,
            runtime_peer_public_key=(
                "existing-peer-key"
            ),
            runtime_address=(
                "10.77.0.20"
            ),
        )

    def test_deleted_reissue_blocked_before_runtime(
        self,
    ):
        client = self._client(
            status=(
                VPNClient.Status.DELETED
            ),
            name="deleted-client",
        )

        with patch(
            "vpn.services."
            "AdapterFactory.get_for_client"
        ) as adapter_factory:
            with self.assertRaisesRegex(
                RuntimeError,
                "клиент удалён",
            ):
                VPNClientService.reissue_config(
                    client=client,
                    actor=self.user,
                )

        adapter_factory.assert_not_called()

        client.refresh_from_db()

        self.assertEqual(
            client.status,
            VPNClient.Status.DELETED,
        )

        self.assertEqual(
            client.runtime_peer_public_key,
            "existing-peer-key",
        )

        self.assertEqual(
            client.revisions.count(),
            0,
        )

    def test_disabled_reissue_blocked_before_runtime(
        self,
    ):
        client = self._client(
            status=(
                VPNClient.Status.DISABLED
            ),
            name="disabled-client",
        )

        with patch(
            "vpn.services."
            "AdapterFactory.get_for_client"
        ) as adapter_factory:
            with self.assertRaisesRegex(
                RuntimeError,
                "сначала включите клиента",
            ):
                VPNClientService.reissue_config(
                    client=client,
                    actor=self.user,
                )

        adapter_factory.assert_not_called()

        client.refresh_from_db()

        self.assertEqual(
            client.status,
            VPNClient.Status.DISABLED,
        )

        self.assertEqual(
            client.runtime_peer_public_key,
            "existing-peer-key",
        )

        self.assertEqual(
            client.revisions.count(),
            0,
        )

    def test_active_status_does_not_block_reissue(
        self,
    ):
        client = self._client(
            status=(
                VPNClient.Status.ACTIVE
            ),
            name="active-client",
        )

        self.assertEqual(
            VPNClientPolicyService
            .reissue_block_reason(
                client
            ),
            "",
        )

        self.assertTrue(
            VPNClientPolicyService
            .can_reissue(
                client
            )
        )
