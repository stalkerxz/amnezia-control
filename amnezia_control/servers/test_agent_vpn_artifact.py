import base64
import json
import struct
import zlib
from unittest.mock import patch

from cryptography.fernet import Fernet

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings

from servers.agent_vpn_hooks import (
    _reissue_agent_awg2,
)
from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)

from vpn.models import VPNClient
from vpn.services import VPNClientService


AWG31 = {
    "HeaderProtectionKey":
        "TEST-HPK",

    "ContentPaddingAddition":
        "10-100",

    "RekeyAfterTime":
        "100-120",

    "RekeyTimeout":
        "3-7",

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
}


def complete_config() -> str:
    lines = [
        "[Interface]",
        "PrivateKey = CLIENT_PRIVATE",
        "Address = 10.78.0.50/32",
        "Jc = 4",
        "Jmin = 40",
        "Jmax = 70",
        "S1 = 12",
        "S2 = 12",
        "S3 = 12",
        "S4 = 12",
        "H1 = 1",
        "H2 = 2",
        "H3 = 3",
        "H4 = 4",
    ]

    for key, value in AWG31.items():
        lines.append(
            f"{key} = {value}"
        )

    lines.extend(
        [
            "",
            "[Peer]",
            "PublicKey = SERVER_PUBLIC",
            (
                "Endpoint = "
                "vpn.example.com:51831"
            ),
            (
                "AllowedIPs = "
                "0.0.0.0/0, ::/0"
            ),
            (
                "PersistentKeepalive = "
                "25-35"
            ),
            "",
        ]
    )

    return "\n".join(lines)


def make_artifact(
    config: str,
) -> str:
    last_config = {
        "allowed_ips": [
            "0.0.0.0/0",
            "::/0",
        ],
        "port":
            51831,
        "config":
            config,
    }

    awg = {
        **AWG31,
        "protocol_version":
            "3.1",
        "port":
            "51831",
        "subnet_address":
            "10.78.0.0",
        "subnet_cidr":
            "24",
        "last_config":
            json.dumps(
                last_config,
                separators=(
                    ",",
                    ":",
                ),
            ),
    }

    profile = {
        "hostName":
            "vpn.example.com",

        "defaultContainer":
            "amnezia-awg2",

        "containers": [
            {
                "container":
                    "amnezia-awg2",

                "awg":
                    awg,
            }
        ],
    }

    payload = json.dumps(
        profile,
        separators=(
            ",",
            ":",
        ),
    ).encode(
        "utf-8"
    )

    packed = (
        struct.pack(
            ">I",
            len(payload),
        )
        + zlib.compress(
            payload,
            8,
        )
    )

    return (
        "vpn://"
        + base64
        .urlsafe_b64encode(
            packed
        )
        .decode(
            "ascii"
        )
        .rstrip("=")
    )


class FakeAdapter:

    def __init__(
        self,
        protocol,
        result,
    ):
        self.protocol = protocol
        self.result = result
        self.removed = []
        self.restored = []

    def remove_peer(
        self,
        actor,
        public_key,
    ):
        self.removed.append(
            public_key
        )

    def _call(
        self,
        actor,
        action,
        **kwargs,
    ):
        if action == "create_peer":
            return self.result

        if action == "activate_peer":
            self.restored.append(
                kwargs
            )

            return {
                "active": True,
            }

        raise AssertionError(
            f"unexpected action: {action}"
        )


@override_settings(
    CONFIG_ENCRYPTION_KEY=(
        Fernet.generate_key().decode()
    )
)
class AgentVPNArtifactTest(TestCase):

    def setUp(self):
        self.user = (
            get_user_model()
            .objects
            .create_user(
                "agent-artifact-admin",
                password="test",
                is_staff=True,
            )
        )

        self.server = Server.objects.create(
            name="agent-artifact",
            host="127.0.0.1",
            public_endpoint_host=(
                "vpn.example.com"
            ),
            public_endpoint_port=51831,
            runtime_backend=(
                Server.RuntimeBackend
                .AWG_AGENT
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
                enabled=True,
                container_status="running",
            )
        )

        self.profile = (
            ProtocolProfile.objects.create(
                server_protocol=self.protocol,
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
                name="client",
                protocol_type=(
                    VPNClient
                    .ProtocolType
                    .AWG2
                ),
                profile=self.profile,
                created_by=self.user,
            )
        )

    def result(
        self,
        *,
        vpn: str,
    ) -> dict:
        return {
            "public_key":
                "NEW_PUBLIC",

            "address":
                "10.78.0.50/32",

            "conf":
                complete_config(),

            "vpn":
                vpn,
        }

    def test_success_stores_validated_artifact(self):
        artifact = make_artifact(
            complete_config()
        )

        fake = FakeAdapter(
            self.protocol,
            self.result(
                vpn=artifact
            ),
        )

        with patch(
            "servers.agent_vpn_hooks."
            "AdapterFactory.get_for_client",
            return_value=fake,
        ):
            _reissue_agent_awg2(
                client=self.client_obj,
                actor=self.user,
            )

        self.client_obj.refresh_from_db()

        self.assertEqual(
            self.client_obj
            .runtime_peer_public_key,
            "NEW_PUBLIC",
        )

        self.assertEqual(
            VPNClientService
            .latest_amneziavpn_config(
                self.client_obj
            ),
            artifact,
        )

        self.assertEqual(
            self.client_obj
            .revisions
            .count(),
            1,
        )

    def test_missing_artifact_cleans_new_and_restores_old(self):
        self.client_obj.runtime_peer_public_key = (
            "OLD_PUBLIC"
        )

        self.client_obj.runtime_address = (
            "10.78.0.49"
        )

        self.client_obj.save(
            update_fields=[
                "runtime_peer_public_key",
                "runtime_address",
            ]
        )

        fake = FakeAdapter(
            self.protocol,
            self.result(
                vpn=""
            ),
        )

        with patch(
            "servers.agent_vpn_hooks."
            "AdapterFactory.get_for_client",
            return_value=fake,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "artifact",
            ):
                _reissue_agent_awg2(
                    client=self.client_obj,
                    actor=self.user,
                )

        self.assertEqual(
            fake.removed,
            [
                "OLD_PUBLIC",
                "NEW_PUBLIC",
            ],
        )

        self.assertEqual(
            len(fake.restored),
            1,
        )

        self.assertEqual(
            fake.restored[0][
                "public_key"
            ],
            "OLD_PUBLIC",
        )

        self.assertEqual(
            fake.restored[0][
                "address"
            ],
            "10.78.0.49/32",
        )

        self.assertEqual(
            self.client_obj
            .revisions
            .count(),
            0,
        )

    def test_malformed_artifact_cleans_new_peer(self):
        fake = FakeAdapter(
            self.protocol,
            self.result(
                vpn="vpn://NOT-VALID"
            ),
        )

        with patch(
            "servers.agent_vpn_hooks."
            "AdapterFactory.get_for_client",
            return_value=fake,
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "malformed",
            ):
                _reissue_agent_awg2(
                    client=self.client_obj,
                    actor=self.user,
                )

        self.assertEqual(
            fake.removed,
            [
                "NEW_PUBLIC",
            ],
        )

        self.assertEqual(
            self.client_obj
            .revisions
            .count(),
            0,
        )

    def test_audit_failure_rolls_back_new_peer_and_revision(self):
        artifact = make_artifact(
            complete_config()
        )

        fake = FakeAdapter(
            self.protocol,
            self.result(
                vpn=artifact
            ),
        )

        with (
            patch(
                "servers.agent_vpn_hooks."
                "AdapterFactory.get_for_client",
                return_value=fake,
            ),
            patch(
                "servers.agent_vpn_hooks."
                "AuditService.log",
                side_effect=RuntimeError(
                    "audit failed"
                ),
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "audit failed",
            ):
                _reissue_agent_awg2(
                    client=self.client_obj,
                    actor=self.user,
                )

        self.assertEqual(
            fake.removed,
            [
                "NEW_PUBLIC",
            ],
        )

        self.client_obj.refresh_from_db()

        self.assertFalse(
            self.client_obj
            .runtime_peer_public_key
        )

        self.assertEqual(
            self.client_obj
            .revisions
            .count(),
            0,
        )


@override_settings(
    CONFIG_ENCRYPTION_KEY=(
        Fernet.generate_key().decode()
    )
)
class AgentCreateRollbackTest(TestCase):

    def setUp(self):
        self.user = (
            get_user_model()
            .objects
            .create_user(
                "agent-create-rollback-admin",
                password="test",
                is_staff=True,
            )
        )

        self.server = Server.objects.create(
            name="agent-create-rollback",
            host="127.0.0.1",
            public_endpoint_host=(
                "vpn.example.com"
            ),
            public_endpoint_port=51831,
            runtime_backend=(
                Server.RuntimeBackend
                .AWG_AGENT
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
                enabled=True,
                container_status="running",
            )
        )

        self.profile = (
            ProtocolProfile.objects.create(
                server_protocol=self.protocol,
                name="full-create",
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
                config_template=(
                    "# routing-mode: full"
                ),
                status=(
                    ProtocolProfile
                    .ProfileStatus
                    .ACTIVE
                ),
            )
        )

    def result(self) -> dict:
        config = complete_config()

        return {
            "public_key":
                "NEW_PUBLIC",

            "address":
                "10.78.0.50/32",

            "conf":
                config,

            "vpn":
                make_artifact(
                    config
                ),
        }

    @staticmethod
    def fail_create_audit(
        *args,
        **kwargs,
    ):
        action = kwargs.get(
            "action"
        )

        if (
            action is None
            and len(args) > 1
        ):
            action = args[1]

        if action == "client.create":
            raise RuntimeError(
                "create audit failed"
            )

    def test_create_audit_failure_rolls_back_db_and_revokes_remote_peer(
        self,
    ):
        client_name = (
            "create-audit-failure"
        )

        class ObservingAdapter(
            FakeAdapter
        ):
            client_exists_during_cleanup = (
                None
            )

            def remove_peer(
                adapter_self,
                actor,
                public_key,
            ):
                (
                    adapter_self
                    .client_exists_during_cleanup
                ) = (
                    VPNClient.objects
                    .filter(
                        name=client_name
                    )
                    .exists()
                )

                return super(
                    ObservingAdapter,
                    adapter_self,
                ).remove_peer(
                    actor,
                    public_key,
                )

        fake = ObservingAdapter(
            self.protocol,
            self.result(),
        )

        with (
            patch(
                "vpn.services."
                "AdapterFactory."
                "get_for_server",
                return_value=fake,
            ),
            patch(
                "servers.agent_vpn_hooks."
                "AdapterFactory.get_for_client",
                return_value=fake,
            ),
            patch(
                "vpn.services."
                "AuditService.log",
                side_effect=(
                    self.fail_create_audit
                ),
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "create audit failed",
            ):
                (
                    VPNClientService
                    .create_client(
                        server=self.server,
                        name=client_name,
                        protocol_type=(
                            VPNClient
                            .ProtocolType
                            .AWG2
                        ),
                        actor=self.user,
                        routing_mode="full",
                    )
                )

        self.assertFalse(
            VPNClient.objects.filter(
                name=client_name
            ).exists()
        )

        self.assertEqual(
            fake.removed,
            [
                "NEW_PUBLIC",
            ],
        )

        self.assertFalse(
            fake
            .client_exists_during_cleanup
        )

    def test_create_cleanup_failure_is_explicit_and_db_still_rolls_back(
        self,
    ):
        client_name = (
            "create-cleanup-failure"
        )

        class CleanupFailAdapter(
            FakeAdapter
        ):
            def remove_peer(
                adapter_self,
                actor,
                public_key,
            ):
                adapter_self.removed.append(
                    public_key
                )

                raise RuntimeError(
                    "cleanup failed"
                )

        fake = CleanupFailAdapter(
            self.protocol,
            self.result(),
        )

        with (
            patch(
                "vpn.services."
                "AdapterFactory."
                "get_for_server",
                return_value=fake,
            ),
            patch(
                "servers.agent_vpn_hooks."
                "AdapterFactory.get_for_client",
                return_value=fake,
            ),
            patch(
                "vpn.services."
                "AuditService.log",
                side_effect=(
                    self.fail_create_audit
                ),
            ),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "remote AWG4 cleanup "
                "was incomplete",
            ):
                (
                    VPNClientService
                    .create_client(
                        server=self.server,
                        name=client_name,
                        protocol_type=(
                            VPNClient
                            .ProtocolType
                            .AWG2
                        ),
                        actor=self.user,
                        routing_mode="full",
                    )
                )

        self.assertFalse(
            VPNClient.objects.filter(
                name=client_name
            ).exists()
        )

        self.assertEqual(
            fake.removed,
            [
                "NEW_PUBLIC",
            ],
        )

    def test_create_success_keeps_peer_and_stores_vpn_artifact(
        self,
    ):
        client_name = (
            "create-success"
        )

        fake = FakeAdapter(
            self.protocol,
            self.result(),
        )

        with (
            patch(
                "vpn.services."
                "AdapterFactory."
                "get_for_server",
                return_value=fake,
            ),
            patch(
                "servers.agent_vpn_hooks."
                "AdapterFactory.get_for_client",
                return_value=fake,
            ),
        ):
            client = (
                VPNClientService
                .create_client(
                    server=self.server,
                    name=client_name,
                    protocol_type=(
                        VPNClient
                        .ProtocolType
                        .AWG2
                    ),
                    actor=self.user,
                    routing_mode="full",
                )
            )

        client.refresh_from_db()

        self.assertEqual(
            client.runtime_peer_public_key,
            "NEW_PUBLIC",
        )

        self.assertEqual(
            client.runtime_address,
            "10.78.0.50",
        )

        self.assertTrue(
            VPNClientService
            .latest_amneziavpn_config(
                client
            )
            .startswith(
                "vpn://"
            )
        )

        self.assertEqual(
            fake.removed,
            [],
        )
