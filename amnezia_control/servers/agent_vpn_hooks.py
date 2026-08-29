from __future__ import annotations

import base64
import binascii
import json
import struct
import uuid
import zlib

from django.db import transaction
from django.utils import timezone

from audit.services import AuditService
from servers.models import Server, ServerProtocol
from vpn.models import VPNClient
from vpn.services import (
    AdapterFactory,
    VPNClientPolicyService,
    VPNClientService,
)


_installed = False
_original_reissue_config = None


def _agent_client_id(client: VPNClient) -> str:
    return str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            (
                "amnezia-control://"
                f"server/{client.server_id}/vpn-client/{client.pk}"
            ),
        )
    )


def _agent_routes(client: VPNClient) -> tuple[str, list[str]]:
    if VPNClientService._profile_is_selective(client.profile):
        allowed = VPNClientService.resolve_profile_allowed_ips(client.profile)
        routes = [item.strip() for item in allowed.split(",") if item.strip()]
        if not routes:
            raise RuntimeError("Selective AWG4 profile contains no routes")
        return "selective", routes
    return "full", ["0.0.0.0/0", "::/0"]


def _validate_agent_config(result: dict) -> tuple[str, str, str]:
    config = str(result.get("conf", ""))
    public_key = str(result.get("public_key", "")).strip()
    address = str(result.get("address", "")).strip().split("/", 1)[0]

    sections = VPNClientService._parse_config_sections(config)
    interface = sections.get("Interface", {})
    peer = sections.get("Peer", {})

    if not config or not public_key or not address:
        raise RuntimeError("AWG4 agent returned incomplete client data")
    if not interface.get("PrivateKey") or not interface.get("Address"):
        raise RuntimeError("AWG4 agent config has no client Interface keys")
    if not peer.get("PublicKey") or not peer.get("Endpoint"):
        raise RuntimeError("AWG4 agent config has no server Peer endpoint")

    return config, public_key, address


def _split_endpoint(
    endpoint: str,
) -> tuple[str, str]:
    endpoint = endpoint.strip()

    if endpoint.startswith("["):
        marker = endpoint.rfind("]:")

        if marker < 0:
            raise RuntimeError(
                "Invalid IPv6 endpoint."
            )

        return (
            endpoint[1:marker],
            endpoint[marker + 2:],
        )

    if ":" not in endpoint:
        raise RuntimeError(
            "Invalid endpoint."
        )

    return tuple(
        endpoint.rsplit(
            ":",
            1,
        )
    )


def _validate_agent_awg31_config(
    config: str,
    *,
    expected_endpoint: str,
    expected_allowed_ips: list[str],
) -> None:
    sections = (
        VPNClientService
        ._parse_config_sections(
            config
        )
    )

    interface = sections.get(
        "Interface",
        {},
    )

    peer = sections.get(
        "Peer",
        {},
    )

    base_required = (
        "Jc",
        "Jmin",
        "Jmax",
        "S1",
        "S2",
        "S3",
        "S4",
        "H1",
        "H2",
        "H3",
        "H4",
    )

    required = (
        base_required
        + VPNClientService
        .AWG31_REQUIRED_METADATA_KEYS
    )

    missing = [
        key
        for key in required
        if not interface.get(key)
    ]

    if missing:
        raise RuntimeError(
            "AWG4 agent returned incomplete "
            "AWG 3.1 client parameters."
        )

    if (
        peer.get("Endpoint")
        != expected_endpoint
    ):
        raise RuntimeError(
            "AWG4 agent returned unexpected "
            "client endpoint."
        )

    routes = [
        item.strip()
        for item in (
            peer.get(
                "AllowedIPs",
                "",
            )
        ).split(",")
        if item.strip()
    ]

    if routes != expected_allowed_ips:
        raise RuntimeError(
            "AWG4 agent returned unexpected "
            "client routes."
        )

    if (
        peer.get("PersistentKeepalive")
        != VPNClientService
        .AWG31_PERSISTENT_KEEPALIVE
    ):
        raise RuntimeError(
            "AWG4 agent returned unexpected "
            "AWG 3.1 keepalive."
        )


def _decode_agent_vpn_artifact(
    value: str,
) -> dict:
    value = value.strip()

    if not value.startswith("vpn://"):
        raise RuntimeError(
            "AWG4 agent returned invalid "
            "AmneziaVPN artifact."
        )

    encoded = value[6:]

    encoded += "=" * (
        (-len(encoded)) % 4
    )

    try:
        raw = (
            base64
            .urlsafe_b64decode(
                encoded
            )
        )

        if len(raw) < 5:
            raise ValueError(
                "payload too short"
            )

        declared = struct.unpack(
            ">I",
            raw[:4],
        )[0]

        payload = zlib.decompress(
            raw[4:]
        )

        if declared != len(payload):
            raise ValueError(
                "qCompress size mismatch"
            )

        profile = json.loads(
            payload.decode(
                "utf-8"
            )
        )

    except (
        binascii.Error,
        ValueError,
        TypeError,
        UnicodeError,
        json.JSONDecodeError,
        zlib.error,
    ) as exc:
        raise RuntimeError(
            "AWG4 agent returned malformed "
            "AmneziaVPN artifact."
        ) from exc

    if not isinstance(
        profile,
        dict,
    ):
        raise RuntimeError(
            "AmneziaVPN artifact root "
            "must be an object."
        )

    return profile


def _validate_agent_vpn_artifact(
    value: str,
    *,
    expected_endpoint: str,
    expected_allowed_ips: list[str],
) -> str:
    value = value.strip()

    if not value:
        raise RuntimeError(
            "AWG4 agent returned incomplete "
            "client data: AmneziaVPN artifact "
            "is missing."
        )

    profile = _decode_agent_vpn_artifact(
        value
    )

    expected_host, expected_port = (
        _split_endpoint(
            expected_endpoint
        )
    )

    if (
        profile.get("hostName")
        != expected_host
    ):
        raise RuntimeError(
            "AmneziaVPN artifact host "
            "does not match endpoint."
        )

    if (
        profile.get("defaultContainer")
        != "amnezia-awg2"
    ):
        raise RuntimeError(
            "AmneziaVPN artifact has "
            "unexpected default container."
        )

    containers = (
        profile.get("containers")
        or []
    )

    if (
        not isinstance(
            containers,
            list,
        )
        or len(containers) != 1
    ):
        raise RuntimeError(
            "AmneziaVPN artifact must contain "
            "exactly one container."
        )

    container = containers[0]

    if (
        not isinstance(
            container,
            dict,
        )
        or container.get("container")
        != "amnezia-awg2"
    ):
        raise RuntimeError(
            "AmneziaVPN AWG container "
            "is invalid."
        )

    awg = (
        container.get("awg")
        or {}
    )

    if not isinstance(
        awg,
        dict,
    ):
        raise RuntimeError(
            "AmneziaVPN AWG payload "
            "is invalid."
        )

    if (
        awg.get("protocol_version")
        != "3.1"
    ):
        raise RuntimeError(
            "AmneziaVPN artifact is not "
            "AWG protocol version 3.1."
        )

    if (
        str(awg.get("port"))
        != str(expected_port)
    ):
        raise RuntimeError(
            "AmneziaVPN artifact port "
            "does not match endpoint."
        )

    missing = [
        key
        for key
        in VPNClientService
        .AWG31_REQUIRED_METADATA_KEYS
        if not awg.get(key)
    ]

    if missing:
        raise RuntimeError(
            "AmneziaVPN artifact has "
            "incomplete AWG 3.1 parameters."
        )

    try:
        last_config = json.loads(
            awg.get(
                "last_config",
                "",
            )
        )

    except (
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        raise RuntimeError(
            "AmneziaVPN last_config "
            "is invalid."
        ) from exc

    if (
        last_config.get("allowed_ips")
        != expected_allowed_ips
    ):
        raise RuntimeError(
            "AmneziaVPN artifact routes "
            "do not match requested routes."
        )

    if (
        str(last_config.get("port"))
        != str(expected_port)
    ):
        raise RuntimeError(
            "AmneziaVPN last_config port "
            "does not match endpoint."
        )

    embedded = str(
        last_config.get("config")
        or ""
    )

    sections = (
        VPNClientService
        ._parse_config_sections(
            embedded
        )
    )

    peer = sections.get(
        "Peer",
        {},
    )

    if (
        peer.get("Endpoint")
        != expected_endpoint
    ):
        raise RuntimeError(
            "AmneziaVPN embedded endpoint "
            "does not match expected endpoint."
        )

    embedded_routes = [
        item.strip()
        for item in (
            peer.get(
                "AllowedIPs",
                "",
            )
        ).split(",")
        if item.strip()
    ]

    if (
        embedded_routes
        != expected_allowed_ips
    ):
        raise RuntimeError(
            "AmneziaVPN embedded routes "
            "do not match requested routes."
        )

    return value


@transaction.atomic
def _reissue_agent_awg2(
    *,
    client: VPNClient,
    actor,
):
    VPNClientPolicyService.assert_reissue_allowed(
        client
    )

    adapter = AdapterFactory.get_for_client(
        client
    )

    mode, allowed_ips = _agent_routes(
        client
    )

    # Resolve endpoint before remote mutation.
    expected_endpoint = (
        VPNClientService
        .resolve_endpoint(
            client.server,
            adapter.protocol,
        )
    )

    previous_public_key = (
        client.runtime_peer_public_key
        or ""
    ).strip()

    previous_address = (
        client.runtime_address
        or ""
    ).strip()

    if (
        previous_public_key
        and not previous_address
    ):
        raise RuntimeError(
            "Cannot safely reissue AWG4 client: "
            "previous runtime address is missing."
        )

    if (
        previous_address
        and "/" not in previous_address
    ):
        previous_address = (
            f"{previous_address}/32"
        )

    previous_removed = False
    new_public_key = ""

    try:
        if previous_public_key:
            adapter.remove_peer(
                actor,
                previous_public_key,
            )

            previous_removed = True

        result = adapter._call(
            actor,
            "create_peer",
            sensitive_output=True,
            client_id=_agent_client_id(
                client
            ),
            client_name=client.name,
            mode=mode,
            allowed_ips=allowed_ips,
        )

        # Capture immediately so any later
        # failure can revoke this new peer.
        new_public_key = str(
            result.get(
                "public_key",
                "",
            )
        ).strip()

        (
            config,
            validated_public_key,
            address,
        ) = _validate_agent_config(
            result
        )

        if (
            validated_public_key
            != new_public_key
        ):
            raise RuntimeError(
                "AWG4 agent returned "
                "inconsistent public key."
            )

        _validate_agent_awg31_config(
            config,
            expected_endpoint=(
                expected_endpoint
            ),
            expected_allowed_ips=(
                allowed_ips
            ),
        )

        vpn_artifact = (
            _validate_agent_vpn_artifact(
                str(
                    result.get("vpn")
                    or ""
                ),
                expected_endpoint=(
                    expected_endpoint
                ),
                expected_allowed_ips=(
                    allowed_ips
                ),
            )
        )

        revision = (
            VPNClientService
            ._store_revision(
                client,
                config,
                amneziavpn_config=(
                    vpn_artifact
                ),
            )
        )

        client.runtime_peer_public_key = (
            new_public_key
        )

        client.runtime_address = address

        client.last_runtime_sync_at = (
            timezone.now()
        )

        client.save(
            update_fields=[
                "runtime_peer_public_key",
                "runtime_address",
                "last_runtime_sync_at",
            ]
        )

        # Audit is part of the transaction.
        # If it fails, remote runtime is restored.
        AuditService.log(
            actor,
            "client.reissue",
            "VPNClient",
            client.id,
            {
                "revision": revision,
                "backend":
                    Server.RuntimeBackend
                    .AWG_AGENT,
                "agent":
                    "awg4",
                "routing_mode":
                    mode,
                "amneziavpn_artifact":
                    True,
            },
        )

    except Exception as exc:
        rollback_incomplete = False

        if new_public_key:
            try:
                adapter.remove_peer(
                    actor,
                    new_public_key,
                )
            except Exception:
                rollback_incomplete = True

        if (
            previous_removed
            and previous_public_key
        ):
            try:
                adapter._call(
                    actor,
                    "activate_peer",
                    public_key=(
                        previous_public_key
                    ),
                    address=(
                        previous_address
                    ),
                    client_id=(
                        _agent_client_id(
                            client
                        )
                    ),
                    client_name=(
                        client.name
                    ),
                )

            except Exception:
                rollback_incomplete = True

        if rollback_incomplete:
            raise RuntimeError(
                "AWG4 client reissue failed "
                "and runtime rollback was "
                "incomplete."
            ) from exc

        raise


def install_agent_vpn_hooks() -> None:
    global _installed
    global _original_reissue_config

    if _installed:
        return

    _original_reissue_config = VPNClientService.reissue_config

    def reissue_config(*, client: VPNClient, actor):
        if (
            client.server.runtime_backend == Server.RuntimeBackend.AWG_AGENT
            and client.protocol_type == ServerProtocol.ProtocolType.AWG2
        ):
            return _reissue_agent_awg2(client=client, actor=actor)
        return _original_reissue_config(client=client, actor=actor)

    VPNClientService.reissue_config = staticmethod(reissue_config)
    _installed = True
