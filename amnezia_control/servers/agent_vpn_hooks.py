from __future__ import annotations

import uuid

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


@transaction.atomic
def _reissue_agent_awg2(*, client: VPNClient, actor):
    VPNClientPolicyService.assert_reissue_allowed(client)

    adapter = AdapterFactory.get_for_client(client)
    previous_public_key = client.runtime_peer_public_key
    if previous_public_key:
        adapter.remove_peer(actor, previous_public_key)

    mode, allowed_ips = _agent_routes(client)
    result = None
    new_public_key = ""

    try:
        result = adapter._call(
            actor,
            "create_peer",
            sensitive_output=True,
            client_id=_agent_client_id(client),
            client_name=client.name,
            mode=mode,
            allowed_ips=allowed_ips,
        )
        config, new_public_key, address = _validate_agent_config(result)
        revision = VPNClientService._store_revision(client, config)

        client.runtime_peer_public_key = new_public_key
        client.runtime_address = address
        client.last_runtime_sync_at = timezone.now()
        client.save(
            update_fields=[
                "runtime_peer_public_key",
                "runtime_address",
                "last_runtime_sync_at",
            ]
        )
    except Exception:
        if new_public_key:
            try:
                adapter.remove_peer(actor, new_public_key)
            except Exception:
                pass
        raise

    AuditService.log(
        actor,
        "client.reissue",
        "VPNClient",
        client.id,
        {
            "revision": revision,
            "backend": Server.RuntimeBackend.AWG_AGENT,
            "agent": "awg4",
            "routing_mode": mode,
        },
    )


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
