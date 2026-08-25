from __future__ import annotations

from ipaddress import ip_network

from servers.models import (
    ProtocolProfile,
    Server,
    ServerProtocol,
)


ROUTING_MODE_FULL = "full"
ROUTING_MODE_SELECTIVE = "selective"

VALID_ROUTING_MODES = {
    ROUTING_MODE_FULL,
    ROUTING_MODE_SELECTIVE,
}


def _profile_is_selective(
    profile: ProtocolProfile,
) -> bool:
    return (
        "# routing-mode: selective"
        in (profile.config_template or "").lower()
    )


def _protocol_runtime_ready(
    protocol: ServerProtocol,
    *,
    server: Server,
) -> bool:
    metadata = (
        protocol.runtime_metadata or {}
    )

    if (
        server.runtime_backend
        == Server.RuntimeBackend.AWG_AGENT
    ):
        return (
            metadata.get(
                "central_protocol_supported"
            )
            is True
            and metadata.get(
                "awg2_metadata_ready"
            )
            is True
            and metadata.get(
                "awg31_metadata_ready"
            )
            is True
        )

    return (
        metadata.get(
            "awg31_metadata_ready"
        )
        is True
    )


def _protocol_supports_mode(
    protocol: ServerProtocol,
    *,
    routing_mode: str,
) -> bool:
    wants_selective = (
        routing_mode
        == ROUTING_MODE_SELECTIVE
    )

    profiles = (
        ProtocolProfile.objects
        .filter(
            server_protocol=protocol,
            protocol_type=(
                ServerProtocol.ProtocolType.AWG2
            ),
            status=(
                ProtocolProfile
                .ProfileStatus
                .ACTIVE
            ),
        )
        .order_by("id")
    )

    return any(
        _profile_is_selective(profile)
        == wants_selective
        for profile in profiles
    )


def _subnet_capacity(
    subnet: str,
) -> int:
    try:
        network = ip_network(
            subnet,
            strict=False,
        )
    except ValueError:
        return 1

    # Для обычных IPv4 VPN-подсетей
    # исключаем network и broadcast.
    if network.version == 4:
        return max(
            int(network.num_addresses) - 2,
            1,
        )

    return max(
        int(network.num_addresses),
        1,
    )


def vpn_server_candidate_rows(
    *,
    routing_mode: str = ROUTING_MODE_FULL,
):
    if routing_mode not in VALID_ROUTING_MODES:
        raise ValueError(
            "Unsupported routing mode"
        )

    servers = (
        Server.objects
        .filter(
            is_enabled=True,
            accepts_new_vpn_clients=True,
            vpn_pool_locked=False,
            health_status="healthy",
        )
        .order_by(
            "-is_default_for_new_clients",
            "name",
            "id",
        )
    )

    rows = []

    for server in servers:
        protocol = (
            ServerProtocol.objects
            .filter(
                server=server,
                protocol_type=(
                    ServerProtocol
                    .ProtocolType
                    .AWG2
                ),
            )
            .first()
        )

        if protocol is None:
            continue

        metadata = (
            protocol.runtime_metadata or {}
        )

        if not protocol.enabled:
            continue

        if protocol.container_status != "running":
            continue

        if not _protocol_runtime_ready(
            protocol,
            server=server,
        ):
            continue

        if not metadata.get(
            "subnet_ready"
        ):
            continue

        if not metadata.get(
            "endpoint_host_ready"
        ):
            continue

        if not metadata.get(
            "endpoint_port_ready"
        ):
            continue

        if not _protocol_supports_mode(
            protocol,
            routing_mode=routing_mode,
        ):
            continue

        try:
            peer_count = int(
                metadata.get("peer_count")
                or 0
            )
        except (
            TypeError,
            ValueError,
        ):
            peer_count = 0

        subnet = (
            metadata.get("subnet")
            or ""
        )

        capacity = _subnet_capacity(
            subnet
        )

        utilization = (
            peer_count / capacity
        )

        db_connections = (
            server.clients
            .exclude(status="deleted")
            .count()
        )

        rows.append(
            {
                "server": server,
                "protocol": protocol,
                "peer_count": peer_count,
                "capacity": capacity,
                "utilization": utilization,
                "db_connections": (
                    db_connections
                ),
                "routing_mode": (
                    routing_mode
                ),
            }
        )

    rows.sort(
        key=lambda row: (
            row["utilization"],
            row["peer_count"],
            row["db_connections"],
            (
                0
                if row[
                    "server"
                ].is_default_for_new_clients
                else 1
            ),
            row["server"].id,
        )
    )

    return rows


def select_vpn_server(
    *,
    routing_mode: str = ROUTING_MODE_FULL,
):
    rows = vpn_server_candidate_rows(
        routing_mode=routing_mode,
    )

    if not rows:
        return None

    return rows[0]["server"]


def resolve_vpn_server_choice(
    *,
    choice: str,
    routing_mode: str,
):
    normalized = (
        choice or "auto"
    ).strip().lower()

    rows = vpn_server_candidate_rows(
        routing_mode=routing_mode,
    )

    if normalized in {
        "",
        "auto",
    }:
        if not rows:
            return None

        return rows[0]["server"]

    if not normalized.isdigit():
        raise ValueError(
            "Invalid server choice"
        )

    requested_id = int(normalized)

    for row in rows:
        if (
            row["server"].id
            == requested_id
        ):
            return row["server"]

    raise ValueError(
        "Selected server is not available "
        "for new VPN clients"
    )


def vpn_server_mode_status(
    *,
    server,
    routing_mode,
):
    if routing_mode not in VALID_ROUTING_MODES:
        raise ValueError(
            "Unsupported routing mode"
        )

    result = {
        "eligible": False,
        "runtime_ready": False,
        "profile_ready": False,
        "peer_count": 0,
        "capacity": 1,
        "utilization": 0.0,
        "reason": "",
    }

    if not server.is_enabled:
        result["reason"] = "Сервер выключен"
        return result

    if server.health_status != "healthy":
        result["reason"] = (
            "Runtime не в состоянии healthy"
        )
        return result

    protocol = (
        ServerProtocol.objects
        .filter(
            server=server,
            protocol_type=(
                ServerProtocol
                .ProtocolType
                .AWG2
            ),
        )
        .first()
    )

    if protocol is None:
        result["reason"] = (
            "AWG2 не настроен"
        )
        return result

    metadata = (
        protocol.runtime_metadata or {}
    )

    try:
        peer_count = int(
            metadata.get("peer_count")
            or 0
        )
    except (
        TypeError,
        ValueError,
    ):
        peer_count = 0

    capacity = _subnet_capacity(
        metadata.get("subnet") or ""
    )

    result.update(
        {
            "peer_count": peer_count,
            "capacity": capacity,
            "utilization": (
                peer_count / capacity
            ),
        }
    )

    if not protocol.enabled:
        result["reason"] = (
            "AWG2 выключен"
        )
        return result

    if protocol.container_status != "running":
        result["reason"] = (
            "AWG2 runtime не запущен"
        )
        return result

    if not _protocol_runtime_ready(
        protocol,
        server=server,
    ):
        if (
            server.runtime_backend
            == Server.RuntimeBackend.AWG_AGENT
        ):
            result["reason"] = (
                "AWG agent readiness не подтверждён"
            )
        else:
            result["reason"] = (
                "AWG 3.1 readiness не подтверждён"
            )

        return result

    if not metadata.get("subnet_ready"):
        result["reason"] = (
            "Подсеть не готова"
        )
        return result

    if not metadata.get(
        "endpoint_host_ready"
    ):
        result["reason"] = (
            "Endpoint host не готов"
        )
        return result

    if not metadata.get(
        "endpoint_port_ready"
    ):
        result["reason"] = (
            "Endpoint port не готов"
        )
        return result

    result["runtime_ready"] = True

    if not _protocol_supports_mode(
        protocol,
        routing_mode=routing_mode,
    ):
        result["reason"] = (
            "Нет активного профиля "
            "для выбранного режима"
        )
        return result

    result["profile_ready"] = True

    result.update(
        {
            "eligible": True,
            "reason": "",
        }
    )

    return result
