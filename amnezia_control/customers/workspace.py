from django.utils import timezone

from vpn.models import VPNClient, XHTTPDevice
from vpn.services import VPNClientService

from .models import ClientDevice, CustomerAccount


def _vpn_kind(client):
    if (
        client.protocol_type
        != VPNClient.ProtocolType.AWG2
    ):
        return "legacy"

    if VPNClientService._profile_is_selective(
        client.profile
    ):
        return "selective"

    return "full"


def _fmt_bytes(value):
    if value is None:
        return "Без лимита"

    units = (
        "Б",
        "КБ",
        "МБ",
        "ГБ",
        "ТБ",
    )

    size = float(
        max(value, 0)
    )

    unit = units[0]

    for candidate in units:
        unit = candidate

        if (
            size < 1024.0
            or candidate == units[-1]
        ):
            break

        size /= 1024.0

    if unit == "Б":
        return f"{int(size)} {unit}"

    return f"{size:.2f} {unit}"


def build_customer_workspace(
    account,
    *,
    now=None,
):
    current_time = (
        now
        or timezone.now()
    )

    account_expired = bool(
        account.expires_at
        and account.expires_at
        <= current_time
    )

    account_ready = (
        account.status
        == CustomerAccount.Status.ACTIVE
        and not account_expired
    )

    rows = []

    full_total = 0
    selective_total = 0
    legacy_total = 0
    xhttp_total = 0
    active_connection_total = 0

    devices = [
        device
        for device in account.devices.all()
        if (
            device.status
            != ClientDevice.Status.DELETED
        )
    ]

    for device in devices:
        device_expired = bool(
            device.expires_at
            and device.expires_at
            <= current_time
        )

        device_ready = bool(
            account_ready
            and device.status
            == ClientDevice.Status.ACTIVE
            and not device_expired
        )

        full = []
        selective = []
        legacy = []

        vpn_clients = [
            client
            for client
            in device.vpn_clients.all()
            if (
                client.status
                != VPNClient.Status.DELETED
            )
        ]

        for client in vpn_clients:
            client.traffic_used_display = (
                _fmt_bytes(
                    client.traffic_used_bytes
                )
            )

            client.traffic_limit_display = (
                _fmt_bytes(
                    client.traffic_limit_bytes
                )
            )

            kind = _vpn_kind(client)

            if kind == "full":
                full.append(client)
                full_total += 1

            elif kind == "selective":
                selective.append(client)
                selective_total += 1

            else:
                legacy.append(client)
                legacy_total += 1

            if (
                client.status
                == VPNClient.Status.ACTIVE
                and device_ready
            ):
                active_connection_total += 1

        xhttp = [
            item
            for item
            in device.xhttp_devices.all()
            if (
                item.status
                != XHTTPDevice.Status.DELETED
            )
        ]

        xhttp_total += len(xhttp)

        if device_ready:
            active_connection_total += sum(
                1
                for item in xhttp
                if (
                    item.status
                    == XHTTPDevice.Status.ACTIVE
                )
            )

        connection_total = (
            len(full)
            + len(selective)
            + len(legacy)
            + len(xhttp)
        )

        rows.append(
            {
                "device": device,
                "device_expired": (
                    device_expired
                ),
                "device_ready": (
                    device_ready
                ),
                "effective_expires_at": (
                    device.effective_expires_at
                ),
                "device_vpn_limit_display": (
                    _fmt_bytes(
                        device.vpn_traffic_limit_bytes
                    )
                ),
                "full": full,
                "selective": selective,
                "legacy": legacy,
                "xhttp": xhttp,
                "connection_total": (
                    connection_total
                ),
                "can_add_connections": (
                    device_ready
                ),
            }
        )

    connection_total = (
        full_total
        + selective_total
        + legacy_total
        + xhttp_total
    )

    return {
        "devices": rows,
        "device_total": len(rows),
        "active_device_total": sum(
            1
            for row in rows
            if row["device_ready"]
        ),
        "disabled_device_total": sum(
            1
            for row in rows
            if (
                row["device"].status
                == ClientDevice.Status.DISABLED
            )
        ),
        "expired_device_total": sum(
            1
            for row in rows
            if row["device_expired"]
        ),
        "connection_total": connection_total,
        "active_connection_total": (
            active_connection_total
        ),
        "full_total": full_total,
        "selective_total": selective_total,
        "legacy_total": legacy_total,
        "xhttp_total": xhttp_total,
        "account_expired": account_expired,
        "account_ready": account_ready,
    }
