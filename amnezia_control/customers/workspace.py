from django.utils import timezone

from vpn.models import VPNClient, XHTTPDevice
from vpn.services import VPNClientService

from .models import ClientDevice, CustomerAccount


def _vpn_kind(client):
    if client.protocol_type != VPNClient.ProtocolType.AWG2:
        return "legacy"

    if VPNClientService._profile_is_selective(
        client.profile
    ):
        return "selective"

    return "full"


def build_customer_workspace(
    account,
    *,
    now=None,
):
    current_time = now or timezone.now()

    account_expired = bool(
        account.expires_at
        and account.expires_at <= current_time
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
        full = []
        selective = []
        legacy = []

        vpn_clients = [
            client
            for client in device.vpn_clients.all()
            if (
                client.status
                != VPNClient.Status.DELETED
            )
        ]

        for client in vpn_clients:
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

            if client.status == VPNClient.Status.ACTIVE:
                active_connection_total += 1

        xhttp = [
            item
            for item in device.xhttp_devices.all()
            if (
                item.status
                != XHTTPDevice.Status.DELETED
            )
        ]

        xhttp_total += len(xhttp)

        active_connection_total += sum(
            1
            for item in xhttp
            if item.status
            == XHTTPDevice.Status.ACTIVE
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
                "full": full,
                "selective": selective,
                "legacy": legacy,
                "xhttp": xhttp,
                "connection_total": (
                    connection_total
                ),
                "can_add_connections": (
                    account_ready
                    and device.status
                    == ClientDevice.Status.ACTIVE
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
            if (
                row["device"].status
                == ClientDevice.Status.ACTIVE
            )
        ),
        "disabled_device_total": sum(
            1
            for row in rows
            if (
                row["device"].status
                == ClientDevice.Status.DISABLED
            )
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
