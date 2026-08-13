from celery import shared_task

from customers.models import (
    ClientDevice,
    CustomerAccount,
)
from vpn.expiration_reminders import (
    ClientExpirationReminderService,
)
from vpn.models import VPNClient, XHTTPDevice
from vpn.services import (
    VPNClientLimitsService,
    VPNClientService,
)
from vpn.xhttp_services import XHTTPDeviceService


def _reconcile_xhttp_device(
    client_device: ClientDevice,
) -> dict:
    available = (
        XHTTPDeviceService.is_device_available(
            client_device
        )
    )

    if available:
        candidates = (
            client_device.xhttp_devices
            .filter(
                status=XHTTPDevice.Status.DISABLED,
                disable_reason=(
                    XHTTPDevice.DisableReason.CLIENT
                ),
            )
            .count()
        )

        XHTTPDeviceService.enable_for_device(
            client_device=client_device,
            actor=None,
        )

        return {
            "device_id": client_device.id,
            "enabled": candidates,
            "disabled": 0,
        }

    candidates = (
        client_device.xhttp_devices
        .filter(
            status=XHTTPDevice.Status.ACTIVE,
        )
        .count()
    )

    XHTTPDeviceService.disable_for_device(
        client_device=client_device,
        actor=None,
    )

    return {
        "device_id": client_device.id,
        "enabled": 0,
        "disabled": candidates,
    }


def _reconcile_xhttp_client(
    client: VPNClient,
) -> dict:
    """Compatibility reconciliation for legacy client-only rows."""

    legacy_devices = client.xhttp_devices.filter(
        device__isnull=True,
    )

    available = (
        client.status == VPNClient.Status.ACTIVE
        and VPNClientService.get_limit_state(client)
        == VPNClient.LimitState.ACTIVE
    )

    if available:
        candidates = legacy_devices.filter(
            status=XHTTPDevice.Status.DISABLED,
            disable_reason=XHTTPDevice.DisableReason.CLIENT,
        ).count()

        XHTTPDeviceService.enable_for_client(
            client=client,
            actor=None,
        )

        return {
            "client_id": client.id,
            "enabled": candidates,
            "disabled": 0,
        }

    candidates = legacy_devices.filter(
        status=XHTTPDevice.Status.ACTIVE,
    ).count()

    XHTTPDeviceService.disable_for_client(
        client=client,
        actor=None,
    )

    return {
        "client_id": client.id,
        "enabled": 0,
        "disabled": candidates,
    }


def _reconcile_all_xhttp_devices() -> dict:
    totals = {
        "devices": 0,
        "legacy_clients": 0,
        "enabled": 0,
        "disabled": 0,
        "errors": [],
    }

    owners = (
        ClientDevice.objects
        .filter(
            xhttp_devices__isnull=False,
        )
        .select_related("account")
        .prefetch_related("xhttp_devices")
        .distinct()
    )

    for owner in owners:
        totals["devices"] += 1

        try:
            result = _reconcile_xhttp_device(
                owner
            )

            totals["enabled"] += result["enabled"]
            totals["disabled"] += result["disabled"]

        except Exception as exc:
            totals["errors"].append(
                {
                    "device_id": owner.id,
                    "error": str(exc)[:200],
                }
            )

    legacy_clients = (
        VPNClient.objects
        .filter(
            xhttp_devices__isnull=False,
            xhttp_devices__device__isnull=True,
        )
        .select_related("server")
        .prefetch_related("xhttp_devices")
        .distinct()
    )

    for client in legacy_clients:
        totals["legacy_clients"] += 1

        try:
            result = _reconcile_xhttp_client(
                client
            )

            totals["enabled"] += result["enabled"]
            totals["disabled"] += result["disabled"]

        except Exception as exc:
            totals["errors"].append(
                {
                    "client_id": client.id,
                    "error": str(exc)[:200],
                }
            )

    return totals


@shared_task
def reconcile_xhttp_device_task(
    device_id: int,
):
    device = (
        ClientDevice.objects
        .select_related("account")
        .prefetch_related("xhttp_devices")
        .filter(pk=device_id)
        .first()
    )

    if not device:
        return {
            "device_id": device_id,
            "missing": True,
        }

    return _reconcile_xhttp_device(
        device
    )


@shared_task
def reconcile_xhttp_account_task(
    account_id: int,
):
    account = (
        CustomerAccount.objects
        .filter(pk=account_id)
        .first()
    )

    if not account:
        return {
            "account_id": account_id,
            "missing": True,
        }

    result = {
        "account_id": account_id,
        "devices": 0,
        "enabled": 0,
        "disabled": 0,
        "errors": [],
    }

    for device in (
        account.devices
        .select_related("account")
        .prefetch_related("xhttp_devices")
        .all()
    ):
        result["devices"] += 1

        try:
            item = _reconcile_xhttp_device(
                device
            )

            result["enabled"] += item["enabled"]
            result["disabled"] += item["disabled"]

        except Exception as exc:
            result["errors"].append(
                {
                    "device_id": device.id,
                    "error": str(exc)[:200],
                }
            )

    return result


@shared_task
def reconcile_xhttp_client_task(
    client_id: int,
):
    client = (
        VPNClient.objects
        .prefetch_related("xhttp_devices")
        .filter(pk=client_id)
        .first()
    )

    if not client:
        return {
            "client_id": client_id,
            "missing": True,
        }

    return _reconcile_xhttp_client(
        client
    )


@shared_task
def reconcile_xhttp_devices_task():
    return _reconcile_all_xhttp_devices()


@shared_task
def enforce_client_limits_task():
    traffic = (
        VPNClientLimitsService
        .sync_traffic_usage(actor=None)
    )

    limits = (
        VPNClientLimitsService
        .enforce_limits(actor=None)
    )

    xhttp = _reconcile_all_xhttp_devices()

    return {
        "traffic": traffic,
        "limits": limits,
        "xhttp": xhttp,
    }


@shared_task
def send_expiration_reminders_task():
    return (
        ClientExpirationReminderService
        .send_reminders()
    )
