from celery import shared_task

from vpn.expiration_reminders import ClientExpirationReminderService
from vpn.models import VPNClient, XHTTPDevice
from vpn.services import VPNClientLimitsService, VPNClientService
from vpn.xhttp_services import XHTTPDeviceService


def _reconcile_xhttp_client(client: VPNClient) -> dict:
    available = (
        client.status == VPNClient.Status.ACTIVE
        and VPNClientService.get_limit_state(client) == VPNClient.LimitState.ACTIVE
    )
    if available:
        candidates = client.xhttp_devices.filter(
            status=XHTTPDevice.Status.DISABLED,
            disable_reason=XHTTPDevice.DisableReason.CLIENT,
        ).count()
        XHTTPDeviceService.enable_for_client(client=client, actor=None)
        return {"client_id": client.id, "enabled": candidates, "disabled": 0}

    candidates = client.xhttp_devices.filter(status=XHTTPDevice.Status.ACTIVE).count()
    XHTTPDeviceService.disable_for_client(client=client, actor=None)
    return {"client_id": client.id, "enabled": 0, "disabled": candidates}


@shared_task
def reconcile_xhttp_client_task(client_id: int):
    client = VPNClient.objects.prefetch_related("xhttp_devices").filter(pk=client_id).first()
    if not client:
        return {"client_id": client_id, "missing": True}
    return _reconcile_xhttp_client(client)


@shared_task
def reconcile_xhttp_devices_task():
    totals = {"clients": 0, "enabled": 0, "disabled": 0, "errors": []}
    clients = (
        VPNClient.objects.filter(xhttp_devices__isnull=False)
        .select_related("server")
        .prefetch_related("xhttp_devices")
        .distinct()
    )
    for client in clients:
        totals["clients"] += 1
        try:
            result = _reconcile_xhttp_client(client)
            totals["enabled"] += result["enabled"]
            totals["disabled"] += result["disabled"]
        except Exception as exc:
            totals["errors"].append({"client_id": client.id, "error": str(exc)[:200]})
    return totals


@shared_task
def enforce_client_limits_task():
    traffic = VPNClientLimitsService.sync_traffic_usage(actor=None)
    limits = VPNClientLimitsService.enforce_limits(actor=None)
    xhttp = reconcile_xhttp_devices_task.run()
    return {"traffic": traffic, "limits": limits, "xhttp": xhttp}


@shared_task
def send_expiration_reminders_task():
    return ClientExpirationReminderService.send_reminders()
