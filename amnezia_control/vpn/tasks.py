from celery import shared_task

from vpn.expiration_reminders import ClientExpirationReminderService
from vpn.services import VPNClientLimitsService


@shared_task
def enforce_client_limits_task():
    traffic = VPNClientLimitsService.sync_traffic_usage(actor=None)
    limits = VPNClientLimitsService.enforce_limits(actor=None)
    return {"traffic": traffic, "limits": limits}


@shared_task
def send_expiration_reminders_task():
    return ClientExpirationReminderService.send_reminders()
