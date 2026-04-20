import logging

from celery import shared_task

from .services import NotificationService

logger = logging.getLogger(__name__)


@shared_task
def deliver_notification_event(event_type: str, payload: dict):
    try:
        NotificationService.deliver(event_type=event_type, payload=payload)
    except Exception:
        logger.exception("Failed to deliver notification event", extra={"event_type": event_type, "payload": payload})


@shared_task
def notify_client_access_limits_task():
    return NotificationService.emit_client_access_limits_notifications()
