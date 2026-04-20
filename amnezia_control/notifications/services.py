import logging
import math
from dataclasses import dataclass

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.mail import send_mail
from django.urls import reverse
from django.utils import timezone

from portal.models import ClientRenewalRequest
from vpn.models import VPNClient

logger = logging.getLogger(__name__)


class NotificationEventType:
    RENEWAL_REQUEST_CREATED = "renewal_request_created"
    RENEWAL_REQUEST_STATUS_CHANGED = "renewal_request_status_changed"
    CLIENT_ACCESS_EXPIRING = "client_access_expiring"
    CLIENT_ACCESS_EXPIRED = "client_access_expired"
    BACKGROUND_JOB_FAILED = "background_job_failed"


class NotificationRecipientType:
    ADMIN = "admin"
    CLIENT = "client"


class NotificationChannel:
    EMAIL = "email"
    TELEGRAM = "telegram"


@dataclass
class NotificationMessage:
    recipient_type: str
    subject: str
    body: str
    recipients: list[str]
    telegram_text: str = ""


class NotificationService:
    TELEGRAM_PREFIXES = {
        NotificationEventType.RENEWAL_REQUEST_CREATED: "[Продление]",
        NotificationEventType.RENEWAL_REQUEST_STATUS_CHANGED: "[Продление]",
        NotificationEventType.CLIENT_ACCESS_EXPIRING: "[Доступ]",
        NotificationEventType.CLIENT_ACCESS_EXPIRED: "[Доступ]",
        NotificationEventType.BACKGROUND_JOB_FAILED: "[Ошибка]",
    }

    @classmethod
    def emit_event(cls, *, event_type: str, payload: dict, async_delivery: bool = True):
        if not getattr(settings, "NOTIFICATIONS_ENABLED", True):
            return
        if async_delivery:
            try:
                from .tasks import deliver_notification_event

                deliver_notification_event.delay(event_type=event_type, payload=payload)
                return
            except Exception:
                logger.exception("Failed to enqueue notification event", extra={"event_type": event_type, "payload": payload})
        cls.deliver(event_type=event_type, payload=payload)

    @classmethod
    def deliver(cls, *, event_type: str, payload: dict):
        messages = cls._build_messages(event_type=event_type, payload=payload)
        if not messages:
            return
        for msg in messages:
            cls._send_email(msg)
            cls._send_telegram(msg=msg, event_type=event_type, payload=payload)

    @classmethod
    def _build_messages(cls, *, event_type: str, payload: dict) -> list[NotificationMessage]:
        if event_type == NotificationEventType.RENEWAL_REQUEST_CREATED:
            return cls._build_renewal_created_messages(payload=payload)
        if event_type == NotificationEventType.RENEWAL_REQUEST_STATUS_CHANGED:
            return cls._build_renewal_status_messages(payload=payload)
        if event_type in {NotificationEventType.CLIENT_ACCESS_EXPIRING, NotificationEventType.CLIENT_ACCESS_EXPIRED}:
            return cls._build_client_access_messages(event_type=event_type, payload=payload)
        if event_type == NotificationEventType.BACKGROUND_JOB_FAILED:
            return cls._build_background_job_failed_messages(payload=payload)
        logger.warning("Unknown notification event", extra={"event_type": event_type})
        return []

    @classmethod
    def _build_renewal_created_messages(cls, *, payload: dict) -> list[NotificationMessage]:
        client_name = payload.get("client_name") or "—"
        has_attachment = bool(payload.get("has_attachment"))
        request_id = payload.get("renewal_request_id")
        text = f"Новая заявка на продление от клиента {client_name}."
        if has_attachment:
            text = f"Новая заявка на продление от клиента {client_name} с вложением."
        queue_url = cls._full_url(reverse("renewal-requests-list"))
        if request_id:
            queue_url = cls._full_url(f"{reverse('renewal-requests-list')}?status=open&request_id={request_id}")
        body = f"{text}\n\nОчередь заявок: {queue_url}"
        telegram_text = f"{text}\nКлиент: {client_name}\n{queue_url}"
        recipients = cls._admin_email_recipients()
        if not recipients:
            recipients = []
        return [
            NotificationMessage(
                recipient_type=NotificationRecipientType.ADMIN,
                subject="Новая заявка на продление",
                body=body,
                recipients=recipients,
                telegram_text=telegram_text,
            )
        ]

    @classmethod
    def _build_renewal_status_messages(cls, *, payload: dict) -> list[NotificationMessage]:
        status = (payload.get("status") or "").strip()
        client_name = payload.get("client_name") or "клиента"
        request_id = payload.get("renewal_request_id")
        client_id = payload.get("client_id")
        messages = []

        admin_text = {
            ClientRenewalRequest.Status.IN_PROGRESS: f"Заявка клиента {client_name} взята в работу.",
            ClientRenewalRequest.Status.DONE: f"Заявка клиента {client_name} обработана.",
            ClientRenewalRequest.Status.DISMISSED: f"Заявка клиента {client_name} отклонена.",
        }.get(status)
        if admin_text:
            link = cls._full_url(reverse("renewal-requests-list"))
            if request_id:
                link = cls._full_url(f"{reverse('renewal-requests-list')}?request_id={request_id}")
            recipients = cls._admin_email_recipients()
            if recipients:
                messages.append(
                    NotificationMessage(
                        recipient_type=NotificationRecipientType.ADMIN,
                        subject="Обновление заявки на продление",
                        body=f"{admin_text}\n\nОткрыть очередь: {link}",
                        recipients=recipients,
                        telegram_text=f"{admin_text}\nКлиент: {client_name}\n{link}",
                    )
                )

        client_text = {
            ClientRenewalRequest.Status.NEW: "Ваша заявка на продление принята.",
            ClientRenewalRequest.Status.IN_PROGRESS: "Оператор взял вашу заявку в работу.",
            ClientRenewalRequest.Status.DONE: "Заявка обработана.",
            ClientRenewalRequest.Status.DISMISSED: "Заявка отклонена.",
            "extend_and_close": "Доступ продлён.",
        }.get(status)
        client_recipients = cls._client_email_recipients(client_id=client_id)
        if client_text and client_recipients:
            messages.append(
                NotificationMessage(
                    recipient_type=NotificationRecipientType.CLIENT,
                    subject="Статус заявки на продление",
                    body=client_text,
                    recipients=client_recipients,
                )
            )
        return messages

    @classmethod
    def _build_client_access_messages(cls, *, event_type: str, payload: dict) -> list[NotificationMessage]:
        client_name = payload.get("client_name") or "—"
        client_id = payload.get("client_id")
        days_left = payload.get("days_left")
        if event_type == NotificationEventType.CLIENT_ACCESS_EXPIRING:
            text = f"Доступ клиента {client_name} истекает через {days_left} дня."
        else:
            text = f"Доступ клиента {client_name} уже истёк."
        recipients = cls._admin_email_recipients()
        link = cls._full_url(reverse("clients-detail", kwargs={"pk": client_id})) if client_id else cls._full_url(reverse("clients-list"))
        return [
            NotificationMessage(
                recipient_type=NotificationRecipientType.ADMIN,
                subject="Срок доступа клиента",
                body=f"{text}\n\nКарточка клиента: {link}",
                recipients=recipients,
                telegram_text=f"{text}\nКлиент: {client_name}\n{link}",
            )
        ]

    @classmethod
    def _build_background_job_failed_messages(cls, *, payload: dict) -> list[NotificationMessage]:
        recipients = cls._admin_email_recipients()
        job_id = payload.get("job_id")
        action = payload.get("action") or "unknown"
        text = f"Сбой фоновой задачи: {action}."
        if job_id:
            text += f" Job #{job_id}."
        return [
            NotificationMessage(
                recipient_type=NotificationRecipientType.ADMIN,
                subject="Сбой фоновой задачи",
                body=text,
                recipients=recipients,
                telegram_text=text,
            )
        ]

    @classmethod
    def _send_email(cls, msg: NotificationMessage):
        if NotificationChannel.EMAIL not in getattr(settings, "NOTIFICATIONS_CHANNELS", [NotificationChannel.EMAIL]):
            return
        if not msg.recipients:
            return
        try:
            send_mail(
                subject=msg.subject,
                message=msg.body,
                from_email=getattr(settings, "NOTIFICATIONS_EMAIL_FROM", ""),
                recipient_list=msg.recipients,
                fail_silently=False,
            )
        except Exception:
            logger.exception(
                "Notification email delivery failed",
                extra={"recipient_type": msg.recipient_type, "subject": msg.subject, "recipients": msg.recipients},
            )

    @classmethod
    def _send_telegram(cls, *, msg: NotificationMessage, event_type: str, payload: dict):
        if NotificationChannel.TELEGRAM not in getattr(settings, "NOTIFICATIONS_CHANNELS", [NotificationChannel.EMAIL]):
            return
        if msg.recipient_type != NotificationRecipientType.ADMIN:
            return
        bot_token = getattr(settings, "NOTIFICATIONS_TELEGRAM_BOT_TOKEN", "").strip()
        chat_ids = getattr(settings, "NOTIFICATIONS_TELEGRAM_ADMIN_CHAT_IDS", [])
        if not bot_token or not chat_ids:
            return
        text = (msg.telegram_text or msg.body or "").strip()
        if not text:
            return
        text = cls._telegram_text_with_prefix(event_type=event_type, text=text)
        from .telegram import send_telegram_message

        for chat_id in chat_ids:
            chat_id_str = str(chat_id)
            try:
                send_telegram_message(bot_token=bot_token, chat_id=chat_id_str, text=text)
            except Exception:
                logger.exception(
                    "Notification telegram delivery failed for admin chat",
                    extra={
                        "event_type": event_type,
                        "recipient_type": msg.recipient_type,
                        "chat_id": chat_id_str,
                        "payload": payload,
                    },
                )

    @classmethod
    def _telegram_text_with_prefix(cls, *, event_type: str, text: str) -> str:
        prefix = cls.TELEGRAM_PREFIXES.get(event_type, "").strip()
        if not prefix:
            return text
        if text.startswith(prefix):
            return text
        return f"{prefix} {text}"

    @staticmethod
    def _admin_email_recipients() -> list[str]:
        User = get_user_model()
        return list(User.objects.filter(is_staff=True, is_active=True).exclude(email="").values_list("email", flat=True))

    @staticmethod
    def _client_email_recipients(*, client_id: int | None) -> list[str]:
        if not client_id:
            return []
        email = (
            VPNClient.objects.filter(id=client_id)
            .exclude(contact_email="")
            .values_list("contact_email", flat=True)
            .first()
        )
        return [email] if email else []

    @staticmethod
    def _full_url(path: str) -> str:
        base_url = getattr(settings, "NOTIFICATIONS_BASE_URL", "").rstrip("/")
        if not base_url:
            return path
        return f"{base_url}{path}"

    @classmethod
    def emit_client_access_limits_notifications(cls) -> dict:
        threshold_days = int(getattr(settings, "NOTIFICATIONS_EXPIRING_DAYS", 3))
        now = timezone.now()
        expiring = 0
        expired = 0
        clients = VPNClient.objects.exclude(status=VPNClient.Status.DELETED).exclude(expires_at__isnull=True)
        for client in clients:
            if client.expires_at <= now:
                # Expired state is absolute and does not depend on day rounding.
                # We dedupe per UTC date to avoid repeated alerts within the day.
                if cls._mark_limit_event_once(client_id=client.id, event_type=NotificationEventType.CLIENT_ACCESS_EXPIRED, marker=now.date().isoformat(), ttl=60 * 60 * 24):
                    cls.emit_event(
                        event_type=NotificationEventType.CLIENT_ACCESS_EXPIRED,
                        payload={"client_id": client.id, "client_name": client.name},
                    )
                    expired += 1
                continue
            # Use explicit ceil-based day semantics to avoid timedelta.days floor behavior.
            # Example: 2 days + 1 hour left => 3 days remaining for notification text.
            days_left = max(1, math.ceil((client.expires_at - now).total_seconds() / 86400))
            if days_left <= threshold_days:
                if cls._mark_limit_event_once(client_id=client.id, event_type=NotificationEventType.CLIENT_ACCESS_EXPIRING, marker=str(days_left), ttl=60 * 60 * 24):
                    cls.emit_event(
                        event_type=NotificationEventType.CLIENT_ACCESS_EXPIRING,
                        payload={"client_id": client.id, "client_name": client.name, "days_left": days_left},
                    )
                    expiring += 1
        return {"expiring": expiring, "expired": expired}

    @staticmethod
    def _mark_limit_event_once(*, client_id: int, event_type: str, marker: str, ttl: int) -> bool:
        cache_key = f"notify:{event_type}:{client_id}:{marker}"
        return cache.add(cache_key, "1", timeout=ttl)
