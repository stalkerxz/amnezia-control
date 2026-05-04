import hashlib
import logging
import math
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.db import IntegrityError
from django.urls import reverse
from django.utils import timezone

from .models import ClientExpirationReminderLog, VPNClient

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ExpirationReminderItem:
    client: VPNClient
    threshold_days: int
    remaining_seconds: int

    @property
    def remaining_days(self) -> int:
        return max(1, math.ceil(self.remaining_seconds / 86400))


class ClientExpirationReminderService:
    @classmethod
    def send_reminders(cls) -> dict:
        if not getattr(settings, "EXPIRATION_REMINDER_ENABLED", True):
            logger.info("Client expiration reminders are disabled")
            return {"enabled": False, "emails_sent": 0, "clients": 0, "logs_created": 0}

        thresholds = cls.get_threshold_days()
        if not thresholds:
            logger.warning("Client expiration reminder thresholds are empty")
            return {"enabled": True, "emails_sent": 0, "clients": 0, "logs_created": 0}

        recipients = cls.get_recipients()
        if not recipients:
            logger.warning("Client expiration reminders skipped: no admin recipients configured")
            return {"enabled": True, "emails_sent": 0, "clients": 0, "logs_created": 0}

        items = cls.collect_pending_items(thresholds=thresholds)
        if not items:
            return {"enabled": True, "emails_sent": 0, "clients": 0, "logs_created": 0}

        subject = f"[Amnezia Control] Истекают VPN-клиенты: {len({item.client.id for item in items})}"
        body = cls.build_email_body(items=items)
        send_mail(
            subject=subject,
            message=body,
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
            recipient_list=recipients,
            fail_silently=False,
        )

        logs_created = cls.create_logs(items=items, recipients=recipients)
        return {
            "enabled": True,
            "emails_sent": 1,
            "clients": len({item.client.id for item in items}),
            "items": len(items),
            "logs_created": logs_created,
        }

    @staticmethod
    def get_threshold_days() -> list[int]:
        raw_value = getattr(settings, "EXPIRATION_REMINDER_DAYS", [7, 3, 1])
        if isinstance(raw_value, str):
            parts = raw_value.split(",")
        else:
            parts = raw_value
        thresholds = []
        for value in parts:
            try:
                days = int(str(value).strip())
            except (TypeError, ValueError):
                continue
            if days > 0 and days not in thresholds:
                thresholds.append(days)
        return sorted(thresholds, reverse=True)

    @staticmethod
    def get_recipients() -> list[str]:
        configured = getattr(settings, "ADMIN_EXPIRATION_REMINDER_EMAILS", [])
        if isinstance(configured, str):
            recipients = [email.strip() for email in configured.split(",") if email.strip()]
        else:
            recipients = [str(email).strip() for email in configured if str(email).strip()]
        if recipients:
            return recipients
        admins = getattr(settings, "ADMINS", ())
        return [email for _name, email in admins if email]

    @classmethod
    def collect_pending_items(cls, *, thresholds: list[int]) -> list[ExpirationReminderItem]:
        now = timezone.now()
        max_threshold = max(thresholds)
        clients = (
            VPNClient.objects.select_related("server")
            .filter(
                status=VPNClient.Status.ACTIVE,
                expires_at__isnull=False,
                expires_at__gt=now,
                expires_at__lte=now + timedelta(days=max_threshold),
            )
            .order_by("expires_at", "id")
        )
        items = []
        for client in clients:
            remaining_seconds = max(0, int((client.expires_at - now).total_seconds()))
            covering_thresholds = [
                threshold
                for threshold in thresholds
                if client.expires_at <= now + timedelta(days=threshold)
            ]
            if not covering_thresholds:
                continue
            threshold = min(covering_thresholds)
            if ClientExpirationReminderLog.objects.filter(
                client=client,
                threshold_days=threshold,
                expires_at_snapshot=client.expires_at,
            ).exists():
                continue
            items.append(
                ExpirationReminderItem(
                    client=client,
                    threshold_days=threshold,
                    remaining_seconds=remaining_seconds,
                )
            )
        return items

    @classmethod
    def build_email_body(cls, *, items: list[ExpirationReminderItem]) -> str:
        lines = [
            "VPN-клиенты близки к окончанию срока действия.",
            "",
            "Сгруппировано по порогам напоминаний.",
        ]
        base_url = cls.get_base_url()
        items_by_threshold = {
            threshold: [item for item in items if item.threshold_days == threshold]
            for threshold in sorted({item.threshold_days for item in items}, reverse=True)
        }
        for threshold, threshold_items in items_by_threshold.items():
            lines.extend(["", f"Порог: {threshold} дн."])
            for item in threshold_items:
                client = item.client
                remaining = str(timedelta(seconds=item.remaining_seconds))
                lines.append(
                    " - "
                    f"ID: {client.id}; "
                    f"name: {client.name}; "
                    f"protocol_type: {client.protocol_type}; "
                    f"expires_at: {timezone.localtime(client.expires_at).isoformat()}; "
                    f"remaining: {remaining} ({item.remaining_days} дн.); "
                    f"status: {client.status}"
                )
                if base_url:
                    detail_path = reverse("clients-detail", kwargs={"pk": client.id})
                    lines.append(f"   link: {base_url}{detail_path}")
        return "\n".join(lines)

    @staticmethod
    def get_base_url() -> str:
        return (getattr(settings, "SITE_URL", "") or getattr(settings, "PUBLIC_BASE_URL", "")).rstrip("/")

    @staticmethod
    def recipient_hash(recipients: list[str]) -> str:
        normalized = ",".join(sorted(email.lower().strip() for email in recipients if email.strip()))
        return hashlib.sha256(normalized.encode()).hexdigest()

    @classmethod
    def create_logs(cls, *, items: list[ExpirationReminderItem], recipients: list[str]) -> int:
        digest = cls.recipient_hash(recipients)
        created = 0
        for item in items:
            try:
                ClientExpirationReminderLog.objects.create(
                    client=item.client,
                    threshold_days=item.threshold_days,
                    expires_at_snapshot=item.client.expires_at,
                    recipient_hash=digest,
                )
                created += 1
            except IntegrityError:
                logger.info(
                    "Client expiration reminder log already exists",
                    extra={"client_id": item.client.id, "threshold_days": item.threshold_days},
                )
        return created
