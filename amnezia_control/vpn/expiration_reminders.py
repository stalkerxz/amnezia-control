import hashlib
import json
import logging
import math
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.core.mail import send_mail
from django.db import IntegrityError
from django.urls import reverse
from django.utils import timezone

from .models import ClientExpirationReminderLog, VPNClient

logger = logging.getLogger(__name__)

TELEGRAM_API_BASE_URL = "https://api.telegram.org"
TELEGRAM_MESSAGE_LIMIT = 4096


@dataclass(frozen=True)
class ExpirationReminderItem:
    client: VPNClient
    threshold_days: int
    remaining_seconds: int

    @property
    def remaining_days(self) -> int:
        return max(1, math.ceil(self.remaining_seconds / 86400))


class ClientExpirationReminderService:
    SUPPORTED_CHANNELS = ("email", "telegram")

    @classmethod
    def send_reminders(cls) -> dict:
        channels = cls.get_channels()
        channel_status = cls.build_channel_status(channels)
        base_result = {
            "enabled": bool(getattr(settings, "EXPIRATION_REMINDER_ENABLED", True)),
            "emails_sent": 0,
            "clients": 0,
            "items": 0,
            "logs_created": 0,
            "channels": channel_status,
        }
        if not base_result["enabled"]:
            logger.info("Client expiration reminders are disabled")
            return base_result

        thresholds = cls.get_threshold_days()
        if not thresholds:
            logger.warning("Client expiration reminder thresholds are empty")
            return base_result

        if not channels:
            logger.warning("Client expiration reminders skipped: no reminder channels enabled")
            return base_result

        items = cls.collect_pending_items(thresholds=thresholds)
        if not items:
            return base_result

        client_count = len({item.client.id for item in items})
        base_result.update({"clients": client_count, "items": len(items)})

        sent_recipients = []
        if "email" in channels:
            recipients = cls.get_recipients()
            if not recipients:
                channel_status["email"]["error"] = "No admin email recipients configured"
                logger.warning("Client expiration email reminders skipped: no admin recipients configured")
            else:
                try:
                    subject = f"[Amnezia Control] Истекают VPN-клиенты: {client_count}"
                    body = cls.build_email_body(items=items)
                    send_mail(
                        subject=subject,
                        message=body,
                        from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
                        recipient_list=recipients,
                        fail_silently=False,
                    )
                    channel_status["email"]["sent"] = True
                    base_result["emails_sent"] = 1
                    sent_recipients.extend(f"email:{recipient}" for recipient in recipients)
                except Exception as exc:  # pragma: no cover - exact backend exceptions vary
                    channel_status["email"]["error"] = str(exc)
                    logger.warning("Client expiration email reminders failed: %s", exc)

        if "telegram" in channels:
            telegram_result = cls.send_telegram_reminder(items=items)
            channel_status["telegram"].update(telegram_result)
            if telegram_result["sent"]:
                sent_recipients.extend(f"telegram:{chat_id}" for chat_id in cls.get_telegram_chat_ids())

        delivered = any(status["enabled"] and status["sent"] for status in channel_status.values())
        if delivered:
            base_result["logs_created"] = cls.create_logs(items=items, recipients=sent_recipients)
        else:
            logger.warning("Client expiration reminders were not logged because no enabled channel delivered")
        return base_result

    @classmethod
    def build_channel_status(cls, channels: list[str]) -> dict:
        return {
            channel: {"enabled": channel in channels, "sent": False, "error": ""}
            for channel in cls.SUPPORTED_CHANNELS
        }

    @classmethod
    def get_channels(cls) -> list[str]:
        raw_value = getattr(settings, "EXPIRATION_REMINDER_CHANNELS", ["email"])
        if isinstance(raw_value, str):
            parts = raw_value.split(",")
        else:
            parts = raw_value
        channels = []
        for value in parts:
            channel = str(value).strip().lower()
            if channel in cls.SUPPORTED_CHANNELS and channel not in channels:
                channels.append(channel)
        return channels

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

    @staticmethod
    def get_telegram_chat_ids() -> list[str]:
        configured = getattr(settings, "TELEGRAM_ADMIN_CHAT_IDS", [])
        if isinstance(configured, str):
            return [chat_id.strip() for chat_id in configured.split(",") if chat_id.strip()]
        return [str(chat_id).strip() for chat_id in configured if str(chat_id).strip()]

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
        lines.extend(cls.build_item_lines(items=items, bullet_prefix=" - ", link_prefix="   link: "))
        return "\n".join(lines)

    @classmethod
    def build_telegram_message(cls, *, items: list[ExpirationReminderItem]) -> str:
        lines = [
            "Истекают VPN-клиенты",
            "",
            "Сгруппировано по порогам напоминаний.",
        ]
        lines.extend(cls.build_item_lines(items=items, bullet_prefix="• ", link_prefix="  link: "))
        return "\n".join(lines)

    @classmethod
    def build_item_lines(cls, *, items: list[ExpirationReminderItem], bullet_prefix: str, link_prefix: str) -> list[str]:
        lines = []
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
                    bullet_prefix
                    + f"ID: {client.id}; "
                    + f"name: {client.name}; "
                    + f"protocol_type: {client.protocol_type}; "
                    + f"expires_at: {timezone.localtime(client.expires_at).isoformat()}; "
                    + f"remaining: {remaining} ({item.remaining_days} дн.); "
                    + f"status: {client.status}"
                )
                if base_url:
                    detail_path = reverse("clients-detail", kwargs={"pk": client.id})
                    lines.append(f"{link_prefix}{base_url}{detail_path}")
        return lines

    @classmethod
    def send_telegram_reminder(cls, *, items: list[ExpirationReminderItem]) -> dict:
        token = getattr(settings, "TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            return {"sent": False, "error": "TELEGRAM_BOT_TOKEN is not configured"}
        chat_ids = cls.get_telegram_chat_ids()
        if not chat_ids:
            return {"sent": False, "error": "TELEGRAM_ADMIN_CHAT_IDS is not configured"}

        chunks = cls.split_telegram_message(cls.build_telegram_message(items=items))
        errors = []
        for chat_id in chat_ids:
            for chunk in chunks:
                try:
                    cls.post_telegram_message(token=token, chat_id=chat_id, text=chunk)
                except Exception as exc:
                    error = cls.redact_secret(str(exc), token)
                    errors.append(f"chat_id={chat_id}: {error}")
                    logger.warning("Telegram expiration reminder failed for chat_id=%s: %s", chat_id, error)
                    break
        return {"sent": not errors, "error": "; ".join(errors)}

    @staticmethod
    def redact_secret(value: str, secret: str) -> str:
        if secret:
            return value.replace(secret, "[redacted]")
        return value

    @staticmethod
    def split_telegram_message(message: str, *, limit: int = TELEGRAM_MESSAGE_LIMIT) -> list[str]:
        if len(message) <= limit:
            return [message]
        chunks = []
        current_lines = []
        current_length = 0
        for line in message.splitlines():
            extra_length = len(line) + (1 if current_lines else 0)
            if current_lines and current_length + extra_length > limit:
                chunks.append("\n".join(current_lines))
                current_lines = []
                current_length = 0
            if len(line) > limit:
                if current_lines:
                    chunks.append("\n".join(current_lines))
                    current_lines = []
                    current_length = 0
                for start in range(0, len(line), limit):
                    chunks.append(line[start : start + limit])
                continue
            current_lines.append(line)
            current_length += len(line) + (1 if current_length else 0)
        if current_lines:
            chunks.append("\n".join(current_lines))
        return chunks

    @staticmethod
    def post_telegram_message(*, token: str, chat_id: str, text: str) -> None:
        url = f"{TELEGRAM_API_BASE_URL}/bot{token}/sendMessage"
        payload = json.dumps({"chat_id": chat_id, "text": text}).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                status = getattr(response, "status", None)
                if status is None:
                    status = response.getcode()
                if status < 200 or status >= 300:
                    body = response.read().decode("utf-8", errors="replace")[:500]
                    raise RuntimeError(f"Telegram API returned HTTP {status}: {body}")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"Telegram API returned HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Telegram API request failed: {exc.reason}") from exc

    @staticmethod
    def get_base_url() -> str:
        return (getattr(settings, "SITE_URL", "") or getattr(settings, "PUBLIC_BASE_URL", "")).rstrip("/")

    @staticmethod
    def recipient_hash(recipients: list[str]) -> str:
        normalized = ",".join(sorted(recipient.lower().strip() for recipient in recipients if recipient.strip()))
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
