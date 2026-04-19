import hashlib
import hmac
import secrets
from datetime import timedelta

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from core.services import get_portal_link_lifetime_days
from vpn.models import VPNClient
from vpn.services import VPNClientPolicyService

from .models import ClientPortalAccess, ClientRenewalRequest


class PortalResolveReason:
    INVALID = "invalid"
    REVOKED = "revoked"
    EXPIRED = "expired"


class PortalAccessService:
    TOKEN_BYTES = 32
    STATUS_ACTIVE = "active"
    STATUS_EXPIRED = "expired"
    STATUS_REVOKED = "revoked"
    STATUS_NOT_ISSUED = "not_issued"

    @classmethod
    def _hash_token(cls, token: str) -> str:
        digest_source = f"{settings.SECRET_KEY}:{token}".encode()
        return hashlib.sha256(digest_source).hexdigest()

    @staticmethod
    def _fernet() -> Fernet:
        key = settings.CONFIG_ENCRYPTION_KEY
        if not key:
            raise ValueError("CONFIG_ENCRYPTION_KEY is required")
        return Fernet(key.encode())

    @classmethod
    def _encrypt_token(cls, token: str) -> str:
        return cls._fernet().encrypt(token.encode()).decode()

    @classmethod
    def _decrypt_token(cls, token_encrypted: str) -> str | None:
        if not token_encrypted:
            return None
        try:
            return cls._fernet().decrypt(token_encrypted.encode()).decode()
        except InvalidToken:
            return None

    @classmethod
    @transaction.atomic
    def issue_for_client(cls, client):
        token = secrets.token_urlsafe(cls.TOKEN_BYTES)
        token_hash = cls._hash_token(token)
        token_encrypted = cls._encrypt_token(token)
        expires_at = timezone.now() + timedelta(days=get_portal_link_lifetime_days())
        access, _ = ClientPortalAccess.objects.get_or_create(
            client=client,
            defaults={"token_hash": token_hash, "token_encrypted": token_encrypted, "enabled": True, "expires_at": expires_at},
        )
        if access.token_hash != token_hash:
            access.token_hash = token_hash
        access.token_encrypted = token_encrypted
        access.enabled = True
        access.revoked_at = None
        access.expires_at = expires_at
        access.save(update_fields=["token_hash", "token_encrypted", "enabled", "revoked_at", "expires_at"])
        return access, token

    @staticmethod
    @transaction.atomic
    def revoke_for_client(client):
        access = ClientPortalAccess.objects.filter(client=client).first()
        if not access:
            return None
        access.enabled = False
        access.revoked_at = timezone.now()
        access.save(update_fields=["enabled", "revoked_at"])
        return access

    @classmethod
    def resolve_token(cls, token: str):
        if not token or len(token) < 40:
            return None, PortalResolveReason.INVALID

        token_hash = cls._hash_token(token)
        access = ClientPortalAccess.objects.select_related("client").filter(token_hash=token_hash).first()
        if not access:
            return None, PortalResolveReason.INVALID

        if not hmac.compare_digest(token_hash, access.token_hash):
            return None, PortalResolveReason.INVALID

        if not access.enabled or access.revoked_at:
            return None, PortalResolveReason.REVOKED

        if access.expires_at and access.expires_at <= timezone.now():
            return None, PortalResolveReason.EXPIRED

        return access, None

    @staticmethod
    def mark_accessed(access: ClientPortalAccess):
        access.last_access_at = timezone.now()
        access.save(update_fields=["last_access_at"])

    @classmethod
    def get_raw_token_for_client(cls, client) -> str | None:
        access = ClientPortalAccess.objects.filter(client=client).first()
        if cls.get_status_for_access(access) != cls.STATUS_ACTIVE:
            return None
        return cls._decrypt_token(access.token_encrypted)

    @classmethod
    def get_status_for_access(cls, access: ClientPortalAccess | None) -> str:
        if not access:
            return cls.STATUS_NOT_ISSUED
        if not access.enabled or access.revoked_at:
            return cls.STATUS_REVOKED
        if access.expires_at and access.expires_at <= timezone.now():
            return cls.STATUS_EXPIRED
        return cls.STATUS_ACTIVE


class RenewalRequestService:
    OPEN_STATUSES = (ClientRenewalRequest.Status.NEW, ClientRenewalRequest.Status.IN_PROGRESS)

    @classmethod
    @transaction.atomic
    def create_or_get_open_from_portal(cls, *, client, note: str = "", attachment=None):
        request_obj = (
            ClientRenewalRequest.objects.select_for_update()
            .filter(client=client, status__in=cls.OPEN_STATUSES)
            .order_by("-created_at")
            .first()
        )
        if request_obj:
            if note and not request_obj.note:
                request_obj.note = note
                request_obj.save(update_fields=["note", "updated_at"])
            if attachment and not request_obj.attachment:
                request_obj.attachment = attachment
                request_obj.attachment_original_name = (attachment.name or "")[:255]
                request_obj.save(update_fields=["attachment", "attachment_original_name", "updated_at"])
            return request_obj, False

        request_obj = ClientRenewalRequest.objects.create(
            client=client,
            status=ClientRenewalRequest.Status.NEW,
            note=note,
            created_from_portal=True,
            attachment=attachment,
            attachment_original_name=((attachment.name or "")[:255] if attachment else ""),
        )
        return request_obj, True

    @classmethod
    def get_open_for_client(cls, *, client):
        return (
            ClientRenewalRequest.objects.filter(client=client, status__in=cls.OPEN_STATUSES)
            .order_by("-created_at")
            .first()
        )


    @classmethod
    def get_latest_for_client(cls, *, client):
        return ClientRenewalRequest.objects.filter(client=client).order_by("-created_at").first()


class PortalReissuePolicyService:
    COOLDOWN_HOURS = 12

    @classmethod
    def cooldown_timedelta(cls):
        return timedelta(hours=cls.COOLDOWN_HOURS)

    @classmethod
    def can_selfservice_reissue(cls, *, access: ClientPortalAccess):
        client = access.client
        if client.status != VPNClient.Status.ACTIVE:
            return False, "Переиздание недоступно: обратитесь к оператору."
        if not client.revisions.exists():
            return False, "Конфигурация ещё не готова. Обратитесь к оператору."
        block_reason = VPNClientPolicyService.reissue_block_reason(client)
        if block_reason:
            return False, block_reason
        if access.last_selfservice_reissue_at:
            next_allowed_at = access.last_selfservice_reissue_at + cls.cooldown_timedelta()
            if next_allowed_at > timezone.now():
                return False, cls.cooldown_message(next_allowed_at)
        return True, ""

    @staticmethod
    def cooldown_message(next_allowed_at):
        local_time = timezone.localtime(next_allowed_at).strftime("%d.%m.%Y %H:%M")
        return f"Переиздать конфигурацию можно позже. Следующая попытка будет доступна после {local_time}."
