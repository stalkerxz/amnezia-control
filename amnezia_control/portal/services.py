import hashlib
import hmac
import secrets
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import ClientPortalAccess


class PortalResolveReason:
    INVALID = "invalid"
    REVOKED = "revoked"
    EXPIRED = "expired"


class PortalAccessService:
    TOKEN_BYTES = 32
    DEFAULT_EXPIRES_IN_DAYS = 30

    @classmethod
    def _hash_token(cls, token: str) -> str:
        digest_source = f"{settings.SECRET_KEY}:{token}".encode()
        return hashlib.sha256(digest_source).hexdigest()

    @classmethod
    @transaction.atomic
    def issue_for_client(cls, client):
        token = secrets.token_urlsafe(cls.TOKEN_BYTES)
        token_hash = cls._hash_token(token)
        expires_at = timezone.now() + timedelta(days=cls.DEFAULT_EXPIRES_IN_DAYS)
        access, _ = ClientPortalAccess.objects.get_or_create(
            client=client,
            defaults={"token_hash": token_hash, "enabled": True, "expires_at": expires_at},
        )
        if access.token_hash != token_hash:
            access.token_hash = token_hash
        access.enabled = True
        access.revoked_at = None
        access.expires_at = expires_at
        access.save(update_fields=["token_hash", "enabled", "revoked_at", "expires_at"])
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
