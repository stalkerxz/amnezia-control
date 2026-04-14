import hashlib
import hmac
import secrets
from datetime import timedelta

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from core.services import get_portal_link_lifetime_days

from .models import ClientPortalAccess


class PortalResolveReason:
    INVALID = "invalid"
    REVOKED = "revoked"
    EXPIRED = "expired"


class PortalAccessService:
    TOKEN_BYTES = 32

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
        if not access or not access.enabled or access.revoked_at:
            return None
        return cls._decrypt_token(access.token_encrypted)
