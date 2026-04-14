import hashlib
import hmac
import secrets

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import ClientPortalAccess


class PortalAccessService:
    TOKEN_BYTES = 32

    @classmethod
    def _hash_token(cls, token: str) -> str:
        digest_source = f"{settings.SECRET_KEY}:{token}".encode()
        return hashlib.sha256(digest_source).hexdigest()

    @classmethod
    @transaction.atomic
    def issue_for_client(cls, client):
        token = secrets.token_urlsafe(cls.TOKEN_BYTES)
        token_hash = cls._hash_token(token)
        access, _ = ClientPortalAccess.objects.get_or_create(
            client=client,
            defaults={"token_hash": token_hash, "enabled": True},
        )
        if access.token_hash != token_hash:
            access.token_hash = token_hash
        access.enabled = True
        access.revoked_at = None
        access.save(update_fields=["token_hash", "enabled", "revoked_at"])
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
            return None
        token_hash = cls._hash_token(token)
        access = (
            ClientPortalAccess.objects.select_related("client")
            .filter(token_hash=token_hash, enabled=True, revoked_at__isnull=True)
            .first()
        )
        if not access:
            return None
        if not hmac.compare_digest(token_hash, access.token_hash):
            return None
        return access

    @staticmethod
    def mark_accessed(access: ClientPortalAccess):
        access.last_access_at = timezone.now()
        access.save(update_fields=["last_access_at"])
