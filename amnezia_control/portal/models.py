from django.db import models

from vpn.models import VPNClient


class ClientPortalAccess(models.Model):
    client = models.OneToOneField(VPNClient, on_delete=models.CASCADE, related_name="portal_access")
    token_hash = models.CharField(max_length=64, unique=True)
    token_encrypted = models.TextField(blank=True, null=True)
    enabled = models.BooleanField(default=True)
    last_access_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return f"portal:{self.client_id}:{'enabled' if self.enabled else 'disabled'}"
