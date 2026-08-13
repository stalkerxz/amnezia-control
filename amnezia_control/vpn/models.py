import uuid

from django.db import models
from django.conf import settings
from servers.models import ProtocolProfile, Server


class VPNClient(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Активен"
        DISABLED = "disabled", "Отключен"
        DELETED = "deleted", "Удален"

    class ProtocolType(models.TextChoices):
        AWG = "awg", "AmneziaWG"
        AWG2 = "awg2", "AWG2"

    class LimitState(models.TextChoices):
        ACTIVE = "active", "Активен"
        EXPIRED = "expired", "Истек"
        TRAFFIC_EXCEEDED = "traffic_exceeded", "Трафик превышен"

    class DisableReason(models.TextChoices):
        NONE = "none", "Нет"
        MANUAL = "manual", "Вручную"
        EXPIRED = "expired", "Истек срок"
        TRAFFIC_EXCEEDED = "traffic_exceeded", "Превышен лимит трафика"
        OWNER = "owner", "Недоступен аккаунт/устройство"

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="clients")
    name = models.CharField(max_length=120)
    contact_email = models.EmailField(blank=True)
    protocol_type = models.CharField(max_length=16, choices=ProtocolType.choices)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    profile = models.ForeignKey(ProtocolProfile, on_delete=models.PROTECT)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)

    # Transitional relation for the multi-device account architecture.
    # Nullable so the schema change is non-destructive for existing clients.
    device = models.ForeignKey(
        "customers.ClientDevice",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="vpn_clients",
    )

    imported_from_runtime = models.BooleanField(default=False)
    runtime_peer_public_key = models.CharField(max_length=128, blank=True)
    runtime_address = models.CharField(max_length=64, blank=True)
    last_runtime_sync_at = models.DateTimeField(null=True, blank=True)

    expires_at = models.DateTimeField(null=True, blank=True)
    traffic_limit_bytes = models.BigIntegerField(null=True, blank=True)
    traffic_used_bytes = models.BigIntegerField(default=0)
    traffic_last_sync_at = models.DateTimeField(null=True, blank=True)
    traffic_sync_error = models.CharField(max_length=160, blank=True)
    limit_state = models.CharField(max_length=24, choices=LimitState.choices, default=LimitState.ACTIVE)
    disable_reason = models.CharField(max_length=24, choices=DisableReason.choices, default=DisableReason.NONE)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("server", "name", "protocol_type")

    def __str__(self):
        return self.name


class ClientConfigRevision(models.Model):
    client = models.ForeignKey(VPNClient, on_delete=models.CASCADE, related_name="revisions")
    revision_number = models.PositiveIntegerField()
    protocol_type = models.CharField(max_length=16, choices=VPNClient.ProtocolType.choices)
    config_blob_encrypted = models.TextField()
    config_hash = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("client", "revision_number", "protocol_type")
        ordering = ("-revision_number",)


class ClientExpirationReminderLog(models.Model):
    client = models.ForeignKey(VPNClient, on_delete=models.CASCADE, related_name="expiration_reminder_logs")
    threshold_days = models.PositiveIntegerField()
    expires_at_snapshot = models.DateTimeField()
    sent_at = models.DateTimeField(auto_now_add=True)
    recipient_hash = models.CharField(max_length=64, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["client", "threshold_days", "expires_at_snapshot"],
                name="unique_client_expiration_reminder",
            )
        ]
        ordering = ("-sent_at",)

    def __str__(self):
        return f"{self.client_id}:{self.threshold_days}:{self.expires_at_snapshot.isoformat()}"


class XHTTPDevice(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Активно"
        DISABLED = "disabled", "Отключено"
        DELETED = "deleted", "Удалено"

    class DisableReason(models.TextChoices):
        NONE = "none", "Нет"
        MANUAL = "manual", "Вручную"
        CLIENT = "client", "Недоступен аккаунт/устройство"

    # Transitional legacy relation.
    # Phase 4 keeps it temporarily so existing XHTTP rows and the old
    # operator flow continue to work while services move to ClientDevice.
    # Legacy compatibility relation.
    # New XHTTP/VLESS connections no longer require a VPNClient.
    client = models.ForeignKey(
        VPNClient,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="xhttp_devices",
    )

    # Logical owner of the VLESS/XHTTP connection.
    device = models.ForeignKey(
        "customers.ClientDevice",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="xhttp_devices",
    )

    # Runtime server is explicit. XHTTP must not infer its Xray host
    # from an unrelated AWG/AWG2 VPNClient.
    server = models.ForeignKey(
        "servers.Server",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="xhttp_devices",
    )

    name = models.CharField(max_length=120)
    client_uuid = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    xray_email = models.CharField(max_length=120, unique=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    disable_reason = models.CharField(
        max_length=16,
        choices=DisableReason.choices,
        default=DisableReason.NONE,
    )
    config_blob_encrypted = models.TextField()
    config_hash = models.CharField(max_length=64)
    last_applied_at = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["client", "name"],
                name="unique_xhttp_device_name_per_client",
            ),
            models.UniqueConstraint(
                fields=["device", "name"],
                name="unique_xhttp_name_per_device",
            ),
        ]
        ordering = ("-created_at",)

    def __str__(self):
        owner = self.device or self.client
        return f"{owner or 'XHTTP'} — {self.name}"
