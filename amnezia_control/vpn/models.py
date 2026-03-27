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

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="clients")
    name = models.CharField(max_length=120)
    protocol_type = models.CharField(max_length=16, choices=ProtocolType.choices)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.ACTIVE)
    profile = models.ForeignKey(ProtocolProfile, on_delete=models.PROTECT)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
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
    qr_payload = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("client", "revision_number", "protocol_type")
        ordering = ("-revision_number",)
