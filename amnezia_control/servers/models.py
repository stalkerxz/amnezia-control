from django.db import models


class Server(models.Model):
    name = models.CharField(max_length=120, unique=True)
    host = models.CharField(max_length=255, default="127.0.0.1")
    port = models.PositiveIntegerField(default=22)
    ssh_username = models.CharField(max_length=120, default="amnezia")
    ssh_private_key_path = models.CharField(max_length=255, blank=True)
    is_enabled = models.BooleanField(default=True)
    health_status = models.CharField(max_length=30, default="unknown")
    last_runtime_sync_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class ServerProtocol(models.Model):
    class ProtocolType(models.TextChoices):
        AWG = "awg", "AmneziaWG"
        AWG2 = "awg2", "AWG2"

    server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="protocols")
    protocol_type = models.CharField(max_length=16, choices=ProtocolType.choices)
    enabled = models.BooleanField(default=True)
    container_name = models.CharField(max_length=120, blank=True)
    container_status = models.CharField(max_length=32, blank=True)
    runtime_metadata = models.JSONField(default=dict, blank=True)
    last_sync_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        unique_together = ("server", "protocol_type")

    def __str__(self):
        return f"{self.server} - {self.protocol_type}"


class ProtocolProfile(models.Model):
    class ProfileStatus(models.TextChoices):
        ACTIVE = "active", "Active"
        ARCHIVED = "archived", "Archived"

    server_protocol = models.ForeignKey(ServerProtocol, on_delete=models.CASCADE, related_name="profiles")
    name = models.CharField(max_length=120)
    protocol_type = models.CharField(max_length=16, choices=ServerProtocol.ProtocolType.choices)
    config_template = models.TextField()
    status = models.CharField(max_length=16, choices=ProfileStatus.choices, default=ProfileStatus.ACTIVE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("server_protocol", "name", "protocol_type")

    def __str__(self):
        return f"{self.name} ({self.protocol_type})"
