from django.db import models
from django.db.models import Q
from django.conf import settings

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
    last_selfservice_reissue_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)
        verbose_name = "Доступ в кабинет клиента"
        verbose_name_plural = "Доступы в кабинет клиента"

    def __str__(self):
        return f"portal:{self.client_id}:{'enabled' if self.enabled else 'disabled'}"


class ClientRenewalRequest(models.Model):
    class Status(models.TextChoices):
        NEW = "new", "Новая"
        IN_PROGRESS = "in_progress", "В работе"
        DONE = "done", "Выполнена"
        DISMISSED = "dismissed", "Отклонена"

    client = models.ForeignKey(VPNClient, on_delete=models.CASCADE, related_name="renewal_requests")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.NEW)
    note = models.TextField(blank=True)
    operator_note = models.TextField(blank=True)
    created_from_portal = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    processed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="processed_renewal_requests",
    )

    class Meta:
        ordering = ("-created_at",)
        verbose_name = "Заявка на продление"
        verbose_name_plural = "Заявки на продление"
        constraints = [
            models.UniqueConstraint(
                fields=("client",),
                condition=Q(status__in=["new", "in_progress"]),
                name="uniq_open_renewal_request_per_client",
            )
        ]

    def __str__(self):
        return f"renewal:{self.client_id}:{self.status}"

    @property
    def is_open(self) -> bool:
        return self.status in {self.Status.NEW, self.Status.IN_PROGRESS}
