from django.core.validators import (
    MaxValueValidator,
    MinValueValidator,
)
from django.db import models


class SystemSettings(models.Model):
    default_account_lifetime_days = models.PositiveIntegerField(
        default=30,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(365),
        ],
    )

    default_renewal_extension_days = models.PositiveIntegerField(
        default=30,
        validators=[
            MinValueValidator(1),
            MaxValueValidator(365),
        ],
    )

    expiration_reminders_enabled = models.BooleanField(
        default=True,
    )

    expiration_reminder_days = models.CharField(
        max_length=64,
        default="7,3,1",
    )

    notify_new_renewal_requests = models.BooleanField(
        default=True,
    )

    portal_link_lifetime_days = models.PositiveIntegerField(default=30)
    portal_renewal_cooldown_hours = models.PositiveIntegerField(default=24)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Системные настройки"
        verbose_name_plural = "Системные настройки"

    def __str__(self):
        return "Системные настройки"

    @classmethod
    def get_solo(cls):
        by_primary = cls.objects.filter(pk=1).first()
        if by_primary:
            return by_primary

        existing = cls.objects.order_by("pk").first()
        if existing:
            return existing

        return cls.objects.create(pk=1)
