from django.db import models


class SystemSettings(models.Model):
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
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

