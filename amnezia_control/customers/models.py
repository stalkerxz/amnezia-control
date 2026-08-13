from django.conf import settings
from django.db import models


class CustomerAccount(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Активен"
        DISABLED = "disabled", "Отключён"
        DELETED = "deleted", "Удалён"

    display_name = models.CharField(max_length=120)
    email = models.EmailField(blank=True)

    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.ACTIVE,
    )

    # На первом этапе это именно срок аккаунта/подписки.
    # Старое VPNClient.expires_at пока сохраняется и продолжает работать.
    expires_at = models.DateTimeField(null=True, blank=True)

    # Клиентский логин подключим отдельным этапом.
    # Сейчас существующие accounts.User используются операторами.
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="customer_account",
    )

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_customer_accounts",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("display_name", "id")
        verbose_name = "Аккаунт клиента"
        verbose_name_plural = "Аккаунты клиентов"

    def __str__(self):
        return self.display_name


class ClientDevice(models.Model):
    class Status(models.TextChoices):
        ACTIVE = "active", "Активно"
        DISABLED = "disabled", "Отключено"
        DELETED = "deleted", "Удалено"

    class Platform(models.TextChoices):
        UNKNOWN = "unknown", "Не указано"
        IOS = "ios", "iPhone / iPad"
        ANDROID = "android", "Android"
        MACOS = "macos", "macOS"
        WINDOWS = "windows", "Windows"
        LINUX = "linux", "Linux"
        OTHER = "other", "Другое"

    account = models.ForeignKey(
        CustomerAccount,
        on_delete=models.CASCADE,
        related_name="devices",
    )

    name = models.CharField(max_length=120)

    platform = models.CharField(
        max_length=16,
        choices=Platform.choices,
        default=Platform.UNKNOWN,
    )

    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.ACTIVE,
    )

    notes = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("account_id", "name", "id")
        verbose_name = "Устройство клиента"
        verbose_name_plural = "Устройства клиентов"

    def __str__(self):
        return f"{self.account} — {self.name}"
