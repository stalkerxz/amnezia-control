from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    is_owner = models.BooleanField(default=True, verbose_name="Владелец")

    class Meta:
        verbose_name = "Пользователь"
        verbose_name_plural = "Пользователи"
