from django import forms
from django.utils.translation import gettext_lazy as _

from .models import SystemSettings


class SystemSettingsForm(forms.ModelForm):
    class Meta:
        model = SystemSettings
        fields = (
            "default_account_lifetime_days",
            "default_renewal_extension_days",
            "portal_link_lifetime_days",
            "portal_renewal_cooldown_hours",
        )
        labels = {
            "default_account_lifetime_days": _(
                "Срок нового аккаунта по умолчанию (дней)"
            ),
            "default_renewal_extension_days": _(
                "Продление по умолчанию (дней)"
            ),
            "portal_link_lifetime_days": _(
                "Срок действия ссылки в кабинет (дней)"
            ),
            "portal_renewal_cooldown_hours": _(
                "Интервал повторного запроса продления (часов)"
            ),
        }
        widgets = {
            "default_account_lifetime_days": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "min": 1,
                    "max": 365,
                }
            ),
            "default_renewal_extension_days": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "min": 1,
                    "max": 365,
                }
            ),
            "portal_link_lifetime_days": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "min": 1,
                    "max": 365,
                }
            ),
            "portal_renewal_cooldown_hours": forms.NumberInput(
                attrs={
                    "class": "form-control",
                    "min": 1,
                    "max": 168,
                }
            ),
        }
