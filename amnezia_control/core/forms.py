from django import forms
from django.utils.translation import gettext_lazy as _

from .models import SystemSettings


class SystemSettingsForm(forms.ModelForm):
    class Meta:
        model = SystemSettings
        fields = (
            "default_account_lifetime_days",
            "default_renewal_extension_days",
            "expiration_reminders_enabled",
            "expiration_reminder_days",
            "notify_new_renewal_requests",
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
            "expiration_reminders_enabled": _(
                "Напоминания об истечении"
            ),
            "expiration_reminder_days": _(
                "Пороги напоминаний (дни)"
            ),
            "notify_new_renewal_requests": _(
                "Уведомлять о новых заявках на продление"
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
            "expiration_reminders_enabled": forms.CheckboxInput(
                attrs={
                    "class": "form-check-input",
                }
            ),
            "expiration_reminder_days": forms.TextInput(
                attrs={
                    "class": "form-control",
                    "placeholder": "7,3,1",
                    "inputmode": "numeric",
                }
            ),
            "notify_new_renewal_requests": forms.CheckboxInput(
                attrs={
                    "class": "form-check-input",
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

    def clean_expiration_reminder_days(self):
        raw_value = (
            self.cleaned_data.get(
                "expiration_reminder_days"
            )
            or ""
        ).strip()

        if not raw_value:
            raise forms.ValidationError(
                _(
                    "Укажите хотя бы один "
                    "порог от 1 до 365 дней."
                )
            )

        values = []

        for raw_part in raw_value.split(","):
            part = raw_part.strip()

            try:
                value = int(part)
            except (TypeError, ValueError):
                raise forms.ValidationError(
                    _(
                        "Пороги задаются числами "
                        "через запятую."
                    )
                )

            if value < 1 or value > 365:
                raise forms.ValidationError(
                    _(
                        "Каждый порог должен быть "
                        "от 1 до 365 дней."
                    )
                )

            if value not in values:
                values.append(value)

        values.sort(reverse=True)

        return ",".join(
            str(value)
            for value in values
        )
